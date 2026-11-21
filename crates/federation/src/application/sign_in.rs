//! Signing in through a provider: the pending authorization there and back, and who the
//! person turns out to be.
//!
//! See `docs/architecture/contexts/federation.md`, "Signing in through a
//! provider". The rule that matters most is in `resolve`: an external
//! identity is never let into an existing account because of an email
//! address.

use crate::application::openid::{OpenIdClient, VerifiedIdentity};
use crate::application::ports::PendingAuthorizationStore;
use crate::application::service::FederationService;
use crate::domain::event::FederationEvent;
use crate::domain::pending_authorization::PendingAuthorization;
use crate::domain::provider::{IdentityProvider, ProviderId};
use hodor_authentication::api::{
    AuthTransaction, Authenticator, AuthenticatorTraits, ExternalInput, Factor, StepInput,
    StepOutcome, TransactionId,
};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, ErrorKind, EventEnvelope, EventMetadata, Secret, SecretBox,
    TenantContext, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;
use time::Duration;

/// The key of the alternative, in flows and in what is submitted to it.
pub const EXTERNAL_STEP: &str = "external";
/// The purpose PKCE verifiers are sealed for.
const CODE_VERIFIER: &str = "federation.code_verifier";
/// A pending authorization lasts as long as a sign-in.
const PENDING_LIFETIME: Duration = Duration::minutes(10);

/// A provider as the sign-in page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedProvider {
    /// Its name in addresses.
    pub alias: String,
    /// What a person reads.
    pub display_name: String,
}

/// Why a sign-in through a provider was refused: recorded, never shown.
struct Refusal {
    provider_id: Option<ProviderId>,
    reason: &'static str,
    detail: Option<String>,
}

impl Refusal {
    const fn new(provider_id: Option<ProviderId>, reason: &'static str) -> Self {
        Self {
            provider_id,
            reason,
            detail: None,
        }
    }
}

/// The page a provider sends people back to: the address to register at
/// the provider. `public_url` is the address people reach this
/// installation at, without a path.
#[must_use]
pub fn callback_address(public_url: &str, tenant_slug: &str, alias: &str) -> String {
    format!(
        "{}/t/{tenant_slug}/account/providers/{alias}/callback",
        public_url.trim_end_matches('/')
    )
}

/// The use cases of signing in through a provider.
#[derive(Clone)]
pub struct ExternalSignIn {
    federation: FederationService,
    openid: OpenIdClient,
    identity: IdentityService,
    pending: Arc<dyn PendingAuthorizationStore>,
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    secrets: Arc<dyn SecretBox>,
    digest: Arc<dyn Digest>,
    clock: Arc<dyn Clock>,
    public_url: String,
}

impl std::fmt::Debug for ExternalSignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalSignIn").finish_non_exhaustive()
    }
}

impl ExternalSignIn {
    /// Wires the use cases to what they need. `public_url` is the address
    /// people reach this installation at, without a path.
    #[allow(clippy::too_many_arguments, reason = "one argument per port")]
    #[must_use]
    pub fn new(
        federation: FederationService,
        openid: OpenIdClient,
        identity: IdentityService,
        pending: Arc<dyn PendingAuthorizationStore>,
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        secrets: Arc<dyn SecretBox>,
        digest: Arc<dyn Digest>,
        clock: Arc<dyn Clock>,
        public_url: &str,
    ) -> Self {
        Self {
            federation,
            openid,
            identity,
            pending,
            units_of_work,
            secrets,
            digest,
            clock,
            public_url: public_url.trim_end_matches('/').to_owned(),
        }
    }

    /// The providers the tenant offers on its sign-in page: the enabled
    /// ones, by alias.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn offered(
        &self,
        tenant: &TenantContext,
    ) -> Result<Vec<OfferedProvider>, DomainError> {
        Ok(self
            .federation
            .providers(tenant)
            .await?
            .into_iter()
            .filter(IdentityProvider::is_enabled)
            .map(|provider| OfferedProvider {
                alias: provider.alias().as_str().to_owned(),
                display_name: provider.snapshot().settings.display_name.clone(),
            })
            .collect())
    }

    /// The page a provider sends people back to: the address to register
    /// at the provider.
    #[must_use]
    pub fn callback_address(&self, tenant_slug: &str, alias: &str) -> String {
        callback_address(&self.public_url, tenant_slug, alias)
    }

    /// An enabled provider of the tenant, by alias. A disabled one is
    /// answered like one that does not exist.
    async fn enabled(
        &self,
        tenant: &TenantContext,
        alias: &str,
    ) -> Result<IdentityProvider, DomainError> {
        let provider = self.federation.provider_by_alias(tenant, alias).await?;
        if provider.is_enabled() {
            Ok(provider)
        } else {
            Err(DomainError::not_found(
                "federation.provider_not_found",
                "there is no such identity provider",
            ))
        }
    }

    /// Starts the pending authorization of a sign-in to a provider and answers with the
    /// address at the provider to send the person to. A pending authorization the sign-in
    /// already had is replaced.
    ///
    /// # Errors
    ///
    /// Returns `federation.provider_not_found` if the tenant has no
    /// enabled provider with this alias, and
    /// `federation.provider_unavailable` if the provider cannot be used.
    pub async fn begin(
        &self,
        tenant: &TenantContext,
        tenant_slug: &str,
        transaction_id: TransactionId,
        alias: &str,
    ) -> Result<String, DomainError> {
        let provider = self.enabled(tenant, alias).await?;
        let redirect_uri = self.callback_address(tenant_slug, provider.alias().as_str());
        let request = self.openid.begin(&provider, &redirect_uri).await?;

        let verifier = Secret::new(request.code_verifier.expose().clone().into_bytes());
        let pending = PendingAuthorization {
            transaction_id,
            provider_id: provider.id(),
            state_hash: self.digest.sha256(request.state.as_bytes()),
            nonce: request.nonce,
            code_verifier: self.secrets.seal(tenant, CODE_VERIFIER, &verifier)?,
            redirect_uri,
            expires_at: self.clock.now() + PENDING_LIFETIME,
        };
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.pending.put(uow.as_mut(), &pending).await?;
        uow.commit().await?;
        Ok(request.url)
    }

    /// Takes the pending authorization of a sign-in, so that it cannot be finished twice.
    async fn take_pending(
        &self,
        tenant: &TenantContext,
        transaction_id: TransactionId,
    ) -> Result<Option<PendingAuthorization>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let pending = self.pending.take(uow.as_mut(), transaction_id).await?;
        uow.commit().await?;
        Ok(pending)
    }

    /// Finishes the pending authorization of a sign-in with what the provider sent back.
    /// Answers the user who signed in, or why nobody did.
    async fn finish(
        &self,
        tenant: &TenantContext,
        transaction_id: TransactionId,
        input: &ExternalInput,
    ) -> Result<Result<UserId, Refusal>, DomainError> {
        // The pending authorization is gone before anything is checked.
        let Some(pending) = self.take_pending(tenant, transaction_id).await? else {
            return Ok(Err(Refusal::new(None, "no_pending_authorization")));
        };
        let refuse = |reason| Ok(Err(Refusal::new(Some(pending.provider_id), reason)));
        if self.clock.now() >= pending.expires_at {
            return refuse("authorization_expired");
        }
        let (Some(alias), Some(code), Some(state)) = (
            input.field("provider"),
            input.field("code"),
            input.field("state"),
        ) else {
            return refuse("answer_incomplete");
        };
        if self.digest.sha256(state.expose().as_bytes()) != pending.state_hash {
            return refuse("state_mismatch");
        }
        let provider = match self.enabled(tenant, alias.expose()).await {
            Ok(provider) if provider.id() == pending.provider_id => provider,
            Ok(_) => return refuse("another_provider"),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return refuse("provider_not_offered");
            }
            Err(error) => return Err(error),
        };

        let opened = self
            .secrets
            .open(tenant, CODE_VERIFIER, &pending.code_verifier)?;
        let code_verifier = String::from_utf8(opened.expose().clone())
            .map(Secret::new)
            .map_err(|_| hodor_kernel::sealing::unreadable("the code verifier is not text"))?;
        let client_secret = self.federation.client_secret(tenant, &provider)?;
        let identity = match self
            .openid
            .finish(
                &provider,
                &client_secret,
                &pending.redirect_uri,
                code.expose(),
                &code_verifier,
                &pending.nonce,
            )
            .await
        {
            Ok(identity) => identity,
            Err(error) if error.code() == "federation.identity_not_verified" => {
                return Ok(Err(Refusal {
                    provider_id: Some(provider.id()),
                    reason: "answer_refused",
                    detail: error.detail().map(str::to_owned),
                }));
            }
            Err(error) => return Err(error),
        };

        self.resolve(tenant, &provider, identity).await
    }

    /// Who an external identity is in this tenant: the user it is linked
    /// to, or a user created for it. Never an existing user it is not
    /// linked to.
    async fn resolve(
        &self,
        tenant: &TenantContext,
        provider: &IdentityProvider,
        identity: VerifiedIdentity,
    ) -> Result<Result<UserId, Refusal>, DomainError> {
        let refuse = |reason| Ok(Err(Refusal::new(Some(provider.id()), reason)));
        let mut uow = self.units_of_work.begin(tenant).await?;

        // By the provider and the subject, and by nothing else.
        let linked = self
            .federation
            .find_user(uow.as_mut(), provider.id(), &identity.subject)
            .await?;
        if let Some(user_id) = linked {
            let may_sign_in = match self.identity.get(tenant, user_id).await {
                Ok(user) => user.may_sign_in(),
                Err(error) if error.kind() == ErrorKind::NotFound => false,
                Err(error) => return Err(error),
            };
            if !may_sign_in {
                return refuse("user_may_not_sign_in");
            }
            self.federation
                .mark_used(uow.as_mut(), provider.id(), &identity.subject)
                .await?;
            uow.commit().await?;
            return Ok(Ok(user_id));
        }

        if !provider.snapshot().settings.creates_users {
            return refuse("not_linked");
        }
        // A user needs a login identifier, and an address nobody vouches
        // for is not one.
        let Some(email) = identity.email.filter(|_| identity.email_verified) else {
            return refuse("no_vouched_email");
        };
        let command = CreateUser {
            kind: UserKind::Human,
            identifiers: vec![(IdentifierKind::Email, email)],
            profile: Profile {
                display_name: identity.name,
                locale: identity.locale,
            },
            confirmed: true,
        };
        let caller = Caller::system();
        let user = match self
            .identity
            .create_in(uow.as_mut(), command, true, caller)
            .await
        {
            Ok(user) => user,
            // The address belongs to a user that exists. This is where an
            // account would be taken over if the two were joined: they
            // are not, and the existing account is left as it was.
            Err(error) if error.code() == "identity.identifier_taken" => {
                return refuse("email_belongs_to_a_user");
            }
            // What the provider said about the person breaks a rule of
            // this tenant's users.
            Err(error) if error.kind() == ErrorKind::Invalid => {
                return refuse("profile_not_usable");
            }
            Err(error) => return Err(error),
        };
        match self
            .federation
            .link(
                uow.as_mut(),
                provider.id(),
                identity.subject,
                user.id(),
                caller,
            )
            .await
        {
            Ok(()) => {}
            // The same person finished two first sign-ins at once; the
            // other one made the link. Nothing of this one is stored.
            Err(error) if error.code() == "federation.identity_already_linked" => {
                return refuse("linked_meanwhile");
            }
            Err(error) => return Err(error),
        }
        uow.commit().await?;
        Ok(Ok(user.id()))
    }

    /// Records why a sign-in was refused, for whoever reads the audit log.
    async fn record_refusal(
        &self,
        tenant: &TenantContext,
        refusal: Refusal,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let caller = Caller::system();
        let metadata = EventMetadata::new(
            tenant.tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.clock.as_ref(),
        );
        let event = FederationEvent::SignInRefused {
            provider_id: refusal.provider_id,
            reason: refusal.reason,
            detail: refusal.detail,
        };
        uow.record_event(EventEnvelope::new(metadata, &event)?);
        uow.commit().await
    }
}

/// The authenticator of the `external` alternative: it establishes who is
/// signing in and proves it, on the word of a provider.
#[derive(Debug, Clone)]
pub struct ExternalIdentityAuthenticator {
    sign_in: ExternalSignIn,
}

impl ExternalIdentityAuthenticator {
    /// Wraps the use cases as an authenticator.
    #[must_use]
    pub const fn new(sign_in: ExternalSignIn) -> Self {
        Self { sign_in }
    }
}

#[async_trait::async_trait]
impl Authenticator for ExternalIdentityAuthenticator {
    fn kind(&self) -> &'static str {
        EXTERNAL_STEP
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: true,
            // One factor. Which kind is not known: Hodor does not know
            // how the provider convinced itself.
            factor: Some(Factor::Knowledge),
            method: Some(EXTERNAL_STEP),
        }
    }

    async fn perform(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let StepInput::External(input) = input else {
            return Ok(StepOutcome::Rejected);
        };
        match self.sign_in.finish(tenant, transaction.id(), input).await? {
            Ok(user) => Ok(StepOutcome::Authenticated { user }),
            Err(refusal) => {
                self.sign_in.record_refusal(tenant, refusal).await?;
                Ok(StepOutcome::Rejected)
            }
        }
    }
}
