//! Signing in through a provider: the way there and back, and who the
//! person turns out to be.
//!
//! See `docs/architecture/contexts/federation.md`, "Signing in through a
//! provider". The rule that matters most is in `resolve`: an external
//! identity is never let into an existing account because of an email
//! address.

use crate::application::github::GitHubClient;
use crate::application::openid::{OpenIdClient, VerifiedIdentity};
use crate::application::ports::{
    DirectoryAnswer, DirectoryClient, DirectoryQuery, LockoutPolicy, PendingAuthorizationStore,
};
use crate::application::saml::{self, SamlClient};
use crate::application::service::FederationService;
use crate::domain::event::FederationEvent;
use crate::domain::link::Subject;
use crate::domain::pending_authorization::{PendingAuthorization, SamlAnswer};
use crate::domain::provider::{IDENTIFIER_PLACE, IdentityProvider, ProviderId, ProviderKind};
use hodor_authentication::api::{
    AttemptGuard, AuthTransaction, Authenticator, AuthenticatorTraits, ExternalInput, Factor,
    StepInput, StepOutcome, TransactionId,
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
/// The purpose the PKCE verifier of a pending authorization is sealed for.
pub const CODE_VERIFIER: &str = "federation.code_verifier";
/// A pending authorization lasts as long as a sign-in.
const PENDING_LIFETIME: Duration = Duration::minutes(10);

/// A provider as the sign-in page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedProvider {
    /// Its name in addresses.
    pub alias: String,
    /// What a person reads.
    pub display_name: String,
    /// How a person signs in through it: by leaving for it, or, for a
    /// directory, by typing an identifier and a password here.
    pub kind: ProviderKind,
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
    github: GitHubClient,
    saml: SamlClient,
    identity: IdentityService,
    pending: Arc<dyn PendingAuthorizationStore>,
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    secrets: Arc<dyn SecretBox>,
    digest: Arc<dyn Digest>,
    clock: Arc<dyn Clock>,
    public_url: String,
    /// What signing in through a directory needs; `None` when this
    /// installation uses no directory.
    directories: Option<Directories>,
}

/// What signing in through a directory needs.
#[derive(Clone)]
struct Directories {
    client: Arc<dyn DirectoryClient>,
    guard: AttemptGuard,
    policy: Arc<dyn LockoutPolicy>,
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
        github: GitHubClient,
        saml: SamlClient,
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
            github,
            saml,
            identity,
            pending,
            units_of_work,
            secrets,
            digest,
            clock,
            public_url: public_url.trim_end_matches('/').to_owned(),
            directories: None,
        }
    }

    /// The same use cases, able to sign people in through directories:
    /// with the client that asks them, and what counts attempts.
    #[must_use]
    pub fn with_directories(
        mut self,
        client: Arc<dyn DirectoryClient>,
        guard: AttemptGuard,
        policy: Arc<dyn LockoutPolicy>,
    ) -> Self {
        self.directories = Some(Directories {
            client,
            guard,
            policy,
        });
        self
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
                kind: provider.snapshot().kind,
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
        let mut redirect_uri = self.callback_address(tenant_slug, provider.alias().as_str());
        let request = match provider.snapshot().kind {
            ProviderKind::OpenIdConnect => self.openid.begin(&provider, &redirect_uri).await?,
            ProviderKind::GitHub => self.github.begin(&provider, &redirect_uri),
            ProviderKind::Saml => {
                let settings = saml::settings_of(&provider).ok_or_else(|| {
                    DomainError::internal(
                        "federation.stored_data_invalid",
                        "a SAML provider has no SAML settings",
                    )
                })?;
                // What a SAML provider answers at, and checks the response
                // against, is the assertion consumer address.
                redirect_uri = saml::saml_assertion_consumer_address(
                    &self.public_url,
                    tenant_slug,
                    provider.alias().as_str(),
                );
                let service_provider = saml::service_provider_at(&redirect_uri);
                self.saml
                    .begin(settings, &service_provider, self.clock.now())
            }
            // Nobody leaves for a directory.
            ProviderKind::Ldap => {
                return Err(DomainError::not_found(
                    "federation.provider_not_found",
                    "there is no such identity provider",
                ));
            }
        };

        let verifier = Secret::new(request.code_verifier.expose().clone().into_bytes());
        let pending = PendingAuthorization {
            transaction_id,
            provider_id: provider.id(),
            state_hash: self.digest.sha256(request.state.as_bytes()),
            nonce: request.nonce,
            code_verifier: self.secrets.seal(tenant, CODE_VERIFIER, &verifier).await?,
            redirect_uri,
            expires_at: self.clock.now() + PENDING_LIFETIME,
            saml_answer: None,
            saml_receipt_hash: None,
        };
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.pending.put(uow.as_mut(), &pending).await?;
        uow.commit().await?;
        Ok(request.url)
    }

    /// Hodor's metadata for a SAML provider of the tenant, to give the
    /// identity provider.
    ///
    /// # Errors
    ///
    /// Returns `federation.provider_not_found` if the tenant has no
    /// enabled SAML provider with this alias.
    pub async fn saml_metadata(
        &self,
        tenant: &TenantContext,
        tenant_slug: &str,
        alias: &str,
    ) -> Result<String, DomainError> {
        let provider = self.enabled(tenant, alias).await?;
        if provider.snapshot().kind != ProviderKind::Saml {
            return Err(DomainError::not_found(
                "federation.provider_not_found",
                "there is no such identity provider",
            ));
        }
        Ok(hodor_saml::metadata(&saml::saml_service_provider(
            &self.public_url,
            tenant_slug,
            provider.alias().as_str(),
        )))
    }

    /// Checks the response a SAML identity provider posted, as it arrives,
    /// against the request of the pending authorization whose state hashes
    /// to `relay_state`, and keeps only its answer there; the response itself
    /// is never stored. Answers with a new receipt for the browser that
    /// posted it: only that browser can finish with the answer. A receipt is
    /// made whether or not there was a pending authorization: the caller
    /// answers the same way.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn keep_saml_response(
        &self,
        tenant: &TenantContext,
        alias: &str,
        relay_state: &str,
        response: &str,
    ) -> Result<String, DomainError> {
        let receipt = self.saml.receipt();
        let provider = match self.enabled(tenant, alias).await {
            Ok(provider) if provider.snapshot().kind == ProviderKind::Saml => provider,
            Ok(_) => return Ok(receipt),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(receipt),
            Err(error) => return Err(error),
        };
        // Only what could be a response is kept: base64, in lines.
        let base64 = response.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'\r' | b'\n')
        });
        if response.is_empty()
            || response.len() > hodor_saml::MAX_POSTED_BYTES
            || !base64
            || relay_state.is_empty()
        {
            return Ok(receipt);
        }
        let state_hash = self.digest.sha256(relay_state.as_bytes());
        let receipt_hash = self.digest.sha256(receipt.as_bytes());
        // Claimed first, in one step: of several responses posted at once for
        // one sign-in, only the one that claims it is checked.
        let mut uow = self.units_of_work.begin(tenant).await?;
        let pending = self
            .pending
            .claim(
                uow.as_mut(),
                provider.id(),
                state_hash,
                receipt_hash,
                self.clock.now(),
            )
            .await?;
        uow.commit().await?;
        // Nothing is checked for a relay state no sign-in is waiting with.
        let Some(pending) = pending else {
            return Ok(receipt);
        };

        // Checked now, against the request of that sign-in; only the answer
        // is kept, never the response.
        let service_provider = saml::service_provider_at(&pending.redirect_uri);
        let answer = match saml::settings_of(&provider) {
            None => SamlAnswer::Refused {
                reason: "another_kind",
            },
            Some(settings) => match SamlClient::finish(
                &provider,
                settings,
                &service_provider,
                response,
                &pending.nonce,
                self.clock.now(),
            ) {
                Ok(identity) => SamlAnswer::Verified {
                    subject: identity.subject,
                    email: identity.email,
                    name: identity.name,
                },
                Err(reason) => SamlAnswer::Refused { reason },
            },
        };
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.pending
            .answer(
                uow.as_mut(),
                provider.id(),
                state_hash,
                receipt_hash,
                &answer,
            )
            .await?;
        uow.commit().await?;
        Ok(receipt)
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
        let (Some(alias), Some(state)) = (input.field("provider"), input.field("state")) else {
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

        if provider.snapshot().kind == ProviderKind::Saml {
            return self
                .finish_with_saml(tenant, &provider, &pending, input)
                .await;
        }
        let Some(code) = input.field("code") else {
            return refuse("answer_incomplete");
        };
        let opened = self
            .secrets
            .open(tenant, CODE_VERIFIER, &pending.code_verifier)
            .await?;
        let code_verifier = String::from_utf8(opened.expose().clone())
            .map(Secret::new)
            .map_err(|_| hodor_kernel::sealing::unreadable("the code verifier is not text"))?;
        let client_secret = self.federation.client_secret(tenant, &provider).await?;
        let answered = match provider.snapshot().kind {
            ProviderKind::OpenIdConnect => {
                self.openid
                    .finish(
                        &provider,
                        &client_secret,
                        &pending.redirect_uri,
                        code.expose(),
                        &code_verifier,
                        &pending.nonce,
                    )
                    .await
            }
            // A directory has no pending authorization to finish, and a
            // SAML provider was finished above.
            ProviderKind::Ldap | ProviderKind::Saml => return refuse("another_kind"),
            ProviderKind::GitHub => {
                self.github
                    .finish(
                        &provider,
                        &client_secret,
                        &pending.redirect_uri,
                        code.expose(),
                    )
                    .await
            }
        };
        let identity = match answered {
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

    /// Finishes the pending authorization of a SAML sign-in with the
    /// response kept for it, checked against this sign-in's request.
    async fn finish_with_saml(
        &self,
        tenant: &TenantContext,
        provider: &IdentityProvider,
        pending: &PendingAuthorization,
        input: &ExternalInput,
    ) -> Result<Result<UserId, Refusal>, DomainError> {
        let refuse = |reason| Ok(Err(Refusal::new(Some(provider.id()), reason)));
        let (Some(answer), Some(kept_receipt)) =
            (pending.saml_answer.as_ref(), pending.saml_receipt_hash)
        else {
            return refuse("no_response");
        };
        // The browser that finishes must be the one that carried the
        // response here: whoever started the sign-in knows its state, and
        // could have handed the address at the identity provider to
        // somebody else.
        let carried = input
            .field("receipt")
            .is_some_and(|receipt| self.digest.sha256(receipt.expose().as_bytes()) == kept_receipt);
        if !carried {
            return refuse("receipt_mismatch");
        }
        match answer {
            SamlAnswer::Refused { reason } => refuse(reason),
            SamlAnswer::Verified {
                subject,
                email,
                name,
            } => {
                let identity = VerifiedIdentity {
                    subject: subject.clone(),
                    email: email.clone(),
                    // SAML has no way of saying whether an address is
                    // vouched for; that is the provider's setting.
                    email_verified: false,
                    name: name.clone(),
                    locale: None,
                };
                self.resolve(tenant, provider, identity).await
            }
        }
    }

    /// Signs a person in through a directory, with what they typed.
    /// Answers the user who signed in, or why nobody did.
    async fn finish_with_directory(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        input: &ExternalInput,
    ) -> Result<Result<UserId, Refusal>, DomainError> {
        let (Some(alias), Some(identifier), Some(password)) = (
            input.field("provider"),
            input.field("identifier"),
            input.field("password"),
        ) else {
            return Ok(Err(Refusal::new(None, "answer_incomplete")));
        };
        let provider = match self.enabled(tenant, alias.expose()).await {
            Ok(provider) => provider,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(Err(Refusal::new(None, "provider_not_offered")));
            }
            Err(error) => return Err(error),
        };
        let refuse = |reason| Ok(Err(Refusal::new(Some(provider.id()), reason)));
        let state = provider.snapshot();
        let (Some(directories), Some(directory), ProviderKind::Ldap) =
            (&self.directories, &state.settings.directory, state.kind)
        else {
            return refuse("another_kind");
        };

        // What the person typed, as the directory will be asked for it.
        let typed = identifier.expose().trim();
        if typed.is_empty() || typed.chars().count() > 255 || typed.chars().any(char::is_control) {
            return refuse("identifier_not_usable");
        }

        // The attempt is counted before the directory is asked. While a
        // lockout is in force this returns "too many attempts" and
        // nothing is asked.
        let key = self
            .digest
            .sha256(format!("directory:{}:{}", provider.id(), typed.to_lowercase()).as_bytes());
        let rules = directories.policy.rules(tenant).await?;
        let address = transaction.snapshot().client.address.as_deref();
        directories
            .guard
            .admit(tenant, &rules, key, address, Caller::system())
            .await?;

        // A directory takes a name with an empty password for an
        // anonymous bind and says it succeeded.
        if password.expose().is_empty() {
            return refuse("empty_password");
        }

        let query = DirectoryQuery {
            address: state.settings.issuer.clone(),
            bind_name: state.settings.client_id.clone(),
            bind_password: self.federation.client_secret(tenant, &provider).await?,
            base: directory.base.clone(),
            filter: directory
                .filter
                .replace(IDENTIFIER_PLACE, &escaped_for_filter(typed)),
            attributes: vec![
                directory.subject_attribute.clone(),
                directory.email_attribute.clone(),
                directory.name_attribute.clone(),
            ],
        };
        let entry = match directories.client.verify(&query, password).await? {
            DirectoryAnswer::Verified(entry) => entry,
            DirectoryAnswer::Refused(reason) => return refuse(reason),
        };

        // A value that is not text is written in hexadecimal.
        let Some(subject) = entry
            .first(&directory.subject_attribute)
            .filter(|value| !value.is_empty())
            .map(|value| match std::str::from_utf8(value) {
                Ok(text) if !text.chars().any(char::is_control) => text.to_owned(),
                _ => value.iter().map(|byte| format!("{byte:02x}")).collect(),
            })
            .and_then(|value| Subject::parse(&value).ok())
        else {
            return refuse("no_subject");
        };
        let text = |attribute: &str, longest: usize| {
            entry
                .first(attribute)
                .and_then(|value| std::str::from_utf8(value).ok())
                .map(str::trim)
                .filter(|value| !value.is_empty() && value.chars().count() <= longest)
                .map(str::to_owned)
        };
        let identity = VerifiedIdentity {
            subject,
            email: text(&directory.email_attribute, 254),
            // A directory does not say. Whether its addresses can be
            // relied on is the provider's setting.
            email_verified: false,
            name: text(&directory.name_attribute, 200),
            locale: None,
        };

        let resolved = self.resolve(tenant, &provider, identity).await?;
        if resolved.is_ok() {
            directories.guard.succeeded(tenant, key).await?;
        }
        Ok(resolved)
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
        // An address counts as vouched for when the provider says so, or
        // when an administrator said that this provider's addresses are.
        let vouched = identity.email_verified || provider.snapshot().settings.trusts_email;
        let Some(email) = identity.email.filter(|_| vouched) else {
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
            second_factor: None,
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
        // A password among what was submitted means a directory: nobody
        // left, so there is no pending authorization to finish.
        let finished = if input.field("password").is_some() {
            self.sign_in
                .finish_with_directory(tenant, transaction, input)
                .await?
        } else {
            self.sign_in.finish(tenant, transaction.id(), input).await?
        };
        match finished {
            Ok(user) => Ok(StepOutcome::Authenticated { user }),
            Err(refusal) => {
                self.sign_in.record_refusal(tenant, refusal).await?;
                Ok(StepOutcome::Rejected)
            }
        }
    }
}

/// What a person typed, made safe to put into a directory's filter: the
/// characters that mean something in a filter become characters to look
/// for (RFC 4515, section 3).
fn escaped_for_filter(typed: &str) -> String {
    let mut escaped = String::with_capacity(typed.len());
    for character in typed.chars() {
        match character {
            '\\' => escaped.push_str("\\5c"),
            '*' => escaped.push_str("\\2a"),
            '(' => escaped.push_str("\\28"),
            ')' => escaped.push_str("\\29"),
            '\0' => escaped.push_str("\\00"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::escaped_for_filter;

    #[test]
    fn what_means_something_in_a_filter_becomes_a_character_to_look_for() {
        assert_eq!(escaped_for_filter("ana"), "ana");
        assert_eq!(
            escaped_for_filter("ana.silva@example.com"),
            "ana.silva@example.com"
        );
        assert_eq!(escaped_for_filter("*"), "\\2a");
        assert_eq!(
            escaped_for_filter("ana)(uid=*"),
            "ana\\29\\28uid=\\2a",
            "a filter cannot be closed and another opened"
        );
        assert_eq!(escaped_for_filter("a\\b"), "a\\5cb");
        assert_eq!(escaped_for_filter("a\0b"), "a\\00b");
        assert_eq!(
            escaped_for_filter("joão"),
            "joão",
            "other letters are themselves"
        );
    }
}
