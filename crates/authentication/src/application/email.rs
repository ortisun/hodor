//! Signing in with a code or a link sent by email: two alternatives of
//! the flow. See `docs/architecture/contexts/authentication.md`, "Signing
//! in with a code or a link by email", and Decision 0036.
//!
//! Asking is the alternative's challenge, with the address among its
//! values. What is sent is kept apart from the transaction, as the
//! SHA-256 of its secret, for the sign-in that asked; presenting it is
//! counted with the password's lockout before it is looked at, and one
//! conditional update uses it up once.

use crate::application::account::{locale_of, written};
use crate::application::authenticators::{identifier_key, lockout_rules};
use crate::application::guard::AttemptGuard;
use crate::application::ports::EmailSignInStore;
use crate::domain::authenticator::{
    Authenticator, AuthenticatorTraits, ExternalInput, Factor, StepChallenge, StepInput,
    StepOutcome,
};
use crate::domain::email::{EmailMethod, EmailSecretHash, EmailSignIn, EmailUse};
use crate::domain::event::AuthenticationEvent;
use crate::domain::transaction::AuthTransaction;
use hodor_identity::api::{IdentifierKind, IdentityService, NormalizedIdentifier};
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, ErrorKind, EventEnvelope, EventMetadata, RandomSource,
    TenantContext, UnitOfWorkFactory,
};
use hodor_notification::api::{EnqueueMessage, Notifier, Template};
use hodor_tenant::api::TenantService;
use std::collections::BTreeMap;
use std::sync::Arc;

/// What the email alternatives need.
#[derive(Clone)]
pub struct EmailSignInPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// Keeps what was sent.
    pub sent: Arc<dyn EmailSignInStore>,
    /// Who an address belongs to.
    pub identity: IdentityService,
    /// The tenant's policy, lockout rules and name.
    pub tenants: TenantService,
    /// Queues the message.
    pub notifier: Notifier,
    /// Counts asking and attempts.
    pub guard: AttemptGuard,
    /// Hashes secrets and addresses.
    pub digest: Arc<dyn Digest>,
    /// Makes codes and tokens.
    pub random: Arc<dyn RandomSource>,
    /// Tells the time.
    pub clock: Arc<dyn Clock>,
    /// The address people reach the installation at, without a path;
    /// links start with it.
    pub public_url: String,
}

impl std::fmt::Debug for EmailSignInPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailSignInPorts")
            .field("public_url", &self.public_url)
            .finish_non_exhaustive()
    }
}

/// Signs a person in with a code, or a link, sent to their address: an
/// alternative of the flow, one authenticator per method.
#[derive(Clone)]
pub struct EmailAuthenticator {
    method: EmailMethod,
    ports: Arc<EmailSignInPorts>,
}

impl std::fmt::Debug for EmailAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailAuthenticator")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

impl EmailAuthenticator {
    /// The kind of the code alternative, its key in the flow the server
    /// runs, and the method recorded for it.
    pub const CODE_KIND: &'static str = "email_code";
    /// The kind of the link alternative, its key, and its method.
    pub const LINK_KIND: &'static str = "email_link";

    /// The alternative that sends a code.
    #[must_use]
    pub fn code(ports: EmailSignInPorts) -> Self {
        Self::new(EmailMethod::Code, ports)
    }

    /// The alternative that sends a link.
    #[must_use]
    pub fn link(ports: EmailSignInPorts) -> Self {
        Self::new(EmailMethod::Link, ports)
    }

    fn new(method: EmailMethod, mut ports: EmailSignInPorts) -> Self {
        ports.public_url = ports.public_url.trim_end_matches('/').to_owned();
        Self {
            method,
            ports: Arc::new(ports),
        }
    }

    /// What requests about a normalized address are counted by, apart from
    /// the counts of signing in and of recovery.
    fn asking_key(&self, typed: &str) -> [u8; 32] {
        let counted = NormalizedIdentifier::parse(IdentifierKind::Email, typed).map_or_else(
            |_| format!("email_sign_in:malformed:{}", typed.trim().to_lowercase()),
            |email| format!("email_sign_in:{}", email.normalized()),
        );
        self.ports.digest.sha256(counted.as_bytes())
    }

    /// The field of the input that carries the secret.
    const fn field(&self) -> &'static str {
        match self.method {
            EmailMethod::Code => "code",
            EmailMethod::Link => "token",
        }
    }

    fn record(
        &self,
        uow: &mut dyn hodor_kernel::UnitOfWork,
        event: &AuthenticationEvent,
    ) -> Result<(), DomainError> {
        let caller = Caller::system();
        let metadata = EventMetadata::new(
            uow.tenant().tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.ports.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }
}

#[async_trait::async_trait]
impl Authenticator for EmailAuthenticator {
    fn kind(&self) -> &'static str {
        self.method.as_str()
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: true,
            // The mailbox's owner signed in to it in a way Hodor did not
            // see; it is counted as an identity provider is, so that a
            // second factor after it makes the sign-in multi-factor.
            factor: Some(Factor::Knowledge),
            second_factor: None,
            method: Some(self.method.as_str()),
        }
    }

    async fn offered(&self, tenant: &TenantContext) -> Result<bool, DomainError> {
        let policy = self
            .ports
            .tenants
            .get(tenant)
            .await?
            .snapshot()
            .settings
            .authentication
            .email_sign_in;
        Ok(match self.method {
            EmailMethod::Code => policy.code,
            EmailMethod::Link => policy.link,
        })
    }

    /// Asking: keeps a code or a link for this sign-in, whoever the
    /// address belongs to, and sends it only to a person who may sign in.
    async fn challenge(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        asked: &ExternalInput,
    ) -> Result<Option<StepChallenge>, DomainError> {
        let ports = &self.ports;
        let typed = asked
            .field("email")
            .map_or("", |value| value.expose().as_str());
        let settings = ports.tenants.get(tenant).await?;
        let settings = settings.snapshot();

        // Counted before anything is looked up: asking is limited like
        // asking for a recovery link, in counts of its own.
        let rules = lockout_rules(&ports.tenants, tenant).await?;
        let address = transaction.snapshot().client.address.as_deref();
        ports
            .guard
            .admit(
                tenant,
                &rules,
                self.asking_key(typed),
                address,
                Caller::system(),
            )
            .await?;

        let email = NormalizedIdentifier::parse(IdentifierKind::Email, typed).ok();
        let person = match &email {
            Some(email) => ports
                .identity
                .find_by_login(tenant, email.normalized())
                .await?
                .filter(|user| user.may_sign_in()),
            None => None,
        };
        let now = ports.clock.now();
        let (sent, secret) = EmailSignIn::issue(
            transaction,
            self.method,
            identifier_key(typed, ports.digest.as_ref()),
            person.as_ref().map(|user| user.id()),
            now,
            ports.random.as_ref(),
            ports.digest.as_ref(),
        );

        let mut uow = ports.units_of_work.begin(tenant).await?;
        ports.sent.replace(uow.as_mut(), &sent).await?;
        if let (Some(user), Some(email)) = (&person, &email) {
            let expires_at = sent.snapshot().expires_at;
            let (template, value) = match self.method {
                EmailMethod::Code => (Template::SignInCode, ("code", secret.expose().to_owned())),
                // The token goes in the fragment, which a browser never
                // sends to a server.
                EmailMethod::Link => (
                    Template::SignInLink,
                    (
                        "link",
                        format!(
                            "{}/t/{}/account/sign-in-link#token={}",
                            ports.public_url,
                            settings.slug,
                            secret.expose()
                        ),
                    ),
                ),
            };
            let variables: BTreeMap<String, String> = [
                (value.0.to_owned(), value.1),
                ("tenant_name".to_owned(), settings.display_name.clone()),
                ("expires_at".to_owned(), written(expires_at)),
            ]
            .into_iter()
            .collect();
            let locale = locale_of(&[
                user.snapshot().profile.locale.as_deref(),
                asked.field("locale").map(|value| value.expose().as_str()),
            ]);
            ports
                .notifier
                .enqueue(
                    uow.as_mut(),
                    EnqueueMessage {
                        recipient: email.display().to_owned(),
                        template,
                        locale,
                        variables,
                        expires_at,
                    },
                )
                .await?;
            self.record(
                uow.as_mut(),
                &AuthenticationEvent::EmailSignInSent {
                    user_id: user.id(),
                    method: self.method.as_str(),
                },
            )?;
        }
        uow.commit().await?;
        Ok(Some(StepChallenge {
            challenge: None,
            enrollment: None,
            options: serde_json::json!({}),
        }))
    }

    async fn perform(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let ports = &self.ports;
        let rules = lockout_rules(&ports.tenants, tenant).await?;
        let address = transaction.snapshot().client.address.as_deref();
        let mut uow = ports.units_of_work.begin(tenant).await?;
        let sent = ports.sent.get(uow.as_mut(), transaction.id()).await?;
        drop(uow);

        // Nothing asked for: there is no address to count against, only
        // where the request comes from.
        let Some(sent) = sent else {
            ports
                .guard
                .admit_address(tenant, &rules, address, Caller::system())
                .await?;
            return Ok(StepOutcome::Rejected);
        };
        let identifier_key = sent.snapshot().identifier_key;
        // Counted before it is looked at, with the counts of the password.
        ports
            .guard
            .admit(tenant, &rules, identifier_key, address, Caller::system())
            .await?;

        let presented = match input {
            StepInput::External(input) => input.field(self.field()).and_then(|value| {
                EmailSecretHash::of_presented(self.method, value.expose(), ports.digest.as_ref())
            }),
            _ => None,
        };
        let Some(presented) = presented else {
            return Ok(StepOutcome::Rejected);
        };

        let mut uow = ports.units_of_work.begin(tenant).await?;
        let used = ports
            .sent
            .use_up(
                uow.as_mut(),
                transaction.id(),
                self.method,
                &presented,
                ports.clock.now(),
            )
            .await?;
        uow.commit().await?;
        match used {
            EmailUse::Accepted(user) => {
                let may_sign_in = match ports.identity.get(tenant, user).await {
                    Ok(found) => found.may_sign_in(),
                    Err(error) if error.kind() == ErrorKind::NotFound => false,
                    Err(error) => return Err(error),
                };
                if !may_sign_in {
                    return Ok(StepOutcome::Rejected);
                }
                ports.guard.succeeded(tenant, identifier_key).await?;
                Ok(StepOutcome::Authenticated { user })
            }
            // Another request of this sign-in is completing it with the
            // same secret: storing a rejection now would overwrite it.
            EmailUse::AlreadyUsed => Err(DomainError::conflict(
                "authentication.transaction_modified_concurrently",
                "this sign-in was advanced by another request",
            )),
            EmailUse::Refused => Ok(StepOutcome::Rejected),
        }
    }
}
