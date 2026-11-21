//! Registration and password recovery.
//!
//! Both are proved through a mailbox: the person asks, receives a link by
//! email and finishes with the token the link carries. See
//! `docs/architecture/contexts/authentication.md`, "Registration and
//! password recovery".

use crate::application::guard::AttemptGuard;
use crate::application::ports::VerificationTokenStore;
use crate::domain::attempt::LockoutRules;
use crate::domain::event::AuthenticationEvent;
use crate::domain::verification::{
    TokenPurpose, VerificationSecret, VerificationToken, VerificationTokenHash,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules, check_acceptable};
use hodor_identity::api::{
    CreateUser, IdentifierKind, IdentityService, NormalizedIdentifier, Profile, UserKind,
};
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, ErrorKind, EventEnvelope, EventMetadata, RandomSource,
    Secret, TenantContext, Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use hodor_notification::api::{EnqueueMessage, Locale, Notifier, Template};
use hodor_session::api::SessionService;
use hodor_tenant::api::{RegistrationPolicy, TenantService, TenantSnapshot};
use std::collections::BTreeMap;
use std::sync::Arc;
use time::Duration;

/// How long a message without a link is worth sending.
const NOTICE_LIFETIME: Duration = Duration::hours(24);

/// What a person gives when asking to register or to recover a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountRequest<'a> {
    /// The email address, as typed.
    pub email: &'a str,
    /// The language the person reads, if they said.
    pub locale: Option<&'a str>,
    /// Where the request came from, used to limit requests.
    pub address: Option<&'a str>,
}

/// The use cases of registration and password recovery.
#[derive(Clone)]
pub struct AccountService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    tokens: Arc<dyn VerificationTokenStore>,
    identity: IdentityService,
    credentials: CredentialService,
    sessions: SessionService,
    tenants: TenantService,
    notifier: Notifier,
    guard: AttemptGuard,
    digest: Arc<dyn Digest>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
    public_url: String,
}

impl std::fmt::Debug for AccountService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountService")
            .field("public_url", &self.public_url)
            .finish_non_exhaustive()
    }
}

fn invalid_token() -> DomainError {
    DomainError::not_found(
        "authentication.verification_token_invalid",
        "this link no longer works; ask for a new one",
    )
}

fn lockout_rules(tenant: &TenantSnapshot) -> LockoutRules {
    let policy = &tenant.settings.lockout;
    let seconds = |value: u32| Duration::seconds(i64::from(value));
    LockoutRules {
        max_failures: u32::from(policy.max_failures),
        window: seconds(policy.window_seconds),
        first_lockout: seconds(policy.first_lockout_seconds),
        longest_lockout: seconds(policy.longest_lockout_seconds),
    }
}

fn password_rules(tenant: &TenantSnapshot) -> PasswordRules {
    let policy = &tenant.settings.password;
    PasswordRules {
        min_length: policy.min_length,
        max_length: policy.max_length,
        history_depth: policy.history_depth,
    }
}

/// A moment written the same in every language, such as
/// `2026-11-21 14:00 UTC`.
fn written(moment: Timestamp) -> String {
    let moment = moment.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        moment.year(),
        u8::from(moment.month()),
        moment.day(),
        moment.hour(),
        moment.minute()
    )
}

/// The language to write to a person in: the first of the given tags that
/// is a language tag, otherwise English.
fn locale_of(preferences: &[Option<&str>]) -> Locale {
    preferences
        .iter()
        .flatten()
        .find_map(|tag| Locale::parse(tag.trim()).ok())
        .unwrap_or_else(Locale::english)
}

impl AccountService {
    /// Wires the use cases to their ports and to the contexts they ask.
    ///
    /// `public_url` is the address people reach the installation at,
    /// without a path; links in messages start with it.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        tokens: Arc<dyn VerificationTokenStore>,
        identity: IdentityService,
        credentials: CredentialService,
        sessions: SessionService,
        tenants: TenantService,
        notifier: Notifier,
        guard: AttemptGuard,
        digest: Arc<dyn Digest>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
        public_url: &str,
    ) -> Self {
        Self {
            units_of_work,
            tokens,
            identity,
            credentials,
            sessions,
            tenants,
            notifier,
            guard,
            digest,
            random,
            clock,
            public_url: public_url.trim_end_matches('/').to_owned(),
        }
    }

    /// Asks to register an email address. If it has no account, a link to
    /// finish is sent to it; if it has one, a note saying so. The answer
    /// is the same in both cases, and when the value is not an address.
    ///
    /// # Errors
    ///
    /// Returns `Forbidden` with code `authentication.registration_closed`
    /// if the tenant does not accept registrations, and `RateLimited` if
    /// too much was asked about this address or from this address.
    pub async fn request_registration(
        &self,
        tenant: &TenantContext,
        request: AccountRequest<'_>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let settings = self.tenants.get(tenant).await?;
        let settings = settings.snapshot();
        if settings.settings.registration != RegistrationPolicy::Open {
            return Err(DomainError::new(
                ErrorKind::Forbidden,
                "authentication.registration_closed",
                "this organization does not accept registrations",
            ));
        }
        self.admit(tenant, settings, "registration", &request, caller)
            .await?;
        let Ok(email) = NormalizedIdentifier::parse(IdentifierKind::Email, request.email) else {
            return Ok(());
        };
        let existing = self
            .identity
            .find_by_login(tenant, email.normalized())
            .await?;
        let locale = locale_of(&[request.locale]);
        let now = self.clock.now();

        let mut uow = self.units_of_work.begin(tenant).await?;
        if existing.is_some() {
            let variables = [("tenant_name", settings.display_name.clone())];
            self.enqueue(
                uow.as_mut(),
                email.display(),
                Template::AlreadyRegistered,
                locale,
                &variables,
                now + NOTICE_LIFETIME,
            )
            .await?;
        } else {
            self.send_link(
                uow.as_mut(),
                settings,
                TokenPurpose::Registration,
                &email,
                None,
                locale,
            )
            .await?;
        }
        uow.commit().await
    }

    /// Finishes a registration: creates the user, already active and with
    /// the address verified, and sets the password.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` with code
    /// `authentication.verification_token_invalid` if the token is
    /// unknown, used, replaced or expired, or if the address acquired an
    /// account in the meantime. Returns `Invalid` if the password or the
    /// display name is not acceptable; the token stays good.
    pub async fn complete_registration(
        &self,
        tenant: &TenantContext,
        token: &str,
        password: &Secret<String>,
        display_name: Option<String>,
        caller: Caller,
    ) -> Result<UserId, DomainError> {
        let hash = self.hash_of(token)?;
        let found = self
            .good_token(tenant, &hash, TokenPurpose::Registration)
            .await?;
        let email = found.snapshot().email.clone();
        let settings = self.tenants.get(tenant).await?;
        let rules = password_rules(settings.snapshot());

        // Everything that can be refused is checked before the token is
        // used up, so that the person can correct it and try again.
        check_acceptable(password, &rules, &[email.as_str()])?;
        let display_name = display_name
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty());
        if display_name
            .as_ref()
            .is_some_and(|name| name.chars().count() > Profile::MAX_DISPLAY_NAME_LENGTH)
        {
            return Err(DomainError::invalid(
                "identity.display_name_invalid",
                "a display name has at most 200 characters",
            ));
        }

        self.use_up(tenant, &hash, TokenPurpose::Registration)
            .await?;

        let command = CreateUser {
            kind: UserKind::Human,
            identifiers: vec![(IdentifierKind::Email, email.clone())],
            profile: Profile {
                display_name,
                locale: Some(found.snapshot().locale.clone()),
            },
            confirmed: true,
        };
        let user = self
            .identity
            .create(tenant, command, caller)
            .await
            .map_err(|error| {
                if error.code() == "identity.identifier_taken" {
                    invalid_token()
                } else {
                    error
                }
            })?;
        if let Some(identifier) = user.identifiers().first() {
            self.identity
                .verify_identifier(tenant, user.id(), identifier.id, caller)
                .await?;
        }
        let new = NewPassword {
            password,
            rules,
            own_names: &[email.as_str()],
        };
        self.credentials
            .set_password(tenant, user.id(), new, false, caller)
            .await?;

        // A person who asked several times and then finished starts again
        // from nothing.
        self.guard
            .succeeded(tenant, self.asking_key("registration", &email))
            .await?;

        let mut uow = self.units_of_work.begin(tenant).await?;
        self.record(
            uow.as_mut(),
            caller,
            &AuthenticationEvent::RegistrationCompleted { user_id: user.id() },
        )?;
        uow.commit().await?;
        Ok(user.id())
    }

    /// Asks to choose a new password. If the address belongs to a user who
    /// may sign in, a link is sent to it. The answer is the same whether
    /// it does or not.
    ///
    /// # Errors
    ///
    /// Returns `RateLimited` if too much was asked about this address or
    /// from this address.
    pub async fn request_recovery(
        &self,
        tenant: &TenantContext,
        request: AccountRequest<'_>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let settings = self.tenants.get(tenant).await?;
        let settings = settings.snapshot();
        self.admit(tenant, settings, "recovery", &request, caller)
            .await?;
        let Ok(email) = NormalizedIdentifier::parse(IdentifierKind::Email, request.email) else {
            return Ok(());
        };
        let Some(user) = self
            .identity
            .find_by_login(tenant, email.normalized())
            .await?
        else {
            return Ok(());
        };
        if !user.may_sign_in() {
            return Ok(());
        }
        let locale = locale_of(&[user.snapshot().profile.locale.as_deref(), request.locale]);

        let mut uow = self.units_of_work.begin(tenant).await?;
        self.send_link(
            uow.as_mut(),
            settings,
            TokenPurpose::PasswordRecovery,
            &email,
            Some(user.id()),
            locale,
        )
        .await?;
        self.record(
            uow.as_mut(),
            caller,
            &AuthenticationEvent::RecoveryRequested { user_id: user.id() },
        )?;
        uow.commit().await
    }

    /// Finishes a recovery: sets the password, ends every session of the
    /// user and tells the owner of the address.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` with code
    /// `authentication.verification_token_invalid` if the token is
    /// unknown, used, replaced or expired, or if the user may no longer
    /// sign in. Returns `Invalid` if the password is not acceptable; the
    /// token stays good.
    pub async fn reset_password(
        &self,
        tenant: &TenantContext,
        token: &str,
        password: &Secret<String>,
        caller: Caller,
    ) -> Result<UserId, DomainError> {
        let hash = self.hash_of(token)?;
        let found = self
            .good_token(tenant, &hash, TokenPurpose::PasswordRecovery)
            .await?;
        let user_id = found.snapshot().user_id.ok_or_else(invalid_token)?;
        let user = match self.identity.get(tenant, user_id).await {
            Ok(user) if user.may_sign_in() => user,
            Ok(_) => return Err(invalid_token()),
            Err(error) if error.kind() == ErrorKind::NotFound => return Err(invalid_token()),
            Err(error) => return Err(error),
        };
        let settings = self.tenants.get(tenant).await?;
        let settings = settings.snapshot();
        let rules = password_rules(settings);
        let own_names: Vec<&str> = user
            .identifiers()
            .iter()
            .map(|identifier| identifier.value.normalized())
            .collect();

        // Refused before the token is used up, so that the person can
        // choose another password with the same link.
        self.credentials
            .check_new_password(
                tenant,
                user_id,
                NewPassword {
                    password,
                    rules,
                    own_names: &own_names,
                },
            )
            .await?;

        self.use_up(tenant, &hash, TokenPurpose::PasswordRecovery)
            .await?;

        let new = NewPassword {
            password,
            rules,
            own_names: &own_names,
        };
        self.credentials
            .set_password(tenant, user_id, new, false, caller)
            .await?;
        self.sessions
            .revoke_all_for_user(tenant, user_id, None, "password_reset", caller)
            .await?;

        // The person just proved they read a message sent to the address.
        let email = &found.snapshot().email;
        let proved = user.identifiers().iter().find(|identifier| {
            identifier.value.kind() == IdentifierKind::Email
                && identifier.value.normalized() == email
        });
        if let Some(identifier) = proved {
            if identifier.verified_at.is_none() {
                self.identity
                    .verify_identifier(tenant, user_id, identifier.id, caller)
                    .await?;
            }
            // A lockout their own forgetting caused must not keep them
            // out. The key is the one the identifier step counts by.
            let counted = format!("{}:{email}", IdentifierKind::Email.as_str());
            self.guard
                .succeeded(tenant, self.digest.sha256(counted.as_bytes()))
                .await?;
        }

        self.guard
            .succeeded(tenant, self.asking_key("recovery", email))
            .await?;

        let now = self.clock.now();
        let mut uow = self.units_of_work.begin(tenant).await?;
        let variables = [("tenant_name", settings.display_name.clone())];
        self.enqueue(
            uow.as_mut(),
            proved.map_or(email.as_str(), |identifier| identifier.value.display()),
            Template::PasswordChanged,
            locale_of(&[
                user.snapshot().profile.locale.as_deref(),
                Some(found.snapshot().locale.as_str()),
            ]),
            &variables,
            now + NOTICE_LIFETIME,
        )
        .await?;
        self.record(
            uow.as_mut(),
            caller,
            &AuthenticationEvent::PasswordReset { user_id },
        )?;
        uow.commit().await?;
        Ok(user_id)
    }

    /// Counts one request against the address asked about and the address
    /// it came from. The counts are kept apart from those of sign-in and
    /// from each other by `scope`.
    async fn admit(
        &self,
        tenant: &TenantContext,
        settings: &TenantSnapshot,
        scope: &str,
        request: &AccountRequest<'_>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        // Different spellings of one address share a count. Something that
        // is not an address is counted by what was typed.
        let key = NormalizedIdentifier::parse(IdentifierKind::Email, request.email).map_or_else(
            |_| {
                let counted = format!("{scope}:malformed:{}", request.email.trim().to_lowercase());
                self.digest.sha256(counted.as_bytes())
            },
            |email| self.asking_key(scope, email.normalized()),
        );
        self.guard
            .admit(
                tenant,
                &lockout_rules(settings),
                key,
                request.address,
                caller,
            )
            .await
    }

    /// What requests about a normalized address are counted by.
    fn asking_key(&self, scope: &str, email: &str) -> [u8; 32] {
        self.digest.sha256(format!("{scope}:{email}").as_bytes())
    }

    fn hash_of(&self, token: &str) -> Result<VerificationTokenHash, DomainError> {
        VerificationTokenHash::of_presented(token, self.digest.as_ref()).ok_or_else(invalid_token)
    }

    async fn good_token(
        &self,
        tenant: &TenantContext,
        hash: &VerificationTokenHash,
        purpose: TokenPurpose,
    ) -> Result<VerificationToken, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.tokens
            .find(uow.as_mut(), hash, purpose)
            .await?
            .filter(|token| token.is_good_at(self.clock.now()))
            .ok_or_else(invalid_token)
    }

    /// Only one request gets past this point for a token.
    async fn use_up(
        &self,
        tenant: &TenantContext,
        hash: &VerificationTokenHash,
        purpose: TokenPurpose,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let used = self
            .tokens
            .use_up(uow.as_mut(), hash, purpose, self.clock.now())
            .await?;
        uow.commit().await?;
        used.map(|_| ()).ok_or_else(invalid_token)
    }

    /// Makes a token, replacing earlier ones for the address, and queues
    /// the message that carries its link, all in the caller's unit of
    /// work.
    async fn send_link(
        &self,
        uow: &mut dyn UnitOfWork,
        settings: &TenantSnapshot,
        purpose: TokenPurpose,
        email: &NormalizedIdentifier,
        user_id: Option<UserId>,
        locale: Locale,
    ) -> Result<(), DomainError> {
        let now = self.clock.now();
        self.tokens
            .replace_earlier(uow, purpose, email.normalized(), now)
            .await?;
        let (token, secret) = VerificationToken::issue(
            purpose,
            email.normalized(),
            user_id,
            locale.as_str(),
            now,
            self.random.as_ref(),
            self.digest.as_ref(),
        );
        self.tokens.insert(uow, &token).await?;

        let (template, page) = match purpose {
            TokenPurpose::Registration => (Template::EmailVerification, "complete-registration"),
            TokenPurpose::PasswordRecovery => (Template::PasswordRecovery, "reset-password"),
        };
        let expires_at = token.snapshot().expires_at;
        let variables = [
            ("link", self.link(settings, page, &secret)),
            ("tenant_name", settings.display_name.clone()),
            ("expires_at", written(expires_at)),
        ];
        self.enqueue(
            uow,
            email.display(),
            template,
            locale,
            &variables,
            expires_at,
        )
        .await
    }

    /// The token goes in the fragment, which a browser never sends to a
    /// server: it does not reach access logs or `Referer` headers.
    fn link(&self, settings: &TenantSnapshot, page: &str, secret: &VerificationSecret) -> String {
        format!(
            "{}/t/{}/account/{page}#token={}",
            self.public_url,
            settings.slug,
            secret.expose()
        )
    }

    async fn enqueue(
        &self,
        uow: &mut dyn UnitOfWork,
        recipient: &str,
        template: Template,
        locale: Locale,
        variables: &[(&str, String)],
        expires_at: Timestamp,
    ) -> Result<(), DomainError> {
        let variables: BTreeMap<String, String> = variables
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect();
        self.notifier
            .enqueue(
                uow,
                EnqueueMessage {
                    recipient: recipient.to_owned(),
                    template,
                    locale,
                    variables,
                    expires_at,
                },
            )
            .await?;
        Ok(())
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &AuthenticationEvent,
    ) -> Result<(), DomainError> {
        let metadata = EventMetadata::new(
            uow.tenant().tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_moment_is_written_the_same_in_every_language() {
        let moment = Timestamp::UNIX_EPOCH + Duration::days(20_778) + Duration::minutes(845);
        assert_eq!(written(moment), "2026-11-21 14:05 UTC");
    }

    #[test]
    fn the_language_is_the_first_valid_preference_or_english() {
        assert_eq!(locale_of(&[None, Some("pt-BR")]).as_str(), "pt-BR");
        assert_eq!(locale_of(&[Some("not a tag"), Some("pt")]).as_str(), "pt");
        assert_eq!(locale_of(&[Some(" pt-BR ")]).as_str(), "pt-BR");
        assert_eq!(locale_of(&[None, None]).as_str(), "en");
        assert_eq!(locale_of(&[Some("")]).as_str(), "en");
    }
}
