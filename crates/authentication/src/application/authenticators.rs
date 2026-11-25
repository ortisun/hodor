//! The built-in authenticators: login identifier, password, authenticator
//! application, WebAuthn, recovery code and passkeys.

use crate::application::guard::AttemptGuard;
use crate::domain::attempt::LockoutRules;
use crate::domain::authenticator::{
    Authenticator, AuthenticatorTraits, ExternalInput, Factor, StepChallenge, StepInput,
    StepOutcome,
};
use crate::domain::transaction::AuthTransaction;
use hodor_credential::api::{
    AssertionResponse, Challenge, CredentialService, PasswordCheck, RecoveryCodeCheck,
    RecoveryCodeService, TotpCheck, TotpService, WebAuthnService,
};
use hodor_identity::api::{IdentityService, NormalizedIdentifier};
use hodor_kernel::{Caller, Digest, DomainError, ErrorKind, TenantContext, UserId};
use hodor_tenant::api::TenantService;
use std::sync::Arc;
use time::Duration;

/// The tenant's lockout rules, which the password and the code of an
/// authenticator application are both counted by.
pub(crate) async fn lockout_rules(
    tenants: &TenantService,
    tenant: &TenantContext,
) -> Result<LockoutRules, DomainError> {
    let settings = tenants
        .get(tenant)
        .await?
        .snapshot()
        .settings
        .lockout
        .clone();
    let seconds = |value: u32| Duration::seconds(i64::from(value));
    Ok(LockoutRules {
        max_failures: u32::from(settings.max_failures),
        window: seconds(settings.window_seconds),
        first_lockout: seconds(settings.first_lockout_seconds),
        longest_lockout: seconds(settings.longest_lockout_seconds),
    })
}

/// The key the attempts of an identifier are counted by. Attempts are
/// counted by the normalized identifier, so that different spellings
/// share one count. Something that is not a well-formed identifier is
/// counted by what was typed.
pub(crate) fn identifier_key(typed: &str, digest: &dyn Digest) -> [u8; 32] {
    let counted = NormalizedIdentifier::from_login(typed).map_or_else(
        || format!("malformed:{}", typed.trim().to_lowercase()),
        |identifier| format!("{}:{}", identifier.kind().as_str(), identifier.normalized()),
    );
    digest.sha256(counted.as_bytes())
}

/// Takes what the person typed as their login identifier and remembers
/// who, if anyone, it belongs to.
///
/// The step is satisfied whatever was typed. Whether the identifier
/// belongs to a user, to a user who may not sign in, or to nobody, the
/// outcome looks the same from outside.
#[derive(Clone)]
pub struct IdentifierAuthenticator {
    identity: IdentityService,
    digest: Arc<dyn Digest>,
}

impl std::fmt::Debug for IdentifierAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentifierAuthenticator")
            .finish_non_exhaustive()
    }
}

impl IdentifierAuthenticator {
    /// Wires the authenticator to the identity context.
    #[must_use]
    pub fn new(identity: IdentityService, digest: Arc<dyn Digest>) -> Self {
        Self { identity, digest }
    }
}

#[async_trait::async_trait]
impl Authenticator for IdentifierAuthenticator {
    fn kind(&self) -> &'static str {
        "identifier"
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: true,
            factor: None,
            second_factor: None,
            method: None,
        }
    }

    async fn perform(
        &self,
        tenant: &TenantContext,
        _transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let StepInput::Identifier(typed) = input else {
            return Ok(StepOutcome::Rejected);
        };
        let candidate = self
            .identity
            .find_by_login(tenant, typed)
            .await?
            .map(|user| user.id());
        Ok(StepOutcome::Identified {
            candidate,
            identifier_key: identifier_key(typed, self.digest.as_ref()),
        })
    }
}

/// Checks the password of the person named by the identifier step.
///
/// A wrong password, an identifier that belongs to nobody, a user without
/// a password and a user who may not sign in all get the same rejection,
/// after the same amount of work.
#[derive(Clone)]
pub struct PasswordAuthenticator {
    credentials: CredentialService,
    identity: IdentityService,
    tenants: TenantService,
    guard: AttemptGuard,
}

impl std::fmt::Debug for PasswordAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordAuthenticator")
            .finish_non_exhaustive()
    }
}

impl PasswordAuthenticator {
    /// Wires the authenticator to the contexts it asks.
    #[must_use]
    pub fn new(
        credentials: CredentialService,
        identity: IdentityService,
        tenants: TenantService,
        guard: AttemptGuard,
    ) -> Self {
        Self {
            credentials,
            identity,
            tenants,
            guard,
        }
    }
}

#[async_trait::async_trait]
impl Authenticator for PasswordAuthenticator {
    fn kind(&self) -> &'static str {
        "password"
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: false,
            factor: Some(Factor::Knowledge),
            second_factor: None,
            method: Some("password"),
        }
    }

    async fn perform(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let StepInput::Password(password) = input else {
            return Ok(StepOutcome::Rejected);
        };
        let Some(identifier_key) = transaction.snapshot().identifier_key else {
            return Ok(StepOutcome::Rejected);
        };

        // The attempt is counted before the password is looked at. While a
        // lockout is in force this returns the "too many attempts" error
        // and nothing else happens.
        let rules = lockout_rules(&self.tenants, tenant).await?;
        let address = transaction.snapshot().client.address.as_deref();
        self.guard
            .admit(tenant, &rules, identifier_key, address, Caller::system())
            .await?;

        // When the identifier belongs to nobody, the same lookups and the
        // same hashing are done for a user that does not exist, so that
        // neither the answer nor the time taken tells the cases apart.
        let user_id = transaction.candidate().unwrap_or_else(UserId::generate);
        let may_sign_in = match self.identity.get(tenant, user_id).await {
            Ok(user) => user.may_sign_in(),
            Err(error) if error.kind() == ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        let check = self
            .credentials
            .verify_password(tenant, Some(user_id), password)
            .await?;

        if matches!(check, PasswordCheck::Verified { .. })
            && may_sign_in
            && transaction.candidate().is_some()
        {
            self.guard.succeeded(tenant, identifier_key).await?;
            Ok(StepOutcome::Proven)
        } else {
            Ok(StepOutcome::Rejected)
        }
    }
}

/// Checks a code of the candidate's authenticator application: something
/// the person has. See `docs/architecture/contexts/authentication.md`,
/// "The authenticator application step".
///
/// The code is checked only once the attempt is admitted, with the same
/// counts and lockouts as the password. A wrong code, a used code and
/// something that is not a code get the same rejection.
#[derive(Clone)]
pub struct TotpAuthenticator {
    totp: TotpService,
    tenants: TenantService,
    guard: AttemptGuard,
}

impl std::fmt::Debug for TotpAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpAuthenticator").finish_non_exhaustive()
    }
}

impl TotpAuthenticator {
    /// The kind flows name it by, and the method recorded for it.
    pub const KIND: &'static str = "totp";

    /// Wires the authenticator to the contexts it asks.
    #[must_use]
    pub fn new(totp: TotpService, tenants: TenantService, guard: AttemptGuard) -> Self {
        Self {
            totp,
            tenants,
            guard,
        }
    }
}

#[async_trait::async_trait]
impl Authenticator for TotpAuthenticator {
    fn kind(&self) -> &'static str {
        Self::KIND
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: false,
            factor: Some(Factor::Possession),
            second_factor: None,
            method: Some(Self::KIND),
        }
    }

    async fn perform(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let StepInput::Totp(code) = input else {
            return Ok(StepOutcome::Rejected);
        };
        let Some(identifier_key) = transaction.snapshot().identifier_key else {
            return Ok(StepOutcome::Rejected);
        };
        let rules = lockout_rules(&self.tenants, tenant).await?;
        let address = transaction.snapshot().client.address.as_deref();
        self.guard
            .admit(tenant, &rules, identifier_key, address, Caller::system())
            .await?;
        match self
            .totp
            .verify(tenant, transaction.candidate(), code)
            .await?
        {
            TotpCheck::Verified => {
                self.guard.succeeded(tenant, identifier_key).await?;
                Ok(StepOutcome::Proven)
            }
            TotpCheck::Rejected => Ok(StepOutcome::Rejected),
        }
    }

    async fn has_means(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
    ) -> Result<bool, DomainError> {
        match transaction.candidate() {
            Some(user) => self.totp.has_totp(tenant, user).await,
            None => Ok(false),
        }
    }
}

/// Checks the answer of a security key or a platform authenticator to a
/// challenge, with the credential context. Proves something the person
/// has.
///
/// The step needs a challenge: the engine asks for one first and keeps it
/// in the transaction. Every answer that does not verify is the same
/// rejection, whatever was wrong with it.
#[derive(Clone, Debug)]
pub struct WebAuthnAuthenticator {
    webauthn: WebAuthnService,
}

impl WebAuthnAuthenticator {
    /// The kind flows name it by, and the key of its step in the flow the
    /// server runs.
    pub const KIND: &'static str = "webauthn";

    /// Wires the authenticator to the credential context.
    #[must_use]
    pub const fn new(webauthn: WebAuthnService) -> Self {
        Self { webauthn }
    }
}

fn answer_of(input: &StepInput) -> Option<AssertionResponse> {
    let StepInput::External(input) = input else {
        return None;
    };
    let field = |name: &str| input.field(name).map(|value| value.expose().as_str());
    AssertionResponse::from_base64url(
        field("credential_id")?,
        field("client_data")?,
        field("authenticator_data")?,
        field("signature")?,
        field("user_handle"),
    )
}

#[async_trait::async_trait]
impl Authenticator for WebAuthnAuthenticator {
    fn kind(&self) -> &'static str {
        Self::KIND
    }

    fn resists_phishing(&self) -> bool {
        true
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: false,
            factor: Some(Factor::Possession),
            second_factor: None,
            method: Some(Self::KIND),
        }
    }

    async fn perform(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let (Some(user), Some(challenge), Some(answer)) = (
            transaction.candidate(),
            transaction.challenge(),
            answer_of(input),
        ) else {
            return Ok(StepOutcome::Rejected);
        };
        let verified = self
            .webauthn
            .verify(tenant, user, &Challenge(*challenge), &answer)
            .await?;
        Ok(if verified {
            StepOutcome::Proven
        } else {
            StepOutcome::Rejected
        })
    }

    async fn has_means(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
    ) -> Result<bool, DomainError> {
        match transaction.candidate() {
            Some(user) => self.webauthn.has_credentials(tenant, user).await,
            None => Ok(false),
        }
    }

    async fn challenge(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        _asked: &ExternalInput,
    ) -> Result<Option<StepChallenge>, DomainError> {
        // The step is performed only for a person who was identified and
        // has credentials; a sign-in that reaches it without one has
        // nothing to answer with.
        let Some(user) = transaction.candidate() else {
            return Ok(None);
        };
        let made = self.webauthn.challenge(tenant, user).await?;
        Ok(Some(StepChallenge {
            challenge: Some(made.challenge.0),
            options: options_json(&made.options)?,
        }))
    }
}

fn options_json(options: &impl serde::Serialize) -> Result<serde_json::Value, DomainError> {
    serde_json::to_value(options).map_err(|error| {
        DomainError::internal(
            "authentication.challenge_not_serializable",
            "the sign-in could not continue",
        )
        .with_detail(error.to_string())
    })
}

/// Signs a person in with a passkey alone, as an alternative of the flow:
/// the credential that answers names the person, and its authenticator
/// verified them. See `docs/architecture/contexts/authentication.md`, "The
/// passkey alternative".
///
/// Every answer is counted against the address it comes from before it is
/// checked. A wrong answer, a passkey of another tenant and a user who may
/// not sign in all get the same rejection.
#[derive(Clone)]
pub struct PasskeyAuthenticator {
    webauthn: WebAuthnService,
    identity: IdentityService,
    tenants: TenantService,
    guard: AttemptGuard,
}

impl std::fmt::Debug for PasskeyAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyAuthenticator")
            .finish_non_exhaustive()
    }
}

impl PasskeyAuthenticator {
    /// The kind flows name it by, the key of its alternative in the flow
    /// the server runs, and the method recorded for it.
    pub const KIND: &'static str = "passkey";

    /// Wires the authenticator to the contexts it asks.
    #[must_use]
    pub const fn new(
        webauthn: WebAuthnService,
        identity: IdentityService,
        tenants: TenantService,
        guard: AttemptGuard,
    ) -> Self {
        Self {
            webauthn,
            identity,
            tenants,
            guard,
        }
    }
}

#[async_trait::async_trait]
impl Authenticator for PasskeyAuthenticator {
    fn kind(&self) -> &'static str {
        Self::KIND
    }

    fn resists_phishing(&self) -> bool {
        true
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: true,
            factor: Some(Factor::Possession),
            // The authenticator verified the person with a PIN or with
            // their body; Hodor cannot tell which, and either is a second
            // kind of evidence.
            second_factor: Some(Factor::Inherence),
            method: Some(Self::KIND),
        }
    }

    async fn perform(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let rules = lockout_rules(&self.tenants, tenant).await?;
        let address = transaction.snapshot().client.address.as_deref();
        self.guard
            .admit_address(tenant, &rules, address, Caller::system())
            .await?;
        let (Some(challenge), Some(answer)) = (transaction.challenge(), answer_of(input)) else {
            return Ok(StepOutcome::Rejected);
        };
        let Some(user) = self
            .webauthn
            .verify_passkey(tenant, &Challenge(*challenge), &answer)
            .await?
        else {
            return Ok(StepOutcome::Rejected);
        };
        let may_sign_in = match self.identity.get(tenant, user).await {
            Ok(found) => found.may_sign_in(),
            Err(error) if error.kind() == ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        Ok(if may_sign_in {
            StepOutcome::Authenticated { user }
        } else {
            StepOutcome::Rejected
        })
    }

    async fn challenge(
        &self,
        _tenant: &TenantContext,
        _transaction: &AuthTransaction,
        _asked: &ExternalInput,
    ) -> Result<Option<StepChallenge>, DomainError> {
        let made = self.webauthn.passkey_challenge();
        Ok(Some(StepChallenge {
            challenge: Some(made.challenge.0),
            options: options_json(&made.options)?,
        }))
    }
}

/// Checks one of the candidate's recovery codes, in place of a second
/// factor they lost: a substitute, never a step of its own. See
/// `docs/architecture/contexts/authentication.md`, "Substitutes".
///
/// The code is checked only once the attempt is admitted, with the same
/// counts and lockouts as the password. A wrong code, a used code, a code
/// of an earlier set and something that is not a code get the same
/// rejection.
#[derive(Clone)]
pub struct RecoveryCodeAuthenticator {
    codes: RecoveryCodeService,
    tenants: TenantService,
    guard: AttemptGuard,
}

impl std::fmt::Debug for RecoveryCodeAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCodeAuthenticator")
            .finish_non_exhaustive()
    }
}

impl RecoveryCodeAuthenticator {
    /// The kind flows name it by, the key it is submitted under, and the
    /// method recorded for it.
    pub const KIND: &'static str = "recovery_code";

    /// Wires the authenticator to the contexts it asks.
    #[must_use]
    pub fn new(codes: RecoveryCodeService, tenants: TenantService, guard: AttemptGuard) -> Self {
        Self {
            codes,
            tenants,
            guard,
        }
    }
}

#[async_trait::async_trait]
impl Authenticator for RecoveryCodeAuthenticator {
    fn kind(&self) -> &'static str {
        Self::KIND
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: false,
            factor: Some(Factor::Possession),
            second_factor: None,
            method: Some(Self::KIND),
        }
    }

    async fn perform(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let StepInput::RecoveryCode(code) = input else {
            return Ok(StepOutcome::Rejected);
        };
        let Some(identifier_key) = transaction.snapshot().identifier_key else {
            return Ok(StepOutcome::Rejected);
        };
        let rules = lockout_rules(&self.tenants, tenant).await?;
        let address = transaction.snapshot().client.address.as_deref();
        self.guard
            .admit(tenant, &rules, identifier_key, address, Caller::system())
            .await?;
        match self
            .codes
            .verify(tenant, transaction.candidate(), code, Caller::system())
            .await?
        {
            RecoveryCodeCheck::Verified { .. } => {
                self.guard.succeeded(tenant, identifier_key).await?;
                Ok(StepOutcome::Proven)
            }
            RecoveryCodeCheck::Rejected => Ok(StepOutcome::Rejected),
        }
    }

    async fn has_means(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
    ) -> Result<bool, DomainError> {
        match transaction.candidate() {
            Some(user) => Ok(self.codes.unused(tenant, user).await? > 0),
            None => Ok(false),
        }
    }
}
