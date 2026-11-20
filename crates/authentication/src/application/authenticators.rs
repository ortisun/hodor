//! The built-in authenticators: login identifier and password.

use crate::application::guard::AttemptGuard;
use crate::domain::attempt::LockoutRules;
use crate::domain::authenticator::{
    Authenticator, AuthenticatorTraits, Factor, StepInput, StepOutcome,
};
use crate::domain::transaction::AuthTransaction;
use hodor_credential::api::{CredentialService, PasswordCheck};
use hodor_identity::api::{IdentityService, NormalizedIdentifier};
use hodor_kernel::{Caller, Digest, DomainError, ErrorKind, TenantContext, UserId};
use hodor_tenant::api::TenantService;
use std::sync::Arc;
use time::Duration;

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
        // Attempts are counted by the normalized identifier, so that
        // different spellings share one count. Something that is not a
        // well-formed identifier is counted by what was typed.
        let counted = NormalizedIdentifier::from_login(typed).map_or_else(
            || format!("malformed:{}", typed.trim().to_lowercase()),
            |identifier| format!("{}:{}", identifier.kind().as_str(), identifier.normalized()),
        );
        let candidate = self
            .identity
            .find_by_login(tenant, typed)
            .await?
            .map(|user| user.id());
        Ok(StepOutcome::Identified {
            candidate,
            identifier_key: self.digest.sha256(counted.as_bytes()),
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

    async fn lockout_rules(&self, tenant: &TenantContext) -> Result<LockoutRules, DomainError> {
        let settings = self
            .tenants
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
        let rules = self.lockout_rules(tenant).await?;
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
