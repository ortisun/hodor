//! A person's own second factors: an authenticator application, security
//! keys and passkeys, and the recovery codes that stand in for them.
//!
//! Specified in `docs/architecture/contexts/authentication.md`, "A
//! person's own factors". The credential context does each thing; this
//! service decides the rules that span several kinds of factor.

use crate::domain::enrollment::EnrollmentKind;
use hodor_credential::api::{
    BegunRegistration, RecoveryCodeService, RecoveryCodes, RegistrationResponse, TotpEnrollment,
    TotpId, TotpService, WebAuthnCredential, WebAuthnCredentialId, WebAuthnRegistrationId,
    WebAuthnService,
};
use hodor_identity::api::{IdentifierKind, IdentityService, User};
use hodor_kernel::{Caller, DomainError, ErrorKind, Secret, TenantContext, Timestamp, UserId};
use hodor_tenant::api::{SecondFactorPolicy, TenantService};

/// How long after signing in a person may change their factors.
pub const RECENT_SIGN_IN: time::Duration = time::Duration::minutes(5);

/// Whether a session signed in to at `signed_in_at` is recent enough at
/// `now` to change factors. A sign-in time in the future is not.
#[must_use]
pub fn signed_in_recently(signed_in_at: Timestamp, now: Timestamp) -> bool {
    signed_in_at <= now && now - signed_in_at <= RECENT_SIGN_IN
}

/// Until when a session signed in to at `signed_in_at` may change factors,
/// if it still may at `now`.
#[must_use]
pub fn recent_sign_in_until(signed_in_at: Timestamp, now: Timestamp) -> Option<Timestamp> {
    signed_in_recently(signed_in_at, now).then(|| signed_in_at + RECENT_SIGN_IN)
}

/// The refusal of a change that needs a recent sign-in.
#[must_use]
pub fn recent_sign_in_required() -> DomainError {
    DomainError::new(
        ErrorKind::Forbidden,
        "authentication.recent_sign_in_required",
        "sign in again to change your second factors",
    )
}

/// Who removes a factor: the person is held by the tenant's policy, an
/// administrator is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remover {
    /// The person, from their own pages.
    Person,
    /// An administrator of the tenant, for a person who lost a factor.
    Administrator,
}

/// A person's factors, as they and an administrator see them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Factors {
    /// Whether an authenticator application is in use; `None` when the
    /// installation offers none.
    pub authenticator_application: Option<bool>,
    /// Security keys and passkeys, oldest first.
    pub keys: Vec<WebAuthnCredential>,
    /// How many unused recovery codes are left.
    pub recovery_codes_remaining: u32,
    /// Whether the tenant requires a second factor.
    pub second_factor_required: bool,
}

impl Factors {
    /// How many second factors the person has: the application and keys.
    #[must_use]
    pub fn second_factors(&self) -> usize {
        usize::from(self.authenticator_application == Some(true)) + self.keys.len()
    }
}

/// A key that was just registered, and the recovery codes made with it
/// when it is the person's first second factor.
#[derive(Debug)]
pub struct RegisteredKey {
    /// The credential.
    pub credential: WebAuthnCredential,
    /// A new set of recovery codes, shown once; `None` when the person
    /// had codes already.
    pub recovery_codes: Option<RecoveryCodes>,
}

/// The use cases of a person's own factors.
#[derive(Clone, Debug)]
pub struct FactorService {
    identity: IdentityService,
    tenants: TenantService,
    webauthn: WebAuthnService,
    recovery_codes: RecoveryCodeService,
    totp: Option<TotpService>,
}

/// How a person is named to an authenticator: their primary login
/// identifier, an email address before a username, and their display name.
fn names_of(user: &User) -> (String, String) {
    let name = user
        .primary_identifier(IdentifierKind::Email)
        .or_else(|| user.primary_identifier(IdentifierKind::Username))
        .map_or_else(
            || user.id().to_string(),
            |identifier| identifier.value.display().to_owned(),
        );
    let display_name = user
        .snapshot()
        .profile
        .display_name
        .clone()
        .unwrap_or_else(|| name.clone());
    (name, display_name)
}

fn totp_unavailable() -> DomainError {
    DomainError::not_found(
        "credential.totp_unavailable",
        "this installation offers no authenticator application",
    )
}

impl FactorService {
    /// Wires the use cases to the contexts they ask. An installation that
    /// cannot keep secrets offers no authenticator application; one that
    /// can adds it with [`Self::with_totp`].
    #[must_use]
    pub const fn new(
        identity: IdentityService,
        tenants: TenantService,
        webauthn: WebAuthnService,
        recovery_codes: RecoveryCodeService,
    ) -> Self {
        Self {
            identity,
            tenants,
            webauthn,
            recovery_codes,
            totp: None,
        }
    }

    /// Offers authenticator applications.
    #[must_use]
    pub fn with_totp(mut self, totp: TotpService) -> Self {
        self.totp = Some(totp);
        self
    }

    fn totp(&self) -> Result<&TotpService, DomainError> {
        self.totp.as_ref().ok_or_else(totp_unavailable)
    }

    /// What a person may set up in this installation, in the order the
    /// pages offer it: an authenticator application only where secrets
    /// can be kept, a security key and a passkey always.
    #[must_use]
    pub fn enrollable(&self) -> Vec<EnrollmentKind> {
        EnrollmentKind::ALL
            .into_iter()
            .filter(|kind| *kind != EnrollmentKind::AuthenticatorApplication || self.totp.is_some())
            .collect()
    }

    async fn second_factor_required(&self, tenant: &TenantContext) -> Result<bool, DomainError> {
        let policy = self
            .tenants
            .get(tenant)
            .await?
            .snapshot()
            .settings
            .authentication
            .second_factor;
        Ok(policy == SecondFactorPolicy::Required)
    }

    /// A person's factors.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the user or the tenant does not exist, and an
    /// error if storage fails.
    pub async fn factors(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<Factors, DomainError> {
        self.identity.get(tenant, user_id).await?;
        let authenticator_application = match &self.totp {
            Some(totp) => Some(totp.has_totp(tenant, user_id).await?),
            None => None,
        };
        Ok(Factors {
            authenticator_application,
            keys: self.webauthn.list(tenant, user_id).await?,
            recovery_codes_remaining: self.recovery_codes.unused(tenant, user_id).await?,
            second_factor_required: self.second_factor_required(tenant).await?,
        })
    }

    /// Begins enrolling an authenticator application, with the tenant's
    /// name as the issuer and the person's primary login identifier as the
    /// account. The secret is returned once.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` with `credential.totp_unavailable` when the
    /// installation offers none, `NotFound` if the user or the tenant does
    /// not exist, and an error if storage fails.
    pub async fn begin_authenticator_application(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<TotpEnrollment, DomainError> {
        let totp = self.totp()?;
        let (account, _) = names_of(&self.identity.get(tenant, user_id).await?);
        let issuer = self
            .tenants
            .get(tenant)
            .await?
            .snapshot()
            .display_name
            .clone();
        totp.begin_enrollment(tenant, user_id, &issuer, &account)
            .await
    }

    /// Confirms an authenticator application with a code it shows, and
    /// makes recovery codes when it is the person's first second factor.
    ///
    /// # Errors
    ///
    /// As [`TotpService::confirm_enrollment`], and `NotFound` with
    /// `credential.totp_unavailable` when the installation offers none.
    pub async fn confirm_authenticator_application(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        code: &Secret<String>,
        caller: Caller,
    ) -> Result<Option<RecoveryCodes>, DomainError> {
        self.totp()?
            .confirm_enrollment(tenant, user_id, code, caller)
            .await?;
        self.recovery_codes
            .generate_if_none(tenant, user_id, caller)
            .await
    }

    /// Confirms the enrollment `id` of an authenticator application, as
    /// [`Self::confirm_authenticator_application`] does, only while it is
    /// the one waiting: what a sign-in began, and nothing begun since.
    ///
    /// # Errors
    ///
    /// As [`TotpService::confirm_enrollment_of`], and `NotFound` with
    /// `credential.totp_unavailable` when the installation offers none.
    pub async fn confirm_begun_authenticator_application(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        id: TotpId,
        code: &Secret<String>,
        caller: Caller,
    ) -> Result<Option<RecoveryCodes>, DomainError> {
        self.totp()?
            .confirm_enrollment_of(tenant, user_id, id, code, caller)
            .await?;
        self.recovery_codes
            .generate_if_none(tenant, user_id, caller)
            .await
    }

    /// Begins registering a security key. The person is named to the
    /// authenticator by their primary login identifier and display name.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the user does not exist, and an error if
    /// storage fails.
    pub async fn begin_webauthn_registration(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<BegunRegistration, DomainError> {
        let (name, display_name) = names_of(&self.identity.get(tenant, user_id).await?);
        self.webauthn
            .begin_registration(tenant, user_id, &name, &display_name)
            .await
    }

    /// Begins registering a passkey. The person is named as for a security
    /// key, with the tenant's name after their display name: every tenant
    /// of an installation shares one relying party, so the person's
    /// authenticator may hold passkeys of several.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the user or the tenant does not exist, and an
    /// error if storage fails.
    pub async fn begin_passkey_registration(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<BegunRegistration, DomainError> {
        let (name, display_name) = names_of(&self.identity.get(tenant, user_id).await?);
        let tenant_name = self
            .tenants
            .get(tenant)
            .await?
            .snapshot()
            .display_name
            .clone();
        self.webauthn
            .begin_passkey_registration(
                tenant,
                user_id,
                &name,
                &format!("{display_name} ({tenant_name})"),
            )
            .await
    }

    /// Finishes registering a WebAuthn credential, and makes recovery codes
    /// when it is the person's first second factor.
    ///
    /// # Errors
    ///
    /// As [`WebAuthnService::finish_registration`].
    pub async fn finish_webauthn_registration(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        id: WebAuthnRegistrationId,
        response: RegistrationResponse,
        caller: Caller,
    ) -> Result<RegisteredKey, DomainError> {
        let credential = self
            .webauthn
            .finish_registration(tenant, user_id, id, response, caller)
            .await?;
        let recovery_codes = self
            .recovery_codes
            .generate_if_none(tenant, user_id, caller)
            .await?;
        Ok(RegisteredKey {
            credential,
            recovery_codes,
        })
    }

    /// Gives one of the person's keys a new name.
    ///
    /// # Errors
    ///
    /// As [`WebAuthnService::rename`].
    pub async fn rename_key(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        id: WebAuthnCredentialId,
        name: &str,
        caller: Caller,
    ) -> Result<WebAuthnCredential, DomainError> {
        self.webauthn
            .rename(tenant, user_id, id, name, caller)
            .await
    }

    /// Refuses taking away the last second factor of a person whose tenant
    /// requires one, when the person is the one taking it.
    fn may_remove(factors: &Factors, by: Remover) -> Result<(), DomainError> {
        if by == Remover::Person && factors.second_factor_required && factors.second_factors() <= 1
        {
            return Err(DomainError::invalid(
                "authentication.last_second_factor",
                "this is your last second factor and your organization requires one; add another first",
            ));
        }
        Ok(())
    }

    /// After a factor went: when none is left, the recovery codes go too.
    async fn after_removal(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let left = self.factors(tenant, user_id).await?;
        if left.second_factors() == 0 {
            self.recovery_codes.remove(tenant, user_id, caller).await?;
        }
        Ok(())
    }

    /// Removes one of the person's keys.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` with `credential.webauthn_credential_not_found`
    /// when the person has no such key, `Invalid` with
    /// `authentication.last_second_factor` when the person removes their
    /// last second factor under a policy that requires one, and an error if
    /// storage fails.
    pub async fn remove_key(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        id: WebAuthnCredentialId,
        by: Remover,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let factors = self.factors(tenant, user_id).await?;
        if !factors.keys.iter().any(|key| key.id() == id) {
            return Err(DomainError::not_found(
                "credential.webauthn_credential_not_found",
                "there is no such security key or passkey",
            ));
        }
        Self::may_remove(&factors, by)?;
        self.webauthn.remove(tenant, user_id, id, caller).await?;
        self.after_removal(tenant, user_id, caller).await
    }

    /// Removes the person's authenticator application.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` with `credential.totp_not_found` when none is in
    /// use, `Invalid` with `authentication.last_second_factor` as for a
    /// key, and an error if storage fails.
    pub async fn remove_authenticator_application(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        by: Remover,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let totp = self.totp()?;
        let factors = self.factors(tenant, user_id).await?;
        if factors.authenticator_application != Some(true) {
            return Err(DomainError::not_found(
                "credential.totp_not_found",
                "no authenticator application is in use",
            ));
        }
        Self::may_remove(&factors, by)?;
        totp.remove(tenant, user_id, caller).await?;
        self.after_removal(tenant, user_id, caller).await
    }

    /// Makes a new set of recovery codes in place of the person's set.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` with `authentication.second_factor_missing` when
    /// the person has no second factor, `Conflict` with
    /// `credential.recovery_codes_conflict` when another set was made at
    /// the same moment, and an error if storage fails.
    pub async fn generate_recovery_codes(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        caller: Caller,
    ) -> Result<RecoveryCodes, DomainError> {
        if self.factors(tenant, user_id).await?.second_factors() == 0 {
            return Err(DomainError::invalid(
                "authentication.second_factor_missing",
                "recovery codes stand in for a second factor; add one first",
            ));
        }
        self.recovery_codes.generate(tenant, user_id, caller).await
    }

    /// Removes a person's recovery codes, for an administrator.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` with `credential.recovery_codes_not_found` when
    /// the person has none, and an error if storage fails.
    pub async fn remove_recovery_codes(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        self.identity.get(tenant, user_id).await?;
        if self.recovery_codes.remove(tenant, user_id, caller).await? {
            Ok(())
        } else {
            Err(DomainError::not_found(
                "credential.recovery_codes_not_found",
                "this person has no recovery codes",
            ))
        }
    }
}
