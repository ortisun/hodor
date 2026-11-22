//! The factors a signed-in person adds to their account, starting with
//! WebAuthn credentials: security keys and passkeys.

use hodor_credential::api::{
    BegunRegistration, RegistrationResponse, WebAuthnCredential, WebAuthnRegistrationId,
    WebAuthnService,
};
use hodor_identity::api::{IdentifierKind, IdentityService, User};
use hodor_kernel::{Caller, DomainError, TenantContext, UserId};
use hodor_tenant::api::TenantService;

/// Registers the factors of a signed-in person. The caller has checked
/// that the person is signed in; proving themselves again before adding a
/// factor comes with the pages that manage factors.
#[derive(Clone, Debug)]
pub struct FactorService {
    identity: IdentityService,
    tenants: TenantService,
    webauthn: WebAuthnService,
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

impl FactorService {
    /// Wires the use cases to the contexts they ask.
    #[must_use]
    pub const fn new(
        identity: IdentityService,
        tenants: TenantService,
        webauthn: WebAuthnService,
    ) -> Self {
        Self {
            identity,
            tenants,
            webauthn,
        }
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

    /// Finishes registering a WebAuthn credential.
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
    ) -> Result<WebAuthnCredential, DomainError> {
        self.webauthn
            .finish_registration(tenant, user_id, id, response, caller)
            .await
    }
}
