//! The factors a signed-in person adds to their account, starting with
//! WebAuthn credentials.

use hodor_credential::api::{
    BegunRegistration, RegistrationResponse, WebAuthnCredential, WebAuthnRegistrationId,
    WebAuthnService,
};
use hodor_identity::api::{IdentifierKind, IdentityService};
use hodor_kernel::{Caller, DomainError, TenantContext, UserId};

/// Registers the factors of a signed-in person. The caller has checked
/// that the person is signed in; proving themselves again before adding a
/// factor comes with the pages that manage factors.
#[derive(Clone, Debug)]
pub struct FactorService {
    identity: IdentityService,
    webauthn: WebAuthnService,
}

impl FactorService {
    /// Wires the use cases to the contexts they ask.
    #[must_use]
    pub const fn new(identity: IdentityService, webauthn: WebAuthnService) -> Self {
        Self { identity, webauthn }
    }

    /// Begins registering a WebAuthn credential. The person is named to the
    /// authenticator by their primary login identifier, an email address
    /// before a username, and by their display name.
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
        let user = self.identity.get(tenant, user_id).await?;
        let name = user
            .primary_identifier(IdentifierKind::Email)
            .or_else(|| user.primary_identifier(IdentifierKind::Username))
            .map_or_else(
                || user_id.to_string(),
                |identifier| identifier.value.display().to_owned(),
            );
        let display_name = user
            .snapshot()
            .profile
            .display_name
            .clone()
            .unwrap_or_else(|| name.clone());
        self.webauthn
            .begin_registration(tenant, user_id, &name, &display_name)
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
