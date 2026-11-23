//! What the OAuth context needs to know of a person, answered by the
//! session and identity contexts: the OAuth context depends on neither.
//!
//! See `docs/architecture/contexts/oauth.md`, "Refresh tokens".

use hodor_identity::api::IdentityService;
use hodor_kernel::{DomainError, ErrorKind, TenantContext, UserId};
use hodor_oauth::api::PersonStanding;
use hodor_session::api::{SessionId, SessionService};

/// [`PersonStanding`] over the session and identity services.
#[derive(Clone)]
pub(crate) struct ServerStanding {
    /// The sessions of people.
    pub(crate) sessions: SessionService,
    /// The people.
    pub(crate) identity: IdentityService,
}

impl std::fmt::Debug for ServerStanding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerStanding").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl PersonStanding for ServerStanding {
    async fn session_is_active(
        &self,
        tenant: &TenantContext,
        user: UserId,
        session: SessionId,
    ) -> Result<bool, DomainError> {
        // Only the active sessions of the person are listed.
        Ok(self
            .sessions
            .list_for_user(tenant, user)
            .await?
            .iter()
            .any(|active| active.id() == session))
    }

    async fn may_sign_in(&self, tenant: &TenantContext, user: UserId) -> Result<bool, DomainError> {
        match self.identity.get(tenant, user).await {
            Ok(person) => Ok(person.may_sign_in()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}
