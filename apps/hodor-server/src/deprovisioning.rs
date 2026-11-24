//! What the provisioning context asks for when it deprovisions a person,
//! answered by the session and OAuth contexts: the provisioning context
//! depends on neither.
//!
//! See `docs/architecture/contexts/provisioning.md`, "Deprovisioning".

use hodor_kernel::{Caller, DomainError, UnitOfWork, UserId};
use hodor_oauth::api::AuthorizationCodeService;
use hodor_provisioning::api::AccessRevoker;
use hodor_session::api::SessionService;

/// [`AccessRevoker`] over the session and OAuth use cases, in the
/// provisioning context's unit of work.
#[derive(Clone)]
pub(crate) struct ServerAccessRevoker {
    /// The sessions of people.
    pub(crate) sessions: SessionService,
    /// The grants of people, with what was issued from them.
    pub(crate) grants: AuthorizationCodeService,
}

impl std::fmt::Debug for ServerAccessRevoker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerAccessRevoker")
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AccessRevoker for ServerAccessRevoker {
    async fn revoke_access(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
        reason: &'static str,
        caller: Caller,
    ) -> Result<(), DomainError> {
        self.sessions
            .revoke_all_for_user_in(uow, user, None, reason, caller)
            .await?;
        self.grants
            .revoke_grants_of_in(uow, user, reason, caller)
            .await?;
        Ok(())
    }
}
