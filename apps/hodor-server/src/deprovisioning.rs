//! What the provisioning context asks for when it deprovisions a person,
//! and the identity context when it disables or deletes a service account
//! or an agent, answered by the session and OAuth contexts: neither asking
//! context depends on them.
//!
//! See `docs/architecture/contexts/provisioning.md`, "Deprovisioning", and
//! `docs/architecture/contexts/identity.md`, "Service accounts and agents".

use hodor_identity::api::WorkloadAccess;
use hodor_kernel::{Caller, DomainError, UnitOfWork, UserId};
use hodor_oauth::api::{AuthorizationCodeService, WorkloadTokens};
use hodor_provisioning::api::AccessRevoker;
use hodor_session::api::SessionService;

/// [`AccessRevoker`] and [`WorkloadAccess`] over the session and OAuth use
/// cases, in the asking context's unit of work.
#[derive(Clone)]
pub(crate) struct ServerAccessRevoker {
    /// The sessions of people.
    pub(crate) sessions: SessionService,
    /// The grants of people, with what was issued from them.
    pub(crate) grants: AuthorizationCodeService,
    /// The access tokens issued for a workload.
    pub(crate) tokens: WorkloadTokens,
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

#[async_trait::async_trait]
impl WorkloadAccess for ServerAccessRevoker {
    async fn revoke_access(
        &self,
        uow: &mut dyn UnitOfWork,
        workload: UserId,
        reason: &'static str,
        caller: Caller,
    ) -> Result<(), DomainError> {
        // A workload has no session and no grant today; whatever it may
        // hold of them ends too, as for a person.
        AccessRevoker::revoke_access(self, uow, workload, reason, caller).await?;
        self.tokens.revoke_in(uow, workload, reason, caller).await?;
        Ok(())
    }
}
