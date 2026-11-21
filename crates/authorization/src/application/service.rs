//! The use cases of the authorization context.

use crate::application::ports::RoleAssignmentStore;
use crate::domain::event::AuthorizationEvent;
use crate::domain::role::{Decision, Permission, Role};
use hodor_kernel::{
    Caller, Clock, DomainError, EventEnvelope, EventMetadata, TenantContext, UnitOfWork,
    UnitOfWorkFactory, UserId,
};
use std::sync::Arc;

/// The use cases of the authorization context.
#[derive(Clone)]
pub struct AuthorizationService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    assignments: Arc<dyn RoleAssignmentStore>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for AuthorizationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationService")
            .finish_non_exhaustive()
    }
}

impl AuthorizationService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        assignments: Arc<dyn RoleAssignmentStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            assignments,
            clock,
        }
    }

    /// Gives a user a role in the tenant. Giving a role the user already
    /// holds changes nothing and announces nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn assign(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        role: Role,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let changed = self
            .assignments
            .assign(uow.as_mut(), user_id, role, self.clock.now())
            .await?;
        if changed {
            let event = AuthorizationEvent::RoleAssigned {
                user_id,
                role: role.as_str(),
            };
            self.record(uow.as_mut(), caller, &event)?;
            uow.commit().await?;
        }
        Ok(())
    }

    /// Takes a role away. Taking away a role the user does not hold
    /// changes nothing and announces nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn revoke(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        role: Role,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let changed = self.assignments.revoke(uow.as_mut(), user_id, role).await?;
        if changed {
            let event = AuthorizationEvent::RoleRevoked {
                user_id,
                role: role.as_str(),
            };
            self.record(uow.as_mut(), caller, &event)?;
            uow.commit().await?;
        }
        Ok(())
    }

    /// The roles a user holds in the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn roles_of(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<Vec<Role>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.assignments.roles_of(uow.as_mut(), user_id).await
    }

    /// Answers whether a user may do something in the tenant. Nothing is
    /// cached: the user's roles are read every time.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails. A caller that cannot get an
    /// answer must refuse.
    pub async fn check(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        permission: Permission,
    ) -> Result<Decision, DomainError> {
        let roles = self.roles_of(tenant, user_id).await?;
        Ok(Decision::for_roles(&roles, permission))
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &AuthorizationEvent,
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
