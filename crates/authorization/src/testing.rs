//! In-memory store and the contract every role assignment store passes.

use crate::api::{Role, RoleAssignmentStore};
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

/// Role assignments kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryRoleAssignments {
    rows: Arc<Mutex<BTreeSet<(TenantId, UserId, Role)>>>,
}

impl InMemoryRoleAssignments {
    fn rows(&self) -> std::sync::MutexGuard<'_, BTreeSet<(TenantId, UserId, Role)>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl RoleAssignmentStore for InMemoryRoleAssignments {
    async fn assign(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        role: Role,
        _now: Timestamp,
    ) -> Result<bool, DomainError> {
        Ok(self
            .rows()
            .insert((uow.tenant().tenant_id(), user_id, role)))
    }

    async fn revoke(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        role: Role,
    ) -> Result<bool, DomainError> {
        Ok(self
            .rows()
            .remove(&(uow.tenant().tenant_id(), user_id, role)))
    }

    async fn roles_of(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Vec<Role>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .iter()
            .filter(|(owner, user, _)| *owner == tenant && *user == user_id)
            .map(|(_, _, role)| *role)
            .collect())
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct Ports<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub assignments: &'a dyn RoleAssignmentStore,
}

impl std::fmt::Debug for Ports<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

async fn assign(ports: &Ports<'_>, tenant: &TenantContext, user: UserId, role: Role) -> bool {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let changed = ports
        .assignments
        .assign(uow.as_mut(), user, role, Timestamp::UNIX_EPOCH)
        .await
        .expect("assign");
    uow.commit().await.expect("commit");
    changed
}

async fn revoke(ports: &Ports<'_>, tenant: &TenantContext, user: UserId, role: Role) -> bool {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let changed = ports
        .assignments
        .revoke(uow.as_mut(), user, role)
        .await
        .expect("revoke");
    uow.commit().await.expect("commit");
    changed
}

async fn roles(ports: &Ports<'_>, tenant: &TenantContext, user: UserId) -> Vec<Role> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .assignments
        .roles_of(uow.as_mut(), user)
        .await
        .expect("roles")
}

/// Runs every rule a role assignment store must obey. Each run uses
/// tenants of its own, so runs can share one database.
///
/// # Panics
///
/// Panics if the implementation breaks a rule.
pub async fn run_contract(ports: Ports<'_>) {
    use Role::{TenantAdministrator, TenantAuditor};
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let (ana, bia) = (UserId::generate(), UserId::generate());

    // Nobody holds a role to begin with.
    assert!(roles(&ports, &tenant, ana).await.is_empty());

    // Assigning says whether anything changed, and is safe to repeat.
    assert!(assign(&ports, &tenant, ana, TenantAuditor).await);
    assert!(!assign(&ports, &tenant, ana, TenantAuditor).await);
    assert!(assign(&ports, &tenant, ana, TenantAdministrator).await);
    assert_eq!(
        roles(&ports, &tenant, ana).await,
        [TenantAdministrator, TenantAuditor]
    );

    // A role belongs to one user in one tenant.
    assert!(roles(&ports, &tenant, bia).await.is_empty());
    assert!(roles(&ports, &elsewhere, ana).await.is_empty());
    assert!(assign(&ports, &elsewhere, ana, TenantAuditor).await);
    assert!(!revoke(&ports, &elsewhere, ana, TenantAdministrator).await);

    // Revoking says whether anything changed, and is safe to repeat.
    assert!(revoke(&ports, &tenant, ana, TenantAdministrator).await);
    assert!(!revoke(&ports, &tenant, ana, TenantAdministrator).await);
    assert_eq!(roles(&ports, &tenant, ana).await, [TenantAuditor]);
    assert_eq!(roles(&ports, &elsewhere, ana).await, [TenantAuditor]);
}
