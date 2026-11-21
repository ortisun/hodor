//! The authorization use cases, run against the in-memory store.

use hodor_authorization::api::{AuthorizationService, Effect, Permission, Role};
use hodor_authorization::testing::{InMemoryRoleAssignments, Ports, run_contract};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp, UserId};
use std::sync::Arc;

struct World {
    service: AuthorizationService,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
    ana: UserId,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    World {
        service: AuthorizationService::new(
            Arc::new(units_of_work.clone()),
            Arc::new(InMemoryRoleAssignments::default()),
            Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
        ),
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
        ana: UserId::generate(),
    }
}

impl World {
    async fn may(&self, tenant: &TenantContext, user: UserId, permission: Permission) -> bool {
        self.service
            .check(tenant, user, permission)
            .await
            .expect("check")
            .is_allowed()
    }
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let assignments = InMemoryRoleAssignments::default();
    run_contract(Ports {
        units_of_work: &units_of_work,
        assignments: &assignments,
    })
    .await;
}

#[tokio::test]
async fn a_user_with_no_role_is_denied_everything() {
    let world = world();
    for permission in Permission::ALL {
        let decision = world
            .service
            .check(&world.tenant, world.ana, permission)
            .await
            .expect("check");
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.reason, "no_matching_role");
    }
}

#[tokio::test]
async fn a_role_allows_what_it_holds_in_its_tenant_only() {
    let world = world();
    let other = TenantContext::assume(TenantId::generate());
    world
        .service
        .assign(
            &world.tenant,
            world.ana,
            Role::TenantAuditor,
            Caller::system(),
        )
        .await
        .expect("assign");

    assert!(
        world
            .may(&world.tenant, world.ana, Permission::AuditRead)
            .await
    );
    assert!(
        !world
            .may(&world.tenant, world.ana, Permission::UsersWrite)
            .await
    );
    // The same user in another tenant, and another user in this one.
    assert!(!world.may(&other, world.ana, Permission::AuditRead).await);
    assert!(
        !world
            .may(&world.tenant, UserId::generate(), Permission::AuditRead)
            .await
    );
}

#[tokio::test]
async fn taking_a_role_away_takes_effect_at_the_next_check() {
    let world = world();
    let role = Role::TenantAdministrator;
    world
        .service
        .assign(&world.tenant, world.ana, role, Caller::system())
        .await
        .expect("assign");
    assert!(
        world
            .may(&world.tenant, world.ana, Permission::UsersWrite)
            .await
    );

    world
        .service
        .revoke(&world.tenant, world.ana, role, Caller::system())
        .await
        .expect("revoke");

    assert!(
        !world
            .may(&world.tenant, world.ana, Permission::UsersWrite)
            .await
    );
    assert!(
        world
            .service
            .roles_of(&world.tenant, world.ana)
            .await
            .expect("roles")
            .is_empty()
    );
}

#[tokio::test]
async fn assigning_and_revoking_are_announced_once_each() {
    let world = world();
    let role = Role::TenantAuditor;
    for _ in 0..2 {
        world
            .service
            .assign(&world.tenant, world.ana, role, Caller::system())
            .await
            .expect("assign");
    }
    for _ in 0..2 {
        world
            .service
            .revoke(&world.tenant, world.ana, role, Caller::system())
            .await
            .expect("revoke");
    }

    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["authorization.role_assigned", "authorization.role_revoked"]
    );
    let payloads: Vec<String> = world
        .units_of_work
        .committed_events()
        .iter()
        .map(|event| event.payload.to_string())
        .collect();
    assert!(
        payloads
            .iter()
            .all(|payload| payload.contains("tenant_auditor"))
    );
}
