//! The tenant use cases, run against the in-memory ports.

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Actor, CorrelationId, ErrorKind, TenantContext, TenantId, Timestamp};
use hodor_tenant::api::{
    Caller, CreateTenant, RegistrationPolicy, TenantService, TenantSettings, TenantStatus,
};
use hodor_tenant::testing::{InMemoryTenants, Ports, run_contract};
use std::sync::Arc;

struct World {
    service: TenantService,
    units_of_work: InMemoryUnitOfWorkFactory,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let tenants = InMemoryTenants::default();
    let service = TenantService::new(
        Arc::new(units_of_work.clone()),
        Arc::new(tenants.clone()),
        Arc::new(tenants),
        Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
    );
    World {
        service,
        units_of_work,
    }
}

fn caller() -> Caller {
    Caller {
        actor: Actor::System,
        correlation_id: CorrelationId::generate(),
    }
}

fn create(slug: &str) -> CreateTenant {
    CreateTenant {
        slug: slug.to_owned(),
        display_name: "Acme".to_owned(),
        open_registration: false,
        system: false,
    }
}

#[tokio::test]
async fn the_in_memory_ports_pass_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let tenants = InMemoryTenants::default();
    run_contract(
        Ports {
            units_of_work: &units_of_work,
            tenants: &tenants,
            directory: &tenants,
        },
        "fake",
    )
    .await;
}

#[tokio::test]
async fn creating_a_tenant_stores_it_active_and_publishes_its_events() {
    let world = world();

    let tenant = world
        .service
        .create(create("acme"), caller())
        .await
        .expect("create");

    assert_eq!(tenant.status(), TenantStatus::Active);
    let stored = world
        .service
        .get(&TenantContext::assume(tenant.id()))
        .await
        .expect("stored");
    assert_eq!(stored.snapshot().settings, TenantSettings::default());
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["tenant.created", "tenant.activated"]
    );
    assert!(
        world
            .units_of_work
            .committed_events()
            .iter()
            .all(|event| event.metadata.tenant_id == tenant.id()),
        "events belong to the new tenant"
    );
}

#[tokio::test]
async fn open_registration_is_a_choice_at_creation() {
    let world = world();
    let command = CreateTenant {
        open_registration: true,
        ..create("open")
    };

    let tenant = world
        .service
        .create(command, caller())
        .await
        .expect("create");

    assert_eq!(
        tenant.snapshot().settings.registration,
        RegistrationPolicy::Open
    );
    assert_eq!(
        world.units_of_work.committed_event_types(),
        [
            "tenant.created",
            "tenant.settings_changed",
            "tenant.activated"
        ]
    );
}

#[tokio::test]
async fn invalid_and_reserved_slugs_create_nothing() {
    let world = world();
    for slug in ["A", "system", "has space"] {
        let error = world
            .service
            .create(create(slug), caller())
            .await
            .expect_err(slug);
        assert_eq!(error.kind(), ErrorKind::Invalid, "{slug}");
    }
    assert!(world.service.list().await.expect("list").is_empty());
    assert!(world.units_of_work.committed_events().is_empty());
}

#[tokio::test]
async fn a_taken_slug_is_a_conflict_and_publishes_nothing() {
    let world = world();
    world
        .service
        .create(create("acme"), caller())
        .await
        .expect("first");
    let published = world.units_of_work.committed_events().len();

    let error = world
        .service
        .create(create("acme"), caller())
        .await
        .expect_err("second");

    assert_eq!(error.code(), "tenant.slug_taken");
    assert_eq!(world.units_of_work.committed_events().len(), published);
}

#[tokio::test]
async fn the_system_tenant_is_created_only_on_request() {
    let world = world();
    let command = CreateTenant {
        system: true,
        ..create("ignored")
    };

    let tenant = world
        .service
        .create(command, caller())
        .await
        .expect("create");

    assert!(tenant.snapshot().slug.is_system());
    let found = world
        .service
        .find_by_slug("system")
        .await
        .expect("find")
        .expect("listed");
    assert_eq!(found.tenant_id, tenant.id());
}

#[tokio::test]
async fn suspending_and_reactivating_update_the_directory() {
    let world = world();
    let tenant = world
        .service
        .create(create("acme"), caller())
        .await
        .expect("create");
    let context = TenantContext::assume(tenant.id());
    let status = async || {
        world
            .service
            .find_by_slug("acme")
            .await
            .expect("find")
            .expect("listed")
            .status
    };

    world
        .service
        .suspend(&context, "unpaid", caller())
        .await
        .expect("suspend");
    assert_eq!(status().await, TenantStatus::Suspended);

    world
        .service
        .reactivate(&context, caller())
        .await
        .expect("reactivate");
    assert_eq!(status().await, TenantStatus::Active);

    assert_eq!(
        world.units_of_work.committed_event_types()[2..],
        ["tenant.suspended", "tenant.reactivated"]
    );
}

#[tokio::test]
async fn a_rejected_change_stores_and_publishes_nothing() {
    let world = world();
    let tenant = world
        .service
        .create(create("acme"), caller())
        .await
        .expect("create");
    let context = TenantContext::assume(tenant.id());
    let published = world.units_of_work.committed_events().len();

    // An active tenant cannot be reactivated.
    let error = world
        .service
        .reactivate(&context, caller())
        .await
        .expect_err("must fail");

    assert_eq!(error.code(), "tenant.invalid_transition");
    assert_eq!(world.units_of_work.committed_events().len(), published);
    assert_eq!(world.service.get(&context).await.expect("get"), tenant);
}

#[tokio::test]
async fn an_unknown_tenant_is_not_found() {
    let world = world();
    let nobody = TenantContext::assume(TenantId::generate());

    let get = world.service.get(&nobody).await.expect_err("get");
    let suspend = world
        .service
        .suspend(&nobody, "reason", caller())
        .await
        .expect_err("suspend");

    assert_eq!(get.kind(), ErrorKind::NotFound);
    assert_eq!(suspend.kind(), ErrorKind::NotFound);
}

#[tokio::test]
async fn deletion_can_be_scheduled_and_cancelled() {
    let world = world();
    let tenant = world
        .service
        .create(create("acme"), caller())
        .await
        .expect("create");
    let context = TenantContext::assume(tenant.id());

    let pending = world
        .service
        .schedule_deletion(&context, None, caller())
        .await
        .expect("schedule");
    assert_eq!(pending.status(), TenantStatus::PendingDeletion);

    let restored = world
        .service
        .cancel_deletion(&context, caller())
        .await
        .expect("cancel");
    assert_eq!(restored.status(), TenantStatus::Suspended);
}
