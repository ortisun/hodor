//! The identity use cases, run against the in-memory port.

use hodor_identity::api::{
    CreateUser, IdentifierKind, IdentityService, Profile, UserKind, UserStatus,
};
use hodor_identity::testing::{InMemoryUsers, Ports, run_contract};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, ErrorKind, TenantContext, TenantId, Timestamp, UserId};
use std::sync::Arc;

struct World {
    service: IdentityService,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let service = IdentityService::new(
        Arc::new(units_of_work.clone()),
        Arc::new(InMemoryUsers::default()),
        Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
    );
    World {
        service,
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn person(email: &str) -> CreateUser {
    CreateUser {
        kind: UserKind::Human,
        identifiers: vec![(IdentifierKind::Email, email.to_owned())],
        profile: Profile::default(),
        confirmed: false,
    }
}

#[tokio::test]
async fn the_in_memory_port_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let users = InMemoryUsers::default();
    run_contract(Ports {
        units_of_work: &units_of_work,
        users: &users,
    })
    .await;
}

#[tokio::test]
async fn registering_creates_a_pending_user_and_publishes_its_events() {
    let world = world();

    let user = world
        .service
        .create(&world.tenant, person("Ana@Example.com"), Caller::system())
        .await
        .expect("create");

    assert_eq!(user.status(), UserStatus::Pending);
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["identity.user_created", "identity.identifier_added"]
    );
    let stored = world
        .service
        .get(&world.tenant, user.id())
        .await
        .expect("stored");
    assert_eq!(
        stored.identifiers()[0].value.normalized(),
        "ana@example.com"
    );
    assert_eq!(stored.identifiers()[0].value.display(), "Ana@Example.com");
}

#[tokio::test]
async fn no_event_ever_contains_personal_data() {
    let world = world();
    let command = CreateUser {
        profile: Profile {
            display_name: Some("Ana Silva".to_owned()),
            locale: Some("pt-BR".to_owned()),
        },
        ..person("private.address@example.com")
    };
    let user = world
        .service
        .create(&world.tenant, command, Caller::system())
        .await
        .expect("create");
    world
        .service
        .add_identifier(
            &world.tenant,
            user.id(),
            IdentifierKind::Username,
            "ana.private",
            Caller::system(),
        )
        .await
        .expect("add");

    let published = format!("{:?}", world.units_of_work.committed_events());
    for secret in ["private.address", "ana.private", "Ana Silva"] {
        assert!(
            !published.contains(secret),
            "{secret} leaked into: {published}"
        );
    }
}

#[tokio::test]
async fn an_invalid_identifier_creates_nothing() {
    let world = world();
    let error = world
        .service
        .create(&world.tenant, person("not-an-email"), Caller::system())
        .await
        .expect_err("invalid");
    assert_eq!(error.code(), "identity.email_invalid");
    assert!(world.units_of_work.committed_events().is_empty());
}

#[tokio::test]
async fn a_taken_identifier_is_a_conflict_and_publishes_nothing() {
    let world = world();
    world
        .service
        .create(&world.tenant, person("ana@example.com"), Caller::system())
        .await
        .expect("first");
    let published = world.units_of_work.committed_events().len();

    let error = world
        .service
        .create(&world.tenant, person("ANA@example.com"), Caller::system())
        .await
        .expect_err("second");

    assert_eq!(error.code(), "identity.identifier_taken");
    assert_eq!(world.units_of_work.committed_events().len(), published);
}

#[tokio::test]
async fn a_typed_login_finds_the_user_however_it_is_spelled() {
    let world = world();
    let user = world
        .service
        .create(&world.tenant, person("ana@example.com"), Caller::system())
        .await
        .expect("create");

    for typed in ["ana@example.com", "  ANA@Example.COM  "] {
        let found = world
            .service
            .find_by_login(&world.tenant, typed)
            .await
            .expect("find");
        assert_eq!(found.map(|u| u.id()), Some(user.id()), "{typed}");
    }
    for typed in ["nobody@example.com", "ana", "not an identifier", "", "@"] {
        let found = world
            .service
            .find_by_login(&world.tenant, typed)
            .await
            .expect("find");
        assert_eq!(found, None, "{typed}");
    }
    // The same address in another tenant is someone else, or nobody.
    let elsewhere = TenantContext::assume(TenantId::generate());
    assert_eq!(
        world
            .service
            .find_by_login(&elsewhere, "ana@example.com")
            .await
            .expect("find"),
        None
    );
}

#[tokio::test]
async fn verifying_an_email_activates_nothing_by_itself_and_is_announced_once() {
    let world = world();
    let user = world
        .service
        .create(&world.tenant, person("ana@example.com"), Caller::system())
        .await
        .expect("create");
    let identifier = user.identifiers()[0].id;

    let verified = world
        .service
        .verify_identifier(&world.tenant, user.id(), identifier, Caller::system())
        .await
        .expect("verify");
    assert!(verified.identifiers()[0].is_verified());
    assert_eq!(
        verified.status(),
        UserStatus::Pending,
        "activation is a separate decision"
    );

    let published = world.units_of_work.committed_events().len();
    world
        .service
        .verify_identifier(&world.tenant, user.id(), identifier, Caller::system())
        .await
        .expect("verify again");
    assert_eq!(world.units_of_work.committed_events().len(), published);
    assert_eq!(
        world
            .service
            .get(&world.tenant, user.id())
            .await
            .expect("get")
            .snapshot()
            .version,
        verified.snapshot().version + 1,
        "the repeated verification stored nothing"
    );
}

#[tokio::test]
async fn the_lifecycle_runs_through_the_use_cases() {
    let world = world();
    let user = world
        .service
        .create(&world.tenant, person("ana@example.com"), Caller::system())
        .await
        .expect("create");
    let (tenant, id) = (&world.tenant, user.id());

    world
        .service
        .activate(tenant, id, Caller::system())
        .await
        .expect("activate");
    world
        .service
        .suspend(tenant, id, "review", Caller::system())
        .await
        .expect("suspend");
    world
        .service
        .reactivate(tenant, id, Caller::system())
        .await
        .expect("reactivate");
    world
        .service
        .deactivate(tenant, id, Caller::system())
        .await
        .expect("deactivate");
    world
        .service
        .restore(tenant, id, Caller::system())
        .await
        .expect("restore");
    world
        .service
        .deactivate(tenant, id, Caller::system())
        .await
        .expect("deactivate");
    let erased = world
        .service
        .mark_deleted(tenant, id, Caller::system())
        .await
        .expect("delete");

    assert_eq!(erased.status(), UserStatus::Deleted);
    assert_eq!(
        world.units_of_work.committed_event_types()[2..],
        [
            "identity.user_activated",
            "identity.user_suspended",
            "identity.user_reactivated",
            "identity.user_deactivated",
            "identity.user_restored",
            "identity.user_deactivated",
            "identity.user_deleted",
        ]
    );
    // The address is free again.
    world
        .service
        .create(tenant, person("ana@example.com"), Caller::system())
        .await
        .expect("register again");
}

#[tokio::test]
async fn a_rejected_change_stores_and_publishes_nothing() {
    let world = world();
    let user = world
        .service
        .create(&world.tenant, person("ana@example.com"), Caller::system())
        .await
        .expect("create");
    let published = world.units_of_work.committed_events().len();

    // A pending user cannot be suspended.
    let error = world
        .service
        .suspend(&world.tenant, user.id(), "reason", Caller::system())
        .await
        .expect_err("must fail");

    assert_eq!(error.code(), "identity.invalid_transition");
    assert_eq!(world.units_of_work.committed_events().len(), published);
    assert_eq!(
        world
            .service
            .get(&world.tenant, user.id())
            .await
            .expect("get"),
        user
    );
}

#[tokio::test]
async fn users_of_other_tenants_and_unknown_users_are_not_found() {
    let world = world();
    let user = world
        .service
        .create(&world.tenant, person("ana@example.com"), Caller::system())
        .await
        .expect("create");
    let elsewhere = TenantContext::assume(TenantId::generate());

    for (tenant, id) in [(&elsewhere, user.id()), (&world.tenant, UserId::generate())] {
        let get = world.service.get(tenant, id).await.expect_err("get");
        let change = world
            .service
            .activate(tenant, id, Caller::system())
            .await
            .expect_err("activate");
        assert_eq!(get.kind(), ErrorKind::NotFound);
        assert_eq!(change.kind(), ErrorKind::NotFound);
    }
}
