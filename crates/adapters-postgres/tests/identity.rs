//! The identity port on PostgreSQL.

use hodor_adapters_postgres::PgUserRepository;
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::{Ports, run_contract};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp};
use std::sync::Arc;

fn service(database: &TestDatabase) -> IdentityService {
    IdentityService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgUserRepository),
        Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
    )
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
async fn the_postgres_port_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_contract(Ports {
        units_of_work: database.app(),
        users: &PgUserRepository,
    })
    .await;
}

#[tokio::test]
async fn a_user_its_identifiers_and_its_events_are_written_together() {
    let database = TestDatabase::start().await;
    let service = service(&database);
    let tenant = TenantContext::assume(TenantId::generate());

    let user = service
        .create(&tenant, person("ana@example.com"), Caller::system())
        .await
        .expect("create");

    let counts: (i64, i64, i64) = sqlx::query_as(
        r#"SELECT (SELECT count(*) FROM identity."user"),
                  (SELECT count(*) FROM identity.user_identifier),
                  (SELECT count(*) FROM platform.outbox)"#,
    )
    .fetch_one(database.owner())
    .await
    .expect("counts");
    assert_eq!(counts, (1, 1, 2));
    assert_eq!(service.get(&tenant, user.id()).await.expect("get"), user);
}

#[tokio::test]
async fn a_taken_identifier_leaves_no_trace() {
    let database = TestDatabase::start().await;
    let service = service(&database);
    let tenant = TenantContext::assume(TenantId::generate());
    service
        .create(&tenant, person("ana@example.com"), Caller::system())
        .await
        .expect("first");

    let error = service
        .create(&tenant, person("ANA@EXAMPLE.COM"), Caller::system())
        .await
        .expect_err("second");

    assert_eq!(error.code(), "identity.identifier_taken");
    let counts: (i64, i64, i64) = sqlx::query_as(
        r#"SELECT (SELECT count(*) FROM identity."user"),
                  (SELECT count(*) FROM identity.user_identifier),
                  (SELECT count(*) FROM platform.outbox)"#,
    )
    .fetch_one(database.owner())
    .await
    .expect("counts");
    assert_eq!(
        counts,
        (1, 1, 2),
        "only the first user and its events exist"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_registrations_of_one_address_yield_one_user() {
    let database = TestDatabase::start().await;
    let service = service(&database);
    let tenant = TenantContext::assume(TenantId::generate());

    let attempts = (0..8).map(|_| {
        let (service, tenant) = (service.clone(), tenant.clone());
        tokio::spawn(async move {
            service
                .create(&tenant, person("ana@example.com"), Caller::system())
                .await
        })
    });
    let mut created = 0;
    for attempt in attempts.collect::<Vec<_>>() {
        match attempt.await.expect("task") {
            Ok(_) => created += 1,
            Err(error) => assert_eq!(error.code(), "identity.identifier_taken"),
        }
    }

    assert_eq!(created, 1, "exactly one registration wins");
    let users: i64 = sqlx::query_scalar(r#"SELECT count(*) FROM identity."user""#)
        .fetch_one(database.owner())
        .await
        .expect("count");
    assert_eq!(users, 1);
}

#[tokio::test]
async fn the_database_refuses_a_second_primary_of_a_kind() {
    let database = TestDatabase::start().await;
    let service = service(&database);
    let tenant = TenantContext::assume(TenantId::generate());
    let user = service
        .create(&tenant, person("ana@example.com"), Caller::system())
        .await
        .expect("create");

    let mut tx = database.app().begin(&tenant).await.expect("begin");
    let forced = sqlx::query(
        "INSERT INTO identity.user_identifier
             (tenant_id, id, user_id, kind, value_normalized, value_display, is_primary, created_at)
         VALUES ($1, gen_random_uuid(), $2, 'email', 'other@example.com', 'other@example.com', true, now())",
    )
    .bind(tenant.tenant_id().as_uuid())
    .bind(user.id().as_uuid())
    .execute(tx.connection())
    .await;
    assert!(
        forced.is_err(),
        "two primary emails for one user must be refused"
    );
}
