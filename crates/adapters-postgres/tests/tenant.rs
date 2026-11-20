//! The tenant ports on PostgreSQL.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgTenantDirectory, PgTenantRepository};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{Actor, CorrelationId, TenantContext, Timestamp};
use hodor_tenant::api::{Caller, CreateTenant, TenantService, TenantStatus};
use hodor_tenant::testing::{Ports, run_contract};
use std::sync::Arc;

fn caller() -> Caller {
    Caller {
        actor: Actor::System,
        correlation_id: CorrelationId::generate(),
    }
}

fn service(database: &TestDatabase) -> TenantService {
    TenantService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
    )
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
async fn the_postgres_ports_pass_the_contract() {
    let database = TestDatabase::start().await;
    let directory = PgTenantDirectory::new(database.app().clone());
    run_contract(
        Ports {
            units_of_work: database.app(),
            tenants: &PgTenantRepository,
            directory: &directory,
        },
        "pg",
    )
    .await;
}

#[tokio::test]
async fn creating_a_tenant_writes_the_row_the_directory_and_the_events_together() {
    let database = TestDatabase::start().await;
    let service = service(&database);

    let tenant = service
        .create(create("acme"), caller())
        .await
        .expect("create");

    let stored = service
        .get(&TenantContext::assume(tenant.id()))
        .await
        .expect("stored");
    assert_eq!(stored, tenant);
    let events: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM platform.outbox WHERE tenant_id = $1 ORDER BY created_at, id",
    )
    .bind(tenant.id().as_uuid())
    .fetch_all(database.owner())
    .await
    .expect("events");
    assert_eq!(events.len(), 2);
    assert!(events.contains(&"tenant.created".to_owned()));
    assert!(events.contains(&"tenant.activated".to_owned()));
}

#[tokio::test]
async fn a_taken_slug_leaves_no_trace() {
    let database = TestDatabase::start().await;
    let service = service(&database);
    service
        .create(create("acme"), caller())
        .await
        .expect("first");

    let error = service
        .create(create("acme"), caller())
        .await
        .expect_err("second");

    assert_eq!(error.code(), "tenant.slug_taken");
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM tenant.tenant),
                (SELECT count(*) FROM platform.tenant_directory),
                (SELECT count(*) FROM platform.outbox)",
    )
    .fetch_one(database.owner())
    .await
    .expect("counts");
    assert_eq!(
        counts,
        (1, 1, 2),
        "only the first tenant and its events exist"
    );
}

#[tokio::test]
async fn the_directory_tracks_status_and_cannot_be_written_by_the_application() {
    let database = TestDatabase::start().await;
    let service = service(&database);
    let tenant = service
        .create(create("acme"), caller())
        .await
        .expect("create");
    let context = TenantContext::assume(tenant.id());

    service
        .suspend(&context, "unpaid", caller())
        .await
        .expect("suspend");
    let found = service
        .find_by_slug("acme")
        .await
        .expect("find")
        .expect("listed");
    assert_eq!(found.status, TenantStatus::Suspended);

    for statement in [
        "UPDATE platform.tenant_directory SET status = 'active'",
        "DELETE FROM platform.tenant_directory",
        "INSERT INTO platform.tenant_directory (slug, tenant_id, status)
         VALUES ('forged', gen_random_uuid(), 'active')",
    ] {
        let result = sqlx::query(statement).execute(database.app().pool()).await;
        assert!(
            result.is_err(),
            "the application role must not run: {statement}"
        );
    }
}

#[tokio::test]
async fn the_database_itself_refuses_a_slug_change_and_a_foreign_row() {
    let database = TestDatabase::start().await;
    let service = service(&database);
    let tenant = service
        .create(create("acme"), caller())
        .await
        .expect("create");
    let context = TenantContext::assume(tenant.id());

    let mut tx = database.app().begin(&context).await.expect("begin");
    let renamed = sqlx::query("UPDATE tenant.tenant SET slug = 'renamed'")
        .execute(tx.connection())
        .await;
    assert!(renamed.is_err(), "a slug change must be refused");
    drop(tx);

    // A tenant cannot plant a row for a different tenant identifier.
    let mut tx = database.app().begin(&context).await.expect("begin");
    let planted = sqlx::query(
        "INSERT INTO tenant.tenant
             (tenant_id, id, slug, display_name, status, settings, created_at, updated_at)
         VALUES ($1, gen_random_uuid(), 'planted', 'x', 'active', '{}', now(), now())",
    )
    .bind(tenant.id().as_uuid())
    .execute(tx.connection())
    .await;
    assert!(
        planted.is_err(),
        "a second row under the same tenant must be refused"
    );
}
