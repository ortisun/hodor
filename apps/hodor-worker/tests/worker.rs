//! The worker binary, run as a real process against a real database.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{
    Actor, CorrelationId, DomainEvent, EventEnvelope, EventMetadata, TenantContext, TenantId,
    Timestamp, UnitOfWorkFactory,
};
use serde::Serialize;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

#[derive(Serialize)]
struct SomethingHappened;

impl DomainEvent for SomethingHappened {
    fn event_type(&self) -> &'static str {
        "test.something_happened"
    }
}

async fn record_events(database: &TestDatabase, tenant: &TenantContext, count: usize) {
    let clock = FixedClock::at(Timestamp::UNIX_EPOCH);
    let mut uow = UnitOfWorkFactory::begin(database.app(), tenant)
        .await
        .expect("begin");
    for _ in 0..count {
        let metadata = EventMetadata::new(
            tenant.tenant_id(),
            Actor::System,
            CorrelationId::generate(),
            &clock,
        );
        uow.record_event(EventEnvelope::new(metadata, &SomethingHappened).expect("event"));
    }
    uow.commit().await.expect("commit");
}

async fn pending(database: &TestDatabase) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM platform.outbox WHERE dispatched_at IS NULL")
        .fetch_one(database.owner())
        .await
        .expect("count")
}

fn start_worker(database: &TestDatabase) -> Child {
    Command::new(env!("CARGO_BIN_EXE_hodor-worker"))
        .env("HODOR_DATABASE_URL", database.app_url())
        .env("HODOR_PLATFORM_DATABASE_URL", database.platform_url())
        .env("HODOR_OPS_ADDR", "127.0.0.1:0")
        .env("HODOR_OUTBOX_POLL_INTERVAL_MS", "50")
        .env("HODOR_LOG_FORMAT", "pretty")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("worker should start")
}

fn terminate(worker: &Child) {
    let status = Command::new("kill")
        .args(["-TERM", &worker.id().to_string()])
        .status()
        .expect("kill should run");
    assert!(status.success(), "sending SIGTERM failed");
}

#[tokio::test]
async fn a_running_worker_delivers_events_and_stops_cleanly() {
    let database = TestDatabase::start().await;
    let a = TenantContext::assume(TenantId::generate());
    let b = TenantContext::assume(TenantId::generate());
    record_events(&database, &a, 3).await;

    let mut worker = start_worker(&database);

    // Events that were waiting, and events that arrive while it runs, are
    // delivered, across tenants.
    record_events(&database, &b, 2).await;
    let mut remaining = pending(&database).await;
    for _ in 0..100 {
        if remaining == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        remaining = pending(&database).await;
    }
    assert_eq!(remaining, 0, "the worker should deliver every event");

    terminate(&worker);
    let status = tokio::task::spawn_blocking(move || worker.wait())
        .await
        .expect("wait task")
        .expect("worker exit status");
    assert!(
        status.success(),
        "the worker should exit with code 0: {status}"
    );
}
