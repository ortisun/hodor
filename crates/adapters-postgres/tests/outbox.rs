//! Outbox behavior against a real database.

use holdor_adapters_postgres::testing::TestDatabase;
use holdor_adapters_postgres::{DispatchReport, OutboxDispatcher, connection};
use holdor_kernel::clock::testing::FixedClock;
use holdor_kernel::{
    Actor, CorrelationId, DomainError, DomainEvent, EventEnvelope, EventHandler, EventMetadata,
    TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Serialize)]
struct SomethingHappened {
    note: &'static str,
}

impl DomainEvent for SomethingHappened {
    fn event_type(&self) -> &'static str {
        "test.something_happened"
    }
}

fn envelope(tenant: &TenantContext) -> EventEnvelope {
    let clock = FixedClock::at(Timestamp::UNIX_EPOCH);
    let metadata = EventMetadata::new(
        tenant.tenant_id(),
        Actor::System,
        CorrelationId::generate(),
        &clock,
    );
    EventEnvelope::new(metadata, &SomethingHappened { note: "hello" }).expect("serializable")
}

/// Writes one row per handled event. The primary key makes a second
/// delivery of the same event fail loudly.
struct RecordingHandler;

#[async_trait::async_trait]
impl EventHandler for RecordingHandler {
    fn name(&self) -> &'static str {
        "recording"
    }

    fn handles(&self, event_type: &str) -> bool {
        event_type.starts_with("test.")
    }

    async fn handle(
        &self,
        uow: &mut dyn UnitOfWork,
        event: &EventEnvelope,
    ) -> Result<(), DomainError> {
        let tenant_id = uow.tenant().tenant_id();
        sqlx::query("INSERT INTO platform.handled (tenant_id, event_id) VALUES ($1, $2)")
            .bind(tenant_id.as_uuid())
            .bind(event.metadata.event_id.as_uuid())
            .execute(connection(uow)?)
            .await
            .map_err(|e| {
                DomainError::internal("test.insert_failed", "insert failed")
                    .with_detail(e.to_string())
            })?;
        Ok(())
    }
}

/// Fails until told otherwise.
struct FlakyHandler {
    healthy: AtomicBool,
}

#[async_trait::async_trait]
impl EventHandler for FlakyHandler {
    fn name(&self) -> &'static str {
        "flaky"
    }

    fn handles(&self, _event_type: &str) -> bool {
        true
    }

    async fn handle(
        &self,
        _uow: &mut dyn UnitOfWork,
        _event: &EventEnvelope,
    ) -> Result<(), DomainError> {
        if self.healthy.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(DomainError::internal("test.flaky", "handler is down"))
        }
    }
}

/// Records a follow-up event for every event it handles, once.
struct ChainingHandler;

#[async_trait::async_trait]
impl EventHandler for ChainingHandler {
    fn name(&self) -> &'static str {
        "chaining"
    }

    fn handles(&self, event_type: &str) -> bool {
        event_type == "test.something_happened"
    }

    async fn handle(
        &self,
        uow: &mut dyn UnitOfWork,
        _event: &EventEnvelope,
    ) -> Result<(), DomainError> {
        let mut follow_up = envelope(uow.tenant());
        follow_up.event_type = "test.follow_up".to_owned();
        uow.record_event(follow_up);
        Ok(())
    }
}

async fn database() -> TestDatabase {
    let database = TestDatabase::start().await;
    for statement in [
        "CREATE TABLE platform.handled (
             tenant_id uuid NOT NULL,
             event_id uuid NOT NULL,
             PRIMARY KEY (tenant_id, event_id)
         )",
        "SELECT platform.enable_tenant_rls('platform.handled')",
    ] {
        sqlx::query(statement)
            .execute(database.owner())
            .await
            .expect("test schema setup");
    }
    database
}

fn dispatcher(database: &TestDatabase, handlers: Vec<Arc<dyn EventHandler>>) -> OutboxDispatcher {
    OutboxDispatcher::new(
        database.platform().clone(),
        database.app().clone(),
        handlers,
    )
}

async fn record(database: &TestDatabase, tenant: &TenantContext, count: usize) {
    let mut uow = UnitOfWorkFactory::begin(database.app(), tenant)
        .await
        .expect("begin");
    for _ in 0..count {
        uow.record_event(envelope(tenant));
    }
    uow.commit().await.expect("commit");
}

async fn scalar(database: &TestDatabase, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(database.owner())
        .await
        .expect("scalar query")
}

#[tokio::test]
async fn events_are_stored_only_when_the_unit_of_work_commits() {
    let database = database().await;
    let tenant = TenantContext::assume(TenantId::generate());

    let mut abandoned = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    abandoned.record_event(envelope(&tenant));
    drop(abandoned);
    assert_eq!(
        scalar(&database, "SELECT count(*) FROM platform.outbox").await,
        0
    );

    record(&database, &tenant, 2).await;
    assert_eq!(
        scalar(&database, "SELECT count(*) FROM platform.outbox").await,
        2
    );
}

#[tokio::test]
async fn an_event_is_delivered_exactly_once() {
    let database = database().await;
    let tenant = TenantContext::assume(TenantId::generate());
    record(&database, &tenant, 1).await;
    let dispatcher = dispatcher(&database, vec![Arc::new(RecordingHandler)]);

    let first = dispatcher.dispatch_batch(10).await.expect("dispatch");
    let second = dispatcher.dispatch_batch(10).await.expect("dispatch");

    assert_eq!(
        first,
        DispatchReport {
            delivered: 1,
            ..DispatchReport::default()
        }
    );
    assert_eq!(second, DispatchReport::default());
    assert_eq!(
        scalar(&database, "SELECT count(*) FROM platform.handled").await,
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_dispatchers_do_not_deliver_twice() {
    let database = database().await;
    let a = TenantContext::assume(TenantId::generate());
    let b = TenantContext::assume(TenantId::generate());
    record(&database, &a, 25).await;
    record(&database, &b, 15).await;

    let first = dispatcher(&database, vec![Arc::new(RecordingHandler)]);
    let second = dispatcher(&database, vec![Arc::new(RecordingHandler)]);
    let (one, two) = tokio::join!(
        tokio::spawn(async move { first.dispatch_batch(100).await.expect("dispatch") }),
        tokio::spawn(async move { second.dispatch_batch(100).await.expect("dispatch") }),
    );
    let (one, two) = (one.expect("task"), two.expect("task"));

    // A duplicate delivery would violate the handler table's primary key and
    // show up as a failure.
    assert_eq!(one.failed + two.failed, 0);
    assert_eq!(one.delivered + two.delivered, 40);
    assert_eq!(
        scalar(&database, "SELECT count(*) FROM platform.handled").await,
        40
    );
    assert_eq!(
        scalar(
            &database,
            "SELECT count(*) FROM platform.outbox WHERE dispatched_at IS NULL"
        )
        .await,
        0
    );
}

#[tokio::test]
async fn a_failed_delivery_is_rolled_back_and_retried() {
    let database = database().await;
    let tenant = TenantContext::assume(TenantId::generate());
    record(&database, &tenant, 1).await;
    let flaky = Arc::new(FlakyHandler {
        healthy: AtomicBool::new(false),
    });
    let dispatcher = dispatcher(&database, vec![Arc::new(RecordingHandler), flaky.clone()]);

    // The recording handler succeeds, then the flaky one fails: the whole
    // delivery is undone, as if the worker had died halfway.
    let failed = dispatcher.dispatch_batch(10).await.expect("dispatch");
    assert_eq!(failed.failed, 1);
    assert_eq!(
        scalar(&database, "SELECT count(*) FROM platform.handled").await,
        0
    );
    assert_eq!(
        scalar(&database, "SELECT attempts::bigint FROM platform.outbox").await,
        1
    );
    let last_error: String = sqlx::query_scalar("SELECT last_error FROM platform.outbox")
        .fetch_one(database.owner())
        .await
        .expect("last_error");
    assert!(last_error.starts_with("flaky: test.flaky"), "{last_error}");

    // Backoff keeps the event out of the next batch.
    let backing_off = dispatcher.dispatch_batch(10).await.expect("dispatch");
    assert_eq!(backing_off, DispatchReport::default());

    // Once the backoff has passed and the handler recovers, it is delivered.
    sqlx::query("UPDATE platform.outbox SET next_attempt_at = now()")
        .execute(database.owner())
        .await
        .expect("skip backoff");
    flaky.healthy.store(true, Ordering::SeqCst);
    let retried = dispatcher.dispatch_batch(10).await.expect("dispatch");
    assert_eq!(retried.delivered, 1);
    assert_eq!(
        scalar(&database, "SELECT count(*) FROM platform.handled").await,
        1
    );
}

#[tokio::test]
async fn events_recorded_by_a_handler_are_delivered_in_a_later_batch() {
    let database = database().await;
    let tenant = TenantContext::assume(TenantId::generate());
    record(&database, &tenant, 1).await;
    let dispatcher = dispatcher(
        &database,
        vec![Arc::new(ChainingHandler), Arc::new(RecordingHandler)],
    );

    assert_eq!(
        dispatcher
            .dispatch_batch(10)
            .await
            .expect("dispatch")
            .delivered,
        1
    );
    assert_eq!(
        scalar(
            &database,
            "SELECT count(*) FROM platform.outbox WHERE event_type = 'test.follow_up'"
        )
        .await,
        1
    );
    assert_eq!(
        dispatcher
            .dispatch_batch(10)
            .await
            .expect("dispatch")
            .delivered,
        1
    );
    assert_eq!(
        scalar(&database, "SELECT count(*) FROM platform.handled").await,
        2
    );
}

#[tokio::test]
async fn a_unit_of_work_from_another_adapter_is_rejected() {
    struct Foreign(TenantContext);

    #[async_trait::async_trait]
    impl UnitOfWork for Foreign {
        fn tenant(&self) -> &TenantContext {
            &self.0
        }
        fn record_event(&mut self, _event: EventEnvelope) {}
        async fn commit(self: Box<Self>) -> Result<(), DomainError> {
            Ok(())
        }
        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }
    }

    let mut foreign = Foreign(TenantContext::assume(TenantId::generate()));
    let error = connection(&mut foreign).expect_err("must be rejected");
    assert_eq!(error.code(), "database.foreign_unit_of_work");
}
