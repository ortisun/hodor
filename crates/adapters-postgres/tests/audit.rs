//! The audit log on PostgreSQL: the contract, the chain under concurrent
//! delivery, and the things that keep a record from being changed.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{OutboxDispatcher, PgAuditLog};
use hodor_audit::api::{AuditHandler, AuditLog, AuditRecord, AuditService, ChainBreak, ChainHead};
use hodor_audit::testing::{Ports, run_contract, sample_event};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    SystemClock, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use std::sync::Arc;

fn service(database: &TestDatabase) -> AuditService {
    AuditService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgAuditLog),
        Arc::new(FakeDigest),
        Arc::new(SystemClock),
    )
}

fn dispatcher(database: &TestDatabase) -> OutboxDispatcher {
    OutboxDispatcher::new(
        database.platform().clone(),
        database.app().clone(),
        vec![Arc::new(AuditHandler::new(service(database)))],
    )
}

async fn begin(database: &TestDatabase, tenant: &TenantContext) -> Box<dyn UnitOfWork> {
    UnitOfWorkFactory::begin(database.app(), tenant)
        .await
        .expect("begin")
}

/// Announces events the way a context does: with a change, in the outbox.
async fn announce(database: &TestDatabase, tenant: &TenantContext, count: u64) {
    let mut uow = begin(database, tenant).await;
    for number in 0..count {
        uow.record_event(sample_event(tenant.tenant_id(), "test.happened", number));
    }
    uow.commit().await.expect("commit");
}

async fn deliver_everything(database: &TestDatabase) {
    let dispatcher = dispatcher(database);
    loop {
        let report = dispatcher.dispatch_batch(100).await.expect("dispatch");
        assert_eq!(report.failed, 0, "no delivery should fail");
        if report.delivered == 0 {
            break;
        }
    }
}

#[tokio::test]
async fn the_postgres_log_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_contract(Ports {
        units_of_work: database.app(),
        log: &PgAuditLog,
    })
    .await;
}

#[tokio::test]
async fn an_append_that_is_not_committed_leaves_nothing_behind() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());

    let mut uow = begin(&database, &tenant).await;
    let head = PgAuditLog.lock_head(uow.as_mut()).await.expect("lock");
    let record = AuditRecord::next(
        tenant.tenant_id(),
        &head,
        &sample_event(tenant.tenant_id(), "test.abandoned", 0),
        Timestamp::UNIX_EPOCH,
        &FakeDigest,
    );
    PgAuditLog
        .append(uow.as_mut(), &record)
        .await
        .expect("append");
    // Ended without committing: what it wrote is never visible to anyone.
    drop(uow);

    let mut uow = begin(&database, &tenant).await;
    assert_eq!(
        PgAuditLog.head(uow.as_mut()).await.expect("head"),
        ChainHead::EMPTY
    );
    assert!(
        PgAuditLog
            .list(uow.as_mut(), 0, 10)
            .await
            .expect("list")
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_event_is_recorded_once_in_order_while_several_workers_deliver() {
    let database = TestDatabase::start().await;
    let busy = TenantContext::assume(TenantId::generate());
    let quiet = TenantContext::assume(TenantId::generate());
    for _ in 0..6 {
        announce(&database, &busy, 10).await;
    }
    announce(&database, &quiet, 7).await;

    // Three workers at once, each taking batches until nothing is left.
    let workers: Vec<_> = (0..3)
        .map(|_| {
            let dispatcher = dispatcher(&database);
            tokio::spawn(async move {
                loop {
                    let report = dispatcher.dispatch_batch(20).await.expect("dispatch");
                    if report.delivered + report.failed + report.skipped == 0 {
                        break;
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        worker.await.expect("worker");
    }
    deliver_everything(&database).await;

    let audit = service(&database);
    for (tenant, expected) in [(&busy, 60_u64), (&quiet, 7)] {
        let verification = audit.verify(tenant).await.expect("verify");
        assert_eq!(verification.records, expected);
        assert!(verification.is_intact(), "{verification:?}");
    }
    // One record per event, and no event left waiting.
    let (records, events, recorded_events, pending): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM audit.record),
                (SELECT count(*) FROM platform.outbox),
                (SELECT count(DISTINCT event_id) FROM audit.record),
                (SELECT count(*) FROM platform.outbox WHERE dispatched_at IS NULL)",
    )
    .fetch_one(database.owner())
    .await
    .expect("count");
    assert_eq!((records, events, recorded_events, pending), (67, 67, 67, 0));
}

#[tokio::test]
async fn nobody_can_change_or_remove_a_record() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    announce(&database, &tenant, 3).await;
    deliver_everything(&database).await;

    let changes = [
        "UPDATE audit.record SET action = 'something.else'",
        "DELETE FROM audit.record",
    ];
    // The application's role, inside the tenant: not permitted.
    for change in changes {
        let mut tx = database.app().begin(&tenant).await.expect("begin");
        let error = sqlx::query(change)
            .execute(tx.connection())
            .await
            .expect_err("refused");
        assert!(error.to_string().contains("permission denied"), "{error}");
    }
    // The role that works across tenants: not permitted either.
    for change in changes {
        let error = sqlx::query(change)
            .execute(database.platform())
            .await
            .expect_err("refused");
        assert!(error.to_string().contains("permission denied"), "{error}");
    }
    // The owner of the table is permitted, and is stopped by the trigger.
    for change in [changes[0], changes[1], "TRUNCATE audit.record"] {
        let error = sqlx::query(change)
            .execute(database.owner())
            .await
            .expect_err("refused");
        assert!(
            error
                .to_string()
                .contains("audit records cannot be changed or removed"),
            "{change}: {error}"
        );
    }

    let verification = service(&database).verify(&tenant).await.expect("verify");
    assert_eq!(verification.records, 3);
    assert!(verification.is_intact());
}

/// Does what only someone who owns the table and disables its protection
/// can do, so that verification has something to find.
async fn force(database: &TestDatabase, change: &'static str) {
    for statement in [
        "ALTER TABLE audit.record DISABLE TRIGGER record_is_append_only",
        change,
        "ALTER TABLE audit.record ENABLE TRIGGER record_is_append_only",
    ] {
        sqlx::query(statement)
            .execute(database.owner())
            .await
            .expect("forced change");
    }
}

#[tokio::test]
async fn a_record_changed_behind_the_protections_is_found_by_verifying() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    announce(&database, &tenant, 8).await;
    deliver_everything(&database).await;
    let audit = service(&database);
    assert!(audit.verify(&tenant).await.expect("verify").is_intact());

    force(
        &database,
        "UPDATE audit.record SET details = jsonb_set(details, '{flag}', 'false') WHERE sequence = 5",
    )
    .await;
    let verification = audit.verify(&tenant).await.expect("verify");
    assert_eq!(verification.records, 4);
    assert_eq!(verification.broken, Some((5, ChainBreak::ContentsChanged)));
}

#[tokio::test]
async fn a_record_removed_behind_the_protections_is_found_by_verifying() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    announce(&database, &tenant, 8).await;
    deliver_everything(&database).await;
    let audit = service(&database);

    // From the middle: the gap is found.
    force(&database, "DELETE FROM audit.record WHERE sequence = 3").await;
    assert_eq!(
        audit.verify(&tenant).await.expect("verify").broken,
        Some((4, ChainBreak::SequenceOutOfOrder))
    );
}

#[tokio::test]
async fn records_removed_from_the_end_are_found_through_the_chain_head() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    announce(&database, &tenant, 8).await;
    deliver_everything(&database).await;

    force(&database, "DELETE FROM audit.record WHERE sequence > 6").await;

    let verification = service(&database).verify(&tenant).await.expect("verify");
    assert_eq!(verification.records, 6);
    assert_eq!(verification.broken, Some((8, ChainBreak::HeadMismatch)));
}

#[tokio::test]
async fn a_chain_head_that_was_moved_is_found_whichever_way_it_was_moved() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    announce(&database, &tenant, 8).await;
    deliver_everything(&database).await;
    let audit = service(&database);

    // Moved back to an earlier record, to pass the newest ones off as if
    // they had never been recorded. Every record is still read.
    sqlx::query(
        "UPDATE audit.chain_head SET sequence = 5,
             hash = (SELECT hash FROM audit.record WHERE sequence = 5)",
    )
    .execute(database.owner())
    .await
    .expect("forced change");
    let verification = audit.verify(&tenant).await.expect("verify");
    assert_eq!(verification.records, 8);
    assert_eq!(verification.broken, Some((5, ChainBreak::HeadMismatch)));

    // Moved past the last record.
    sqlx::query("UPDATE audit.chain_head SET sequence = 11")
        .execute(database.owner())
        .await
        .expect("forced change");
    let verification = audit.verify(&tenant).await.expect("verify");
    assert_eq!(verification.records, 8);
    assert_eq!(verification.broken, Some((11, ChainBreak::HeadMismatch)));

    // A head for a tenant that has no records at all.
    let empty = TenantContext::assume(TenantId::generate());
    sqlx::query("INSERT INTO audit.chain_head (tenant_id, sequence, hash) VALUES ($1, 3, $2)")
        .bind(empty.tenant_id().as_uuid())
        .bind([7_u8; 32].as_slice())
        .execute(database.owner())
        .await
        .expect("forced change");
    let verification = audit.verify(&empty).await.expect("verify");
    assert_eq!(verification.records, 0);
    assert_eq!(verification.broken, Some((3, ChainBreak::HeadMismatch)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verifying_while_records_are_appended_never_reports_a_break() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    announce(&database, &tenant, 200).await;
    let audit = service(&database);

    let appending = {
        let dispatcher = dispatcher(&database);
        tokio::spawn(async move {
            while dispatcher
                .dispatch_batch(10)
                .await
                .expect("dispatch")
                .delivered
                > 0
            {}
        })
    };
    let mut checks = 0;
    while !appending.is_finished() {
        let verification = audit.verify(&tenant).await.expect("verify");
        assert!(verification.is_intact(), "{verification:?}");
        checks += 1;
    }
    appending.await.expect("appending");

    let verification = audit.verify(&tenant).await.expect("verify");
    assert_eq!(verification.records, 200);
    assert!(verification.is_intact());
    assert!(checks > 0, "the chain was verified while it grew");
}
