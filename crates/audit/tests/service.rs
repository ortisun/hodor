//! The audit use cases, run against the in-memory log.

use hodor_audit::api::{AuditHandler, AuditService, ChainBreak, Verification};
use hodor_audit::testing::{InMemoryAuditLog, Ports, run_contract, sample_event};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{EventHandler, TenantContext, TenantId, Timestamp, UnitOfWorkFactory};
use std::sync::Arc;
use time::Duration;

struct World {
    service: AuditService,
    handler: AuditHandler,
    log: InMemoryAuditLog,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let log = InMemoryAuditLog::default();
    let service = AuditService::new(
        Arc::new(units_of_work.clone()),
        Arc::new(log.clone()),
        Arc::new(FakeDigest),
        Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH + Duration::days(1))),
    );
    World {
        handler: AuditHandler::new(service.clone()),
        service,
        log,
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

impl World {
    /// Hands events to the handler as the outbox dispatcher does: each in
    /// a unit of work of its tenant.
    async fn happen(&self, tenant: &TenantContext, count: u64) {
        for number in 0..count {
            let event = sample_event(tenant.tenant_id(), "test.happened", number);
            let mut uow = self.units_of_work.begin(tenant).await.expect("begin");
            self.handler
                .handle(uow.as_mut(), &event)
                .await
                .expect("recorded");
            uow.commit().await.expect("commit");
        }
    }

    async fn verify(&self) -> Verification {
        self.service.verify(&self.tenant).await.expect("verify")
    }
}

#[tokio::test]
async fn the_in_memory_log_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let log = InMemoryAuditLog::default();
    run_contract(Ports {
        units_of_work: &units_of_work,
        log: &log,
    })
    .await;
}

#[tokio::test]
async fn every_event_becomes_one_record_carrying_what_the_event_carried() {
    let world = world();
    let event = sample_event(world.tenant.tenant_id(), "identity.user_created", 4);
    let mut uow = world
        .units_of_work
        .begin(&world.tenant)
        .await
        .expect("begin");

    assert!(world.handler.handles("identity.user_created"));
    assert!(world.handler.handles("anything.at_all"));
    world
        .handler
        .handle(uow.as_mut(), &event)
        .await
        .expect("recorded");
    uow.commit().await.expect("commit");

    let records = world
        .service
        .list(&world.tenant, 0, 10)
        .await
        .expect("list");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.sequence, 1);
    assert_eq!(record.event_id, event.metadata.event_id);
    assert_eq!(record.action, "identity.user_created");
    assert_eq!(record.actor, event.metadata.actor);
    assert_eq!(record.correlation_id, event.metadata.correlation_id);
    assert_eq!(record.details, event.payload);
    assert_eq!(
        record.recorded_at,
        Timestamp::UNIX_EPOCH + Duration::days(1)
    );
    // Recording announces nothing itself: an audit record of an audit
    // record would never end.
    assert!(world.units_of_work.committed_events().is_empty());
}

#[tokio::test]
async fn a_chain_of_many_records_verifies_and_is_listed_a_page_at_a_time() {
    let world = world();
    // More than one page of verification.
    world.happen(&world.tenant, 1_203).await;

    assert_eq!(
        world.verify().await,
        Verification {
            records: 1_203,
            broken: None
        }
    );
    let page = world
        .service
        .list(&world.tenant, 1_000, 5_000)
        .await
        .expect("list");
    assert_eq!(page.len(), 200, "a list returns at most 200 records");
    assert_eq!(page[0].sequence, 1_001);
}

#[tokio::test]
async fn a_tenant_with_no_records_verifies() {
    let world = world();
    assert_eq!(
        world.verify().await,
        Verification {
            records: 0,
            broken: None
        }
    );
}

#[tokio::test]
async fn each_tenant_has_a_chain_of_its_own() {
    let world = world();
    let other = TenantContext::assume(TenantId::generate());
    world.happen(&world.tenant, 3).await;
    world.happen(&other, 2).await;

    let mine = world
        .service
        .list(&world.tenant, 0, 10)
        .await
        .expect("list");
    let theirs = world.service.list(&other, 0, 10).await.expect("list");
    assert_eq!(mine.len(), 3);
    assert_eq!(theirs.len(), 2);
    assert_eq!(theirs[0].sequence, 1);
    assert_eq!(theirs[0].previous_hash, [0; 32]);
    assert!(
        world
            .service
            .verify(&other)
            .await
            .expect("verify")
            .is_intact()
    );
}

#[tokio::test]
async fn an_event_of_another_tenant_is_refused() {
    let world = world();
    let foreign = sample_event(TenantId::generate(), "test.happened", 0);
    let mut uow = world
        .units_of_work
        .begin(&world.tenant)
        .await
        .expect("begin");

    let error = world
        .handler
        .handle(uow.as_mut(), &foreign)
        .await
        .expect_err("refused");

    assert_eq!(error.code(), "audit.foreign_event");
}

#[tokio::test]
async fn the_same_event_is_not_recorded_twice() {
    let world = world();
    let event = sample_event(world.tenant.tenant_id(), "test.happened", 0);
    for expected_ok in [true, false] {
        let mut uow = world
            .units_of_work
            .begin(&world.tenant)
            .await
            .expect("begin");
        let result = world.handler.handle(uow.as_mut(), &event).await;
        assert_eq!(result.is_ok(), expected_ok);
        if expected_ok {
            uow.commit().await.expect("commit");
        }
    }
    assert_eq!(world.verify().await.records, 1);
}

#[tokio::test]
async fn a_changed_record_is_found_at_its_place() {
    let world = world();
    world.happen(&world.tenant, 10).await;

    world.log.tamper(world.tenant.tenant_id(), 6, |record| {
        record.details = serde_json::json!({ "zeta": "something else" });
    });

    assert_eq!(
        world.verify().await,
        Verification {
            records: 6,
            broken: Some((7, ChainBreak::ContentsChanged))
        }
    );
}

#[tokio::test]
async fn a_changed_record_with_a_recomputed_hash_breaks_the_next_link() {
    let world = world();
    world.happen(&world.tenant, 10).await;
    let tenant = world.tenant.tenant_id();

    // Someone who can also recompute the hash of the record they changed
    // is given away by the record that follows it.
    world.log.tamper(tenant, 6, |record| {
        record.action = "test.something_else".to_owned();
        record.hash = record.computed_hash(tenant, &FakeDigest);
    });

    assert_eq!(
        world.verify().await.broken,
        Some((8, ChainBreak::PreviousHashMismatch))
    );
}

#[tokio::test]
async fn a_removed_record_is_found_where_the_gap_is() {
    let world = world();
    world.happen(&world.tenant, 10).await;

    world.log.remove(world.tenant.tenant_id(), 3);

    assert_eq!(
        world.verify().await,
        Verification {
            records: 3,
            broken: Some((5, ChainBreak::SequenceOutOfOrder))
        }
    );
}
