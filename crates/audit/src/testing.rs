//! In-memory log and the contract every audit log passes.

use crate::api::{AuditLog, AuditRecord, ChainHead};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    Actor, CorrelationId, DomainError, EventEnvelope, EventId, EventMetadata, TenantContext,
    TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use time::Duration;

/// Audit records kept in memory. It does not make concurrent appends
/// take turns, and it keeps what an abandoned unit of work appended;
/// tests that need either run against PostgreSQL.
#[derive(Debug, Clone, Default)]
pub struct InMemoryAuditLog {
    rows: Arc<Mutex<BTreeMap<TenantId, Vec<AuditRecord>>>>,
}

impl InMemoryAuditLog {
    fn rows(&self) -> std::sync::MutexGuard<'_, BTreeMap<TenantId, Vec<AuditRecord>>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Changes a stored record, as someone with access to the storage
    /// could. For tests of verification.
    ///
    /// # Panics
    ///
    /// Panics if the tenant has no record at that position.
    pub fn tamper(&self, tenant: TenantId, index: usize, change: impl FnOnce(&mut AuditRecord)) {
        let mut rows = self.rows();
        let records = rows.get_mut(&tenant).expect("the tenant has records");
        change(&mut records[index]);
    }

    /// Removes a stored record, as someone with access to the storage
    /// could. For tests of verification.
    ///
    /// # Panics
    ///
    /// Panics if the tenant has no record at that position.
    pub fn remove(&self, tenant: TenantId, index: usize) {
        self.rows()
            .get_mut(&tenant)
            .expect("the tenant has records")
            .remove(index);
    }
}

fn head_of(records: Option<&Vec<AuditRecord>>) -> ChainHead {
    records
        .and_then(|records| records.iter().max_by_key(|record| record.sequence))
        .map_or(ChainHead::EMPTY, AuditRecord::as_head)
}

#[async_trait::async_trait]
impl AuditLog for InMemoryAuditLog {
    async fn lock_head(&self, uow: &mut dyn UnitOfWork) -> Result<ChainHead, DomainError> {
        self.head(uow).await
    }

    async fn append(
        &self,
        uow: &mut dyn UnitOfWork,
        record: &AuditRecord,
    ) -> Result<(), DomainError> {
        let mut rows = self.rows();
        let records = rows.entry(uow.tenant().tenant_id()).or_default();
        if records
            .iter()
            .any(|stored| stored.event_id == record.event_id || stored.sequence == record.sequence)
        {
            return Err(DomainError::conflict(
                "audit.already_recorded",
                "the event was already recorded",
            ));
        }
        records.push(record.clone());
        Ok(())
    }

    async fn head(&self, uow: &mut dyn UnitOfWork) -> Result<ChainHead, DomainError> {
        Ok(head_of(self.rows().get(&uow.tenant().tenant_id())))
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: u64,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, DomainError> {
        let mut found: Vec<AuditRecord> = self
            .rows()
            .get(&uow.tenant().tenant_id())
            .into_iter()
            .flatten()
            .filter(|record| record.sequence > after)
            .cloned()
            .collect();
        found.sort_by_key(|record| record.sequence);
        found.truncate(limit as usize);
        Ok(found)
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct Ports<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The log under test.
    pub log: &'a dyn AuditLog,
}

impl std::fmt::Debug for Ports<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

/// An event of the given tenant, with contents that exercise storage:
/// nested values, a list, text that needs escaping.
#[must_use]
pub fn sample_event(tenant: TenantId, action: &str, number: u64) -> EventEnvelope {
    EventEnvelope {
        metadata: EventMetadata {
            event_id: EventId::generate(),
            tenant_id: tenant,
            // Finer than the database keeps, to show that the record is
            // the same before and after storage.
            occurred_at: Timestamp::UNIX_EPOCH
                + Duration::seconds(i64::try_from(number).unwrap_or(0))
                + Duration::nanoseconds(123_456_789),
            actor: if number.is_multiple_of(2) {
                Actor::User(UserId::generate())
            } else {
                Actor::Anonymous
            },
            correlation_id: CorrelationId::generate(),
        },
        event_type: action.to_owned(),
        payload: serde_json::json!({
            "zeta": number,
            "alpha": { "reason": "line one\nline \"two\" é", "list": [3, 1, 2] },
            "flag": true,
            "nothing": null,
        }),
    }
}

async fn append(ports: &Ports<'_>, tenant: &TenantContext, number: u64) -> AuditRecord {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let head = ports.log.lock_head(uow.as_mut()).await.expect("lock head");
    let record = AuditRecord::next(
        tenant.tenant_id(),
        &head,
        &sample_event(tenant.tenant_id(), "test.happened", number),
        Timestamp::UNIX_EPOCH + Duration::hours(1),
        &FakeDigest,
    );
    ports
        .log
        .append(uow.as_mut(), &record)
        .await
        .expect("append");
    uow.commit().await.expect("commit");
    record
}

async fn head(ports: &Ports<'_>, tenant: &TenantContext) -> ChainHead {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.log.head(uow.as_mut()).await.expect("head")
}

async fn list(
    ports: &Ports<'_>,
    tenant: &TenantContext,
    after: u64,
    limit: u32,
) -> Vec<AuditRecord> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .log
        .list(uow.as_mut(), after, limit)
        .await
        .expect("list")
}

/// Runs every rule an audit log must obey. Each run uses tenants of its
/// own, so runs can share one database.
///
/// # Panics
///
/// Panics if the implementation breaks a rule.
pub async fn run_contract(ports: Ports<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());

    // A tenant with no records has the empty head and an empty list.
    assert_eq!(head(&ports, &tenant).await, ChainHead::EMPTY);
    assert!(list(&ports, &tenant, 0, 10).await.is_empty());

    // Records come back exactly as they were appended, in order, and each
    // still gives its own hash.
    let mut appended = Vec::new();
    for number in 0..5 {
        appended.push(append(&ports, &tenant, number).await);
    }
    let stored = list(&ports, &tenant, 0, 100).await;
    assert_eq!(stored, appended);
    for record in &stored {
        assert_eq!(
            record.computed_hash(tenant.tenant_id(), &FakeDigest),
            record.hash,
            "record {} changed in storage",
            record.sequence
        );
    }
    assert_eq!(
        stored.iter().map(|r| r.sequence).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5]
    );
    assert_eq!(head(&ports, &tenant).await, appended[4].as_head());

    // A list starts after the given sequence and respects its limit.
    assert_eq!(list(&ports, &tenant, 2, 2).await, appended[2..4]);
    assert!(list(&ports, &tenant, 5, 10).await.is_empty());

    // Another tenant has a chain of its own, starting from nothing.
    assert_eq!(head(&ports, &elsewhere).await, ChainHead::EMPTY);
    assert!(list(&ports, &elsewhere, 0, 10).await.is_empty());
    let other = append(&ports, &elsewhere, 0).await;
    assert_eq!(other.sequence, 1);
    assert_eq!(other.previous_hash, [0; 32]);
    assert_eq!(list(&ports, &tenant, 0, 100).await.len(), 5);

    // An event is recorded once: appending it again is refused, and so is
    // a second record with a sequence that is taken.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let current = ports.log.lock_head(uow.as_mut()).await.expect("lock head");
    let mut again = appended[4].clone();
    again.sequence = current.sequence + 1;
    let error = ports
        .log
        .append(uow.as_mut(), &again)
        .await
        .expect_err("the event was already recorded");
    assert_eq!(error.code(), "audit.already_recorded");
    drop(uow);

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let mut taken = appended[4].clone();
    taken.event_id = EventId::generate();
    let error = ports
        .log
        .append(uow.as_mut(), &taken)
        .await
        .expect_err("the sequence is taken");
    assert_eq!(error.code(), "audit.already_recorded");
    drop(uow);
}
