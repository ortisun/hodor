//! In-memory stores and the contracts every implementation of them passes.

use crate::api::{AttemptCounter, AttemptStore, AttemptSubject, LockoutRules};
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use time::Duration;

/// Attempt counters kept in memory. It does not serialize concurrent
/// access; tests that need that run against PostgreSQL.
#[derive(Debug, Clone, Default)]
pub struct InMemoryAttempts {
    rows: Arc<Mutex<BTreeMap<(TenantId, AttemptSubject), AttemptCounter>>>,
}

impl InMemoryAttempts {
    fn rows(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, AttemptSubject), AttemptCounter>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl AttemptStore for InMemoryAttempts {
    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        subject: &AttemptSubject,
        now: Timestamp,
    ) -> Result<AttemptCounter, DomainError> {
        Ok(self
            .rows()
            .entry((uow.tenant().tenant_id(), *subject))
            .or_insert_with(|| AttemptCounter::new(*subject, now))
            .clone())
    }

    async fn save(
        &self,
        uow: &mut dyn UnitOfWork,
        counter: &AttemptCounter,
    ) -> Result<(), DomainError> {
        self.rows().insert(
            (uow.tenant().tenant_id(), *counter.subject()),
            counter.clone(),
        );
        Ok(())
    }

    async fn clear(
        &self,
        uow: &mut dyn UnitOfWork,
        subject: &AttemptSubject,
    ) -> Result<(), DomainError> {
        self.rows().remove(&(uow.tenant().tenant_id(), *subject));
        Ok(())
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct AttemptPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub attempts: &'a dyn AttemptStore,
}

impl std::fmt::Debug for AttemptPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttemptPorts").finish_non_exhaustive()
    }
}

/// A fixed, whole-second moment, so that stored timestamps compare equal
/// after a round trip through any storage.
const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;
const RULES: LockoutRules = LockoutRules {
    max_failures: 3,
    window: Duration::minutes(15),
    first_lockout: Duration::minutes(1),
    longest_lockout: Duration::hours(1),
};

async fn lock(
    ports: &AttemptPorts<'_>,
    tenant: &TenantContext,
    subject: &AttemptSubject,
) -> AttemptCounter {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let counter = ports
        .attempts
        .lock(uow.as_mut(), subject, MOMENT)
        .await
        .expect("lock");
    uow.commit().await.expect("commit");
    counter
}

async fn count(
    ports: &AttemptPorts<'_>,
    tenant: &TenantContext,
    subject: &AttemptSubject,
) -> AttemptCounter {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let mut counter = ports
        .attempts
        .lock(uow.as_mut(), subject, MOMENT)
        .await
        .expect("lock");
    counter.count(&RULES, MOMENT);
    ports
        .attempts
        .save(uow.as_mut(), &counter)
        .await
        .expect("save");
    uow.commit().await.expect("commit");
    counter
}

/// Runs the whole contract of an attempt store. Each case uses a tenant of
/// its own, so runs can share one database.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_attempt_contract(ports: AttemptPorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let identifier = AttemptSubject::Identifier([1; 32]);
    let address = AttemptSubject::Address([1; 32]);

    // A subject never seen before has an empty counter.
    let fresh = lock(&ports, &tenant, &identifier).await;
    assert_eq!(fresh, AttemptCounter::new(identifier, MOMENT));

    // What is saved is what is loaded next, lockout included.
    count(&ports, &tenant, &identifier).await;
    count(&ports, &tenant, &identifier).await;
    let locked = count(&ports, &tenant, &identifier).await;
    assert_eq!(locked.lockouts(), 1);
    assert_eq!(lock(&ports, &tenant, &identifier).await, locked);
    assert_eq!(
        locked.locked_until(MOMENT),
        Some(MOMENT + Duration::minutes(1))
    );

    // An identifier and an address with the same digest are different
    // subjects.
    assert_eq!(lock(&ports, &tenant, &address).await.failures(), 0);

    // Another tenant has its own counters.
    let elsewhere = TenantContext::assume(TenantId::generate());
    assert_eq!(lock(&ports, &elsewhere, &identifier).await.lockouts(), 0);

    // Clearing forgets everything about one subject and nothing else.
    count(&ports, &tenant, &address).await;
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .attempts
        .clear(uow.as_mut(), &identifier)
        .await
        .expect("clear");
    uow.commit().await.expect("commit");
    assert_eq!(
        lock(&ports, &tenant, &identifier).await,
        AttemptCounter::new(identifier, MOMENT)
    );
    assert_eq!(lock(&ports, &tenant, &address).await.failures(), 1);
}
