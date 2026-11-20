//! In-memory stores and the contracts every implementation of them passes.

use crate::api::{
    AttemptCounter, AttemptStore, AttemptSubject, AuthFlow, AuthTransaction, LockoutRules,
    TransactionId, TransactionStore,
};
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use hodor_session::api::ClientInfo;
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

/// Sign-ins in progress kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryTransactions {
    rows: Arc<Mutex<BTreeMap<(TenantId, TransactionId), AuthTransaction>>>,
}

impl InMemoryTransactions {
    fn rows(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, TransactionId), AuthTransaction>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn next_version(transaction: &AuthTransaction) -> AuthTransaction {
    let mut state = transaction.snapshot().clone();
    state.version += 1;
    AuthTransaction::from_snapshot(state)
}

#[async_trait::async_trait]
impl TransactionStore for InMemoryTransactions {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: &AuthTransaction,
    ) -> Result<(), DomainError> {
        self.rows().insert(
            (uow.tenant().tenant_id(), transaction.id()),
            transaction.clone(),
        );
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TransactionId,
    ) -> Result<Option<AuthTransaction>, DomainError> {
        Ok(self.rows().get(&(uow.tenant().tenant_id(), id)).cloned())
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: &AuthTransaction,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), transaction.id());
        let mut rows = self.rows();
        let stored = rows.get(&key).ok_or_else(|| {
            DomainError::not_found(
                "authentication.transaction_not_found",
                "this sign-in does not exist; start again",
            )
        })?;
        if stored.snapshot().version != transaction.snapshot().version {
            return Err(DomainError::conflict(
                "authentication.transaction_modified_concurrently",
                "this sign-in was advanced by another request",
            ));
        }
        rows.insert(key, next_version(transaction));
        Ok(())
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct TransactionPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub transactions: &'a dyn TransactionStore,
}

impl std::fmt::Debug for TransactionPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionPorts").finish_non_exhaustive()
    }
}

async fn stored(
    ports: &TransactionPorts<'_>,
    tenant: &TenantContext,
    id: TransactionId,
) -> Option<AuthTransaction> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.transactions.get(uow.as_mut(), id).await.expect("get")
}

async fn update(
    ports: &TransactionPorts<'_>,
    tenant: &TenantContext,
    transaction: &AuthTransaction,
) -> Result<(), DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await?;
    ports.transactions.update(uow.as_mut(), transaction).await?;
    uow.commit().await
}

/// Runs the whole contract of a transaction store. Each run uses tenants
/// of its own, so runs can share one database.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_transaction_contract(ports: TransactionPorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let flow = AuthFlow::built_in();
    let client = ClientInfo {
        address: Some("203.0.113.9".to_owned()),
        description: Some("Example Browser 1.0".to_owned()),
    };
    let transaction = AuthTransaction::start(&flow, client, MOMENT);

    // A stored transaction is loaded unchanged, within its tenant only.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .transactions
        .insert(uow.as_mut(), &transaction)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
    assert_eq!(
        stored(&ports, &tenant, transaction.id()).await,
        Some(transaction.clone())
    );
    assert_eq!(stored(&ports, &elsewhere, transaction.id()).await, None);
    assert_eq!(
        stored(&ports, &tenant, TransactionId::generate()).await,
        None
    );

    // Progress is stored, and raises the version.
    let mut advanced = transaction.clone();
    advanced.record_identified(Some(hodor_kernel::UserId::generate()), [5; 32]);
    advanced.record_rejection();
    update(&ports, &tenant, &advanced).await.expect("update");
    let reloaded = stored(&ports, &tenant, transaction.id())
        .await
        .expect("exists");
    assert_eq!(reloaded.snapshot().version, 1);
    assert_eq!(reloaded.snapshot().current_step, 1);
    assert_eq!(reloaded.snapshot().candidate, advanced.snapshot().candidate);
    assert_eq!(reloaded.snapshot().identifier_key, Some([5; 32]));
    assert_eq!(reloaded.snapshot().rejections, 1);
    assert!(reloaded.snapshot().identified);

    // Of two requests working from the same version, the second is
    // refused. This is what makes completion happen once.
    let (mut first, mut second) = (reloaded.clone(), reloaded.clone());
    first.record_satisfied(Some("password"));
    second.record_satisfied(Some("password"));
    first.complete(&flow, MOMENT).expect("complete");
    second.complete(&flow, MOMENT).expect("complete");
    update(&ports, &tenant, &first).await.expect("first");
    let error = update(&ports, &tenant, &second).await.expect_err("second");
    assert_eq!(
        error.code(),
        "authentication.transaction_modified_concurrently"
    );
    let ended = stored(&ports, &tenant, transaction.id())
        .await
        .expect("exists");
    assert_eq!(ended.snapshot().satisfied_methods, ["password"]);
    assert_eq!(ended.snapshot().status, first.snapshot().status);

    // A transaction cannot be updated from another tenant.
    let error = update(&ports, &elsewhere, &ended)
        .await
        .expect_err("cross-tenant");
    assert_eq!(error.code(), "authentication.transaction_not_found");
}
