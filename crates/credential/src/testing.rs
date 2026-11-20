//! In-memory ports, a fake hasher and the contract every password store
//! passes.

use crate::api::{
    HistoricHash, PasswordHash, PasswordHasher, PasswordRecord, PasswordStore, PasswordVerification,
};
use hodor_kernel::{
    DomainError, ErrorKind, Secret, TenantContext, TenantId, Timestamp, UnitOfWork,
    UnitOfWorkFactory, UserId,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Password records kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryPasswords {
    rows: Arc<Mutex<BTreeMap<(TenantId, UserId), PasswordRecord>>>,
}

impl InMemoryPasswords {
    fn rows(&self) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, UserId), PasswordRecord>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn with_version(record: &PasswordRecord, version: u32) -> PasswordRecord {
    PasswordRecord::from_stored(
        record.user_id(),
        record.hash().clone(),
        record.must_change(),
        record.changed_at(),
        record.history().to_vec(),
        version,
    )
}

#[async_trait::async_trait]
impl PasswordStore for InMemoryPasswords {
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Option<PasswordRecord>, DomainError> {
        Ok(self
            .rows()
            .get(&(uow.tenant().tenant_id(), user_id))
            .cloned())
    }

    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        record: &PasswordRecord,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), record.user_id());
        let mut rows = self.rows();
        if rows.contains_key(&key) {
            return Err(DomainError::conflict(
                "credential.password_exists",
                "the user already has a password",
            ));
        }
        rows.insert(key, record.clone());
        Ok(())
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        record: &PasswordRecord,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), record.user_id());
        let mut rows = self.rows();
        let stored = rows.get(&key).ok_or_else(|| {
            DomainError::not_found("credential.password_not_found", "the user has no password")
        })?;
        if stored.version() != record.version() {
            return Err(DomainError::conflict(
                "credential.password_modified_concurrently",
                "the password was changed by someone else; try again",
            ));
        }
        rows.insert(key, with_version(record, record.version() + 1));
        Ok(())
    }

    async fn delete(&self, uow: &mut dyn UnitOfWork, user_id: UserId) -> Result<bool, DomainError> {
        Ok(self
            .rows()
            .remove(&(uow.tenant().tenant_id(), user_id))
            .is_some())
    }
}

/// A hasher for tests. It is instant, its "hashes" contain the password in
/// the clear, and it must never be used outside tests.
///
/// It imitates what matters to the use cases: hashes carry a generation
/// that stands for the parameters, a check against nothing is counted, and
/// overload can be switched on.
#[derive(Debug, Default)]
pub struct FakeHasher {
    generation: AtomicU32,
    overloaded: AtomicBool,
    hashes: AtomicUsize,
    verifications: AtomicUsize,
    checks_against_nothing: AtomicUsize,
}

impl FakeHasher {
    /// Simulates raising the hashing parameters: hashes made before this
    /// call still verify, and ask for renewal.
    pub fn raise_parameters(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Makes every operation fail as overloaded, or stop failing.
    pub fn set_overloaded(&self, overloaded: bool) {
        self.overloaded.store(overloaded, Ordering::SeqCst);
    }

    /// How many hashes were computed.
    #[must_use]
    pub fn hashes(&self) -> usize {
        self.hashes.load(Ordering::SeqCst)
    }

    /// How many real verifications were computed.
    #[must_use]
    pub fn verifications(&self) -> usize {
        self.verifications.load(Ordering::SeqCst)
    }

    /// How many checks against nothing were computed.
    #[must_use]
    pub fn checks_against_nothing(&self) -> usize {
        self.checks_against_nothing.load(Ordering::SeqCst)
    }

    fn admit(&self) -> Result<(), DomainError> {
        if self.overloaded.load(Ordering::SeqCst) {
            Err(DomainError::new(
                ErrorKind::Unavailable,
                "credential.hashing_overloaded",
                "the server is busy; try again in a moment",
            ))
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait]
impl PasswordHasher for FakeHasher {
    async fn hash(&self, password: &Secret<String>) -> Result<PasswordHash, DomainError> {
        self.admit()?;
        self.hashes.fetch_add(1, Ordering::SeqCst);
        Ok(PasswordHash::new(format!(
            "fake${}${}",
            self.generation.load(Ordering::SeqCst),
            password.expose()
        )))
    }

    async fn verify(
        &self,
        password: &Secret<String>,
        hash: &PasswordHash,
    ) -> Result<PasswordVerification, DomainError> {
        self.admit()?;
        self.verifications.fetch_add(1, Ordering::SeqCst);
        let mut parts = hash.as_str().splitn(3, '$');
        let (Some("fake"), Some(generation), Some(stored)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(DomainError::internal(
                "credential.hashing_failed",
                "the operation could not be completed",
            ));
        };
        Ok(PasswordVerification {
            matches: stored == password.expose(),
            needs_renewal: generation != self.generation.load(Ordering::SeqCst).to_string(),
        })
    }

    async fn verify_nothing(&self, _password: &Secret<String>) -> Result<(), DomainError> {
        self.admit()?;
        self.checks_against_nothing.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct Ports<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub passwords: &'a dyn PasswordStore,
}

impl std::fmt::Debug for Ports<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

/// A fixed, whole-second moment, so that stored timestamps compare equal
/// after a round trip through any storage.
const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;

fn hash(label: &str) -> PasswordHash {
    PasswordHash::new(format!("stored-hash-{label}"))
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

async fn insert(
    ports: &Ports<'_>,
    tenant: &TenantContext,
    record: &PasswordRecord,
) -> Result<(), DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await?;
    ports.passwords.insert(uow.as_mut(), record).await?;
    uow.commit().await
}

async fn update(
    ports: &Ports<'_>,
    tenant: &TenantContext,
    record: &PasswordRecord,
) -> Result<(), DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await?;
    ports.passwords.update(uow.as_mut(), record).await?;
    uow.commit().await
}

async fn get(ports: &Ports<'_>, tenant: &TenantContext, user_id: UserId) -> Option<PasswordRecord> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .passwords
        .get(uow.as_mut(), user_id)
        .await
        .expect("get")
}

async fn delete(ports: &Ports<'_>, tenant: &TenantContext, user_id: UserId) -> bool {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let removed = ports
        .passwords
        .delete(uow.as_mut(), user_id)
        .await
        .expect("delete");
    uow.commit().await.expect("commit");
    removed
}

/// Runs the whole contract. Each case uses tenants of its own, so runs can
/// share one database.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_contract(ports: Ports<'_>) {
    a_stored_record_is_loaded_unchanged(&ports).await;
    a_user_has_one_password(&ports).await;
    a_record_is_invisible_from_another_tenant(&ports).await;
    the_history_is_stored_in_order(&ports).await;
    a_stale_update_is_rejected(&ports).await;
    an_update_cannot_reach_another_tenant(&ports).await;
    deleting_removes_the_password_and_its_history(&ports).await;
}

async fn a_stored_record_is_loaded_unchanged(ports: &Ports<'_>) {
    let tenant = tenant();
    let record = PasswordRecord::new(UserId::generate(), hash("first"), true, MOMENT);
    insert(ports, &tenant, &record).await.expect("insert");
    assert_eq!(get(ports, &tenant, record.user_id()).await, Some(record));
    assert_eq!(get(ports, &tenant, UserId::generate()).await, None);
}

async fn a_user_has_one_password(ports: &Ports<'_>) {
    let tenant = tenant();
    let user_id = UserId::generate();
    insert(
        ports,
        &tenant,
        &PasswordRecord::new(user_id, hash("first"), false, MOMENT),
    )
    .await
    .expect("first");
    let error = insert(
        ports,
        &tenant,
        &PasswordRecord::new(user_id, hash("second"), false, MOMENT),
    )
    .await
    .expect_err("second");
    assert_eq!(error.code(), "credential.password_exists");
    assert_eq!(
        get(ports, &tenant, user_id).await.expect("exists").hash(),
        &hash("first")
    );
}

async fn a_record_is_invisible_from_another_tenant(ports: &Ports<'_>) {
    let (home, elsewhere) = (tenant(), tenant());
    let record = PasswordRecord::new(UserId::generate(), hash("first"), false, MOMENT);
    insert(ports, &home, &record).await.expect("insert");
    assert_eq!(get(ports, &elsewhere, record.user_id()).await, None);
    // The same user identifier in another tenant is another password.
    insert(
        ports,
        &elsewhere,
        &PasswordRecord::new(record.user_id(), hash("other"), false, MOMENT),
    )
    .await
    .expect("independent");
    assert_eq!(
        get(ports, &home, record.user_id())
            .await
            .expect("exists")
            .hash(),
        &hash("first")
    );
}

async fn the_history_is_stored_in_order(ports: &Ports<'_>) {
    let tenant = tenant();
    let user_id = UserId::generate();
    insert(
        ports,
        &tenant,
        &PasswordRecord::new(user_id, hash("1"), true, MOMENT),
    )
    .await
    .expect("insert");

    // Three changes with a history depth of two, each stored and reloaded.
    for label in ["2", "3", "4"] {
        let mut record = get(ports, &tenant, user_id).await.expect("exists");
        record.replace(hash(label), false, 2, MOMENT);
        update(ports, &tenant, &record).await.expect("update");
    }

    let stored = get(ports, &tenant, user_id).await.expect("exists");
    assert_eq!(stored.hash(), &hash("4"));
    assert!(!stored.must_change());
    assert_eq!(stored.version(), 3);
    let history: Vec<&HistoricHash> = stored.history().iter().collect();
    assert_eq!(history.len(), 2, "trimmed to the depth");
    assert_eq!(history[0].hash, hash("3"), "newest first");
    assert_eq!(history[1].hash, hash("2"));
}

async fn a_stale_update_is_rejected(ports: &Ports<'_>) {
    let tenant = tenant();
    let user_id = UserId::generate();
    insert(
        ports,
        &tenant,
        &PasswordRecord::new(user_id, hash("1"), false, MOMENT),
    )
    .await
    .expect("insert");

    let mut first = get(ports, &tenant, user_id).await.expect("exists");
    let mut second = first.clone();
    first.replace(hash("first-writer"), false, 5, MOMENT);
    second.replace(hash("second-writer"), false, 5, MOMENT);
    update(ports, &tenant, &first).await.expect("first update");
    let error = update(ports, &tenant, &second)
        .await
        .expect_err("stale update");
    assert_eq!(error.code(), "credential.password_modified_concurrently");
    assert_eq!(
        get(ports, &tenant, user_id).await.expect("exists").hash(),
        &hash("first-writer")
    );
}

async fn an_update_cannot_reach_another_tenant(ports: &Ports<'_>) {
    let (home, elsewhere) = (tenant(), tenant());
    let record = PasswordRecord::new(UserId::generate(), hash("1"), false, MOMENT);
    insert(ports, &home, &record).await.expect("insert");

    let mut tampered = record.clone();
    tampered.replace(hash("tampered"), false, 5, MOMENT);
    let error = update(ports, &elsewhere, &tampered)
        .await
        .expect_err("cross-tenant");
    assert_eq!(error.code(), "credential.password_not_found");
    assert!(!delete(ports, &elsewhere, record.user_id()).await);
    assert_eq!(get(ports, &home, record.user_id()).await, Some(record));
}

async fn deleting_removes_the_password_and_its_history(ports: &Ports<'_>) {
    let tenant = tenant();
    let user_id = UserId::generate();
    insert(
        ports,
        &tenant,
        &PasswordRecord::new(user_id, hash("1"), false, MOMENT),
    )
    .await
    .expect("insert");
    let mut record = get(ports, &tenant, user_id).await.expect("exists");
    record.replace(hash("2"), false, 5, MOMENT);
    update(ports, &tenant, &record).await.expect("update");

    assert!(delete(ports, &tenant, user_id).await);
    assert_eq!(get(ports, &tenant, user_id).await, None);
    assert!(
        !delete(ports, &tenant, user_id).await,
        "nothing left to delete"
    );
    // A new password starts with an empty history.
    insert(
        ports,
        &tenant,
        &PasswordRecord::new(user_id, hash("fresh"), false, MOMENT),
    )
    .await
    .expect("insert again");
    assert!(
        get(ports, &tenant, user_id)
            .await
            .expect("exists")
            .history()
            .is_empty()
    );
}
