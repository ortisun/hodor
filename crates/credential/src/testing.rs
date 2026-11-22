//! In-memory ports, a fake hasher and the contract every password store
//! passes.

use crate::api::{
    AccessToken, AccessTokenHash, AccessTokenId, AccessTokenStore, HistoricHash, PasswordHash,
    PasswordHasher, PasswordRecord, PasswordStore, PasswordVerification,
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

/// Access tokens kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryAccessTokens {
    rows: Arc<Mutex<BTreeMap<(TenantId, AccessTokenId), AccessToken>>>,
}

impl InMemoryAccessTokens {
    fn rows(&self) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, AccessTokenId), AccessToken>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl AccessTokenStore for InMemoryAccessTokens {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &AccessToken,
    ) -> Result<(), DomainError> {
        self.rows()
            .insert((uow.tenant().tenant_id(), token.id()), token.clone());
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: AccessTokenId,
    ) -> Result<Option<AccessToken>, DomainError> {
        Ok(self.rows().get(&(uow.tenant().tenant_id(), id)).cloned())
    }

    async fn find_by_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &AccessTokenHash,
    ) -> Result<Option<AccessToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .iter()
            .find(|((owner, _), token)| *owner == tenant && &token.snapshot().token_hash == hash)
            .map(|(_, token)| token.clone()))
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &AccessToken,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), token.id());
        let mut rows = self.rows();
        if !rows.contains_key(&key) {
            return Err(DomainError::not_found(
                "credential.access_token_not_found",
                "the access token does not exist",
            ));
        }
        rows.insert(key, token.clone());
        Ok(())
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct AccessTokenPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub tokens: &'a dyn AccessTokenStore,
}

impl std::fmt::Debug for AccessTokenPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessTokenPorts").finish_non_exhaustive()
    }
}

/// A random source for the contract whose every call gives different
/// bytes, so that every token made with it is different.
struct ContractRandom;

impl hodor_kernel::RandomSource for ContractRandom {
    fn fill(&self, buffer: &mut [u8]) {
        let unique = AccessTokenId::generate().as_uuid();
        for (byte, source) in buffer
            .iter_mut()
            .zip(unique.as_bytes().iter().rev().cycle())
        {
            *byte = *source;
        }
    }
}

/// Runs every rule an access token store must obey. Each run uses tenants
/// of its own, so runs can share one database.
///
/// # Panics
///
/// Panics if the implementation breaks a rule.
pub async fn run_access_token_contract(ports: AccessTokenPorts<'_>) {
    use hodor_kernel::random::testing::FakeDigest;
    let tenant = tenant();
    let elsewhere = self::tenant();
    let moment = Timestamp::UNIX_EPOCH;
    let (token, _) = AccessToken::issue(
        UserId::generate(),
        "first administrator",
        time::Duration::hours(1),
        moment,
        &ContractRandom,
        &FakeDigest,
    )
    .expect("valid token");
    let hash = token.snapshot().token_hash;

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .tokens
        .insert(uow.as_mut(), &token)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");

    // A stored token is loaded unchanged, by identifier and by hash, in
    // its own tenant only.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .tokens
            .get(uow.as_mut(), token.id())
            .await
            .expect("get"),
        Some(token.clone())
    );
    assert_eq!(
        ports
            .tokens
            .find_by_hash(uow.as_mut(), &hash)
            .await
            .expect("find"),
        Some(token.clone())
    );
    drop(uow);
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .tokens
            .get(uow.as_mut(), token.id())
            .await
            .expect("get"),
        None
    );
    assert_eq!(
        ports
            .tokens
            .find_by_hash(uow.as_mut(), &hash)
            .await
            .expect("find"),
        None
    );
    // Nor can another tenant change it.
    let mut revoked = token.clone();
    revoked.revoke(moment + time::Duration::minutes(5));
    let error = ports
        .tokens
        .update(uow.as_mut(), &revoked)
        .await
        .expect_err("another tenant's token");
    assert_eq!(error.code(), "credential.access_token_not_found");
    drop(uow);

    // A revocation is stored.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .tokens
        .update(uow.as_mut(), &revoked)
        .await
        .expect("update");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .tokens
            .find_by_hash(uow.as_mut(), &hash)
            .await
            .expect("find"),
        Some(revoked)
    );

    // An unknown hash and an unknown identifier find nothing.
    assert_eq!(
        ports
            .tokens
            .find_by_hash(uow.as_mut(), &AccessTokenHash::from_stored([9; 32]))
            .await
            .expect("find"),
        None
    );
    assert_eq!(
        ports
            .tokens
            .get(uow.as_mut(), AccessTokenId::generate())
            .await
            .expect("get"),
        None
    );
}

/// Authenticator applications kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryTotps {
    rows: Arc<Mutex<BTreeMap<(TenantId, crate::api::TotpId), crate::api::Totp>>>,
}

impl InMemoryTotps {
    fn rows(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, crate::api::TotpId), crate::api::Totp>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn find(
        &self,
        tenant: TenantId,
        user_id: UserId,
        status: crate::api::TotpStatus,
    ) -> Option<crate::api::Totp> {
        self.rows()
            .iter()
            .find(|((owner, _), totp)| {
                *owner == tenant
                    && totp.snapshot().user_id == user_id
                    && totp.snapshot().status == status
            })
            .map(|(_, totp)| totp.clone())
    }
}

#[async_trait::async_trait]
impl crate::api::TotpStore for InMemoryTotps {
    async fn active(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Option<crate::api::Totp>, DomainError> {
        Ok(self.find(
            uow.tenant().tenant_id(),
            user_id,
            crate::api::TotpStatus::Active,
        ))
    }

    async fn pending(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Option<crate::api::Totp>, DomainError> {
        Ok(self.find(
            uow.tenant().tenant_id(),
            user_id,
            crate::api::TotpStatus::Pending,
        ))
    }

    async fn replace_pending(
        &self,
        uow: &mut dyn UnitOfWork,
        enrollment: &crate::api::Totp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let user_id = enrollment.snapshot().user_id;
        let mut rows = self.rows();
        rows.retain(|(owner, _), totp| {
            !(*owner == tenant
                && totp.snapshot().user_id == user_id
                && totp.snapshot().status == crate::api::TotpStatus::Pending)
        });
        rows.insert((tenant, enrollment.id()), enrollment.clone());
        Ok(())
    }

    async fn activate(
        &self,
        uow: &mut dyn UnitOfWork,
        confirmed: &crate::api::Totp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let user_id = confirmed.snapshot().user_id;
        let mut rows = self.rows();
        let waiting = rows
            .get(&(tenant, confirmed.id()))
            .is_some_and(|stored| stored.snapshot().status == crate::api::TotpStatus::Pending);
        if !waiting {
            return Err(DomainError::not_found(
                "credential.totp_enrollment_not_found",
                "there is no enrollment of an authenticator application waiting to be confirmed; begin again",
            ));
        }
        rows.retain(|(owner, _), totp| {
            !(*owner == tenant
                && totp.snapshot().user_id == user_id
                && totp.snapshot().status == crate::api::TotpStatus::Active)
        });
        rows.insert((tenant, confirmed.id()), confirmed.clone());
        Ok(())
    }

    async fn use_step(
        &self,
        uow: &mut dyn UnitOfWork,
        id: crate::api::TotpId,
        step: u64,
    ) -> Result<bool, DomainError> {
        let mut rows = self.rows();
        let Some(totp) = rows.get_mut(&(uow.tenant().tenant_id(), id)) else {
            return Ok(false);
        };
        let mut state = totp.snapshot().clone();
        if state.status != crate::api::TotpStatus::Active
            || state.last_used_step.is_some_and(|last| step <= last)
        {
            return Ok(false);
        }
        state.last_used_step = Some(step);
        *totp = crate::api::Totp::from_snapshot(state);
        Ok(true)
    }

    async fn remove(&self, uow: &mut dyn UnitOfWork, user_id: UserId) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.rows();
        let had = rows.iter().any(|((owner, _), totp)| {
            *owner == tenant
                && totp.snapshot().user_id == user_id
                && totp.snapshot().status == crate::api::TotpStatus::Active
        });
        rows.retain(|(owner, _), totp| !(*owner == tenant && totp.snapshot().user_id == user_id));
        Ok(had)
    }
}

/// A stand-in for HMAC-SHA-1 in tests of use cases: deterministic, mixes
/// every byte of the key and the message, and is not HMAC. The real one is
/// tested against the vectors of RFC 6238 in `adapters-crypto`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeHmacSha1;

impl crate::api::HmacSha1 for FakeHmacSha1 {
    fn mac(&self, key: &[u8], message: &[u8]) -> [u8; 20] {
        let mut out = [0_u8; 20];
        let mut state: u32 = 0x811c_9dc5;
        for (index, byte) in key.iter().chain(message).enumerate() {
            state = (state ^ u32::from(*byte)).wrapping_mul(0x0100_0193);
            out[index % 20] ^= state.to_be_bytes()[index % 4];
        }
        for (index, slot) in out.iter_mut().enumerate() {
            state = (state ^ u32::try_from(index).unwrap_or(0)).wrapping_mul(0x0100_0193);
            *slot ^= state.to_be_bytes()[0];
        }
        out
    }
}

/// Reads the Base32 secret of an enrollment back into bytes, as an
/// authenticator application does.
///
/// # Panics
///
/// Panics if the text is not Base32 of RFC 4648 without padding.
#[must_use]
pub fn base32_secret(text: &str) -> Vec<u8> {
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bytes = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for character in text.chars() {
        let value =
            u32::try_from(ALPHABET.find(character).expect("a Base32 character")).expect("small");
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from((buffer >> bits) & 0xff).expect("one byte"));
        }
    }
    bytes
}

/// The ports under test.
#[derive(Clone)]
pub struct TotpPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub totps: &'a dyn crate::api::TotpStore,
}

impl std::fmt::Debug for TotpPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpPorts").finish_non_exhaustive()
    }
}

/// Runs every rule a store of authenticator applications must obey. Each
/// run uses tenants of its own, so runs can share one database.
///
/// # Panics
///
/// Panics if the implementation breaks a rule.
#[allow(
    clippy::too_many_lines,
    reason = "one contract, read from top to bottom"
)]
pub async fn run_totp_contract(ports: TotpPorts<'_>) {
    use crate::api::{Totp, TotpStatus};
    use hodor_kernel::SealedSecret;
    let tenant = tenant();
    let elsewhere = self::tenant();
    let user = UserId::generate();
    let moment = Timestamp::UNIX_EPOCH + time::Duration::days(20_000);
    let sealed = |byte: u8| SealedSecret::from_stored(vec![byte; 40]);

    // Nothing is stored for a new user.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .totps
            .active(uow.as_mut(), user)
            .await
            .expect("active"),
        None
    );
    assert_eq!(
        ports
            .totps
            .pending(uow.as_mut(), user)
            .await
            .expect("pending"),
        None
    );
    drop(uow);

    // A new enrollment takes the place of the earlier one still waiting.
    let first = Totp::begin(user, sealed(1), moment);
    let second = Totp::begin(user, sealed(2), moment);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .totps
        .replace_pending(uow.as_mut(), &first)
        .await
        .expect("first");
    ports
        .totps
        .replace_pending(uow.as_mut(), &second)
        .await
        .expect("second");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .totps
            .pending(uow.as_mut(), user)
            .await
            .expect("pending"),
        Some(second.clone())
    );
    assert_eq!(
        ports
            .totps
            .active(uow.as_mut(), user)
            .await
            .expect("active"),
        None
    );
    drop(uow);

    // Another tenant sees nothing, cannot put it in use, use it or remove it.
    let mut confirmed = second.clone();
    confirmed.confirm(100, moment);
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .totps
            .pending(uow.as_mut(), user)
            .await
            .expect("pending"),
        None
    );
    assert_eq!(
        ports
            .totps
            .activate(uow.as_mut(), &confirmed)
            .await
            .expect_err("another tenant's enrollment")
            .code(),
        "credential.totp_enrollment_not_found"
    );
    assert!(
        !ports
            .totps
            .remove(uow.as_mut(), user)
            .await
            .expect("remove")
    );
    drop(uow);

    // Putting it in use stores it unchanged, as the one in use.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .totps
        .activate(uow.as_mut(), &confirmed)
        .await
        .expect("activate");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .totps
            .active(uow.as_mut(), user)
            .await
            .expect("active"),
        Some(confirmed.clone())
    );
    assert_eq!(
        ports
            .totps
            .pending(uow.as_mut(), user)
            .await
            .expect("pending"),
        None
    );
    // It cannot be put in use a second time.
    assert_eq!(
        ports
            .totps
            .activate(uow.as_mut(), &confirmed)
            .await
            .expect_err("no longer pending")
            .code(),
        "credential.totp_enrollment_not_found"
    );
    drop(uow);

    // A step is used only when it is later than the last one, and only in
    // its own tenant.
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert!(
        !ports
            .totps
            .use_step(uow.as_mut(), confirmed.id(), 200)
            .await
            .expect("use")
    );
    drop(uow);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        !ports
            .totps
            .use_step(uow.as_mut(), confirmed.id(), 99)
            .await
            .expect("earlier")
    );
    assert!(
        !ports
            .totps
            .use_step(uow.as_mut(), confirmed.id(), 100)
            .await
            .expect("same")
    );
    assert!(
        ports
            .totps
            .use_step(uow.as_mut(), confirmed.id(), 101)
            .await
            .expect("later")
    );
    assert!(
        !ports
            .totps
            .use_step(uow.as_mut(), confirmed.id(), 101)
            .await
            .expect("again")
    );
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .totps
            .active(uow.as_mut(), user)
            .await
            .expect("active")
            .map(|totp| totp.snapshot().last_used_step),
        Some(Some(101))
    );
    drop(uow);

    // A new application waiting does not disturb the one in use; once
    // confirmed it replaces it.
    let third = Totp::begin(user, sealed(3), moment);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .totps
        .replace_pending(uow.as_mut(), &third)
        .await
        .expect("third");
    assert_eq!(
        ports
            .totps
            .active(uow.as_mut(), user)
            .await
            .expect("active")
            .map(|t| t.id()),
        Some(confirmed.id())
    );
    let mut third_confirmed = third.clone();
    third_confirmed.confirm(500, moment);
    ports
        .totps
        .activate(uow.as_mut(), &third_confirmed)
        .await
        .expect("activate");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let active = ports
        .totps
        .active(uow.as_mut(), user)
        .await
        .expect("active")
        .expect("one");
    assert_eq!(active, third_confirmed);
    assert_eq!(active.snapshot().status, TotpStatus::Active);
    // The application replaced cannot be used any more.
    assert!(
        !ports
            .totps
            .use_step(uow.as_mut(), confirmed.id(), 1_000)
            .await
            .expect("use")
    );
    drop(uow);

    // Removing takes everything away and says whether one was in use.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .totps
        .replace_pending(uow.as_mut(), &Totp::begin(user, sealed(4), moment))
        .await
        .expect("waiting");
    assert!(
        ports
            .totps
            .remove(uow.as_mut(), user)
            .await
            .expect("remove")
    );
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .totps
            .active(uow.as_mut(), user)
            .await
            .expect("active"),
        None
    );
    assert_eq!(
        ports
            .totps
            .pending(uow.as_mut(), user)
            .await
            .expect("pending"),
        None
    );
    assert!(!ports.totps.remove(uow.as_mut(), user).await.expect("again"));
}

type WebAuthnRows =
    BTreeMap<(TenantId, crate::api::WebAuthnCredentialId), crate::api::WebAuthnCredential>;
type RegistrationRows =
    BTreeMap<(TenantId, crate::api::WebAuthnRegistrationId), crate::api::PendingRegistration>;

/// WebAuthn credentials and pending registrations kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryWebAuthn {
    credentials: Arc<Mutex<WebAuthnRows>>,
    registrations: Arc<Mutex<RegistrationRows>>,
}

impl InMemoryWebAuthn {
    fn credentials(&self) -> std::sync::MutexGuard<'_, WebAuthnRows> {
        self.credentials.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn registrations(&self) -> std::sync::MutexGuard<'_, RegistrationRows> {
        self.registrations.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl crate::api::WebAuthnStore for InMemoryWebAuthn {
    async fn insert_registration(
        &self,
        uow: &mut dyn UnitOfWork,
        registration: &crate::api::PendingRegistration,
    ) -> Result<(), DomainError> {
        self.registrations().insert(
            (uow.tenant().tenant_id(), registration.snapshot().id),
            registration.clone(),
        );
        Ok(())
    }

    async fn take_registration(
        &self,
        uow: &mut dyn UnitOfWork,
        id: crate::api::WebAuthnRegistrationId,
    ) -> Result<Option<crate::api::PendingRegistration>, DomainError> {
        Ok(self.registrations().remove(&(uow.tenant().tenant_id(), id)))
    }

    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        credential: &crate::api::WebAuthnCredential,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.credentials();
        if rows.iter().any(|((owner, _), existing)| {
            *owner == tenant
                && existing.snapshot().credential_id == credential.snapshot().credential_id
        }) {
            return Err(DomainError::conflict(
                "credential.webauthn_credential_exists",
                "this security key is already registered",
            ));
        }
        rows.insert((tenant, credential.id()), credential.clone());
        Ok(())
    }

    async fn list_for_user(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Vec<crate::api::WebAuthnCredential>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut found: Vec<_> = self
            .credentials()
            .iter()
            .filter(|((owner, _), credential)| *owner == tenant && credential.user_id() == user_id)
            .map(|(_, credential)| credential.clone())
            .collect();
        found.sort_by_key(|credential| (credential.snapshot().created_at, credential.id()));
        Ok(found)
    }

    async fn find_by_credential_id(
        &self,
        uow: &mut dyn UnitOfWork,
        credential_id: &[u8],
    ) -> Result<Option<crate::api::WebAuthnCredential>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .credentials()
            .iter()
            .find(|((owner, _), credential)| {
                *owner == tenant && credential.snapshot().credential_id == credential_id
            })
            .map(|(_, credential)| credential.clone()))
    }

    async fn record_use(
        &self,
        uow: &mut dyn UnitOfWork,
        credential: &crate::api::WebAuthnCredential,
        previous_count: u32,
    ) -> Result<bool, DomainError> {
        let key = (uow.tenant().tenant_id(), credential.id());
        let mut rows = self.credentials();
        match rows.get(&key) {
            Some(stored) if stored.snapshot().sign_count == previous_count => {
                rows.insert(key, credential.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct WebAuthnPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub store: &'a dyn crate::api::WebAuthnStore,
}

impl std::fmt::Debug for WebAuthnPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebAuthnPorts").finish_non_exhaustive()
    }
}

/// A credential as a store keeps it, made directly: the contract is about
/// storage, not about the checks.
#[must_use]
pub fn stored_credential(
    user_id: UserId,
    credential_id: Vec<u8>,
    created_at: Timestamp,
) -> crate::api::WebAuthnCredential {
    crate::api::WebAuthnCredential::from_snapshot(crate::api::WebAuthnCredentialSnapshot {
        id: crate::api::WebAuthnCredentialId::generate(),
        user_id,
        credential_id,
        public_key: vec![0xa0],
        algorithm: crate::api::CoseAlgorithm::Es256,
        sign_count: 3,
        backup_eligible: true,
        backed_up: false,
        discoverable: Some(true),
        transports: vec!["internal".to_owned(), "usb".to_owned()],
        name: "Blue key".to_owned(),
        created_at,
        last_used_at: None,
    })
}

/// Runs every rule a WebAuthn store must obey. Each run uses tenants of
/// its own, so runs can share one database.
///
/// # Panics
///
/// Panics if the implementation breaks a rule.
pub async fn run_webauthn_contract(ports: WebAuthnPorts<'_>) {
    let tenant = tenant();
    let elsewhere = self::tenant();
    let moment = Timestamp::UNIX_EPOCH + time::Duration::days(20_000);
    let user = UserId::generate();
    let identifier = crate::api::WebAuthnCredentialId::generate()
        .as_uuid()
        .as_bytes()
        .to_vec();
    let first = stored_credential(user, identifier.clone(), moment);
    let second = stored_credential(user, vec![7; 64], moment + time::Duration::minutes(1));

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .store
        .insert(uow.as_mut(), &second)
        .await
        .expect("insert");
    ports
        .store
        .insert(uow.as_mut(), &first)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");

    // A user's credentials come back unchanged, oldest first, in their
    // own tenant only.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .store
            .list_for_user(uow.as_mut(), user)
            .await
            .expect("list"),
        vec![first.clone(), second.clone()]
    );
    assert_eq!(
        ports
            .store
            .list_for_user(uow.as_mut(), UserId::generate())
            .await
            .expect("list"),
        Vec::new()
    );
    // A credential is found by the identifier the authenticator made,
    // whoever it belongs to.
    assert_eq!(
        ports
            .store
            .find_by_credential_id(uow.as_mut(), &identifier)
            .await
            .expect("find"),
        Some(first.clone())
    );
    assert_eq!(
        ports
            .store
            .find_by_credential_id(uow.as_mut(), &[9; 16])
            .await
            .expect("find"),
        None
    );
    // The same credential identifier cannot be registered twice in a
    // tenant, for anyone.
    let error = ports
        .store
        .insert(
            uow.as_mut(),
            &stored_credential(UserId::generate(), identifier.clone(), moment),
        )
        .await
        .expect_err("a duplicate");
    assert_eq!(error.code(), "credential.webauthn_credential_exists");
    drop(uow);

    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .store
            .list_for_user(uow.as_mut(), user)
            .await
            .expect("list"),
        Vec::new()
    );
    // Another tenant has its own credentials, even with the same
    // identifier, and cannot change this tenant's.
    ports
        .store
        .insert(
            uow.as_mut(),
            &stored_credential(user, identifier.clone(), moment),
        )
        .await
        .expect("another tenant's own");
    assert!(
        !ports
            .store
            .record_use(uow.as_mut(), &first, 3)
            .await
            .expect("record")
    );
    uow.commit().await.expect("commit");
    // This tenant's credential is not found from the other one, even
    // where the other has one with the same identifier of its own.
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    let theirs = ports
        .store
        .find_by_credential_id(uow.as_mut(), &identifier)
        .await
        .expect("find")
        .expect("the other tenant's own");
    assert_ne!(theirs.id(), first.id());
    assert_eq!(
        ports
            .store
            .find_by_credential_id(uow.as_mut(), &[7; 64])
            .await
            .expect("find"),
        None
    );
    drop(uow);

    // A use is stored only over the counter that was read.
    let mut used = first.clone();
    let mut snapshot = used.snapshot().clone();
    snapshot.sign_count = 4;
    snapshot.backed_up = true;
    snapshot.last_used_at = Some(moment + time::Duration::hours(1));
    used = crate::api::WebAuthnCredential::from_snapshot(snapshot);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        ports
            .store
            .record_use(uow.as_mut(), &used, 3)
            .await
            .expect("record")
    );
    assert!(
        !ports
            .store
            .record_use(uow.as_mut(), &used, 3)
            .await
            .expect("record")
    );
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .store
            .list_for_user(uow.as_mut(), user)
            .await
            .expect("list")[0],
        used
    );
    drop(uow);

    // A pending registration is taken once, in its own tenant only, and
    // keeps whether it is for a passkey.
    let pending = crate::api::PendingRegistration::begin(user, true, &ContractRandom, moment);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .store
        .insert_registration(uow.as_mut(), &pending)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .store
            .take_registration(uow.as_mut(), pending.snapshot().id)
            .await
            .expect("take"),
        None
    );
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .store
            .take_registration(uow.as_mut(), pending.snapshot().id)
            .await
            .expect("take"),
        Some(pending.clone())
    );
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .store
            .take_registration(uow.as_mut(), pending.snapshot().id)
            .await
            .expect("take"),
        None
    );
}

type StoredSet = (crate::api::RecoveryCodeSetId, Vec<([u8; 32], bool)>);

/// Recovery codes kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryRecoveryCodes {
    sets: Arc<Mutex<BTreeMap<(TenantId, UserId), StoredSet>>>,
}

impl InMemoryRecoveryCodes {
    fn sets(&self) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, UserId), StoredSet>> {
        self.sets.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl crate::api::RecoveryCodeStore for InMemoryRecoveryCodes {
    async fn replace(
        &self,
        uow: &mut dyn UnitOfWork,
        set: &crate::api::RecoveryCodeSet,
    ) -> Result<(), DomainError> {
        let codes = set.code_hashes.iter().map(|hash| (*hash, false)).collect();
        self.sets()
            .insert((uow.tenant().tenant_id(), set.user_id), (set.id, codes));
        Ok(())
    }

    async fn use_code(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        code_hash: &[u8; 32],
    ) -> Result<bool, DomainError> {
        let mut sets = self.sets();
        let Some((_, codes)) = sets.get_mut(&(uow.tenant().tenant_id(), user_id)) else {
            return Ok(false);
        };
        match codes
            .iter_mut()
            .find(|(hash, used)| hash == code_hash && !*used)
        {
            Some((_, used)) => {
                *used = true;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn unused(&self, uow: &mut dyn UnitOfWork, user_id: UserId) -> Result<u32, DomainError> {
        let count = self
            .sets()
            .get(&(uow.tenant().tenant_id(), user_id))
            .map_or(0, |(_, codes)| {
                codes.iter().filter(|(_, used)| !used).count()
            });
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn remove(&self, uow: &mut dyn UnitOfWork, user_id: UserId) -> Result<bool, DomainError> {
        Ok(self
            .sets()
            .remove(&(uow.tenant().tenant_id(), user_id))
            .is_some())
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct RecoveryCodePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub codes: &'a dyn crate::api::RecoveryCodeStore,
}

impl std::fmt::Debug for RecoveryCodePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCodePorts").finish_non_exhaustive()
    }
}

/// Runs every rule a store of recovery codes must obey. Each run uses
/// tenants of its own, so runs can share one database.
///
/// # Panics
///
/// Panics if the implementation breaks a rule.
#[allow(
    clippy::too_many_lines,
    reason = "one contract, read from top to bottom"
)]
pub async fn run_recovery_code_contract(ports: RecoveryCodePorts<'_>) {
    use crate::api::{RecoveryCodeSet, RecoveryCodeSetId};
    let tenant = tenant();
    let elsewhere = self::tenant();
    let user = UserId::generate();
    let other = UserId::generate();
    let moment = Timestamp::UNIX_EPOCH + time::Duration::days(20_000);
    let hash = |byte: u8| [byte; 32];
    let set = |user_id: UserId, bytes: &[u8]| RecoveryCodeSet {
        id: RecoveryCodeSetId::generate(),
        user_id,
        created_at: moment,
        code_hashes: bytes.iter().map(|byte| hash(*byte)).collect(),
    };
    let codes = ports.codes;

    // Nothing is stored for a new user.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(codes.unused(uow.as_mut(), user).await.expect("unused"), 0);
    assert!(
        !codes
            .use_code(uow.as_mut(), user, &hash(1))
            .await
            .expect("use")
    );
    assert!(!codes.remove(uow.as_mut(), user).await.expect("remove"));
    drop(uow);

    // A set is stored, and each of its codes is good for one use.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    codes
        .replace(uow.as_mut(), &set(user, &[1, 2, 3]))
        .await
        .expect("replace");
    codes
        .replace(uow.as_mut(), &set(other, &[1, 9]))
        .await
        .expect("other user");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(codes.unused(uow.as_mut(), user).await.expect("unused"), 3);
    assert!(
        codes
            .use_code(uow.as_mut(), user, &hash(1))
            .await
            .expect("first use")
    );
    assert!(
        !codes
            .use_code(uow.as_mut(), user, &hash(1))
            .await
            .expect("second use")
    );
    assert!(
        !codes
            .use_code(uow.as_mut(), user, &hash(7))
            .await
            .expect("not a code of the set")
    );
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(codes.unused(uow.as_mut(), user).await.expect("unused"), 2);
    assert!(
        !codes
            .use_code(uow.as_mut(), user, &hash(1))
            .await
            .expect("used before")
    );

    // A code is the user's own: another user's code does not work, and
    // using one does not use the other user's equal code.
    assert!(
        !codes
            .use_code(uow.as_mut(), user, &hash(9))
            .await
            .expect("another user's code")
    );
    assert_eq!(codes.unused(uow.as_mut(), other).await.expect("unused"), 2);
    drop(uow);

    // Nothing of one tenant is seen or used from another.
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(codes.unused(uow.as_mut(), user).await.expect("unused"), 0);
    assert!(
        !codes
            .use_code(uow.as_mut(), user, &hash(2))
            .await
            .expect("from another tenant")
    );
    assert!(
        !codes
            .remove(uow.as_mut(), user)
            .await
            .expect("remove from another tenant")
    );
    drop(uow);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(codes.unused(uow.as_mut(), user).await.expect("unused"), 2);
    drop(uow);

    // A new set ends the old one whole, used codes and unused ones.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    codes
        .replace(uow.as_mut(), &set(user, &[4]))
        .await
        .expect("new set");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(codes.unused(uow.as_mut(), user).await.expect("unused"), 1);
    assert!(
        !codes
            .use_code(uow.as_mut(), user, &hash(2))
            .await
            .expect("a code of the old set")
    );
    assert!(
        codes
            .use_code(uow.as_mut(), user, &hash(4))
            .await
            .expect("a code of the new set")
    );
    uow.commit().await.expect("commit");

    // Removing takes the set away, and only the user's.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(codes.remove(uow.as_mut(), user).await.expect("remove"));
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(codes.unused(uow.as_mut(), user).await.expect("unused"), 0);
    assert!(!codes.remove(uow.as_mut(), user).await.expect("again"));
    assert_eq!(codes.unused(uow.as_mut(), other).await.expect("unused"), 2);
}
