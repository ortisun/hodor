//! In-memory stores, a stand-in provider and stand-in bundle endpoints,
//! and the contracts every key store, trust domain store and key provider
//! pass.

use crate::api::{
    CheckedSource, DueRefreshes, GeneratedKey, KeyAlgorithm, KeyMaterial, KeyProvider, KeyState,
    KeyStore, KeyUse, KeyVersion, KeyVersionId, KeyVersionSnapshot, SignatureEncoding, TrustBundle,
    TrustDomain, TrustDomainId, TrustDomainStore,
};
use hodor_kernel::{
    DestinationCheck, DomainError, HttpClient, HttpRequest, HttpResponse, PublicKey, Secret,
    SignatureVerifier, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use time::Duration;

/// Key versions kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryKeys {
    rows: Arc<Mutex<BTreeMap<(TenantId, KeyVersionId), KeyVersion>>>,
}

impl InMemoryKeys {
    fn rows(&self) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, KeyVersionId), KeyVersion>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl KeyStore for InMemoryKeys {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        version: &KeyVersion,
    ) -> Result<(), DomainError> {
        self.rows()
            .insert((uow.tenant().tenant_id(), version.id()), version.clone());
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: KeyVersionId,
    ) -> Result<Option<KeyVersion>, DomainError> {
        Ok(self.rows().get(&(uow.tenant().tenant_id(), id)).cloned())
    }

    async fn list_for_use(
        &self,
        uow: &mut dyn UnitOfWork,
        key_use: KeyUse,
    ) -> Result<Vec<KeyVersion>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .iter()
            .filter(|((owner, _), version)| *owner == tenant && version.key_use() == key_use)
            .map(|(_, version)| version.clone())
            .collect())
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        version: &KeyVersion,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), version.id());
        let mut rows = self.rows();
        let Some(stored) = rows.get(&key) else {
            return Err(DomainError::not_found(
                "keys.version_not_found",
                "the key version does not exist",
            ));
        };
        // Only the lifecycle changes; the key stays as it was made.
        let mut changed = stored.snapshot().clone();
        let new = version.snapshot();
        changed.state = new.state;
        changed.activated_at = new.activated_at;
        changed.retiring_at = new.retiring_at;
        changed.retire_after = new.retire_after;
        changed.retired_at = new.retired_at;
        changed.revoked_at = new.revoked_at;
        changed.revocation_reason.clone_from(&new.revocation_reason);
        rows.insert(key, KeyVersion::from_snapshot(changed));
        Ok(())
    }
}

/// A provider for tests of use cases: its "signature" is the message with
/// the tenant, version and algorithm in front, and its material names them,
/// so a test can see that the right key was asked for. Its public keys are
/// made up. Never use outside tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeKeyProvider;

fn label(tenant: &TenantContext, version: KeyVersionId, algorithm: KeyAlgorithm) -> Vec<u8> {
    format!(
        "fake|{}|{version}|{}|",
        tenant.tenant_id(),
        algorithm.as_str()
    )
    .into_bytes()
}

fn refused() -> DomainError {
    DomainError::internal("keys.unusable", "the key could not be used")
}

fn check(
    tenant: &TenantContext,
    version: &KeyVersion,
    key_use: KeyUse,
) -> Result<Vec<u8>, DomainError> {
    let expected = label(tenant, version.id(), version.algorithm());
    if version.key_use() != key_use || version.material().as_bytes() != expected.as_slice() {
        return Err(refused());
    }
    Ok(expected)
}

#[async_trait::async_trait]
impl KeyProvider for FakeKeyProvider {
    fn name(&self) -> &'static str {
        "fake"
    }

    async fn generate(
        &self,
        tenant: &TenantContext,
        version: KeyVersionId,
        algorithm: KeyAlgorithm,
    ) -> Result<GeneratedKey, DomainError> {
        let public_key = match algorithm {
            KeyAlgorithm::Es256 => Some(PublicKey::P256 {
                x: vec![1; 32],
                y: vec![2; 32],
            }),
            KeyAlgorithm::Rs256 | KeyAlgorithm::Ps256 => Some(PublicKey::Rsa {
                modulus: vec![3; 256],
                exponent: vec![1, 0, 1],
            }),
            KeyAlgorithm::A256Gcm => None,
        };
        Ok(GeneratedKey {
            public_key,
            material: KeyMaterial::from_stored(label(tenant, version, algorithm)),
        })
    }

    async fn sign(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        message: &[u8],
        encoding: SignatureEncoding,
    ) -> Result<Vec<u8>, DomainError> {
        let mut signature = check(tenant, version, KeyUse::Signing)?;
        if encoding == SignatureEncoding::Der {
            signature.extend_from_slice(b"der|");
        }
        signature.extend_from_slice(message);
        Ok(signature)
    }

    async fn encrypt(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        associated: &[u8],
        plaintext: &Secret<Vec<u8>>,
    ) -> Result<Vec<u8>, DomainError> {
        let mut ciphertext = check(tenant, version, KeyUse::Data)?;
        ciphertext.extend_from_slice(associated);
        ciphertext.push(0);
        ciphertext.extend(plaintext.expose().iter().rev());
        Ok(ciphertext)
    }

    async fn decrypt(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        associated: &[u8],
        ciphertext: &[u8],
    ) -> Result<Secret<Vec<u8>>, DomainError> {
        let mut prefix = check(tenant, version, KeyUse::Data)?;
        prefix.extend_from_slice(associated);
        prefix.push(0);
        let rest = ciphertext
            .strip_prefix(prefix.as_slice())
            .ok_or_else(refused)?;
        Ok(Secret::new(rest.iter().rev().copied().collect()))
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct Ports<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub keys: &'a dyn KeyStore,
}

impl std::fmt::Debug for Ports<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

/// A fixed, whole-second moment, so that stored timestamps compare equal
/// after a round trip through any storage.
const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

/// A pending version of `algorithm`, made by the fake provider.
///
/// # Panics
///
/// Panics if the version cannot be made, which does not happen.
#[must_use]
pub fn pending_version(
    tenant: &TenantContext,
    algorithm: KeyAlgorithm,
    at: Timestamp,
) -> KeyVersion {
    let id = KeyVersionId::generate();
    let public_key = match algorithm {
        KeyAlgorithm::Es256 => Some(PublicKey::P256 {
            x: vec![1; 32],
            y: vec![2; 32],
        }),
        KeyAlgorithm::Rs256 | KeyAlgorithm::Ps256 => Some(PublicKey::Rsa {
            modulus: vec![3; 256],
            exponent: vec![1, 0, 1],
        }),
        KeyAlgorithm::A256Gcm => None,
    };
    let generated = GeneratedKey {
        public_key,
        material: KeyMaterial::from_stored(label(tenant, id, algorithm)),
    };
    KeyVersion::create(id, algorithm, "fake", generated, at)
        .expect("a valid version")
        .0
}

async fn insert(ports: &Ports<'_>, tenant: &TenantContext, version: &KeyVersion) {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .keys
        .insert(uow.as_mut(), version)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
}

async fn update(
    ports: &Ports<'_>,
    tenant: &TenantContext,
    version: &KeyVersion,
) -> Result<(), DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await?;
    ports.keys.update(uow.as_mut(), version).await?;
    uow.commit().await
}

async fn get(ports: &Ports<'_>, tenant: &TenantContext, id: KeyVersionId) -> Option<KeyVersion> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.keys.get(uow.as_mut(), id).await.expect("get")
}

async fn list(ports: &Ports<'_>, tenant: &TenantContext, key_use: KeyUse) -> Vec<KeyVersionId> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let mut ids: Vec<KeyVersionId> = ports
        .keys
        .list_for_use(uow.as_mut(), key_use)
        .await
        .expect("list")
        .iter()
        .map(KeyVersion::id)
        .collect();
    ids.sort();
    ids
}

/// Runs the whole contract. Each case uses tenants of its own, so runs can
/// share one database.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_contract(ports: Ports<'_>) {
    every_kind_of_version_is_loaded_unchanged(&ports).await;
    a_version_is_found_within_its_tenant_only(&ports).await;
    a_key_set_holds_the_versions_of_its_use_only(&ports).await;
    the_lifecycle_is_stored_and_the_key_never_changes(&ports).await;
    an_update_cannot_reach_another_tenant(&ports).await;
}

async fn every_kind_of_version_is_loaded_unchanged(ports: &Ports<'_>) {
    let tenant = tenant();
    for algorithm in KeyAlgorithm::ALL {
        let version = pending_version(&tenant, algorithm, MOMENT);
        insert(ports, &tenant, &version).await;
        assert_eq!(
            get(ports, &tenant, version.id()).await,
            Some(version),
            "a version of {} must load back unchanged",
            algorithm.as_str()
        );
    }
    assert_eq!(get(ports, &tenant, KeyVersionId::generate()).await, None);
}

async fn a_version_is_found_within_its_tenant_only(ports: &Ports<'_>) {
    let (home, elsewhere) = (tenant(), tenant());
    let version = pending_version(&home, KeyAlgorithm::Es256, MOMENT);
    insert(ports, &home, &version).await;
    assert!(get(ports, &home, version.id()).await.is_some());
    assert_eq!(get(ports, &elsewhere, version.id()).await, None);
    assert!(list(ports, &elsewhere, KeyUse::Signing).await.is_empty());
}

async fn a_key_set_holds_the_versions_of_its_use_only(ports: &Ports<'_>) {
    let tenant = tenant();
    let signing = pending_version(&tenant, KeyAlgorithm::Es256, MOMENT);
    let other_signing = pending_version(&tenant, KeyAlgorithm::Rs256, MOMENT);
    let data = pending_version(&tenant, KeyAlgorithm::A256Gcm, MOMENT);
    for version in [&signing, &other_signing, &data] {
        insert(ports, &tenant, version).await;
    }
    let mut expected = vec![signing.id(), other_signing.id()];
    expected.sort();
    assert_eq!(list(ports, &tenant, KeyUse::Signing).await, expected);
    assert_eq!(list(ports, &tenant, KeyUse::Data).await, vec![data.id()]);
    assert!(list(ports, &tenant, KeyUse::Encryption).await.is_empty());
}

async fn the_lifecycle_is_stored_and_the_key_never_changes(ports: &Ports<'_>) {
    let tenant = tenant();
    let made = pending_version(&tenant, KeyAlgorithm::Es256, MOMENT);
    insert(ports, &tenant, &made).await;

    let mut changed: KeyVersionSnapshot = made.snapshot().clone();
    changed.state = KeyState::Revoked;
    changed.activated_at = Some(MOMENT + Duration::minutes(1));
    changed.retiring_at = Some(MOMENT + Duration::minutes(2));
    changed.retire_after = Some(MOMENT + Duration::hours(1));
    changed.revoked_at = Some(MOMENT + Duration::minutes(3));
    changed.revocation_reason = Some("leaked".to_owned());
    let expected = KeyVersion::from_snapshot(changed.clone());

    // An update that also tries to change the key, which must be ignored.
    changed.material = KeyMaterial::from_stored(b"another key".to_vec());
    changed.public_key = Some(PublicKey::P256 {
        x: vec![9; 32],
        y: vec![9; 32],
    });
    update(ports, &tenant, &KeyVersion::from_snapshot(changed))
        .await
        .expect("update");
    assert_eq!(get(ports, &tenant, made.id()).await, Some(expected));

    let mut retired = made.snapshot().clone();
    retired.state = KeyState::Retired;
    retired.activated_at = Some(MOMENT);
    retired.retiring_at = Some(MOMENT);
    retired.retire_after = Some(MOMENT);
    retired.retired_at = Some(MOMENT + Duration::seconds(1));
    let other = pending_version(&tenant, KeyAlgorithm::Es256, MOMENT);
    insert(ports, &tenant, &other).await;
    let mut retired_other = other.snapshot().clone();
    retired_other.state = retired.state;
    retired_other.activated_at = retired.activated_at;
    retired_other.retiring_at = retired.retiring_at;
    retired_other.retire_after = retired.retire_after;
    retired_other.retired_at = retired.retired_at;
    let retired_other = KeyVersion::from_snapshot(retired_other);
    update(ports, &tenant, &retired_other)
        .await
        .expect("retire");
    assert_eq!(get(ports, &tenant, other.id()).await, Some(retired_other));
}

async fn an_update_cannot_reach_another_tenant(ports: &Ports<'_>) {
    let (home, elsewhere) = (tenant(), tenant());
    let version = pending_version(&home, KeyAlgorithm::Es256, MOMENT);
    insert(ports, &home, &version).await;
    let mut revoked = version.snapshot().clone();
    revoked.state = KeyState::Revoked;
    revoked.revoked_at = Some(MOMENT);
    revoked.revocation_reason = Some("from elsewhere".to_owned());
    let error = update(ports, &elsewhere, &KeyVersion::from_snapshot(revoked))
        .await
        .expect_err("another tenant's version");
    assert_eq!(error.code(), "keys.version_not_found");
    assert_eq!(get(ports, &home, version.id()).await, Some(version));
    let unknown = pending_version(&home, KeyAlgorithm::Es256, MOMENT);
    let error = update(ports, &home, &unknown)
        .await
        .expect_err("never stored");
    assert_eq!(error.code(), "keys.version_not_found");
}

/// Whether each tenant refuses the first format, kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemorySealingStates {
    refused: Arc<Mutex<BTreeMap<TenantId, Timestamp>>>,
}

#[async_trait::async_trait]
impl crate::api::SealingStateStore for InMemorySealingStates {
    async fn first_format_refused(&self, uow: &mut dyn UnitOfWork) -> Result<bool, DomainError> {
        let refused = self.refused.lock().unwrap_or_else(|e| e.into_inner());
        Ok(refused.contains_key(&uow.tenant().tenant_id()))
    }

    async fn refuse_first_format(
        &self,
        uow: &mut dyn UnitOfWork,
        at: Timestamp,
    ) -> Result<(), DomainError> {
        let mut refused = self.refused.lock().unwrap_or_else(|e| e.into_inner());
        refused.entry(uow.tenant().tenant_id()).or_insert(at);
        Ok(())
    }
}

/// A stand-in for secrets of the first format: a first byte of `1`, then
/// the tenant and purpose, then the secret reversed. Never use outside
/// tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeFirstFormat;

impl FakeFirstFormat {
    fn label(tenant: &TenantContext, purpose: &str) -> Vec<u8> {
        let mut label = vec![1];
        label.extend(format!("first|{}|{purpose}|", tenant.tenant_id()).into_bytes());
        label
    }

    /// Seals as the first format did.
    #[must_use]
    pub fn seal(
        tenant: &TenantContext,
        purpose: &str,
        secret: &Secret<Vec<u8>>,
    ) -> hodor_kernel::SealedSecret {
        let mut bytes = Self::label(tenant, purpose);
        bytes.extend(secret.expose().iter().rev());
        hodor_kernel::SealedSecret::from_stored(bytes)
    }
}

impl crate::api::FirstFormatSecrets for FakeFirstFormat {
    fn is_first_format(&self, sealed: &hodor_kernel::SealedSecret) -> bool {
        sealed.as_bytes().first() == Some(&1)
    }

    fn open(
        &self,
        tenant: &TenantContext,
        purpose: &str,
        sealed: &hodor_kernel::SealedSecret,
    ) -> Result<Secret<Vec<u8>>, DomainError> {
        let rest = sealed
            .as_bytes()
            .strip_prefix(Self::label(tenant, purpose).as_slice())
            .ok_or_else(|| hodor_kernel::sealing::unreadable("another tenant or purpose"))?;
        Ok(Secret::new(rest.iter().rev().copied().collect()))
    }
}

/// Trust domains kept in memory, for every tenant; also finds those due
/// across tenants, as the worker's port does.
#[derive(Debug, Clone, Default)]
pub struct InMemoryTrustDomains {
    rows: Arc<Mutex<BTreeMap<(TenantId, TrustDomainId), TrustDomain>>>,
}

impl InMemoryTrustDomains {
    fn rows(&self) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, TrustDomainId), TrustDomain>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn trust_domain_not_found() -> DomainError {
    DomainError::not_found(
        "keys.trust_domain_not_found",
        "there is no such trust domain",
    )
}

#[async_trait::async_trait]
impl TrustDomainStore for InMemoryTrustDomains {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        domain: &TrustDomain,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.rows();
        if rows
            .iter()
            .any(|((owner, _), kept)| *owner == tenant && kept.name() == domain.name())
        {
            return Err(DomainError::conflict(
                "keys.trust_domain_name_taken",
                "the tenant already has a trust domain of that name",
            ));
        }
        rows.insert((tenant, domain.id()), domain.clone());
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TrustDomainId,
    ) -> Result<Option<TrustDomain>, DomainError> {
        Ok(self.rows().get(&(uow.tenant().tenant_id(), id)).cloned())
    }

    async fn find_by_name(
        &self,
        uow: &mut dyn UnitOfWork,
        name: &str,
    ) -> Result<Option<TrustDomain>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .iter()
            .find(|((owner, _), kept)| *owner == tenant && kept.name().as_str() == name)
            .map(|(_, kept)| kept.clone()))
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<TrustDomainId>,
        limit: u32,
    ) -> Result<Vec<TrustDomain>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .iter()
            .filter(|((owner, id), _)| *owner == tenant && after.is_none_or(|after| *id > after))
            .take(limit as usize)
            .map(|(_, kept)| kept.clone())
            .collect())
    }

    async fn count(&self, uow: &mut dyn UnitOfWork) -> Result<u32, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let count = self
            .rows()
            .keys()
            .filter(|(owner, _)| *owner == tenant)
            .count();
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        domain: &TrustDomain,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), domain.id());
        let mut rows = self.rows();
        let Some(kept) = rows.get(&key) else {
            return Err(trust_domain_not_found());
        };
        if kept.version() != domain.version() {
            return Err(DomainError::conflict(
                "keys.trust_domain_changed",
                "the trust domain changed meanwhile; read it again",
            ));
        }
        let mut changed = domain.snapshot().clone();
        // The name never changes, whatever is given.
        changed.name = kept.name().clone();
        changed.created_at = kept.snapshot().created_at;
        changed.version += 1;
        rows.insert(key, TrustDomain::from_snapshot(changed));
        Ok(())
    }

    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TrustDomainId,
    ) -> Result<bool, DomainError> {
        Ok(self
            .rows()
            .remove(&(uow.tenant().tenant_id(), id))
            .is_some())
    }

    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TrustDomainId,
    ) -> Result<Option<TrustDomain>, DomainError> {
        self.get(uow, id).await
    }

    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TrustDomainId,
    ) -> Result<Option<TrustDomain>, DomainError> {
        self.get(uow, id).await
    }
}

#[async_trait::async_trait]
impl DueRefreshes for InMemoryTrustDomains {
    async fn due(
        &self,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<(TenantId, TrustDomainId)>, DomainError> {
        let mut due: Vec<(Timestamp, TenantId, TrustDomainId)> = self
            .rows()
            .iter()
            .filter(|(_, kept)| kept.is_due(now))
            .filter_map(|((tenant, id), kept)| {
                kept.snapshot().next_refresh_at.map(|at| (at, *tenant, *id))
            })
            .collect();
        due.sort();
        Ok(due
            .into_iter()
            .take(limit as usize)
            .map(|(_, tenant, id)| (tenant, id))
            .collect())
    }
}

/// Bundle endpoints for tests: each address answers what it is told, or
/// fails as it is told; an address it does not know answers `404`. As a
/// destination check, it refuses the addresses it is told are forbidden.
/// Never use outside tests.
#[derive(Debug, Clone, Default)]
pub struct FakeBundleEndpoints {
    answers: Arc<Mutex<BTreeMap<String, Result<HttpResponse, DomainError>>>>,
    forbidden: Arc<Mutex<BTreeSet<String>>>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl FakeBundleEndpoints {
    /// The address answers `status` with `body`.
    pub fn answer(&self, url: &str, status: u16, body: &[u8]) {
        self.answers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                url.to_owned(),
                Ok(HttpResponse {
                    status,
                    headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                    body: body.to_vec(),
                }),
            );
    }

    /// The address answers the bundle `bundle` with `200`.
    pub fn serve(&self, url: &str, bundle: &serde_json::Value) {
        self.answer(url, 200, bundle.to_string().as_bytes());
    }

    /// Fetching the address fails with `code`, as the guarded client's
    /// errors do.
    pub fn fail(&self, url: &str, code: &'static str) {
        self.answers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                url.to_owned(),
                Err(DomainError::invalid(code, "refused by the test")),
            );
    }

    /// The destination check refuses the address.
    pub fn forbid(&self, url: &str) {
        self.forbidden
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(url.to_owned());
    }

    /// Every address fetched, in order.
    #[must_use]
    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[async_trait::async_trait]
impl HttpClient for FakeBundleEndpoints {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
        self.asked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.url.clone());
        self.answers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&request.url)
            .cloned()
            .unwrap_or_else(|| {
                Ok(HttpResponse {
                    status: 404,
                    headers: Vec::new(),
                    body: Vec::new(),
                })
            })
    }
}

#[async_trait::async_trait]
impl DestinationCheck for FakeBundleEndpoints {
    async fn check(&self, url: &str) -> Result<(), DomainError> {
        if self
            .forbidden
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(url)
        {
            return Err(DomainError::invalid(
                "http.destination_forbidden",
                "refused by the test",
            ));
        }
        Ok(())
    }
}

/// A bundle with one `x509-svid` authority, whose certificate is only a
/// DER sequence, and one `jwt-svid` key per identifier, each a P-256 point
/// made from the identifier. Never a real authority.
#[must_use]
pub fn sample_bundle(sequence: Option<u64>, key_ids: &[&str]) -> serde_json::Value {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    let mut keys = vec![serde_json::json!({
        "use": "x509-svid",
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode([7_u8; 32]),
        "y": URL_SAFE_NO_PAD.encode([8_u8; 32]),
        "x5c": [STANDARD.encode([0x30, 0x03, 0x02, 0x01, 0x01])],
    })];
    for key_id in key_ids {
        let seed = key_id.bytes().fold(0_u8, u8::wrapping_add);
        keys.push(serde_json::json!({
            "use": "jwt-svid",
            "kty": "EC",
            "crv": "P-256",
            "kid": key_id,
            "x": URL_SAFE_NO_PAD.encode([seed; 32]),
            "y": URL_SAFE_NO_PAD.encode([seed.wrapping_add(1); 32]),
        }));
    }
    let mut bundle = serde_json::json!({ "keys": keys });
    if let Some(sequence) = sequence {
        bundle["spiffe_sequence"] = serde_json::json!(sequence);
    }
    bundle
}

fn read_bundle(sequence: Option<u64>, key_ids: &[&str]) -> TrustBundle {
    TrustBundle::parse(sample_bundle(sequence, key_ids).to_string().as_bytes())
        .expect("a sample bundle reads")
}

/// The ports a store of trust domains is tried through.
#[derive(Clone)]
pub struct TrustDomainContract<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub store: &'a dyn TrustDomainStore,
    /// Its search across tenants.
    pub due: &'a dyn DueRefreshes,
}

impl std::fmt::Debug for TrustDomainContract<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustDomainContract")
            .finish_non_exhaustive()
    }
}

/// Runs the contract of trust domain stores. Each case uses tenants of its
/// own, so runs can share one database.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_trust_domain_contract(ports: TrustDomainContract<'_>) {
    every_source_loads_back_unchanged(&ports).await;
    one_name_in_two_tenants_is_two_trust_domains_never_mixed(&ports).await;
    a_name_is_taken_once_in_a_tenant(&ports).await;
    an_update_needs_the_version_it_read_and_its_tenant(&ports).await;
    trust_domains_are_listed_a_page_at_a_time_and_counted_per_tenant(&ports).await;
    a_removal_reaches_its_tenant_only(&ports).await;
    the_due_search_finds_only_what_is_due_in_any_tenant(&ports).await;
}

async fn stored(ports: &TrustDomainContract<'_>, tenant: &TenantContext, domain: &TrustDomain) {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .store
        .insert(uow.as_mut(), domain)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
}

async fn read(
    ports: &TrustDomainContract<'_>,
    tenant: &TenantContext,
    id: TrustDomainId,
) -> Option<TrustDomain> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.store.get(uow.as_mut(), id).await.expect("get")
}

async fn by_name(
    ports: &TrustDomainContract<'_>,
    tenant: &TenantContext,
    name: &str,
) -> Option<TrustDomain> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .store
        .find_by_name(uow.as_mut(), name)
        .await
        .expect("find")
}

async fn changed(
    ports: &TrustDomainContract<'_>,
    tenant: &TenantContext,
    domain: &TrustDomain,
) -> Result<(), DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await?;
    ports.store.update(uow.as_mut(), domain).await?;
    uow.commit().await
}

fn endpoint_source(sequence: u64) -> CheckedSource {
    CheckedSource::BundleEndpoint {
        url: "https://spire.example.com/bundle".to_owned(),
        bundle: read_bundle(Some(sequence), &["one"]),
    }
}

async fn every_source_loads_back_unchanged(ports: &TrustDomainContract<'_>) {
    let tenant = tenant();
    let uploaded = TrustDomain::add(
        "uploaded.example",
        CheckedSource::Uploaded(read_bundle(None, &["a", "b"])),
        MOMENT,
    )
    .expect("uploaded");
    let mut fetched =
        TrustDomain::add("fetched.example", endpoint_source(3), MOMENT).expect("fetched");
    let mesh = TrustDomain::add("cluster.local", CheckedSource::Mesh, MOMENT).expect("mesh");
    for domain in [&uploaded, &fetched, &mesh] {
        stored(ports, &tenant, domain).await;
        assert_eq!(
            read(ports, &tenant, domain.id()).await.as_ref(),
            Some(domain),
            "a trust domain of source {} loads back unchanged",
            domain.source().as_str()
        );
    }
    // A lease, then a failed fetch: every field of the refresh is stored.
    let later = MOMENT + Duration::minutes(5);
    fetched
        .lease(later, later + Duration::seconds(70))
        .expect("due");
    changed(ports, &tenant, &fetched).await.expect("leased");
    let mut leased = read(ports, &tenant, fetched.id()).await.expect("there");
    assert_eq!(leased.version(), fetched.version() + 1);
    assert_eq!(
        leased.snapshot().leased_until,
        Some(later + Duration::seconds(70))
    );
    leased.record_fetch(
        Err(DomainError::invalid(
            "keys.bundle_endpoint_unreachable",
            "x",
        )),
        later,
    );
    changed(ports, &tenant, &leased).await.expect("recorded");
    let failing = read(ports, &tenant, fetched.id()).await.expect("there");
    assert_eq!(failing.snapshot().failing_since, Some(later));
    assert_eq!(
        failing.snapshot().last_error.as_deref(),
        Some("keys.bundle_endpoint_unreachable")
    );
    assert_eq!(failing.bundle(), fetched.bundle());
    assert_eq!(failing.snapshot().leased_until, None);
    assert_eq!(read(ports, &tenant, TrustDomainId::generate()).await, None);
}

async fn one_name_in_two_tenants_is_two_trust_domains_never_mixed(ports: &TrustDomainContract<'_>) {
    let (home, elsewhere) = (tenant(), tenant());
    let ours = TrustDomain::add(
        "cluster.local",
        CheckedSource::Uploaded(read_bundle(Some(1), &["ours"])),
        MOMENT,
    )
    .expect("ours");
    let theirs = TrustDomain::add(
        "cluster.local",
        CheckedSource::Uploaded(read_bundle(Some(9), &["theirs"])),
        MOMENT,
    )
    .expect("theirs");
    stored(ports, &home, &ours).await;
    stored(ports, &elsewhere, &theirs).await;
    let found = by_name(ports, &home, "cluster.local").await.expect("ours");
    assert_eq!(found, ours);
    assert!(found.bundle().expect("bundle").jwt_key("theirs").is_none());
    let found = by_name(ports, &elsewhere, "cluster.local")
        .await
        .expect("theirs");
    assert_eq!(found, theirs);
    assert_eq!(read(ports, &elsewhere, ours.id()).await, None);
    assert_eq!(read(ports, &home, theirs.id()).await, None);
    assert_eq!(by_name(ports, &tenant(), "cluster.local").await, None);
}

async fn a_name_is_taken_once_in_a_tenant(ports: &TrustDomainContract<'_>) {
    let tenant = tenant();
    let first = TrustDomain::add("prod.example", CheckedSource::Mesh, MOMENT).expect("first");
    stored(ports, &tenant, &first).await;
    let second = TrustDomain::add("prod.example", CheckedSource::Mesh, MOMENT).expect("second");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let error = ports
        .store
        .insert(uow.as_mut(), &second)
        .await
        .expect_err("taken");
    assert_eq!(error.code(), "keys.trust_domain_name_taken");
}

async fn an_update_needs_the_version_it_read_and_its_tenant(ports: &TrustDomainContract<'_>) {
    let (home, elsewhere) = (tenant(), tenant());
    let domain = TrustDomain::add("versioned.example", CheckedSource::Mesh, MOMENT).expect("added");
    stored(ports, &home, &domain).await;
    let mut first = domain.clone();
    first.replace(
        CheckedSource::Uploaded(read_bundle(Some(1), &["a"])),
        MOMENT + Duration::seconds(1),
    );
    changed(ports, &home, &first).await.expect("first change");
    // A second change from the same reading is refused.
    let mut stale = domain.clone();
    stale.replace(CheckedSource::Mesh, MOMENT + Duration::seconds(2));
    assert_eq!(
        changed(ports, &home, &stale)
            .await
            .expect_err("stale")
            .code(),
        "keys.trust_domain_changed"
    );
    let kept = read(ports, &home, domain.id()).await.expect("there");
    assert_eq!(kept.source(), crate::api::TrustSource::Uploaded);
    assert_eq!(kept.version(), domain.version() + 1);
    // Another tenant cannot change it, even with the right version.
    assert_eq!(
        changed(ports, &elsewhere, &kept)
            .await
            .expect_err("elsewhere")
            .code(),
        "keys.trust_domain_not_found"
    );
}

async fn trust_domains_are_listed_a_page_at_a_time_and_counted_per_tenant(
    ports: &TrustDomainContract<'_>,
) {
    let (tenant, other) = (tenant(), tenant());
    let mut ids = Vec::new();
    for index in 0..3 {
        let domain = TrustDomain::add(&format!("d{index}.example"), CheckedSource::Mesh, MOMENT)
            .expect("added");
        ids.push(domain.id());
        stored(ports, &tenant, &domain).await;
    }
    stored(
        ports,
        &other,
        &TrustDomain::add("d0.example", CheckedSource::Mesh, MOMENT).expect("added"),
    )
    .await;
    ids.sort();
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let first: Vec<TrustDomainId> = ports
        .store
        .list(uow.as_mut(), None, 2)
        .await
        .expect("list")
        .iter()
        .map(TrustDomain::id)
        .collect();
    assert_eq!(first, ids[..2]);
    let rest: Vec<TrustDomainId> = ports
        .store
        .list(uow.as_mut(), Some(ids[1]), 2)
        .await
        .expect("list")
        .iter()
        .map(TrustDomain::id)
        .collect();
    assert_eq!(rest, ids[2..]);
    assert_eq!(ports.store.count(uow.as_mut()).await.expect("count"), 3);
}

async fn a_removal_reaches_its_tenant_only(ports: &TrustDomainContract<'_>) {
    let (home, elsewhere) = (tenant(), tenant());
    let domain = TrustDomain::add("removed.example", CheckedSource::Mesh, MOMENT).expect("added");
    stored(ports, &home, &domain).await;
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert!(
        !ports
            .store
            .remove(uow.as_mut(), domain.id())
            .await
            .expect("remove")
    );
    uow.commit().await.expect("commit");
    assert!(read(ports, &home, domain.id()).await.is_some());
    let mut uow = ports.units_of_work.begin(&home).await.expect("begin");
    assert!(
        ports
            .store
            .remove(uow.as_mut(), domain.id())
            .await
            .expect("remove")
    );
    uow.commit().await.expect("commit");
    assert_eq!(read(ports, &home, domain.id()).await, None);
    assert_eq!(by_name(ports, &home, "removed.example").await, None);
}

async fn the_due_search_finds_only_what_is_due_in_any_tenant(ports: &TrustDomainContract<'_>) {
    let (one, two) = (tenant(), tenant());
    let due_here = TrustDomain::add("due.example", endpoint_source(1), MOMENT).expect("added");
    let due_there = TrustDomain::add("due.example", endpoint_source(1), MOMENT).expect("added");
    let uploaded = TrustDomain::add(
        "uploaded.example",
        CheckedSource::Uploaded(read_bundle(None, &[])),
        MOMENT,
    )
    .expect("added");
    let mesh = TrustDomain::add("mesh.example", CheckedSource::Mesh, MOMENT).expect("added");
    let mut leased = TrustDomain::add("leased.example", endpoint_source(1), MOMENT).expect("added");
    stored(ports, &one, &due_here).await;
    stored(ports, &two, &due_there).await;
    stored(ports, &one, &uploaded).await;
    stored(ports, &one, &mesh).await;
    stored(ports, &one, &leased).await;
    let now = MOMENT + Duration::minutes(5);
    leased.lease(now, now + Duration::minutes(1)).expect("due");
    changed(ports, &one, &leased).await.expect("leased");

    let found = ports.due.due(now, 10_000).await.expect("due");
    assert!(found.contains(&(one.tenant_id(), due_here.id())));
    assert!(found.contains(&(two.tenant_id(), due_there.id())));
    for absent in [uploaded.id(), mesh.id(), leased.id()] {
        assert!(!found.iter().any(|(_, id)| *id == absent));
    }
    // Not yet due a moment before.
    let before = ports
        .due
        .due(now - Duration::seconds(1), 10_000)
        .await
        .expect("due");
    assert!(!before.iter().any(|(_, id)| *id == due_here.id()));
    // The lease ends.
    let after = ports
        .due
        .due(now + Duration::minutes(1), 10_000)
        .await
        .expect("due");
    assert!(after.iter().any(|(_, id)| *id == leased.id()));
}

/// The provider under test, and what checks its signatures.
pub struct ProviderPorts<'a> {
    /// The provider under test.
    pub provider: &'a dyn KeyProvider,
    /// Checks signatures written in the JOSE encoding, independently of
    /// the provider.
    pub verifier: &'a dyn SignatureVerifier,
    /// The signing algorithms the provider makes keys of: at least one.
    pub signing: &'a [KeyAlgorithm],
    /// Whether the provider makes data keys.
    pub data: bool,
}

impl std::fmt::Debug for ProviderPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderPorts")
            .field("provider", &self.provider.name())
            .field("signing", &self.signing)
            .field("data", &self.data)
            .finish_non_exhaustive()
    }
}

/// Makes a key with the provider and keeps it as a pending version, as
/// the keys context does.
///
/// # Panics
///
/// Panics if the provider cannot make the key, or answers something that
/// is not a version of `algorithm`.
pub async fn made_by(
    provider: &dyn KeyProvider,
    tenant: &TenantContext,
    algorithm: KeyAlgorithm,
) -> KeyVersion {
    let id = KeyVersionId::generate();
    let generated = provider
        .generate(tenant, id, algorithm)
        .await
        .expect("the provider makes the key");
    KeyVersion::create(
        id,
        algorithm,
        provider.name_for(algorithm),
        generated,
        MOMENT,
    )
    .expect("what the provider answered is a version of the algorithm")
    .0
}

/// The same version with other material, as if a row had been copied.
#[must_use]
pub fn with_material(version: &KeyVersion, material: &KeyMaterial) -> KeyVersion {
    let mut snapshot = version.snapshot().clone();
    snapshot.material = material.clone();
    KeyVersion::from_snapshot(snapshot)
}

/// An ECDSA signature in DER, an ASN.1 sequence of two positive integers,
/// written as JOSE writes it: each integer in `size` bytes. `None` for
/// anything else, trailing bytes and integers written longer than DER
/// allows included.
#[must_use]
pub fn der_to_jose(der: &[u8], size: usize) -> Option<Vec<u8>> {
    fn length(bytes: &[u8]) -> Option<(usize, &[u8])> {
        let (&first, rest) = bytes.split_first()?;
        match first {
            0..=0x7f => Some((usize::from(first), rest)),
            0x81 => {
                let (&value, rest) = rest.split_first()?;
                (value >= 0x80).then_some((usize::from(value), rest))
            }
            _ => None,
        }
    }
    fn integer(bytes: &[u8], size: usize) -> Option<(Vec<u8>, &[u8])> {
        let (&tag, rest) = bytes.split_first()?;
        if tag != 0x02 {
            return None;
        }
        let (length, rest) = length(rest)?;
        if length == 0 || rest.len() < length {
            return None;
        }
        let (value, rest) = rest.split_at(length);
        // Positive, and no longer than it needs to be.
        if value[0] & 0x80 != 0 || (value.len() > 1 && value[0] == 0 && value[1] & 0x80 == 0) {
            return None;
        }
        let value = if value[0] == 0 { &value[1..] } else { value };
        if value.len() > size {
            return None;
        }
        let mut padded = vec![0; size - value.len()];
        padded.extend_from_slice(value);
        Some((padded, rest))
    }
    let (&tag, rest) = der.split_first()?;
    if tag != 0x30 {
        return None;
    }
    let (length, rest) = length(rest)?;
    if rest.len() != length {
        return None;
    }
    let (mut first, rest) = integer(rest, size)?;
    let (second, rest) = integer(rest, size)?;
    if !rest.is_empty() {
        return None;
    }
    first.extend_from_slice(&second);
    Some(first)
}

/// Runs the whole contract of a key provider. Each case makes keys in
/// tenants of its own.
///
/// # Panics
///
/// Panics when the provider breaks the contract.
pub async fn run_provider_contract(ports: ProviderPorts<'_>) {
    assert!(!ports.signing.is_empty(), "a provider signs");
    each_signing_key_signs_in_both_encodings(&ports).await;
    two_keys_are_never_the_same(&ports).await;
    material_is_refused_for_another_tenant_version_or_algorithm(&ports).await;
    changed_material_and_another_providers_versions_are_refused(&ports).await;
    a_key_of_one_use_is_refused_for_the_other(&ports).await;
    if ports.data {
        a_data_key_decrypts_only_what_it_encrypted_with_its_associated_data(&ports).await;
    } else {
        let refused = ports
            .provider
            .generate(&tenant(), KeyVersionId::generate(), KeyAlgorithm::A256Gcm)
            .await;
        assert!(refused.is_err(), "a provider without data keys makes none");
    }
}

async fn each_signing_key_signs_in_both_encodings(ports: &ProviderPorts<'_>) {
    let tenant = tenant();
    for &algorithm in ports.signing {
        let version = made_by(ports.provider, &tenant, algorithm).await;
        let name = algorithm.as_str();
        let checked = algorithm.signature().expect("a signing algorithm");
        let public = version
            .public_key()
            .expect("a signing key has a public key");
        let message = b"a message of the contract";

        let jose = ports
            .provider
            .sign(&tenant, &version, message, SignatureEncoding::Jose)
            .await
            .expect("sign in the JOSE encoding");
        assert!(
            ports.verifier.verify(checked, public, message, &jose),
            "{name}: the JOSE signature checks with the public key"
        );
        assert!(
            !ports
                .verifier
                .verify(checked, public, b"another message", &jose),
            "{name}: and checks nothing else"
        );

        let der = ports
            .provider
            .sign(&tenant, &version, message, SignatureEncoding::Der)
            .await
            .expect("sign in the DER encoding");
        let as_jose = if algorithm == KeyAlgorithm::Es256 {
            assert_eq!(jose.len(), 64, "{name}: two numbers of 32 bytes");
            der_to_jose(&der, 32).expect("an ASN.1 sequence of two integers")
        } else {
            der
        };
        assert!(
            ports.verifier.verify(checked, public, message, &as_jose),
            "{name}: the DER signature checks with the public key"
        );
    }
}

async fn two_keys_are_never_the_same(ports: &ProviderPorts<'_>) {
    let tenant = tenant();
    let algorithm = ports.signing[0];
    let first = made_by(ports.provider, &tenant, algorithm).await;
    let second = made_by(ports.provider, &tenant, algorithm).await;
    assert_ne!(first.public_key(), second.public_key());
    assert_ne!(first.material(), second.material());
}

async fn refuses(
    ports: &ProviderPorts<'_>,
    tenant: &TenantContext,
    version: &KeyVersion,
    case: &str,
) {
    for encoding in [SignatureEncoding::Jose, SignatureEncoding::Der] {
        let error = ports
            .provider
            .sign(tenant, version, b"m", encoding)
            .await
            .expect_err(case);
        assert_eq!(error.code(), "keys.unusable", "{case}");
    }
}

async fn material_is_refused_for_another_tenant_version_or_algorithm(ports: &ProviderPorts<'_>) {
    let (tenant, elsewhere) = (self::tenant(), self::tenant());
    let algorithm = ports.signing[0];
    let version = made_by(ports.provider, &tenant, algorithm).await;
    let other = made_by(ports.provider, &tenant, algorithm).await;
    // The other tenant has a key of the same version identifier.
    refuses(ports, &elsewhere, &version, "another tenant").await;
    refuses(
        ports,
        &tenant,
        &with_material(&other, version.material()),
        "another version",
    )
    .await;
    // Material of one tenant's version put on another tenant's version.
    let theirs = made_by(ports.provider, &elsewhere, algorithm).await;
    refuses(
        ports,
        &elsewhere,
        &with_material(&theirs, version.material()),
        "another tenant's material",
    )
    .await;
    if let Some(&second) = ports.signing.iter().find(|&&each| each != algorithm) {
        let of_second = made_by(ports.provider, &tenant, second).await;
        refuses(
            ports,
            &tenant,
            &with_material(&of_second, version.material()),
            "another algorithm",
        )
        .await;
    }
}

async fn changed_material_and_another_providers_versions_are_refused(ports: &ProviderPorts<'_>) {
    let tenant = tenant();
    let version = made_by(ports.provider, &tenant, ports.signing[0]).await;
    let length = version.material().as_bytes().len();
    for position in [0, length / 2, length - 1] {
        let mut bytes = version.material().as_bytes().to_vec();
        bytes[position] ^= 1;
        let changed = with_material(&version, &KeyMaterial::from_stored(bytes));
        refuses(ports, &tenant, &changed, "changed material").await;
    }
    let mut foreign = version.snapshot().clone();
    foreign.provider = "another_provider".to_owned();
    refuses(
        ports,
        &tenant,
        &KeyVersion::from_snapshot(foreign),
        "a version of another provider",
    )
    .await;
}

async fn a_key_of_one_use_is_refused_for_the_other(ports: &ProviderPorts<'_>) {
    let tenant = tenant();
    let signing = made_by(ports.provider, &tenant, ports.signing[0]).await;
    let secret = Secret::new(b"s".to_vec());
    assert!(
        ports
            .provider
            .encrypt(&tenant, &signing, b"x", &secret)
            .await
            .is_err()
    );
    assert!(
        ports
            .provider
            .decrypt(&tenant, &signing, b"x", &[1])
            .await
            .is_err()
    );
    if ports.data {
        let data = made_by(ports.provider, &tenant, KeyAlgorithm::A256Gcm).await;
        refuses(ports, &tenant, &data, "a data key").await;
    }
}

async fn a_data_key_decrypts_only_what_it_encrypted_with_its_associated_data(
    ports: &ProviderPorts<'_>,
) {
    let (tenant, elsewhere) = (self::tenant(), self::tenant());
    let data = made_by(ports.provider, &tenant, KeyAlgorithm::A256Gcm).await;
    let secret = Secret::new(b"the client secret of a provider".to_vec());
    let sealed = ports
        .provider
        .encrypt(&tenant, &data, b"federation.client_secret", &secret)
        .await
        .expect("encrypt");
    assert!(
        !sealed
            .windows(secret.expose().len())
            .any(|window| window == secret.expose().as_slice()),
        "nothing of the secret in the clear"
    );
    let opened = ports
        .provider
        .decrypt(&tenant, &data, b"federation.client_secret", &sealed)
        .await
        .expect("decrypt");
    assert_eq!(opened.expose(), secret.expose());
    assert!(
        ports
            .provider
            .decrypt(&tenant, &data, b"ldap.bind_password", &sealed)
            .await
            .is_err()
    );
    assert!(
        ports
            .provider
            .decrypt(&elsewhere, &data, b"federation.client_secret", &sealed)
            .await
            .is_err()
    );
}
