//! In-memory store, a stand-in provider, and the contract every key store
//! passes.

use crate::api::{
    GeneratedKey, KeyAlgorithm, KeyMaterial, KeyProvider, KeyState, KeyStore, KeyUse, KeyVersion,
    KeyVersionId, KeyVersionSnapshot,
};
use hodor_kernel::{
    DomainError, PublicKey, Secret, TenantContext, TenantId, Timestamp, UnitOfWork,
    UnitOfWorkFactory,
};
use std::collections::BTreeMap;
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
    ) -> Result<Vec<u8>, DomainError> {
        let mut signature = check(tenant, version, KeyUse::Signing)?;
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
