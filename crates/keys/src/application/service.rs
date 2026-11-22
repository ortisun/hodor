//! The use cases of the keys context.

use crate::application::ports::{KeyProvider, KeyStore};
use crate::domain::event::KeyEvent;
use crate::domain::key::{KeyAlgorithm, KeyUse, KeyVersion, KeyVersionId};
use crate::domain::key_set::{KeySet, not_found};
use crate::domain::rotation::{RotationChange, RotationPolicy};
use hodor_kernel::{
    Caller, Clock, DomainError, EventEnvelope, EventMetadata, TenantContext, UnitOfWork,
    UnitOfWorkFactory,
};
use std::sync::Arc;
use time::Duration;

/// A signature, and the version that made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// The version that signed, published as the key identifier.
    pub key_version_id: KeyVersionId,
    /// The algorithm it signed with.
    pub algorithm: KeyAlgorithm,
    /// The signature.
    pub bytes: Vec<u8>,
}

/// What one step of rotation changed in a tenant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RotationReport {
    /// Versions made.
    pub created: u64,
    /// Versions activated.
    pub activated: u64,
    /// Versions retired.
    pub retired: u64,
}

impl RotationReport {
    /// Whether the step changed anything.
    #[must_use]
    pub const fn changed(&self) -> bool {
        self.created + self.activated + self.retired > 0
    }

    /// Adds what another step changed.
    pub const fn add(&mut self, other: Self) {
        self.created += other.created;
        self.activated += other.activated;
        self.retired += other.retired;
    }
}

/// The use cases of the keys context.
#[derive(Clone)]
pub struct KeyService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    keys: Arc<dyn KeyStore>,
    provider: Arc<dyn KeyProvider>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for KeyService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyService").finish_non_exhaustive()
    }
}

impl KeyService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        keys: Arc<dyn KeyStore>,
        provider: Arc<dyn KeyProvider>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            keys,
            provider,
            clock,
        }
    }

    /// Asks the provider for a new key of `algorithm` and stores it as a
    /// pending version.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider cannot make the key or storage
    /// fails.
    pub async fn create_version(
        &self,
        tenant: &TenantContext,
        algorithm: KeyAlgorithm,
        caller: Caller,
    ) -> Result<KeyVersion, DomainError> {
        let id = KeyVersionId::generate();
        let generated = self.provider.generate(tenant, id, algorithm).await?;
        let (version, event) = KeyVersion::create(
            id,
            algorithm,
            self.provider.name(),
            generated,
            self.clock.now(),
        )?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.keys.insert(uow.as_mut(), &version).await?;
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await?;
        Ok(version)
    }

    /// Makes a pending version the active one of its algorithm. The version
    /// it replaces starts retiring and may retire once `overlap` has
    /// passed: for a signing key, the lifetime of the longest-lived token it
    /// may have signed.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such version, `Conflict`
    /// `keys.not_pending` unless it is pending, and `Invalid` if the overlap
    /// is negative.
    pub async fn activate(
        &self,
        tenant: &TenantContext,
        id: KeyVersionId,
        overlap: Duration,
        caller: Caller,
    ) -> Result<KeyVersion, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut set = self.set_of(uow.as_mut(), id).await?;
        let activation = set.activate(id, overlap, self.clock.now())?;
        // In the order given: the replaced version first, so that one
        // version per algorithm is active after every write.
        for version in &activation.changed {
            self.keys.update(uow.as_mut(), version).await?;
        }
        self.record(uow.as_mut(), caller, &activation.event)?;
        uow.commit().await?;
        activation
            .changed
            .into_iter()
            .find(|version| version.id() == id)
            .ok_or_else(not_found)
    }

    /// Makes a pending version the active one of its algorithm only if the
    /// algorithm has none, so that two callers making the first key at once
    /// never replace each other's.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` `keys.already_active` if an active version exists
    /// when this is checked, `Conflict` `keys.activation_conflict` if one
    /// was activated at the same moment, and what [`KeyService::activate`]
    /// returns.
    pub async fn activate_first(
        &self,
        tenant: &TenantContext,
        id: KeyVersionId,
        caller: Caller,
    ) -> Result<KeyVersion, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut set = self.set_of(uow.as_mut(), id).await?;
        let activation = set.activate_first(id, self.clock.now())?;
        for version in &activation.changed {
            self.keys.update(uow.as_mut(), version).await?;
        }
        self.record(uow.as_mut(), caller, &activation.event)?;
        uow.commit().await?;
        activation
            .changed
            .into_iter()
            .find(|version| version.id() == id)
            .ok_or_else(not_found)
    }

    /// Retires a retiring version whose time has passed.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such version, `Conflict`
    /// `keys.not_retiring` unless it is retiring and `keys.still_needed`
    /// before its time.
    pub async fn retire(
        &self,
        tenant: &TenantContext,
        id: KeyVersionId,
        caller: Caller,
    ) -> Result<KeyVersion, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut set = self.set_of(uow.as_mut(), id).await?;
        let (version, event) = set.retire(id, self.clock.now())?;
        self.keys.update(uow.as_mut(), &version).await?;
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await?;
        Ok(version)
    }

    /// Revokes a version, with a reason. Revoking a revoked version changes
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such version and `Invalid` if
    /// the reason is empty or longer than 200 characters.
    pub async fn revoke(
        &self,
        tenant: &TenantContext,
        id: KeyVersionId,
        reason: &str,
        caller: Caller,
    ) -> Result<KeyVersion, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut set = self.set_of(uow.as_mut(), id).await?;
        let Some((version, event)) = set.revoke(id, reason, self.clock.now())? else {
            return set.version(id).cloned().ok_or_else(not_found);
        };
        self.keys.update(uow.as_mut(), &version).await?;
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await?;
        Ok(version)
    }

    /// The tenant's key set of one use.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn key_set(
        &self,
        tenant: &TenantContext,
        key_use: KeyUse,
    ) -> Result<KeySet, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let versions = self.keys.list_for_use(uow.as_mut(), key_use).await?;
        KeySet::from_versions(key_use, versions)
    }

    /// Runs one step of rotation in the tenant's signing key set: retires,
    /// makes and activates the versions whose time has come under
    /// `policy`. Each change is its own transaction and its own event.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider cannot make a key or storage fails;
    /// the changes made before the error stay made.
    pub async fn rotate_due(
        &self,
        tenant: &TenantContext,
        policy: &RotationPolicy,
        caller: Caller,
    ) -> Result<RotationReport, DomainError> {
        let set = self.key_set(tenant, KeyUse::Signing).await?;
        let mut report = RotationReport::default();
        for change in set.rotation_plan(policy, self.clock.now()) {
            match change {
                RotationChange::Retire(id) => {
                    self.retire(tenant, id, caller).await?;
                    report.retired += 1;
                }
                RotationChange::Activate(id) => {
                    self.activate(tenant, id, policy.overlap(), caller).await?;
                    report.activated += 1;
                }
                RotationChange::Prepare(algorithm) => {
                    self.create_version(tenant, algorithm, caller).await?;
                    report.created += 1;
                }
                RotationChange::CreateAndActivate(algorithm) => {
                    let version = self.create_version(tenant, algorithm, caller).await?;
                    report.created += 1;
                    self.activate(tenant, version.id(), policy.overlap(), caller)
                        .await?;
                    report.activated += 1;
                }
            }
        }
        Ok(report)
    }

    /// Activates a new signing version of `algorithm` at once, for an
    /// operator who will not wait for the schedule: the pending version
    /// published longest if there is one, a new one otherwise. The version
    /// it replaces starts retiring with the policy's overlap.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` `keys.algorithm_unsuitable` for an algorithm that
    /// does not sign, `Conflict` `keys.activation_conflict` if another
    /// activation happened at the same moment, and an error if the provider
    /// cannot make a key or storage fails.
    pub async fn rotate_now(
        &self,
        tenant: &TenantContext,
        algorithm: KeyAlgorithm,
        policy: &RotationPolicy,
        caller: Caller,
    ) -> Result<KeyVersion, DomainError> {
        if algorithm.key_use() != KeyUse::Signing {
            return Err(DomainError::invalid(
                "keys.algorithm_unsuitable",
                "the algorithm does not sign",
            ));
        }
        let set = self.key_set(tenant, KeyUse::Signing).await?;
        let id = match set.oldest_pending(algorithm) {
            Some(pending) => pending.id(),
            None => self.create_version(tenant, algorithm, caller).await?.id(),
        };
        self.activate(tenant, id, policy.overlap(), caller).await
    }

    /// The signing versions that are published for those who check
    /// signatures: pending, active and retiring, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn published_keys(
        &self,
        tenant: &TenantContext,
    ) -> Result<Vec<KeyVersion>, DomainError> {
        let set = self.key_set(tenant, KeyUse::Signing).await?;
        Ok(set.published().into_iter().cloned().collect())
    }

    /// Signs `message` with the active version of a signing algorithm.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` `keys.algorithm_unsuitable` for an algorithm that
    /// does not sign, `Conflict` `keys.no_active_version` when the algorithm
    /// has no active version, and an error if the provider cannot sign.
    pub async fn sign(
        &self,
        tenant: &TenantContext,
        algorithm: KeyAlgorithm,
        message: &[u8],
    ) -> Result<Signature, DomainError> {
        if algorithm.key_use() != KeyUse::Signing {
            return Err(DomainError::invalid(
                "keys.algorithm_unsuitable",
                "the algorithm does not sign",
            ));
        }
        let set = self.key_set(tenant, KeyUse::Signing).await?;
        let version = set.active(algorithm).ok_or_else(|| {
            DomainError::conflict(
                "keys.no_active_version",
                "the tenant has no active key for the algorithm",
            )
        })?;
        let bytes = self.provider.sign(tenant, version, message).await?;
        Ok(Signature {
            key_version_id: version.id(),
            algorithm,
            bytes,
        })
    }

    async fn set_of(
        &self,
        uow: &mut dyn UnitOfWork,
        id: KeyVersionId,
    ) -> Result<KeySet, DomainError> {
        let version = self.keys.get(uow, id).await?.ok_or_else(not_found)?;
        let key_use = version.key_use();
        let versions = self.keys.list_for_use(uow, key_use).await?;
        KeySet::from_versions(key_use, versions)
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &KeyEvent,
    ) -> Result<(), DomainError> {
        let metadata = EventMetadata::new(
            uow.tenant().tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }
}
