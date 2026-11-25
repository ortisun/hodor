//! API keys: the port and the use cases.
//!
//! See `docs/architecture/contexts/credential.md`, "API keys". Which
//! names are scopes, whether the holder is a workload that may act, and
//! whether an application exists are asked by whoever calls these use
//! cases: this context knows none of them.

use crate::domain::api_key::{
    ApiKey, ApiKeyEvent, ApiKeyHash, ApiKeyId, ApiKeySecret, ApiKeySettings, LAST_USE_PRECISION,
    MAX_API_KEYS,
};
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, EventEnvelope, EventMetadata, RandomSource, TenantContext,
    Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;
use time::Duration;

/// Stores API keys. Every method works inside the tenant the unit of work
/// is bound to.
#[async_trait::async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Stores a new key.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails, or if the holder is not a user
    /// of the tenant.
    async fn insert(&self, uow: &mut dyn UnitOfWork, key: &ApiKey) -> Result<(), DomainError>;

    /// Loads a key of the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ApiKeyId,
    ) -> Result<Option<ApiKey>, DomainError>;

    /// Loads the key of the tenant with the given hash.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find_by_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &ApiKeyHash,
    ) -> Result<Option<ApiKey>, DomainError>;

    /// The keys of `holder`, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list_of(
        &self,
        uow: &mut dyn UnitOfWork,
        holder: UserId,
    ) -> Result<Vec<ApiKey>, DomainError>;

    /// Stores a change of a key loaded earlier: its expiry, its
    /// revocation, the key that replaced it.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such key.
    async fn update(&self, uow: &mut dyn UnitOfWork, key: &ApiKey) -> Result<(), DomainError>;

    /// Records that `id` was used at `now`, unless a use was recorded less
    /// than `precision` before. Answers whether it wrote.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn record_use(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ApiKeyId,
        now: Timestamp,
        precision: Duration,
    ) -> Result<bool, DomainError>;
}

/// The use cases of API keys.
#[derive(Clone)]
pub struct ApiKeyService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    keys: Arc<dyn ApiKeyStore>,
    digest: Arc<dyn Digest>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ApiKeyService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyService").finish_non_exhaustive()
    }
}

fn not_found() -> DomainError {
    DomainError::not_found("credential.api_key_not_found", "the API key does not exist")
}

fn too_many() -> DomainError {
    DomainError::conflict(
        "credential.too_many_api_keys",
        "a service account or an agent holds at most 10 keys that work",
    )
}

impl ApiKeyService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        keys: Arc<dyn ApiKeyStore>,
        digest: Arc<dyn Digest>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            keys,
            digest,
            random,
            clock,
        }
    }

    /// Makes a key for `holder`. The key itself is returned once.
    ///
    /// # Errors
    ///
    /// `Invalid` for settings or a lifetime that break their rules, and
    /// `Conflict` with code `credential.too_many_api_keys` when the holder
    /// already holds ten keys that work.
    pub async fn create(
        &self,
        tenant: &TenantContext,
        holder: UserId,
        settings: ApiKeySettings,
        lifetime: Duration,
        caller: Caller,
    ) -> Result<(ApiKey, ApiKeySecret), DomainError> {
        let now = self.clock.now();
        let (key, secret, event) = ApiKey::create(
            holder,
            settings,
            lifetime,
            now,
            self.random.as_ref(),
            self.digest.as_ref(),
        )?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        if self.working(uow.as_mut(), holder, now).await? >= MAX_API_KEYS {
            return Err(too_many());
        }
        self.keys.insert(uow.as_mut(), &key).await?;
        self.record(uow.as_mut(), caller, &[event])?;
        uow.commit().await?;
        Ok((key, secret))
    }

    /// The keys of `holder`, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn list(
        &self,
        tenant: &TenantContext,
        holder: UserId,
    ) -> Result<Vec<ApiKey>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.keys.list_of(uow.as_mut(), holder).await
    }

    /// Replaces a key of `holder` with a new one living `lifetime`; the old
    /// one keeps working for `overlap`. The new key is returned once.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `credential.api_key_not_found` for a key that
    /// is not the holder's, and what [`ApiKey::rotate`] refuses.
    pub async fn rotate(
        &self,
        tenant: &TenantContext,
        holder: UserId,
        id: ApiKeyId,
        lifetime: Duration,
        overlap: Duration,
        caller: Caller,
    ) -> Result<(ApiKey, ApiKeySecret), DomainError> {
        let now = self.clock.now();
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut old = self.load(uow.as_mut(), holder, id).await?;
        let (next, secret, event) = old.rotate(
            lifetime,
            overlap,
            now,
            self.random.as_ref(),
            self.digest.as_ref(),
        )?;
        // The new key takes the place of the old one, which is no longer
        // counted while it works for its overlap: the count is unchanged.
        self.keys.insert(uow.as_mut(), &next).await?;
        self.keys.update(uow.as_mut(), &old).await?;
        self.record(uow.as_mut(), caller, &[event])?;
        uow.commit().await?;
        Ok((next, secret))
    }

    /// Ends a key of `holder` at once. Ending a revoked key changes
    /// nothing.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `credential.api_key_not_found` for a key that
    /// is not the holder's.
    pub async fn revoke(
        &self,
        tenant: &TenantContext,
        holder: UserId,
        id: ApiKeyId,
        reason: &str,
        caller: Caller,
    ) -> Result<ApiKey, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut key = self.load(uow.as_mut(), holder, id).await?;
        if let Some(event) = key.revoke(reason, self.clock.now()) {
            self.keys.update(uow.as_mut(), &key).await?;
            self.record(uow.as_mut(), caller, &[event])?;
            uow.commit().await?;
        }
        Ok(key)
    }

    /// Revokes every key of `holder` that is not revoked yet, with
    /// `reason`, in the caller's unit of work. Answers how many.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails. After an error the unit of work
    /// must be abandoned.
    pub async fn revoke_all_of_in(
        &self,
        uow: &mut dyn UnitOfWork,
        holder: UserId,
        reason: &str,
        caller: Caller,
    ) -> Result<usize, DomainError> {
        let now = self.clock.now();
        let mut revoked = 0;
        for mut key in self.keys.list_of(uow, holder).await? {
            if let Some(event) = key.revoke(reason, now) {
                self.keys.update(uow, &key).await?;
                self.record(uow, caller, &[event])?;
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    /// Says which key a presented value is, if it is one that works, and
    /// records its use. A value that is malformed, unknown in this tenant,
    /// expired or revoked finds nothing; they are not told apart. Whoever
    /// accepts the key must still ask whether its holder may act, and what
    /// its scopes allow.
    ///
    /// # Errors
    ///
    /// Returns an error only if storage fails.
    pub async fn authenticate(
        &self,
        tenant: &TenantContext,
        presented: &str,
    ) -> Result<Option<ApiKey>, DomainError> {
        let Some(hash) = ApiKeyHash::of_presented(presented, self.digest.as_ref()) else {
            return Ok(None);
        };
        let now = self.clock.now();
        let mut uow = self.units_of_work.begin(tenant).await?;
        let Some(key) = self
            .keys
            .find_by_hash(uow.as_mut(), &hash)
            .await?
            .filter(|key| key.is_good_at(now))
        else {
            return Ok(None);
        };
        if self
            .keys
            .record_use(uow.as_mut(), key.id(), now, LAST_USE_PRECISION)
            .await?
        {
            uow.commit().await?;
        }
        Ok(Some(key))
    }

    /// The time this service reads, for telling a key's status.
    #[must_use]
    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }

    async fn working(
        &self,
        uow: &mut dyn UnitOfWork,
        holder: UserId,
        now: Timestamp,
    ) -> Result<usize, DomainError> {
        Ok(self
            .keys
            .list_of(uow, holder)
            .await?
            .iter()
            .filter(|key| key.is_good_at(now) && key.snapshot().replaced_by.is_none())
            .count())
    }

    async fn load(
        &self,
        uow: &mut dyn UnitOfWork,
        holder: UserId,
        id: ApiKeyId,
    ) -> Result<ApiKey, DomainError> {
        self.keys
            .get(uow, id)
            .await?
            .filter(|key| key.holder_id() == holder)
            .ok_or_else(not_found)
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        events: &[ApiKeyEvent],
    ) -> Result<(), DomainError> {
        for event in events {
            let metadata = EventMetadata::new(
                uow.tenant().tenant_id(),
                caller.actor,
                caller.correlation_id,
                self.clock.as_ref(),
            );
            uow.record_event(EventEnvelope::new(metadata, event)?);
        }
        Ok(())
    }
}
