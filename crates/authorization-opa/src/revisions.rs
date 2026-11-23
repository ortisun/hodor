//! The latest revision each tenant published, which the engine compares a
//! decision's revision with. See "A lagging instance" in the
//! authorization context.

use crate::ports::BundleStore;
use hodor_kernel::{Clock, DomainError, TenantContext, TenantId, Timestamp, UnitOfWorkFactory};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

/// How long a tenant's latest revision is kept before it is read again.
const KEPT_FOR: time::Duration = time::Duration::seconds(10);
/// At most this many tenants are kept.
const MAX_KEPT: usize = 10_000;

/// Where the engine learns each tenant's latest published revision.
#[async_trait::async_trait]
pub trait PublishedRevisions: Send + Sync {
    /// The latest revision `tenant` published and when, if it published
    /// one.
    ///
    /// # Errors
    ///
    /// Returns an error if it cannot be read.
    async fn latest(&self, tenant: TenantId) -> Result<Option<(u64, Timestamp)>, DomainError>;
}

/// What was read for a tenant, and when.
type Kept = (Option<(u64, Timestamp)>, Timestamp);

/// [`PublishedRevisions`] read from the bundles' store and kept for 10
/// seconds.
pub struct StoredRevisions {
    units: Arc<dyn UnitOfWorkFactory>,
    bundles: Arc<dyn BundleStore>,
    clock: Arc<dyn Clock>,
    kept: Mutex<BTreeMap<TenantId, Kept>>,
}

impl std::fmt::Debug for StoredRevisions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredRevisions").finish_non_exhaustive()
    }
}

impl StoredRevisions {
    /// Revisions read through `units` from `bundles`.
    #[must_use]
    pub fn new(
        units: Arc<dyn UnitOfWorkFactory>,
        bundles: Arc<dyn BundleStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units,
            bundles,
            clock,
            kept: Mutex::new(BTreeMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl PublishedRevisions for StoredRevisions {
    async fn latest(&self, tenant: TenantId) -> Result<Option<(u64, Timestamp)>, DomainError> {
        let now = self.clock.now();
        {
            let kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some((latest, read_at)) = kept.get(&tenant)
                && now - *read_at < KEPT_FOR
            {
                return Ok(*latest);
            }
        }
        // The tenant comes from the caller's credential, through the
        // engine's `TenantContext`.
        let mut uow = self.units.begin(&TenantContext::assume(tenant)).await?;
        let latest = self.bundles.latest_revision(uow.as_mut()).await?;
        uow.commit().await?;
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        if kept.len() >= MAX_KEPT {
            kept.retain(|_, (_, read_at)| now - *read_at < KEPT_FOR);
            if kept.len() >= MAX_KEPT {
                kept.clear();
            }
        }
        kept.insert(tenant, (latest, now));
        Ok(latest)
    }
}
