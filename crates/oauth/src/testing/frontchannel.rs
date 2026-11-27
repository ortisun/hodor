//! The in-memory store of front-channel logout, and the contract every
//! store of the frames of a sign-out passes.

use super::lock;
use crate::api::{FrontChannelLogout, FrontChannelLogoutStore, HandleHash};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    DomainError, RandomSource, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use hodor_session::api::SessionId;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use time::Duration;

/// The frames of each tenant's sign-outs, by the hash of their handle.
type Rows = BTreeMap<(TenantId, [u8; 32]), FrontChannelLogout>;

/// The frames of sign-outs kept in memory, across tenants.
#[derive(Debug, Clone, Default)]
pub struct InMemoryFrontChannelLogouts {
    rows: Arc<Mutex<Rows>>,
}

impl InMemoryFrontChannelLogouts {
    /// Every row of `tenant`, for tests that look behind the use cases.
    #[must_use]
    pub fn all(&self, tenant: TenantId) -> Vec<FrontChannelLogout> {
        lock(&self.rows)
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, kept)| kept.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl FrontChannelLogoutStore for InMemoryFrontChannelLogouts {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        kept: &FrontChannelLogout,
    ) -> Result<(), DomainError> {
        lock(&self.rows).insert(
            (uow.tenant().tenant_id(), *kept.handle_hash.as_bytes()),
            kept.clone(),
        );
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &HandleHash,
    ) -> Result<Option<FrontChannelLogout>, DomainError> {
        Ok(lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), *hash.as_bytes()))
            .cloned())
    }
}

/// The ports under test.
#[derive(Clone, Copy)]
pub struct FrontChannelLogoutStorePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub store: &'a dyn FrontChannelLogoutStore,
    /// Makes the handles.
    pub random: &'a dyn RandomSource,
}

impl std::fmt::Debug for FrontChannelLogoutStorePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrontChannelLogoutStorePorts")
            .finish_non_exhaustive()
    }
}

/// A moment whole to the microsecond, as PostgreSQL keeps it.
fn moment() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

fn frames(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("https://app{i}.example.com/fc?iss=https%3A%2F%2Fid&sid={i}"))
        .collect()
}

async fn stored(
    ports: FrontChannelLogoutStorePorts<'_>,
    tenant: &TenantContext,
    frames: Vec<String>,
) -> FrontChannelLogout {
    let (kept, _) = FrontChannelLogout::keep(
        SessionId::generate(),
        frames,
        moment(),
        ports.random,
        &FakeDigest,
    )
    .expect("frames to keep");
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .store
        .insert(uow.as_mut(), &kept)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
    kept
}

async fn found(
    ports: FrontChannelLogoutStorePorts<'_>,
    tenant: &TenantContext,
    hash: &HandleHash,
) -> Option<FrontChannelLogout> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.store.find(uow.as_mut(), hash).await.expect("find")
}

/// Runs every check of the contract against `ports`.
pub async fn run_frontchannel_logout_contract(ports: FrontChannelLogoutStorePorts<'_>) {
    frames_are_stored_whole_and_found_by_their_hash(ports).await;
    frames_are_found_only_in_their_own_tenant(ports).await;
}

async fn frames_are_stored_whole_and_found_by_their_hash(ports: FrontChannelLogoutStorePorts<'_>) {
    let home = tenant();
    let one = stored(ports, &home, frames(1)).await;
    let three = stored(ports, &home, frames(3)).await;
    assert_eq!(found(ports, &home, &one.handle_hash).await, Some(one));
    assert_eq!(
        found(ports, &home, &three.handle_hash).await,
        Some(three.clone()),
        "the frames whole, in their order"
    );
    assert_eq!(
        found(ports, &home, &HandleHash::from_stored([7; 32])).await,
        None,
        "an unknown hash finds nothing"
    );
}

async fn frames_are_found_only_in_their_own_tenant(ports: FrontChannelLogoutStorePorts<'_>) {
    let (home, other) = (tenant(), tenant());
    let kept = stored(ports, &home, frames(2)).await;
    assert_eq!(
        found(ports, &other, &kept.handle_hash).await,
        None,
        "another tenant never finds them"
    );
    assert_eq!(found(ports, &home, &kept.handle_hash).await, Some(kept));
}
