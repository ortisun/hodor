//! In-memory ports and the contract every implementation of them passes.
//!
//! The contract is a set of plain async functions. The in-memory fake and
//! the PostgreSQL adapter both run it, which is what makes the fake a
//! faithful stand-in in the use case tests.

use crate::api::{DirectoryEntry, Slug, Tenant, TenantDirectory, TenantRepository};
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Tenants kept in memory, implementing both ports.
#[derive(Debug, Clone, Default)]
pub struct InMemoryTenants {
    rows: Arc<Mutex<BTreeMap<TenantId, Tenant>>>,
}

impl InMemoryTenants {
    fn rows(&self) -> std::sync::MutexGuard<'_, BTreeMap<TenantId, Tenant>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn with_version(tenant: &Tenant, version: u32) -> Tenant {
    let mut state = tenant.snapshot().clone();
    state.version = version;
    Tenant::from_snapshot(state)
}

#[async_trait::async_trait]
impl TenantRepository for InMemoryTenants {
    async fn insert(&self, uow: &mut dyn UnitOfWork, tenant: &Tenant) -> Result<(), DomainError> {
        let mut rows = self.rows();
        if uow.tenant().tenant_id() != tenant.id() {
            return Err(DomainError::internal(
                "tenant.context_mismatch",
                "the operation could not be completed",
            ));
        }
        let slug = &tenant.snapshot().slug;
        if rows.values().any(|other| &other.snapshot().slug == slug) {
            return Err(DomainError::conflict(
                "tenant.slug_taken",
                "another tenant already has this slug",
            ));
        }
        rows.insert(tenant.id(), tenant.clone());
        Ok(())
    }

    async fn get(&self, uow: &mut dyn UnitOfWork) -> Result<Option<Tenant>, DomainError> {
        Ok(self.rows().get(&uow.tenant().tenant_id()).cloned())
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, tenant: &Tenant) -> Result<(), DomainError> {
        let mut rows = self.rows();
        let stored = rows
            .get(&uow.tenant().tenant_id())
            .filter(|stored| stored.id() == tenant.id())
            .ok_or_else(|| {
                DomainError::not_found("tenant.not_found", "the tenant does not exist")
            })?;
        if stored.snapshot().version != tenant.snapshot().version {
            return Err(DomainError::conflict(
                "tenant.modified_concurrently",
                "the tenant was changed by someone else; reload and try again",
            ));
        }
        rows.insert(
            tenant.id(),
            with_version(tenant, tenant.snapshot().version + 1),
        );
        Ok(())
    }
}

#[async_trait::async_trait]
impl TenantDirectory for InMemoryTenants {
    async fn find_by_slug(&self, slug: &str) -> Result<Option<DirectoryEntry>, DomainError> {
        Ok(self
            .rows()
            .values()
            .find(|tenant| tenant.snapshot().slug.as_str() == slug)
            .map(entry))
    }

    async fn list(&self) -> Result<Vec<DirectoryEntry>, DomainError> {
        let mut entries: Vec<DirectoryEntry> = self.rows().values().map(entry).collect();
        entries.sort_by(|a, b| a.slug.as_str().cmp(b.slug.as_str()));
        Ok(entries)
    }
}

fn entry(tenant: &Tenant) -> DirectoryEntry {
    DirectoryEntry {
        slug: tenant.snapshot().slug.clone(),
        tenant_id: tenant.id(),
        status: tenant.status(),
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct Ports<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The repository under test.
    pub tenants: &'a dyn TenantRepository,
    /// The directory under test.
    pub directory: &'a dyn TenantDirectory,
}

impl std::fmt::Debug for Ports<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

/// A fixed, whole-second moment, so that stored timestamps compare equal
/// after a round trip through any storage.
const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;

fn new_tenant(slug: &str) -> Tenant {
    let (mut tenant, _) = Tenant::create(Slug::parse(slug).expect("valid slug"), "Example", MOMENT)
        .expect("valid tenant");
    tenant.activate(MOMENT).expect("activation");
    tenant
}

async fn store(ports: &Ports<'_>, tenant: &Tenant) -> Result<(), DomainError> {
    let context = TenantContext::assume(tenant.id());
    let mut uow = ports.units_of_work.begin(&context).await?;
    ports.tenants.insert(uow.as_mut(), tenant).await?;
    uow.commit().await
}

async fn load(ports: &Ports<'_>, tenant_id: TenantId) -> Option<Tenant> {
    let context = TenantContext::assume(tenant_id);
    let mut uow = ports.units_of_work.begin(&context).await.expect("begin");
    ports.tenants.get(uow.as_mut()).await.expect("get")
}

/// Runs the whole contract. `prefix` keeps slugs apart when several runs
/// share one database.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_contract(ports: Ports<'_>, prefix: &str) {
    a_stored_tenant_is_loaded_unchanged(&ports, prefix).await;
    a_slug_can_be_taken_only_once(&ports, prefix).await;
    a_tenant_is_invisible_from_another_tenant(&ports, prefix).await;
    an_update_is_stored_and_raises_the_version(&ports, prefix).await;
    a_stale_update_is_rejected(&ports, prefix).await;
    an_update_cannot_reach_another_tenant(&ports, prefix).await;
    the_directory_follows_the_tenants(&ports, prefix).await;
}

async fn a_stored_tenant_is_loaded_unchanged(ports: &Ports<'_>, prefix: &str) {
    let tenant = new_tenant(&format!("{prefix}-roundtrip"));
    store(ports, &tenant).await.expect("insert");
    assert_eq!(load(ports, tenant.id()).await, Some(tenant));
}

async fn a_slug_can_be_taken_only_once(ports: &Ports<'_>, prefix: &str) {
    let slug = format!("{prefix}-taken");
    store(ports, &new_tenant(&slug))
        .await
        .expect("first insert");
    let error = store(ports, &new_tenant(&slug))
        .await
        .expect_err("second insert");
    assert_eq!(error.code(), "tenant.slug_taken");
}

async fn a_tenant_is_invisible_from_another_tenant(ports: &Ports<'_>, prefix: &str) {
    let tenant = new_tenant(&format!("{prefix}-hidden"));
    store(ports, &tenant).await.expect("insert");
    assert_eq!(load(ports, TenantId::generate()).await, None);
}

async fn an_update_is_stored_and_raises_the_version(ports: &Ports<'_>, prefix: &str) {
    let tenant = new_tenant(&format!("{prefix}-update"));
    store(ports, &tenant).await.expect("insert");

    let context = TenantContext::assume(tenant.id());
    let mut uow = ports.units_of_work.begin(&context).await.expect("begin");
    let mut loaded = ports
        .tenants
        .get(uow.as_mut())
        .await
        .expect("get")
        .expect("exists");
    loaded.suspend("contract test", MOMENT).expect("suspend");
    ports
        .tenants
        .update(uow.as_mut(), &loaded)
        .await
        .expect("update");
    uow.commit().await.expect("commit");

    let stored = load(ports, tenant.id()).await.expect("exists");
    assert_eq!(stored.status(), loaded.status());
    assert_eq!(
        stored.snapshot().status_reason.as_deref(),
        Some("contract test")
    );
    assert_eq!(stored.snapshot().version, tenant.snapshot().version + 1);
}

async fn a_stale_update_is_rejected(ports: &Ports<'_>, prefix: &str) {
    let tenant = new_tenant(&format!("{prefix}-stale"));
    store(ports, &tenant).await.expect("insert");
    let context = TenantContext::assume(tenant.id());

    // Two readers load the same version; the first to write wins.
    let mut first = load(ports, tenant.id()).await.expect("exists");
    let mut second = first.clone();
    first.suspend("first", MOMENT).expect("suspend");
    second.suspend("second", MOMENT).expect("suspend");

    let mut uow = ports.units_of_work.begin(&context).await.expect("begin");
    ports
        .tenants
        .update(uow.as_mut(), &first)
        .await
        .expect("first update");
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&context).await.expect("begin");
    let error = ports
        .tenants
        .update(uow.as_mut(), &second)
        .await
        .expect_err("stale update");
    assert_eq!(error.code(), "tenant.modified_concurrently");

    let stored = load(ports, tenant.id()).await.expect("exists");
    assert_eq!(stored.snapshot().status_reason.as_deref(), Some("first"));
}

async fn an_update_cannot_reach_another_tenant(ports: &Ports<'_>, prefix: &str) {
    let victim = new_tenant(&format!("{prefix}-victim"));
    store(ports, &victim).await.expect("insert");
    let mut tampered = victim.clone();
    tampered.suspend("tampering", MOMENT).expect("suspend");

    // A unit of work of some other tenant tries to update the victim.
    let other = TenantContext::assume(TenantId::generate());
    let mut uow = ports.units_of_work.begin(&other).await.expect("begin");
    let error = ports
        .tenants
        .update(uow.as_mut(), &tampered)
        .await
        .expect_err("cross-tenant update");
    assert_eq!(error.code(), "tenant.not_found");

    assert_eq!(load(ports, victim.id()).await, Some(victim));
}

async fn the_directory_follows_the_tenants(ports: &Ports<'_>, prefix: &str) {
    let slug = format!("{prefix}-listed");
    assert_eq!(
        ports.directory.find_by_slug(&slug).await.expect("find"),
        None
    );

    let tenant = new_tenant(&slug);
    store(ports, &tenant).await.expect("insert");
    let found = ports
        .directory
        .find_by_slug(&slug)
        .await
        .expect("find")
        .expect("listed");
    assert_eq!(found.tenant_id, tenant.id());
    assert_eq!(found.status, tenant.status());

    // A status change shows up in the directory.
    let context = TenantContext::assume(tenant.id());
    let mut uow = ports.units_of_work.begin(&context).await.expect("begin");
    let mut loaded = ports
        .tenants
        .get(uow.as_mut())
        .await
        .expect("get")
        .expect("exists");
    loaded.suspend("contract test", MOMENT).expect("suspend");
    ports
        .tenants
        .update(uow.as_mut(), &loaded)
        .await
        .expect("update");
    uow.commit().await.expect("commit");
    let found = ports
        .directory
        .find_by_slug(&slug)
        .await
        .expect("find")
        .expect("listed");
    assert_eq!(found.status, loaded.status());

    let listed = ports.directory.list().await.expect("list");
    assert!(listed.iter().any(|entry| entry.slug.as_str() == slug));
    assert!(
        listed
            .windows(2)
            .all(|pair| pair[0].slug.as_str() <= pair[1].slug.as_str()),
        "the list is ordered by slug"
    );
}
