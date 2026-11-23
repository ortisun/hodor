//! In-memory stores of the bundles, and the contract every store passes.

use crate::bundle::{Author, BundleSigner, PublishedBundle};
use crate::instance::{Instance, InstanceName};
use crate::ports::{
    BundleStore, InstanceStatus, InstanceStatusStore, InstanceStore, UploadedDecision,
    UploadedDecisionStore,
};
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// An instance and the digest of its credential.
type InstanceRow = (Instance, [u8; 32]);

/// Instances kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryInstances {
    rows: Arc<Mutex<Vec<InstanceRow>>>,
}

#[async_trait::async_trait]
impl InstanceStore for InMemoryInstances {
    async fn add(&self, instance: &Instance, credential: [u8; 32]) -> Result<(), DomainError> {
        let mut rows = lock(&self.rows);
        if rows.iter().any(|(kept, _)| kept.name() == instance.name()) {
            return Err(DomainError::conflict(
                "authorization.policy_agent_instance_exists",
                "an instance of this name exists",
            ));
        }
        rows.push((instance.clone(), credential));
        Ok(())
    }

    async fn find_by_credential(
        &self,
        credential: [u8; 32],
    ) -> Result<Option<Instance>, DomainError> {
        Ok(lock(&self.rows)
            .iter()
            .find(|(_, kept)| *kept == credential)
            .map(|(instance, _)| instance.clone()))
    }

    async fn find_by_name(&self, name: &InstanceName) -> Result<Option<Instance>, DomainError> {
        Ok(lock(&self.rows)
            .iter()
            .find(|(instance, _)| instance.name() == name)
            .map(|(instance, _)| instance.clone()))
    }

    async fn list(&self) -> Result<Vec<Instance>, DomainError> {
        let mut all: Vec<Instance> = lock(&self.rows).iter().map(|(i, _)| i.clone()).collect();
        all.sort_by(|a, b| a.name().cmp(b.name()));
        Ok(all)
    }

    async fn disable(&self, name: &InstanceName, at: Timestamp) -> Result<bool, DomainError> {
        let mut rows = lock(&self.rows);
        let Some((instance, _)) = rows
            .iter_mut()
            .find(|(instance, _)| instance.name() == name && instance.disabled_at().is_none())
        else {
            return Ok(false);
        };
        *instance = Instance::from_stored(
            instance.id(),
            instance.name().clone(),
            instance.tenant(),
            instance.registered_at(),
            Some(at),
        );
        Ok(true)
    }
}

/// Bundles kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryBundles {
    rows: Arc<Mutex<BTreeMap<(TenantId, u64), PublishedBundle>>>,
}

#[async_trait::async_trait]
impl BundleStore for InMemoryBundles {
    async fn append(
        &self,
        uow: &mut dyn UnitOfWork,
        bundle: &PublishedBundle,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), bundle.revision);
        let mut rows = lock(&self.rows);
        if rows.contains_key(&key) {
            return Err(DomainError::conflict(
                "authorization.bundle_revision_taken",
                "another publication took this revision",
            ));
        }
        rows.insert(key, bundle.clone());
        Ok(())
    }

    async fn latest(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<PublishedBundle>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows)
            .range((tenant, 0)..=(tenant, u64::MAX))
            .next_back()
            .map(|(_, bundle)| bundle.clone()))
    }
}

/// A status is kept per tenant and instance.
type StatusKey = (TenantId, crate::instance::InstanceId);

/// Statuses kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryStatuses {
    rows: Arc<Mutex<BTreeMap<StatusKey, InstanceStatus>>>,
}

#[async_trait::async_trait]
impl InstanceStatusStore for InMemoryStatuses {
    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        status: &InstanceStatus,
    ) -> Result<(), DomainError> {
        lock(&self.rows).insert((uow.tenant().tenant_id(), status.instance), status.clone());
        Ok(())
    }

    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<InstanceStatus>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut found: Vec<InstanceStatus> = lock(&self.rows)
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, status)| status.clone())
            .collect();
        found.sort_by_key(|status| (status.reported_at, status.instance));
        Ok(found)
    }
}

/// Uploaded decisions kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryUploadedDecisions {
    rows: Arc<Mutex<Vec<(TenantId, UploadedDecision)>>>,
}

#[async_trait::async_trait]
impl UploadedDecisionStore for InMemoryUploadedDecisions {
    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        decisions: &[UploadedDecision],
    ) -> Result<u64, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = lock(&self.rows);
        let mut new = 0;
        for decision in decisions {
            let kept = rows.iter().any(|(owner, row)| {
                *owner == tenant
                    && row.instance == decision.instance
                    && row.decision_id == decision.decision_id
            });
            if !kept {
                rows.push((tenant, decision.clone()));
                new += 1;
            }
        }
        Ok(new)
    }

    async fn latest(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<UploadedDecision>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows)
            .iter()
            .rev()
            .filter(|(owner, _)| *owner == tenant)
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .map(|(_, decision)| decision.clone())
            .collect())
    }
}

/// The files of a bundle's archive, in order, for tests that look inside
/// or change one.
///
/// # Panics
///
/// Panics if the archive is not one.
#[must_use]
pub fn unpack(archive: &[u8]) -> Vec<(String, Vec<u8>)> {
    crate::archive::untar(&crate::archive::gunzip(archive, 64 << 20).expect("gzip"))
}

/// An archive of `files`, in order, for tests that build a bundle by hand.
///
/// # Panics
///
/// Panics if a path cannot be held.
#[must_use]
pub fn pack(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    crate::archive::gzip(&crate::archive::tar(files).expect("tar"))
}

/// A signer for tests that is not a signature: the message's length,
/// repeated. Never use outside tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeSigner;

impl BundleSigner for FakeSigner {
    fn key_id(&self) -> &str {
        "fake"
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DomainError> {
        Ok(message.len().to_be_bytes().repeat(8))
    }
}

/// The stores under test.
pub struct BundlePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The instances.
    pub instances: &'a dyn InstanceStore,
    /// The bundles.
    pub bundles: &'a dyn BundleStore,
    /// The statuses.
    pub statuses: &'a dyn InstanceStatusStore,
    /// The uploaded decisions.
    pub decisions: &'a dyn UploadedDecisionStore,
}

impl std::fmt::Debug for BundlePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundlePorts").finish_non_exhaustive()
    }
}

/// A time with whole microseconds, as storage keeps them.
fn at(minutes: i64) -> Timestamp {
    Timestamp::UNIX_EPOCH + time::Duration::days(20_000) + time::Duration::minutes(minutes)
}

fn digest_of(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn bundle(revision: u64, author: Author) -> PublishedBundle {
    let archive = vec![u8::try_from(revision % 256).unwrap_or(0); 64];
    PublishedBundle {
        revision,
        author,
        digest: digest_of(u8::try_from(revision % 256).unwrap_or(0)),
        archive,
        published_at: at(i64::try_from(revision).unwrap_or(0)),
    }
}

async fn latest(ports: &BundlePorts<'_>, tenant: &TenantContext) -> Option<PublishedBundle> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let found = ports.bundles.latest(uow.as_mut()).await.expect("latest");
    uow.commit().await.expect("commit");
    found
}

async fn append(
    ports: &BundlePorts<'_>,
    tenant: &TenantContext,
    bundle: &PublishedBundle,
) -> Result<(), DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.bundles.append(uow.as_mut(), bundle).await?;
    uow.commit().await.expect("commit");
    Ok(())
}

/// Runs every rule the stores of the bundles must obey. Each run uses
/// names and tenants of its own, so runs can share one database.
///
/// # Panics
///
/// Panics if an implementation breaks a rule.
pub async fn run_bundle_contract(ports: BundlePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let suffix = tenant.tenant_id().as_uuid().simple().to_string();

    // Instances: found by credential and by name, listed by name, and a
    // name is taken once.
    let shared = Instance::new(
        InstanceName::parse(&format!("shared-{}", &suffix[..12])).expect("name"),
        None,
        at(0),
    );
    let own = Instance::new(
        InstanceName::parse(&format!("own-{}", &suffix[..12])).expect("name"),
        Some(tenant.tenant_id()),
        at(1),
    );
    let shared_credential = digest_of(1).map(|byte| byte ^ suffix.as_bytes()[0]);
    let own_credential = digest_of(2).map(|byte| byte ^ suffix.as_bytes()[1]);
    ports
        .instances
        .add(&shared, shared_credential)
        .await
        .expect("add shared");
    ports
        .instances
        .add(&own, own_credential)
        .await
        .expect("add own");
    assert_eq!(
        ports
            .instances
            .find_by_credential(shared_credential)
            .await
            .expect("find"),
        Some(shared.clone())
    );
    assert_eq!(
        ports
            .instances
            .find_by_name(own.name())
            .await
            .expect("find"),
        Some(own.clone())
    );
    assert_eq!(
        ports
            .instances
            .find_by_credential(digest_of(3).map(|b| b ^ suffix.as_bytes()[2]))
            .await
            .expect("find"),
        None
    );
    let again = Instance::new(shared.name().clone(), None, at(2));
    assert_eq!(
        ports
            .instances
            .add(&again, digest_of(4))
            .await
            .map_err(|e| e.code().to_owned()),
        Err("authorization.policy_agent_instance_exists".to_owned())
    );
    let listed = ports.instances.list().await.expect("list");
    let position = |instance: &Instance| listed.iter().position(|i| i.id() == instance.id());
    assert!(position(&own) < position(&shared), "by name");

    // Disabling keeps the instance, with when it was disabled, once.
    assert!(
        ports
            .instances
            .disable(own.name(), at(5))
            .await
            .expect("disable")
    );
    assert!(
        !ports
            .instances
            .disable(own.name(), at(6))
            .await
            .expect("disable")
    );
    let disabled = ports
        .instances
        .find_by_credential(own_credential)
        .await
        .expect("find")
        .expect("kept");
    assert_eq!(disabled.disabled_at(), Some(at(5)));
    assert_eq!(disabled.tenant(), Some(tenant.tenant_id()));

    // Bundles: the latest revision, whole; a revision is taken once; a
    // tenant sees only its own.
    assert_eq!(latest(&ports, &tenant).await, None);
    let first = bundle(1, Author::Operator);
    let second = bundle(2, Author::Tenant);
    append(&ports, &tenant, &first).await.expect("first");
    append(&ports, &tenant, &second).await.expect("second");
    assert_eq!(latest(&ports, &tenant).await, Some(second.clone()));
    assert_eq!(
        append(&ports, &tenant, &bundle(2, Author::Operator))
            .await
            .map_err(|e| e.code().to_owned()),
        Err("authorization.bundle_revision_taken".to_owned())
    );
    assert_eq!(latest(&ports, &elsewhere).await, None);
    append(&ports, &elsewhere, &first)
        .await
        .expect("same revision, other tenant");
    assert_eq!(latest(&ports, &tenant).await, Some(second));

    // Statuses: one per instance, replaced by the next report.
    let report = |revision: &str, minutes| InstanceStatus {
        instance: shared.id(),
        active_revision: Some(revision.to_owned()),
        last_activation: Some(at(minutes)),
        error: None,
        reported_at: at(minutes),
    };
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .statuses
        .record(uow.as_mut(), &report("1", 10))
        .await
        .expect("record");
    ports
        .statuses
        .record(uow.as_mut(), &report("2", 11))
        .await
        .expect("record");
    let failing = InstanceStatus {
        instance: own.id(),
        active_revision: None,
        last_activation: None,
        error: Some("bundle_error: signature verification failed".to_owned()),
        reported_at: at(12),
    };
    ports
        .statuses
        .record(uow.as_mut(), &failing)
        .await
        .expect("record");
    let statuses = ports.statuses.list(uow.as_mut()).await.expect("list");
    uow.commit().await.expect("commit");
    assert_eq!(statuses, vec![report("2", 11), failing]);
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert!(
        ports
            .statuses
            .list(uow.as_mut())
            .await
            .expect("list")
            .is_empty()
    );
    uow.commit().await.expect("commit");

    // Uploaded decisions: kept once by instance and identifier, newest
    // first, per tenant.
    let decision = |id: &str, minutes| UploadedDecision {
        instance: shared.id(),
        decision_id: id.to_owned(),
        path: "hodor/tenants/t/resource_servers/r/decision".to_owned(),
        revision: Some("2".to_owned()),
        allowed: Some(minutes % 2 == 0),
        decided_at: Some(at(minutes)),
        received_at: at(minutes),
    };
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let new = ports
        .decisions
        .record(uow.as_mut(), &[decision("a", 20), decision("b", 21)])
        .await
        .expect("record");
    assert_eq!(new, 2);
    let mut repeated = decision("a", 20);
    repeated.allowed = None;
    let again = ports
        .decisions
        .record(uow.as_mut(), &[repeated, decision("c", 22)])
        .await
        .expect("record");
    assert_eq!(again, 1);
    let found = ports
        .decisions
        .latest(uow.as_mut(), 2)
        .await
        .expect("latest");
    uow.commit().await.expect("commit");
    assert_eq!(found, vec![decision("c", 22), decision("b", 21)]);
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert!(
        ports
            .decisions
            .latest(uow.as_mut(), 10)
            .await
            .expect("latest")
            .is_empty()
    );
    uow.commit().await.expect("commit");
}
