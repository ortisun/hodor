//! In-memory stores of the bundles and of the policy lifecycle, a checker
//! that stands in for `opa`, and the contracts every store passes.

use crate::bundle::{Author, BundleFile, BundleSigner, PublishedBundle};
use crate::instance::{Instance, InstanceName};
use crate::policy::{
    Diagnostic, PolicyVersion, Report, SimulatedAnswer, Simulation, SimulationId, SimulationState,
    TestResult, VersionState,
};
use crate::ports::{
    BundleStore, InstanceStatus, InstanceStatusStore, InstanceStore, PolicyChecker,
    PolicyVersionStore, PublicationStore, SimulationStore, UploadedDecision, UploadedDecisionStore,
};
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use serde_json::Value;
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

/// Versions kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryPolicyVersions {
    rows: Arc<Mutex<BTreeMap<(TenantId, u64), PolicyVersion>>>,
}

#[async_trait::async_trait]
impl PolicyVersionStore for InMemoryPolicyVersions {
    async fn create(
        &self,
        uow: &mut dyn UnitOfWork,
        version: &PolicyVersion,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), version.number);
        let mut rows = lock(&self.rows);
        if rows.contains_key(&key) {
            return Err(DomainError::conflict(
                "authorization.policy_version_taken",
                "another draft took this number",
            ));
        }
        rows.insert(key, version.clone());
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        number: u64,
    ) -> Result<Option<PolicyVersion>, DomainError> {
        Ok(lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), number))
            .cloned())
    }

    async fn latest_number(&self, uow: &mut dyn UnitOfWork) -> Result<Option<u64>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows)
            .range((tenant, 0)..=(tenant, u64::MAX))
            .next_back()
            .map(|((_, number), _)| *number))
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<PolicyVersion>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows)
            .range((tenant, 0)..=(tenant, u64::MAX))
            .rev()
            .take(limit as usize)
            .map(|(_, version)| PolicyVersion {
                files: Vec::new(),
                ..version.clone()
            })
            .collect())
    }

    async fn waiting(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<PolicyVersion>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut waiting: Vec<PolicyVersion> = lock(&self.rows)
            .range((tenant, 0)..=(tenant, u64::MAX))
            .map(|(_, version)| version.clone())
            .filter(|version| version.state.is_waiting())
            .collect();
        waiting.sort_by_key(|version| (version.changed_at, version.number));
        waiting.truncate(limit as usize);
        Ok(waiting)
    }

    async fn transition(
        &self,
        uow: &mut dyn UnitOfWork,
        number: u64,
        from: VersionState,
        to: VersionState,
        report: Option<&Report>,
        at: Timestamp,
    ) -> Result<bool, DomainError> {
        let mut rows = lock(&self.rows);
        match rows.get_mut(&(uow.tenant().tenant_id(), number)) {
            Some(version) if version.state == from => {
                version.state = to;
                version.report = report.cloned();
                version.changed_at = at;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// Publications kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryPublications {
    rows: Arc<Mutex<BTreeMap<(TenantId, u64), u64>>>,
}

#[async_trait::async_trait]
impl PublicationStore for InMemoryPublications {
    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        revision: u64,
        version: u64,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), revision);
        let mut rows = lock(&self.rows);
        if rows.contains_key(&key) {
            return Err(DomainError::conflict(
                "authorization.policy_publication_taken",
                "this revision is recorded already",
            ));
        }
        rows.insert(key, version);
        Ok(())
    }

    async fn version_of(
        &self,
        uow: &mut dyn UnitOfWork,
        revision: u64,
    ) -> Result<Option<u64>, DomainError> {
        Ok(lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), revision))
            .copied())
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<(u64, u64)>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows)
            .range((tenant, 0)..=(tenant, u64::MAX))
            .rev()
            .take(limit as usize)
            .map(|((_, revision), version)| (*revision, *version))
            .collect())
    }
}

/// Simulations kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemorySimulations {
    rows: Arc<Mutex<BTreeMap<(TenantId, SimulationId), Simulation>>>,
}

#[async_trait::async_trait]
impl SimulationStore for InMemorySimulations {
    async fn create(
        &self,
        uow: &mut dyn UnitOfWork,
        simulation: &Simulation,
    ) -> Result<(), DomainError> {
        lock(&self.rows).insert(
            (uow.tenant().tenant_id(), simulation.id),
            simulation.clone(),
        );
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        id: SimulationId,
    ) -> Result<Option<Simulation>, DomainError> {
        Ok(lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), id))
            .cloned())
    }

    async fn waiting(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<Simulation>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut waiting: Vec<Simulation> = lock(&self.rows)
            .iter()
            .filter(|((owner, _), simulation)| {
                *owner == tenant && simulation.state == SimulationState::Waiting
            })
            .map(|(_, simulation)| simulation.clone())
            .collect();
        waiting.sort_by_key(|simulation| simulation.asked_at);
        waiting.truncate(limit as usize);
        Ok(waiting)
    }

    async fn finish(
        &self,
        uow: &mut dyn UnitOfWork,
        id: SimulationId,
        state: SimulationState,
        compared_with: Option<u64>,
        results: &[SimulatedAnswer],
        report: Option<&Report>,
        at: Timestamp,
    ) -> Result<bool, DomainError> {
        let mut rows = lock(&self.rows);
        match rows.get_mut(&(uow.tenant().tenant_id(), id)) {
            Some(simulation) if simulation.state == SimulationState::Waiting => {
                simulation.state = state;
                simulation.compared_with = compared_with;
                simulation.results = results.to_vec();
                simulation.report = report.cloned();
                simulation.inputs = Vec::new();
                simulation.done_at = Some(at);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// Stands in for `opa`. A module is refused when it holds `refuse`, a test
/// fails when its module holds `fail`, and a decision is the input's field
/// `answer`, or undefined without one; the files' text `deny everything`
/// makes every decision `{"allow": false}`. Every call is counted, and
/// `broken` makes every run fail to start.
#[derive(Debug, Default)]
pub struct FakeChecker {
    /// Runs that could not start, when set.
    pub broken: std::sync::atomic::AtomicBool,
    /// How many runs were asked for.
    pub runs: std::sync::atomic::AtomicU64,
}

impl FakeChecker {
    fn start(&self) -> Result<(), DomainError> {
        self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.broken.load(std::sync::atomic::Ordering::SeqCst) {
            Err(DomainError::internal(
                "authorization.policy_checker_unavailable",
                "the checker could not run",
            ))
        } else {
            Ok(())
        }
    }

    fn refused(files: &[BundleFile]) -> Report {
        Report {
            diagnostics: files
                .iter()
                .filter(|file| String::from_utf8_lossy(&file.contents).contains("refuse"))
                .map(|file| Diagnostic {
                    file: Some(file.path.clone()),
                    row: Some(1),
                    code: "rego_parse_error".to_owned(),
                    message: "refused by the fake checker".to_owned(),
                })
                .collect(),
            tests: Vec::new(),
        }
    }
}

#[async_trait::async_trait]
impl PolicyChecker for FakeChecker {
    async fn check(&self, _tenant: TenantId, files: &[BundleFile]) -> Result<Report, DomainError> {
        self.start()?;
        Ok(Self::refused(files))
    }

    async fn test(&self, _tenant: TenantId, files: &[BundleFile]) -> Result<Report, DomainError> {
        self.start()?;
        let mut report = Self::refused(files);
        report.tests = files
            .iter()
            .filter(|file| crate::bundle::is_test(&file.path))
            .map(|file| TestResult {
                package: "data.fake".to_owned(),
                name: format!("test_{}", file.path.replace(['/', '.'], "_")),
                passed: !String::from_utf8_lossy(&file.contents).contains("fail"),
                error: None,
            })
            .collect();
        Ok(report)
    }

    async fn evaluate(
        &self,
        _tenant: TenantId,
        files: &[BundleFile],
        _package: &str,
        inputs: &[Value],
    ) -> Result<Result<Vec<Option<Value>>, Report>, DomainError> {
        self.start()?;
        let refused = Self::refused(files);
        if !refused.passed() {
            return Ok(Err(refused));
        }
        let deny = files
            .iter()
            .any(|file| String::from_utf8_lossy(&file.contents).contains("deny everything"));
        Ok(Ok(inputs
            .iter()
            .map(|input| {
                if deny {
                    Some(serde_json::json!({"allow": false}))
                } else {
                    input.get("answer").cloned()
                }
            })
            .collect()))
    }
}

/// The stores of the lifecycle under test.
pub struct LifecyclePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The bundles a publication names.
    pub bundles: &'a dyn BundleStore,
    /// The versions.
    pub versions: &'a dyn PolicyVersionStore,
    /// The publications.
    pub publications: &'a dyn PublicationStore,
    /// The simulations.
    pub simulations: &'a dyn SimulationStore,
}

impl std::fmt::Debug for LifecyclePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LifecyclePorts").finish_non_exhaustive()
    }
}

fn version(number: u64, state: VersionState) -> PolicyVersion {
    PolicyVersion {
        number,
        author: if number.is_multiple_of(2) {
            Author::Operator
        } else {
            Author::Tenant
        },
        files: vec![
            BundleFile {
                path: "data.json".to_owned(),
                contents: format!("{{\"n\":{number}}}").into_bytes(),
            },
            BundleFile {
                path: "p/policy.rego".to_owned(),
                contents: b"package hodor.tenants.x.p\n\ndecision := {\"allow\": true}\n".to_vec(),
            },
        ],
        digest: [u8::try_from(number % 256).unwrap_or(0); 32],
        state,
        report: None,
        drafted_at: at(i64::try_from(number).unwrap_or(0)),
        changed_at: at(i64::try_from(number).unwrap_or(0)),
    }
}

/// Runs every rule the stores of the lifecycle must obey. Each run uses
/// tenants of its own, so runs can share one database.
///
/// # Panics
///
/// Panics if an implementation breaks a rule.
pub async fn run_lifecycle_contract(ports: LifecyclePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());

    // Versions: created once per number, found whole, listed without
    // files, the highest number known.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .versions
            .latest_number(uow.as_mut())
            .await
            .expect("latest"),
        None
    );
    for number in 1..=3 {
        ports
            .versions
            .create(uow.as_mut(), &version(number, VersionState::Draft))
            .await
            .expect("create");
    }
    uow.commit().await.expect("commit");
    // A failed statement ends its transaction: the attempt has one of its
    // own.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let taken = ports
        .versions
        .create(uow.as_mut(), &version(2, VersionState::Draft))
        .await
        .expect_err("a number is taken once");
    assert_eq!(taken.code(), "authorization.policy_version_taken");
    drop(uow);

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .versions
            .latest_number(uow.as_mut())
            .await
            .expect("latest"),
        Some(3)
    );
    let found = ports
        .versions
        .find(uow.as_mut(), 2)
        .await
        .expect("find")
        .expect("version 2");
    assert_eq!(found, version(2, VersionState::Draft));
    let listed = ports.versions.list(uow.as_mut(), 2).await.expect("list");
    assert_eq!(listed.iter().map(|v| v.number).collect::<Vec<_>>(), [3, 2]);
    assert!(
        listed.iter().all(|v| v.files.is_empty()),
        "listed without files"
    );
    assert_eq!(listed[0].digest, version(3, VersionState::Draft).digest);
    uow.commit().await.expect("commit");

    // A transition happens only from the state it names, once, with its
    // report.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        ports
            .versions
            .transition(
                uow.as_mut(),
                1,
                VersionState::Draft,
                VersionState::Validating,
                None,
                at(10)
            )
            .await
            .expect("transition")
    );
    assert!(
        !ports
            .versions
            .transition(
                uow.as_mut(),
                1,
                VersionState::Draft,
                VersionState::Validating,
                None,
                at(11)
            )
            .await
            .expect("transition"),
        "not from a state it left"
    );
    assert!(
        ports
            .versions
            .transition(
                uow.as_mut(),
                3,
                VersionState::Draft,
                VersionState::Validating,
                None,
                at(5)
            )
            .await
            .expect("transition")
    );
    let waiting = ports
        .versions
        .waiting(uow.as_mut(), 10)
        .await
        .expect("waiting");
    assert_eq!(
        waiting.iter().map(|v| v.number).collect::<Vec<_>>(),
        [3, 1],
        "oldest change first"
    );
    assert!(
        waiting.iter().all(|v| !v.files.is_empty()),
        "with their files"
    );
    let report = Report {
        diagnostics: vec![Diagnostic {
            file: Some("p/policy.rego".to_owned()),
            row: Some(3),
            code: "rego_type_error".to_owned(),
            message: "undefined function http.send".to_owned(),
        }],
        tests: vec![TestResult {
            package: "data.x".to_owned(),
            name: "test_a".to_owned(),
            passed: false,
            error: Some("boom".to_owned()),
        }],
    };
    assert!(
        ports
            .versions
            .transition(
                uow.as_mut(),
                1,
                VersionState::Validating,
                VersionState::Rejected,
                Some(&report),
                at(12)
            )
            .await
            .expect("transition")
    );
    let rejected = ports
        .versions
        .find(uow.as_mut(), 1)
        .await
        .expect("find")
        .expect("version 1");
    assert_eq!(rejected.state, VersionState::Rejected);
    assert_eq!(rejected.report.as_ref(), Some(&report));
    assert_eq!(rejected.changed_at, at(12));
    uow.commit().await.expect("commit");

    // Publications: one per revision, the version found by revision.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    for revision in 1..=2 {
        ports
            .bundles
            .append(uow.as_mut(), &bundle(revision, Author::Tenant))
            .await
            .expect("bundle");
    }
    ports
        .publications
        .record(uow.as_mut(), 1, 3)
        .await
        .expect("record");
    ports
        .publications
        .record(uow.as_mut(), 2, 2)
        .await
        .expect("record");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let taken = ports
        .publications
        .record(uow.as_mut(), 2, 3)
        .await
        .expect_err("a revision is recorded once");
    assert_eq!(taken.code(), "authorization.policy_publication_taken");
    drop(uow);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .publications
            .version_of(uow.as_mut(), 1)
            .await
            .expect("of"),
        Some(3)
    );
    assert_eq!(
        ports
            .publications
            .version_of(uow.as_mut(), 9)
            .await
            .expect("of"),
        None
    );
    assert_eq!(
        ports
            .publications
            .list(uow.as_mut(), 10)
            .await
            .expect("list"),
        [(2, 2), (1, 3)]
    );
    uow.commit().await.expect("commit");

    // Simulations: waiting until finished once, the inputs erased.
    let simulation = Simulation {
        id: SimulationId::generate(),
        version: 3,
        namespace: "https://documents.example.com".to_owned(),
        inputs: vec![serde_json::json!({"action": "read", "subject": {"id": "ana"}})],
        compared_with: None,
        results: Vec::new(),
        report: None,
        state: SimulationState::Waiting,
        asked_at: at(20),
        done_at: None,
    };
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .simulations
        .create(uow.as_mut(), &simulation)
        .await
        .expect("create");
    assert_eq!(
        ports
            .simulations
            .find(uow.as_mut(), simulation.id)
            .await
            .expect("find")
            .as_ref(),
        Some(&simulation)
    );
    assert_eq!(
        ports
            .simulations
            .waiting(uow.as_mut(), 10)
            .await
            .expect("waiting"),
        std::slice::from_ref(&simulation)
    );
    let results = [SimulatedAnswer {
        index: 0,
        candidate: Some(serde_json::json!({"allow": true})),
        published: None,
        differs: true,
    }];
    assert!(
        ports
            .simulations
            .finish(
                uow.as_mut(),
                simulation.id,
                SimulationState::Done,
                Some(2),
                &results,
                None,
                at(21)
            )
            .await
            .expect("finish")
    );
    assert!(
        !ports
            .simulations
            .finish(
                uow.as_mut(),
                simulation.id,
                SimulationState::Failed,
                None,
                &[],
                None,
                at(22)
            )
            .await
            .expect("finish"),
        "finished once"
    );
    let done = ports
        .simulations
        .find(uow.as_mut(), simulation.id)
        .await
        .expect("find")
        .expect("simulation");
    assert_eq!(done.state, SimulationState::Done);
    assert!(done.inputs.is_empty(), "the inputs are erased");
    assert_eq!(done.results, results);
    assert_eq!(done.compared_with, Some(2));
    assert_eq!(done.done_at, Some(at(21)));
    assert!(
        ports
            .simulations
            .waiting(uow.as_mut(), 10)
            .await
            .expect("waiting")
            .is_empty()
    );
    uow.commit().await.expect("commit");

    // Nothing of one tenant is seen from another.
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .versions
            .latest_number(uow.as_mut())
            .await
            .expect("latest"),
        None
    );
    assert_eq!(
        ports.versions.find(uow.as_mut(), 2).await.expect("find"),
        None
    );
    assert!(
        ports
            .versions
            .list(uow.as_mut(), 10)
            .await
            .expect("list")
            .is_empty()
    );
    assert!(
        ports
            .versions
            .waiting(uow.as_mut(), 10)
            .await
            .expect("waiting")
            .is_empty()
    );
    assert!(
        !ports
            .versions
            .transition(
                uow.as_mut(),
                3,
                VersionState::Validating,
                VersionState::Validated,
                None,
                at(30)
            )
            .await
            .expect("transition")
    );
    assert_eq!(
        ports
            .publications
            .version_of(uow.as_mut(), 1)
            .await
            .expect("of"),
        None
    );
    assert!(
        ports
            .publications
            .list(uow.as_mut(), 10)
            .await
            .expect("list")
            .is_empty()
    );
    assert_eq!(
        ports
            .simulations
            .find(uow.as_mut(), simulation.id)
            .await
            .expect("find"),
        None
    );
    uow.commit().await.expect("commit");
}
