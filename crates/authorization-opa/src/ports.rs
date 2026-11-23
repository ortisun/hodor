//! What the bundles need from storage.

use crate::bundle::{BundleFile, PublishedBundle};
use crate::instance::{Instance, InstanceId, InstanceName};
use crate::policy::{
    PolicyVersion, Report, SimulatedAnswer, Simulation, SimulationId, SimulationState, VersionState,
};
use hodor_kernel::{DomainError, TenantId, Timestamp, UnitOfWork};
use serde_json::Value;

/// The instances of the installation. Not bound to a tenant: a shared
/// instance serves several, and a credential is checked before any tenant
/// is known.
#[async_trait::async_trait]
pub trait InstanceStore: Send + Sync {
    /// Stores a new instance with the digest of its credential.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_agent_instance_exists` for a name
    /// already taken, or an error if storage fails.
    async fn add(&self, instance: &Instance, credential: [u8; 32]) -> Result<(), DomainError>;

    /// The instance a credential's digest belongs to, disabled or not.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find_by_credential(
        &self,
        credential: [u8; 32],
    ) -> Result<Option<Instance>, DomainError>;

    /// The instance of a name.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find_by_name(&self, name: &InstanceName) -> Result<Option<Instance>, DomainError>;

    /// Every instance, by name.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(&self) -> Result<Vec<Instance>, DomainError>;

    /// Disables the instance of a name, if it is enabled. Returns whether
    /// it was.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn disable(&self, name: &InstanceName, at: Timestamp) -> Result<bool, DomainError>;
}

/// A tenant's published bundles. Bound to the tenant of the unit of work.
#[async_trait::async_trait]
pub trait BundleStore: Send + Sync {
    /// Stores a new revision. Bundles are never changed or removed.
    ///
    /// # Errors
    ///
    /// Returns `authorization.bundle_revision_taken` if the revision
    /// exists, or an error if storage fails.
    async fn append(
        &self,
        uow: &mut dyn UnitOfWork,
        bundle: &PublishedBundle,
    ) -> Result<(), DomainError>;

    /// The latest revision, if the tenant has one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn latest(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<PublishedBundle>, DomainError>;

    /// The latest revision and when it was published, without its
    /// archive. The engine asks it on every decision it checks for lag.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn latest_revision(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<(u64, Timestamp)>, DomainError> {
        Ok(self
            .latest(uow)
            .await?
            .map(|bundle| (bundle.revision, bundle.published_at)))
    }
}

/// The last status an instance reported for a tenant's bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceStatus {
    /// Who reported it.
    pub instance: InstanceId,
    /// The revision it runs, if it activated one.
    pub active_revision: Option<String>,
    /// When it last activated a revision.
    pub last_activation: Option<Timestamp>,
    /// Its last error, if it has one.
    pub error: Option<String>,
    /// When it reported.
    pub reported_at: Timestamp,
}

/// The status of each instance for a tenant. Bound to the tenant of the
/// unit of work.
#[async_trait::async_trait]
pub trait InstanceStatusStore: Send + Sync {
    /// Keeps `status`, replacing the instance's earlier report.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        status: &InstanceStatus,
    ) -> Result<(), DomainError>;

    /// The last report of every instance, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<InstanceStatus>, DomainError>;
}

/// A decision an instance uploaded, as Hodor keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadedDecision {
    /// Who uploaded it.
    pub instance: InstanceId,
    /// Its identifier, given by the instance.
    pub decision_id: String,
    /// The path that was asked.
    pub path: String,
    /// The revision of the tenant's bundle it was made with.
    pub revision: Option<String>,
    /// Whether it allowed, when the result says so.
    pub allowed: Option<bool>,
    /// When it was made, if the instance says.
    pub decided_at: Option<Timestamp>,
    /// When Hodor received it.
    pub received_at: Timestamp,
}

/// The decisions instances uploaded for a tenant. Bound to the tenant of
/// the unit of work.
#[async_trait::async_trait]
pub trait UploadedDecisionStore: Send + Sync {
    /// Keeps `decisions`. One already kept, by instance and identifier, is
    /// kept once. Returns how many were new.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        decisions: &[UploadedDecision],
    ) -> Result<u64, DomainError>;

    /// The latest `limit` decisions, newest received first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn latest(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<UploadedDecision>, DomainError>;
}

/// A tenant's policy versions. Bound to the tenant of the unit of work.
#[async_trait::async_trait]
pub trait PolicyVersionStore: Send + Sync {
    /// Stores a new version.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_version_taken` if its number exists,
    /// or an error if storage fails.
    async fn create(
        &self,
        uow: &mut dyn UnitOfWork,
        version: &PolicyVersion,
    ) -> Result<(), DomainError>;

    /// The version of a number.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        number: u64,
    ) -> Result<Option<PolicyVersion>, DomainError>;

    /// The highest number taken, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn latest_number(&self, uow: &mut dyn UnitOfWork) -> Result<Option<u64>, DomainError>;

    /// The latest `limit` versions, newest first, without their files.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<PolicyVersion>, DomainError>;

    /// The versions waiting for the worker, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn waiting(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<PolicyVersion>, DomainError>;

    /// Moves a version from `from` to `to` with `report`, at `at`, if it is
    /// still in `from`. Returns whether it was.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn transition(
        &self,
        uow: &mut dyn UnitOfWork,
        number: u64,
        from: VersionState,
        to: VersionState,
        report: Option<&Report>,
        at: Timestamp,
    ) -> Result<bool, DomainError>;
}

/// Which version each revision was built from. Bound to the tenant of the
/// unit of work.
#[async_trait::async_trait]
pub trait PublicationStore: Send + Sync {
    /// Records that `revision` was built from version `version`.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_publication_taken` if the revision is
    /// recorded, or an error if storage fails.
    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        revision: u64,
        version: u64,
    ) -> Result<(), DomainError>;

    /// The version `revision` was built from, if it was built from one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn version_of(
        &self,
        uow: &mut dyn UnitOfWork,
        revision: u64,
    ) -> Result<Option<u64>, DomainError>;

    /// The latest `limit` publications as (revision, version), newest
    /// first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<(u64, u64)>, DomainError>;
}

/// A tenant's simulations. Bound to the tenant of the unit of work.
#[async_trait::async_trait]
pub trait SimulationStore: Send + Sync {
    /// Stores a new simulation, waiting.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn create(
        &self,
        uow: &mut dyn UnitOfWork,
        simulation: &Simulation,
    ) -> Result<(), DomainError>;

    /// The simulation of an identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        id: SimulationId,
    ) -> Result<Option<Simulation>, DomainError>;

    /// The simulations waiting, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn waiting(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<Simulation>, DomainError>;

    /// Ends a waiting simulation in `state`: keeps the results or the
    /// report, and erases its inputs. Returns whether it was waiting.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    #[allow(clippy::too_many_arguments)]
    async fn finish(
        &self,
        uow: &mut dyn UnitOfWork,
        id: SimulationId,
        state: SimulationState,
        compared_with: Option<u64>,
        results: &[SimulatedAnswer],
        report: Option<&Report>,
        at: Timestamp,
    ) -> Result<bool, DomainError>;
}

/// Runs the `opa` binary on a version's files. Specified in Decision 0026.
///
/// Every method answers `Ok` with what the policy did, even when it did
/// not compile or a run took too long: that is a fault of the policy, in
/// the report. `Err` is only for a run that could not start, which is
/// tried again later.
#[async_trait::async_trait]
pub trait PolicyChecker: Send + Sync {
    /// Compiles `files`, placed under `tenant`'s tree, in strict mode
    /// against the capabilities file.
    ///
    /// # Errors
    ///
    /// Returns an error if the check could not run.
    async fn check(&self, tenant: TenantId, files: &[BundleFile]) -> Result<Report, DomainError>;

    /// Runs the tests among `files`.
    ///
    /// # Errors
    ///
    /// Returns an error if the tests could not run.
    async fn test(&self, tenant: TenantId, files: &[BundleFile]) -> Result<Report, DomainError>;

    /// Evaluates the rule `decision` of `package` for each of `inputs`.
    /// Returns, input by input, the answer or `None` where it is not
    /// defined; or the report of why the files did not compile.
    ///
    /// # Errors
    ///
    /// Returns an error if the evaluation could not run.
    async fn evaluate(
        &self,
        tenant: TenantId,
        files: &[BundleFile],
        package: &str,
        inputs: &[Value],
    ) -> Result<Result<Vec<Option<Value>>, Report>, DomainError>;
}
