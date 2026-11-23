//! What the bundles need from storage.

use crate::bundle::PublishedBundle;
use crate::instance::{Instance, InstanceId, InstanceName};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork};

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
