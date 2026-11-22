//! What the tenant context needs from storage.

use crate::domain::slug::Slug;
use crate::domain::tenant::{Tenant, TenantStatus};
use hodor_kernel::{DomainError, TenantId, UnitOfWork};

/// Stores and loads the tenant aggregate. Every method works inside the
/// tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait TenantRepository: Send + Sync {
    /// Stores a new tenant.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error with code `tenant.slug_taken` if another
    /// tenant already has the slug.
    async fn insert(&self, uow: &mut dyn UnitOfWork, tenant: &Tenant) -> Result<(), DomainError>;

    /// Loads the tenant the unit of work is bound to, if it exists.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or holds data that cannot be read.
    async fn get(&self, uow: &mut dyn UnitOfWork) -> Result<Option<Tenant>, DomainError>;

    /// Stores changes to a tenant loaded earlier.
    ///
    /// The tenant's version must be the one that was loaded. On success the
    /// stored version is one higher.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error with code `tenant.modified_concurrently`
    /// if the stored version differs, and `NotFound` if the tenant does not
    /// exist.
    async fn update(&self, uow: &mut dyn UnitOfWork, tenant: &Tenant) -> Result<(), DomainError>;
}

/// What the directory knows about a tenant: enough to route a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// The tenant's slug.
    pub slug: Slug,
    /// The tenant's identifier.
    pub tenant_id: TenantId,
    /// The tenant's status.
    pub status: TenantStatus,
}

/// Finds tenants across the installation. This is the one port of the
/// context that is not bound to a tenant, because it is how a tenant is
/// found in the first place.
#[async_trait::async_trait]
pub trait TenantDirectory: Send + Sync {
    /// Returns the entry for a slug, if a tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup fails.
    async fn find_by_slug(&self, slug: &str) -> Result<Option<DirectoryEntry>, DomainError>;

    /// Returns every tenant, ordered by slug.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup fails.
    async fn list(&self) -> Result<Vec<DirectoryEntry>, DomainError>;
}
