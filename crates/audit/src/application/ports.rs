//! What the audit context needs from storage.

use crate::domain::record::{AuditRecord, ChainHead};
use hodor_kernel::{DomainError, UnitOfWork};

/// Stores a tenant's audit records. Every method works inside the tenant
/// the unit of work is bound to.
#[async_trait::async_trait]
pub trait AuditLog: Send + Sync {
    /// Returns the head of the tenant's chain and keeps it locked until
    /// the unit of work ends, so that nobody else can append meanwhile.
    /// A tenant with no records has the empty head.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn lock_head(&self, uow: &mut dyn UnitOfWork) -> Result<ChainHead, DomainError>;

    /// Appends a record and makes it the head. The record must follow the
    /// head returned by [`Self::lock_head`] in the same unit of work.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if the event was already recorded or the
    /// sequence is taken.
    async fn append(
        &self,
        uow: &mut dyn UnitOfWork,
        record: &AuditRecord,
    ) -> Result<(), DomainError>;

    /// Returns the head of the tenant's chain without locking it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn head(&self, uow: &mut dyn UnitOfWork) -> Result<ChainHead, DomainError>;

    /// Returns up to `limit` records of the tenant whose sequence is
    /// greater than `after`, in order.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: u64,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, DomainError>;
}
