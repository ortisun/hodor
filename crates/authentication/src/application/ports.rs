//! What the authentication context needs from storage.

use crate::domain::attempt::{AttemptCounter, AttemptSubject};
use crate::domain::transaction::{AuthTransaction, TransactionId};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork};

/// Keeps the attempt counters of a tenant. Every method works inside the
/// tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait AttemptStore: Send + Sync {
    /// Loads the counter of a subject, creating an empty one if there is
    /// none, and keeps it to itself until the unit of work ends.
    ///
    /// Two units of work asking for the same subject are served one after
    /// the other. That is what makes the limit exact when many attempts
    /// arrive at once.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        subject: &AttemptSubject,
        now: Timestamp,
    ) -> Result<AttemptCounter, DomainError>;

    /// Stores a counter obtained from [`AttemptStore::lock`] in the same
    /// unit of work.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn save(
        &self,
        uow: &mut dyn UnitOfWork,
        counter: &AttemptCounter,
    ) -> Result<(), DomainError>;

    /// Forgets everything counted against a subject.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn clear(
        &self,
        uow: &mut dyn UnitOfWork,
        subject: &AttemptSubject,
    ) -> Result<(), DomainError>;
}

/// Stores sign-ins in progress. Every method works inside the tenant the
/// unit of work is bound to.
#[async_trait::async_trait]
pub trait TransactionStore: Send + Sync {
    /// Stores a new transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: &AuthTransaction,
    ) -> Result<(), DomainError>;

    /// Loads a transaction of the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TransactionId,
    ) -> Result<Option<AuthTransaction>, DomainError>;

    /// Stores changes to a transaction loaded earlier.
    ///
    /// The transaction's version must be the one that was loaded. This is
    /// what makes completion happen once: of two requests that try to
    /// complete the same transaction, the second finds a newer version.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` with code
    /// `authentication.transaction_modified_concurrently` if the stored
    /// version differs, and `NotFound` if the tenant has no such
    /// transaction.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: &AuthTransaction,
    ) -> Result<(), DomainError>;
}
