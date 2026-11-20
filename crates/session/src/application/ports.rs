//! What the session context needs from storage.

use crate::domain::session::{Session, SessionId, TokenHash};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};

/// Stores and loads sessions. Every method works inside the tenant the
/// unit of work is bound to.
#[async_trait::async_trait]
pub trait SessionStore: Send + Sync {
    /// Stores a new session.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert(&self, uow: &mut dyn UnitOfWork, session: &Session) -> Result<(), DomainError>;

    /// Loads a session of the tenant by identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: SessionId,
    ) -> Result<Option<Session>, DomainError>;

    /// Loads the session of the tenant whose token has the given hash.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find_by_token_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &TokenHash,
    ) -> Result<Option<Session>, DomainError>;

    /// Stores what can change in a session: its token hash, its last
    /// activity and its revocation.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such session.
    async fn update(&self, uow: &mut dyn UnitOfWork, session: &Session) -> Result<(), DomainError>;

    /// Returns a user's sessions that are not revoked and whose absolute
    /// expiry is after `now`, newest first. The caller filters out those
    /// that are idle for too long.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list_for_user(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        now: Timestamp,
    ) -> Result<Vec<Session>, DomainError>;
}
