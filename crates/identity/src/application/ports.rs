//! What the identity context needs from storage.

use crate::domain::identifier::NormalizedIdentifier;
use crate::domain::user::User;
use hodor_kernel::{DomainError, UnitOfWork, UserId};

/// Stores and loads users with their login identifiers. Every method works
/// inside the tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait UserRepository: Send + Sync {
    /// Stores a new user.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error with code `identity.identifier_taken` if
    /// another user of the tenant already has one of the login identifiers.
    async fn insert(&self, uow: &mut dyn UnitOfWork, user: &User) -> Result<(), DomainError>;

    /// Loads a user of the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or holds data that cannot be read.
    async fn get(&self, uow: &mut dyn UnitOfWork, id: UserId) -> Result<Option<User>, DomainError>;

    /// Loads the user of the tenant who has the given login identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or holds data that cannot be read.
    async fn find_by_identifier(
        &self,
        uow: &mut dyn UnitOfWork,
        identifier: &NormalizedIdentifier,
    ) -> Result<Option<User>, DomainError>;

    /// Returns up to `limit` users of the tenant in the order they were
    /// created, starting after the given user.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<UserId>,
        limit: u32,
    ) -> Result<Vec<User>, DomainError>;

    /// Stores changes to a user loaded earlier, including changes to the
    /// login identifiers.
    ///
    /// The user's version must be the one that was loaded. On success the
    /// stored version is one higher.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` with code `identity.user_modified_concurrently`
    /// if the stored version differs, `Conflict` with code
    /// `identity.identifier_taken` if a login identifier belongs to another
    /// user, and `NotFound` if the user does not exist in the tenant.
    async fn update(&self, uow: &mut dyn UnitOfWork, user: &User) -> Result<(), DomainError>;
}
