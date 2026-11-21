//! What the authorization context needs from storage.

use crate::domain::role::Role;
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};

/// Stores which user holds which role. Every method works inside the
/// tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait RoleAssignmentStore: Send + Sync {
    /// Gives a user a role. Returns whether anything changed: `false` if
    /// the user already held it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn assign(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        role: Role,
        now: Timestamp,
    ) -> Result<bool, DomainError>;

    /// Takes a role away. Returns whether anything changed: `false` if
    /// the user did not hold it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn revoke(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        role: Role,
    ) -> Result<bool, DomainError>;

    /// The roles a user holds in the tenant, in a fixed order.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn roles_of(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Vec<Role>, DomainError>;
}
