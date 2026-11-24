//! What the provisioning context needs from storage.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "Ports".

use crate::domain::attribute::{GroupAttribute, UserAttribute};
use crate::domain::query::{Found, ListQuery};
use crate::domain::resource::{StoredGroupSupplement, StoredUserSupplement};
use hodor_kernel::{DomainError, GroupId, UnitOfWork, UserId};

/// Stores what this context keeps of users, and finds users with a
/// filter. Every method works inside the tenant the unit of work is bound
/// to.
#[async_trait::async_trait]
pub trait ProvisionedUserRepository: Send + Sync {
    /// What is kept of a user, if anything.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
    ) -> Result<Option<StoredUserSupplement>, DomainError>;

    /// Stores what is kept of a user, in place of what was.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn put(
        &self,
        uow: &mut dyn UnitOfWork,
        stored: &StoredUserSupplement,
    ) -> Result<(), DomainError>;

    /// The users SCIM shows, people not marked Deleted, that match the
    /// query's filter, in its order: how many there are, and the
    /// identifiers of those on its page.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        query: &ListQuery<UserAttribute>,
    ) -> Result<Found<UserId>, DomainError>;
}

/// Stores what this context keeps of groups, and finds groups with a
/// filter. Every method works inside the tenant the unit of work is bound
/// to.
#[async_trait::async_trait]
pub trait ProvisionedGroupRepository: Send + Sync {
    /// What is kept of a group, if anything.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
    ) -> Result<Option<StoredGroupSupplement>, DomainError>;

    /// Stores what is kept of a group, in place of what was.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn put(
        &self,
        uow: &mut dyn UnitOfWork,
        stored: &StoredGroupSupplement,
    ) -> Result<(), DomainError>;

    /// Removes what is kept of a group; nothing when nothing was.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn remove(&self, uow: &mut dyn UnitOfWork, group: GroupId) -> Result<(), DomainError>;

    /// The groups that match the query's filter, in its order: how many
    /// there are, and the identifiers of those on its page.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        query: &ListQuery<GroupAttribute>,
    ) -> Result<Found<GroupId>, DomainError>;
}
