//! What the identity context needs from storage.

use crate::domain::group::{Group, GroupMember};
use crate::domain::identifier::NormalizedIdentifier;
use crate::domain::user::User;
use hodor_kernel::{DomainError, GroupId, Timestamp, UnitOfWork, UserId};

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

/// Stores and loads groups and their members. Every method works inside
/// the tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait GroupRepository: Send + Sync {
    /// Stores a new group.
    ///
    /// # Errors
    ///
    /// `Conflict` with code `identity.group_name_taken` if another group
    /// of the tenant has the same name without regard to case.
    async fn insert(&self, uow: &mut dyn UnitOfWork, group: &Group) -> Result<(), DomainError>;

    /// Loads a group of the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: GroupId,
    ) -> Result<Option<Group>, DomainError>;

    /// Returns up to `limit` groups in the order they were created,
    /// starting after the given group.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<GroupId>,
        limit: u32,
    ) -> Result<Vec<Group>, DomainError>;

    /// Stores a change of name or description of a group loaded earlier.
    /// The version must be the one that was loaded; the stored one is one
    /// higher.
    ///
    /// # Errors
    ///
    /// `Conflict` with code `identity.group_modified_concurrently` if the
    /// stored version differs, `identity.group_name_taken` if the name is
    /// another group's, and `NotFound` if the group does not exist.
    async fn update(&self, uow: &mut dyn UnitOfWork, group: &Group) -> Result<(), DomainError>;

    /// Deletes a group with every membership it is part of, and says how
    /// many direct members it had; `None` if it did not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn delete(
        &self,
        uow: &mut dyn UnitOfWork,
        id: GroupId,
    ) -> Result<Option<u64>, DomainError>;

    /// Adds a member to a group, and says whether it was not one already.
    /// The group and the member exist in the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn add_member(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
        member: GroupMember,
        now: Timestamp,
    ) -> Result<bool, DomainError>;

    /// Takes a member out of a group, and says whether it was one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn remove_member(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
        member: GroupMember,
    ) -> Result<bool, DomainError>;

    /// Returns up to `limit` direct members of a group, users before
    /// groups, each in the order of their identifiers, starting after the
    /// given member.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn members(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
        after: Option<GroupMember>,
        limit: u32,
    ) -> Result<Vec<GroupMember>, DomainError>;

    /// Waits for, and takes until the unit of work ends, the tenant's one
    /// lock on nesting, so that changes to it happen one after the other.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn lock_nesting(&self, uow: &mut dyn UnitOfWork) -> Result<(), DomainError>;

    /// Every link from a group to a group inside it, container first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn nesting(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Vec<(GroupId, GroupId)>, DomainError>;

    /// The groups a user is directly in.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn groups_of(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
    ) -> Result<Vec<GroupId>, DomainError>;
}

/// The tenant's bound on the depth of groups.
#[async_trait::async_trait]
pub trait GroupPolicy: Send + Sync {
    /// The deepest a group of the tenant may be, read in the unit of work
    /// of the change.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn max_depth(&self, uow: &mut dyn UnitOfWork) -> Result<u8, DomainError>;
}
