//! What the authorization context needs from storage and from the other
//! contexts.

use crate::domain::binding::EngineBinding;
use crate::domain::request::{Attributes, Namespace, Subject};
use crate::domain::role::Role;
use hodor_kernel::{DomainError, TenantContext, Timestamp, UnitOfWork, UserId};

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

/// Stores a tenant's bindings. Every method works inside the tenant the
/// unit of work is bound to.
#[async_trait::async_trait]
pub trait EngineBindingStore: Send + Sync {
    /// Stores a binding, replacing the one of the same namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn put(
        &self,
        uow: &mut dyn UnitOfWork,
        binding: &EngineBinding,
    ) -> Result<(), DomainError>;

    /// The binding of a namespace, if there is one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or what is stored is not a valid
    /// binding.
    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
    ) -> Result<Option<EngineBinding>, DomainError>;

    /// Every binding of the tenant, ordered by namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or what is stored is not a valid
    /// binding.
    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<EngineBinding>, DomainError>;

    /// Removes the binding of a namespace. Returns whether there was one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
    ) -> Result<bool, DomainError>;
}

/// Resolves what Hodor knows about a subject: a user of the identity
/// context or a client of the OAuth context.
#[async_trait::async_trait]
pub trait SubjectAttributeSource: Send + Sync {
    /// The attributes of `subject` in `tenant`. A subject Hodor does not
    /// know has none: it is not told apart from one that has none.
    ///
    /// # Errors
    ///
    /// Returns an error if they cannot be resolved.
    async fn attributes_of(
        &self,
        tenant: &TenantContext,
        subject: &Subject,
    ) -> Result<Attributes, DomainError>;
}
