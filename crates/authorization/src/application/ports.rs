//! What the authorization context needs from storage and from the other
//! contexts.

use crate::domain::binding::EngineBinding;
use crate::domain::condition::{Condition, ConditionInput};
use crate::domain::native::{
    AssignmentScope, PermissionDefinition, PermissionName, RoleAssignment, RoleDefinition, RoleKey,
};
use crate::domain::request::{Attributes, Namespace, Subject};
use crate::domain::role::Role;
use hodor_kernel::{DomainError, TenantContext, Timestamp, UnitOfWork, UserId};
use std::sync::Arc;
use std::time::Duration;

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

/// Stores a tenant's permissions, roles and assignments of native
/// role-based access control, and its role revision. Every method works
/// inside the tenant the unit of work is bound to. The built-in roles of
/// `hodor:admin` are not stored here: their assignments go through
/// [`RoleAssignmentStore`].
#[async_trait::async_trait]
pub trait NativeRoleStore: Send + Sync {
    /// Raises the tenant's role revision and returns the new one. Called
    /// first in every transaction that changes roles, so that it also
    /// keeps two such transactions of one tenant from running at once.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn raise_revision(&self, uow: &mut dyn UnitOfWork) -> Result<u64, DomainError>;

    /// The tenant's role revision: zero before anything was changed.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn revision(&self, uow: &mut dyn UnitOfWork) -> Result<u64, DomainError>;

    /// Stores a permission, replacing its description if it exists.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn put_permission(
        &self,
        uow: &mut dyn UnitOfWork,
        permission: &PermissionDefinition,
    ) -> Result<(), DomainError>;

    /// Removes a permission, and removes it from every role. Returns
    /// whether there was one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn remove_permission(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
        permission: &PermissionName,
    ) -> Result<bool, DomainError>;

    /// The permissions of a resource server, ordered by name.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn permissions(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
    ) -> Result<Vec<PermissionDefinition>, DomainError>;

    /// Stores a role with what it holds and includes, replacing the role of
    /// the same key.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails, or a permission or an included
    /// role it names does not exist.
    async fn put_role(
        &self,
        uow: &mut dyn UnitOfWork,
        role: &RoleDefinition,
    ) -> Result<(), DomainError>;

    /// Every role of the tenant, ordered by namespace and name.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or what is stored is not a valid
    /// role.
    async fn roles(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<RoleDefinition>, DomainError>;

    /// Removes a role and its assignments. Returns whether there was one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails, or another role includes it.
    async fn remove_role(
        &self,
        uow: &mut dyn UnitOfWork,
        key: &RoleKey,
    ) -> Result<bool, DomainError>;

    /// Stores an assignment, replacing the one of the same principal, role
    /// and scope.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails, or the role does not exist.
    async fn put_assignment(
        &self,
        uow: &mut dyn UnitOfWork,
        assignment: &RoleAssignment,
    ) -> Result<(), DomainError>;

    /// Removes the assignment of a role to a principal with a scope.
    /// Returns whether there was one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn remove_assignment(
        &self,
        uow: &mut dyn UnitOfWork,
        principal: &Subject,
        role: &RoleKey,
        scope: &AssignmentScope,
    ) -> Result<bool, DomainError>;

    /// A principal's assignments of roles the tenant defined, ordered by
    /// role and scope. Assignments of the built-in roles are not among
    /// them.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or what is stored is not valid.
    async fn assignments_of(
        &self,
        uow: &mut dyn UnitOfWork,
        principal: &Subject,
    ) -> Result<Vec<RoleAssignment>, DomainError>;
}

/// Checks and compiles conditions. The native engine and `RoleService`
/// know conditions only through this port; `hodor-authorization-native`
/// implements it over Common Expression Language (Decision 0025).
pub trait ConditionLanguage: Send + Sync {
    /// Checks a condition and compiles it.
    ///
    /// # Errors
    ///
    /// - `authorization.condition_invalid` if it does not parse, names a
    ///   variable other than `subject`, `resource`, `action` and `context`,
    ///   or uses what conditions do not offer.
    /// - `authorization.condition_too_costly` if it is too large or nests
    ///   comprehensions too deep.
    fn compile(&self, condition: &Condition) -> Result<Arc<dyn CompiledCondition>, DomainError>;
}

/// A condition ready to run any number of times.
pub trait CompiledCondition: Send + Sync {
    /// Runs the condition against `input`, giving up at `time_limit`.
    /// Gives whether it holds.
    ///
    /// # Errors
    ///
    /// `authorization.condition_failed` if it gives something other than a
    /// boolean, reads what the input does not carry, goes past its bounds
    /// or fails in any other way.
    fn holds(&self, input: &ConditionInput, time_limit: Duration) -> Result<bool, DomainError>;
}
