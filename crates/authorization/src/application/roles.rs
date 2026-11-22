//! The use cases of native role-based access control: declaring
//! permissions, defining roles and assigning them.
//!
//! See `docs/architecture/contexts/authorization.md`, "Operations of native
//! role-based access control".

use crate::application::ports::NativeRoleStore;
use crate::domain::event::AuthorizationEvent;
use crate::domain::native::{
    AssignmentScope, PermissionDefinition, PermissionName, RoleAssignment, RoleContents,
    RoleDefinition, RoleGraph, RoleKey,
};
use crate::domain::request::{Namespace, Subject};
use hodor_kernel::{
    Caller, Clock, DomainError, EventEnvelope, EventMetadata, TenantContext, Timestamp, UnitOfWork,
    UnitOfWorkFactory,
};
use std::collections::BTreeSet;
use std::sync::Arc;

/// When an assignment starts and ends, both optional.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Validity {
    /// From when it allows.
    pub from: Option<Timestamp>,
    /// Until when it allows.
    pub until: Option<Timestamp>,
}

/// The use cases of native role-based access control.
#[derive(Clone)]
pub struct RoleService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    store: Arc<dyn NativeRoleStore>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for RoleService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleService").finish_non_exhaustive()
    }
}

fn changed(
    uow: &mut dyn UnitOfWork,
    clock: &dyn Clock,
    caller: Caller,
    event: &AuthorizationEvent,
) -> Result<(), DomainError> {
    let metadata = EventMetadata::new(
        uow.tenant().tenant_id(),
        caller.actor,
        caller.correlation_id,
        clock,
    );
    uow.record_event(EventEnvelope::new(metadata, event)?);
    Ok(())
}

fn assignment_event(assignment: &RoleAssignment, revoked: bool) -> AuthorizationEvent {
    let principal_kind = assignment.principal().kind().as_str();
    let principal = assignment.principal().id().to_owned();
    let namespace = assignment.role().namespace.as_str().to_owned();
    let role = assignment.role().name.as_str().to_owned();
    let application = assignment
        .scope()
        .application()
        .map(|application| application.as_str().to_owned());
    if revoked {
        AuthorizationEvent::PrincipalRoleRevoked {
            principal_kind,
            principal,
            namespace,
            role,
            application,
        }
    } else {
        AuthorizationEvent::PrincipalRoleAssigned {
            principal_kind,
            principal,
            namespace,
            role,
            application,
        }
    }
}

impl RoleService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        store: Arc<dyn NativeRoleStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            store,
            clock,
        }
    }

    /// Opens a unit of work that changes roles: it raises the tenant's role
    /// revision first, which also keeps two changes of one tenant from
    /// running at once.
    async fn changing(&self, tenant: &TenantContext) -> Result<Box<dyn UnitOfWork>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.store.raise_revision(uow.as_mut()).await?;
        Ok(uow)
    }

    async fn declared(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
    ) -> Result<BTreeSet<PermissionName>, DomainError> {
        Ok(self
            .store
            .permissions(uow, namespace)
            .await?
            .into_iter()
            .map(|permission| permission.name().clone())
            .collect())
    }

    /// Declares a permission of a resource server, or describes it again.
    /// The same declaration again changes nothing and announces nothing.
    ///
    /// # Errors
    ///
    /// The errors of [`PermissionDefinition::new`], and storage errors.
    pub async fn declare_permission(
        &self,
        tenant: &TenantContext,
        namespace: Namespace,
        name: PermissionName,
        description: &str,
        caller: Caller,
    ) -> Result<PermissionDefinition, DomainError> {
        let permission = PermissionDefinition::new(namespace, name, description)?;
        let mut uow = self.changing(tenant).await?;
        let existing = self
            .store
            .permissions(uow.as_mut(), permission.namespace())
            .await?;
        if existing.contains(&permission) {
            return Ok(permission);
        }
        self.store.put_permission(uow.as_mut(), &permission).await?;
        let event = AuthorizationEvent::PermissionDeclared {
            namespace: permission.namespace().as_str().to_owned(),
            permission: permission.name().as_str().to_owned(),
        };
        changed(uow.as_mut(), self.clock.as_ref(), caller, &event)?;
        uow.commit().await?;
        Ok(permission)
    }

    /// Removes a permission, and removes it from every role. Returns
    /// whether there was one.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub async fn remove_permission(
        &self,
        tenant: &TenantContext,
        namespace: &Namespace,
        name: &PermissionName,
        caller: Caller,
    ) -> Result<bool, DomainError> {
        let mut uow = self.changing(tenant).await?;
        if !self
            .store
            .remove_permission(uow.as_mut(), namespace, name)
            .await?
        {
            return Ok(false);
        }
        let event = AuthorizationEvent::PermissionRemoved {
            namespace: namespace.as_str().to_owned(),
            permission: name.as_str().to_owned(),
        };
        changed(uow.as_mut(), self.clock.as_ref(), caller, &event)?;
        uow.commit().await?;
        Ok(true)
    }

    /// The permissions of a resource server, ordered by name.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub async fn permissions(
        &self,
        tenant: &TenantContext,
        namespace: &Namespace,
    ) -> Result<Vec<PermissionDefinition>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.store.permissions(uow.as_mut(), namespace).await
    }

    /// Creates a role or replaces it. Defining it again with the same
    /// contents changes nothing and announces nothing.
    ///
    /// # Errors
    ///
    /// The errors of [`RoleDefinition::new`] and [`RoleGraph::check`], such
    /// as `authorization.role_cycle`, and storage errors.
    pub async fn define_role(
        &self,
        tenant: &TenantContext,
        key: RoleKey,
        contents: RoleContents,
        caller: Caller,
    ) -> Result<RoleDefinition, DomainError> {
        let now = self.clock.now();
        // Checks the role on its own before anything is read.
        let fresh = RoleDefinition::new(key.clone(), contents.clone(), now)?;
        let mut uow = self.changing(tenant).await?;
        let graph = RoleGraph::new(self.store.roles(uow.as_mut()).await?);
        let role = match graph.get(&key) {
            Some(existing) if existing.contents() == fresh.contents() => {
                return Ok(existing.clone());
            }
            Some(existing) => existing.replaced(contents, now)?,
            None => fresh,
        };
        let declared = self.declared(uow.as_mut(), &key.namespace).await?;
        graph.check(&role, &declared)?;
        self.store.put_role(uow.as_mut(), &role).await?;
        let event = AuthorizationEvent::RoleDefined {
            namespace: key.namespace.as_str().to_owned(),
            name: key.name.as_str().to_owned(),
        };
        changed(uow.as_mut(), self.clock.as_ref(), caller, &event)?;
        uow.commit().await?;
        Ok(role)
    }

    /// Removes a role that no other role includes, with its assignments.
    /// Returns whether there was one.
    ///
    /// # Errors
    ///
    /// `authorization.role_in_use` if another role includes it, and storage
    /// errors.
    pub async fn remove_role(
        &self,
        tenant: &TenantContext,
        key: &RoleKey,
        caller: Caller,
    ) -> Result<bool, DomainError> {
        let mut uow = self.changing(tenant).await?;
        let graph = RoleGraph::new(self.store.roles(uow.as_mut()).await?);
        if graph.get(key).is_none() {
            return Ok(false);
        }
        let including = graph.including(key);
        if let Some(first) = including.first() {
            return Err(DomainError::conflict(
                "authorization.role_in_use",
                "a role that another role includes cannot be removed",
            )
            .with_detail(first.reference()));
        }
        self.store.remove_role(uow.as_mut(), key).await?;
        let event = AuthorizationEvent::RoleRemoved {
            namespace: key.namespace.as_str().to_owned(),
            name: key.name.as_str().to_owned(),
        };
        changed(uow.as_mut(), self.clock.as_ref(), caller, &event)?;
        uow.commit().await?;
        Ok(true)
    }

    /// The tenant's roles, ordered by namespace and name.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub async fn roles(&self, tenant: &TenantContext) -> Result<Vec<RoleDefinition>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.store.roles(uow.as_mut()).await
    }

    /// One role, if it exists.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub async fn role(
        &self,
        tenant: &TenantContext,
        key: &RoleKey,
    ) -> Result<Option<RoleDefinition>, DomainError> {
        Ok(self
            .roles(tenant)
            .await?
            .into_iter()
            .find(|role| role.key() == key))
    }

    /// Gives a role to a principal, for the tenant or one application, with
    /// an optional start and end. Giving it again replaces the start and
    /// end; with nothing changed it changes nothing and announces nothing.
    ///
    /// # Errors
    ///
    /// - The errors of [`RoleAssignment::new`].
    /// - `authorization.role_not_found` if the role does not exist.
    /// - Storage errors.
    pub async fn assign(
        &self,
        tenant: &TenantContext,
        principal: Subject,
        role: RoleKey,
        scope: AssignmentScope,
        validity: Validity,
        caller: Caller,
    ) -> Result<RoleAssignment, DomainError> {
        let assignment = RoleAssignment::new(
            principal,
            role,
            scope,
            validity.from,
            validity.until,
            self.clock.now(),
        )?;
        let mut uow = self.changing(tenant).await?;
        let graph = RoleGraph::new(self.store.roles(uow.as_mut()).await?);
        if graph.get(assignment.role()).is_none() {
            return Err(DomainError::invalid(
                "authorization.role_not_found",
                "only a role that exists can be given",
            )
            .with_detail(assignment.role().reference()));
        }
        let existing = self
            .store
            .assignments_of(uow.as_mut(), assignment.principal())
            .await?
            .into_iter()
            .find(|held| held.same_grant(&assignment));
        if let Some(held) = existing
            && held.valid_from() == assignment.valid_from()
            && held.valid_until() == assignment.valid_until()
        {
            return Ok(held);
        }
        self.store.put_assignment(uow.as_mut(), &assignment).await?;
        changed(
            uow.as_mut(),
            self.clock.as_ref(),
            caller,
            &assignment_event(&assignment, false),
        )?;
        uow.commit().await?;
        Ok(assignment)
    }

    /// Takes a role away from a principal. Returns whether it was held.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub async fn revoke(
        &self,
        tenant: &TenantContext,
        principal: &Subject,
        role: &RoleKey,
        scope: &AssignmentScope,
        caller: Caller,
    ) -> Result<bool, DomainError> {
        let mut uow = self.changing(tenant).await?;
        let held = self
            .store
            .assignments_of(uow.as_mut(), principal)
            .await?
            .into_iter()
            .find(|held| held.role() == role && held.scope() == scope);
        let Some(held) = held else {
            return Ok(false);
        };
        self.store
            .remove_assignment(uow.as_mut(), principal, role, scope)
            .await?;
        changed(
            uow.as_mut(),
            self.clock.as_ref(),
            caller,
            &assignment_event(&held, true),
        )?;
        uow.commit().await?;
        Ok(true)
    }

    /// A principal's assignments of roles the tenant defined.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub async fn assignments_of(
        &self,
        tenant: &TenantContext,
        principal: &Subject,
    ) -> Result<Vec<RoleAssignment>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.store.assignments_of(uow.as_mut(), principal).await
    }
}
