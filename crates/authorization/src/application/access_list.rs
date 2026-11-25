//! The use cases of access control lists: granting an entry, removing it,
//! reading and listing entries.
//!
//! See `docs/architecture/contexts/authorization.md`, "Operations of
//! access control lists".

use crate::application::ports::{AccessListStore, NativeRoleStore};
use crate::domain::access_list::{AccessEntry, AccessEntryFilter, AccessEntryId};
use crate::domain::event::AuthorizationEvent;
use crate::domain::native::PermissionName;
use crate::domain::request::{Namespace, Subject};
use hodor_kernel::{
    Caller, Clock, DomainError, EventEnvelope, EventMetadata, Page, PageRequest, TenantContext,
    UnitOfWork, UnitOfWorkFactory,
};
use std::sync::Arc;

/// What granting answers: the entry, and whether it is new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Granted {
    /// The entry that gives what was asked.
    pub entry: AccessEntry,
    /// `false` when the entry existed already, and nothing changed.
    pub created: bool,
}

/// The use cases of access control lists.
#[derive(Clone)]
pub struct AccessListService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    entries: Arc<dyn AccessListStore>,
    roles: Arc<dyn NativeRoleStore>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for AccessListService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessListService").finish_non_exhaustive()
    }
}

fn entry_event(entry: &AccessEntry, removed: bool) -> AuthorizationEvent {
    let entry_id = entry.id().to_string();
    let namespace = entry.namespace().as_str().to_owned();
    let permission = entry.permission().as_str().to_owned();
    let resource = entry.resource_id().to_owned();
    let principal_kind = entry.principal().kind().as_str();
    let principal = entry.principal().id().to_owned();
    if removed {
        AuthorizationEvent::AccessEntryRemoved {
            entry: entry_id,
            namespace,
            permission,
            resource,
            principal_kind,
            principal,
        }
    } else {
        AuthorizationEvent::AccessEntryGranted {
            entry: entry_id,
            namespace,
            permission,
            resource,
            principal_kind,
            principal,
        }
    }
}

fn record(
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

impl AccessListService {
    /// Wires the use cases to their ports. The permissions an entry may
    /// name are read from the store of native roles.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        entries: Arc<dyn AccessListStore>,
        roles: Arc<dyn NativeRoleStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            entries,
            roles,
            clock,
        }
    }

    /// Lets `principal` do what `permission` says to the resource
    /// `resource_id` of `namespace`. When an entry already does, answers it
    /// without changing or announcing anything.
    ///
    /// # Errors
    ///
    /// - The errors of [`AccessEntry::new`].
    /// - `authorization.permission_not_declared` for a permission the
    ///   resource server does not declare.
    /// - Storage errors.
    pub async fn grant(
        &self,
        tenant: &TenantContext,
        namespace: Namespace,
        permission: PermissionName,
        resource_id: &str,
        principal: Subject,
        caller: Caller,
    ) -> Result<Granted, DomainError> {
        let entry = AccessEntry::new(
            AccessEntryId::generate(),
            namespace,
            permission,
            resource_id,
            principal,
            self.clock.now(),
        )?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        let declared = self
            .roles
            .permissions(uow.as_mut(), entry.namespace())
            .await?
            .iter()
            .any(|declared| declared.name() == entry.permission());
        if !declared {
            return Err(DomainError::invalid(
                "authorization.permission_not_declared",
                "an entry names only a permission declared for its resource server",
            )
            .with_detail(entry.permission().as_str()));
        }
        if let Some(existing) = self.entries.same_as(uow.as_mut(), &entry).await? {
            return Ok(Granted {
                entry: existing,
                created: false,
            });
        }
        if !self.entries.insert(uow.as_mut(), &entry).await? {
            // Granted at the same moment by someone else: theirs stands.
            let existing = self.entries.same_as(uow.as_mut(), &entry).await?;
            return existing
                .map(|entry| Granted {
                    entry,
                    created: false,
                })
                .ok_or_else(|| {
                    DomainError::conflict(
                        "authorization.access_entry_changed",
                        "the entry changed while it was being granted",
                    )
                });
        }
        record(
            uow.as_mut(),
            self.clock.as_ref(),
            caller,
            &entry_event(&entry, false),
        )?;
        uow.commit().await?;
        Ok(Granted {
            entry,
            created: true,
        })
    }

    /// Removes an entry. Returns whether there was one.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub async fn remove(
        &self,
        tenant: &TenantContext,
        id: AccessEntryId,
        caller: Caller,
    ) -> Result<bool, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let Some(removed) = self.entries.remove(uow.as_mut(), id).await? else {
            return Ok(false);
        };
        record(
            uow.as_mut(),
            self.clock.as_ref(),
            caller,
            &entry_event(&removed, true),
        )?;
        uow.commit().await?;
        Ok(true)
    }

    /// One entry, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub async fn entry(
        &self,
        tenant: &TenantContext,
        id: AccessEntryId,
    ) -> Result<Option<AccessEntry>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.entries.get(uow.as_mut(), id).await
    }

    /// One page of the entries of a resource server that pass `filter`,
    /// oldest first.
    ///
    /// # Errors
    ///
    /// `request.query_invalid` for a cursor that was not given out, and
    /// storage errors.
    pub async fn entries(
        &self,
        tenant: &TenantContext,
        filter: &AccessEntryFilter,
        page: &PageRequest,
    ) -> Result<Page<AccessEntry>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.entries.list(uow.as_mut(), filter, page).await
    }
}
