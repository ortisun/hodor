//! The use cases of service accounts and agents.
//!
//! Specified in `docs/architecture/contexts/identity.md`, "Service
//! accounts and agents". A workload is a user of its kind, changed through
//! the use cases of users, with its owners beside it.

use crate::application::groups::record;
use crate::application::ports::{WorkloadAccess, WorkloadRepository};
use crate::application::service::{CreateUser, IdentityService};
use crate::domain::user::{User, UserKind, UserStatus};
use crate::domain::workload::{Workload, WorkloadEvent, checked_owners, workload_profile};
use hodor_kernel::{
    Caller, Clock, Cursor, DomainError, ErrorKind, Page, PageRequest, TenantContext, UnitOfWork,
    UnitOfWorkFactory, UserId,
};
use std::sync::Arc;

/// The reason a disabled workload's tokens are revoked with.
pub const WORKLOAD_DISABLED: &str = "workload_disabled";

/// The reason a deleted workload's tokens are revoked with.
pub const WORKLOAD_DELETED: &str = "workload_deleted";

/// What is needed to create a service account or an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorkload {
    /// `ServiceAccount` or `Agent`.
    pub kind: UserKind,
    /// Its name, 1 to 200 characters.
    pub name: String,
    /// The people responsible for it, 1 to 10.
    pub owners: Vec<UserId>,
}

/// A change to a workload: what is left out stays as it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeWorkload {
    /// A new name.
    pub name: Option<String>,
    /// The new owners, replacing every one it has.
    pub owners: Option<Vec<UserId>>,
}

/// The use cases of service accounts and agents.
#[derive(Clone)]
pub struct WorkloadService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    identity: IdentityService,
    workloads: Arc<dyn WorkloadRepository>,
    access: Arc<dyn WorkloadAccess>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for WorkloadService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadService").finish_non_exhaustive()
    }
}

fn workload_not_found() -> DomainError {
    DomainError::not_found(
        "identity.workload_not_found",
        "the service account or agent does not exist",
    )
}

fn kind_refused() -> DomainError {
    DomainError::invalid(
        "identity.workload_kind_invalid",
        "a workload is a service account or an agent",
    )
}

impl WorkloadService {
    /// Wires the use cases to their ports. `identity` is the use cases of
    /// users, wired with the groups and organizations a deleted workload
    /// leaves.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        identity: IdentityService,
        workloads: Arc<dyn WorkloadRepository>,
        access: Arc<dyn WorkloadAccess>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            identity,
            workloads,
            access,
            clock,
        }
    }

    /// Creates a service account or an agent, active, with its owners.
    ///
    /// # Errors
    ///
    /// `Invalid` for a kind that is not a workload's, a name that breaks
    /// its rule, no owner or too many, or an owner that is not a person;
    /// `NotFound` with code `identity.user_not_found` for an owner that is
    /// not a user of the tenant or is Deleted.
    pub async fn create(
        &self,
        tenant: &TenantContext,
        command: CreateWorkload,
        caller: Caller,
    ) -> Result<Workload, DomainError> {
        if !command.kind.is_workload() {
            return Err(kind_refused());
        }
        let profile = workload_profile(&command.name)?;
        let owners = checked_owners(&command.owners)?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.check_owners(uow.as_mut(), &owners).await?;
        let user = self
            .identity
            .create_in(
                uow.as_mut(),
                CreateUser {
                    kind: command.kind,
                    identifiers: Vec::new(),
                    profile,
                    confirmed: true,
                },
                false,
                caller,
            )
            .await?;
        self.workloads
            .replace_owners(uow.as_mut(), user.id(), &owners, self.clock.now())
            .await?;
        let events = WorkloadEvent::of_change(user.id(), command.kind, &[], &owners);
        record(uow.as_mut(), &caller, self.clock.as_ref(), &events)?;
        let workload = self.load(uow.as_mut(), command.kind, user.id()).await?;
        uow.commit().await?;
        Ok(workload)
    }

    /// A workload of `kind` that is not deleted, with its owners.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `identity.workload_not_found` for anything
    /// else.
    pub async fn get(
        &self,
        tenant: &TenantContext,
        kind: UserKind,
        id: UserId,
    ) -> Result<Workload, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), kind, id).await
    }

    /// The workloads of `kind` that are not deleted, in the order they
    /// were created, a page at a time.
    ///
    /// # Errors
    ///
    /// `Invalid` with code `request.cursor_invalid` for a cursor this use
    /// case did not give out.
    pub async fn list(
        &self,
        tenant: &TenantContext,
        kind: UserKind,
        page: &PageRequest,
    ) -> Result<Page<Workload>, DomainError> {
        let after = page
            .cursor()
            .map(|cursor| {
                cursor.as_str().parse::<UserId>().map_err(|_| {
                    DomainError::invalid("request.cursor_invalid", "the cursor is not valid")
                })
            })
            .transpose()?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        // One more than asked for, to know whether there is a next page.
        let mut users = self
            .workloads
            .list(uow.as_mut(), kind, after, page.limit() + 1)
            .await?;
        let more = users.len() > page.limit() as usize;
        users.truncate(page.limit() as usize);
        let next_cursor = more
            .then(|| users.last().map(|user| Cursor::new(user.id().to_string())))
            .flatten();
        let mut items = Vec::with_capacity(users.len());
        for user in users {
            let owners = self.workloads.owners(uow.as_mut(), user.id()).await?;
            if let Some(workload) = Workload::of(user, kind, owners) {
                items.push(workload);
            }
        }
        Ok(Page { items, next_cursor })
    }

    /// Renames a workload, replaces its owners, or both.
    ///
    /// # Errors
    ///
    /// As [`WorkloadService::create`], and `NotFound` with code
    /// `identity.workload_not_found` for a workload of `kind` that does not
    /// exist or is deleted.
    pub async fn change(
        &self,
        tenant: &TenantContext,
        kind: UserKind,
        id: UserId,
        change: ChangeWorkload,
        caller: Caller,
    ) -> Result<Workload, DomainError> {
        let profile = change.name.as_deref().map(workload_profile).transpose()?;
        let owners = change.owners.as_deref().map(checked_owners).transpose()?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        let workload = self.load(uow.as_mut(), kind, id).await?;
        if let Some(profile) = profile
            && profile.display_name.as_deref() != Some(workload.name())
        {
            let now = self.clock.now();
            self.identity
                .change_in(uow.as_mut(), id, caller, |user| {
                    Ok(vec![user.change_profile(profile, now)?])
                })
                .await?;
        }
        if let Some(owners) = owners {
            self.check_owners(uow.as_mut(), &owners).await?;
            let events = WorkloadEvent::of_change(id, kind, workload.owners(), &owners);
            if !events.is_empty() {
                self.workloads
                    .replace_owners(uow.as_mut(), id, &owners, self.clock.now())
                    .await?;
                record(uow.as_mut(), &caller, self.clock.as_ref(), &events)?;
            }
        }
        let workload = self.load(uow.as_mut(), kind, id).await?;
        uow.commit().await?;
        Ok(workload)
    }

    /// Disables a workload: it is deactivated, and every token issued for
    /// it is revoked, in one unit of work. A workload suspended as a user
    /// is deactivated too; a deactivated one is left as it is.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `identity.workload_not_found` for a workload
    /// of `kind` that does not exist or is deleted.
    pub async fn disable(
        &self,
        tenant: &TenantContext,
        kind: UserKind,
        id: UserId,
        caller: Caller,
    ) -> Result<Workload, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let workload = self.load(uow.as_mut(), kind, id).await?;
        if workload.user().status() == UserStatus::Deactivated {
            return Ok(workload);
        }
        self.deactivate(uow.as_mut(), workload.user(), caller)
            .await?;
        self.access
            .revoke_access(uow.as_mut(), id, WORKLOAD_DISABLED, caller)
            .await?;
        let workload = self.load(uow.as_mut(), kind, id).await?;
        uow.commit().await?;
        Ok(workload)
    }

    /// Enables a disabled workload. Tokens revoked when it was disabled
    /// stay revoked; a workload that was suspended as a user has its
    /// tokens revoked now, before it is reactivated, so that none of them
    /// comes back either.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `identity.workload_not_found` for a workload
    /// of `kind` that does not exist or is deleted.
    pub async fn enable(
        &self,
        tenant: &TenantContext,
        kind: UserKind,
        id: UserId,
        caller: Caller,
    ) -> Result<Workload, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let workload = self.load(uow.as_mut(), kind, id).await?;
        let now = self.clock.now();
        match workload.user().status() {
            UserStatus::Active => return Ok(workload),
            UserStatus::Suspended => {
                self.access
                    .revoke_access(uow.as_mut(), id, WORKLOAD_DISABLED, caller)
                    .await?;
                self.identity
                    .change_in(uow.as_mut(), id, caller, |user| {
                        Ok(vec![user.reactivate(now)?])
                    })
                    .await?;
            }
            UserStatus::Pending => {
                self.identity
                    .change_in(uow.as_mut(), id, caller, |user| {
                        Ok(vec![user.activate(now)?])
                    })
                    .await?;
            }
            UserStatus::Deactivated | UserStatus::Deleted => {
                self.identity
                    .change_in(uow.as_mut(), id, caller, |user| {
                        Ok(vec![user.restore(now)?])
                    })
                    .await?;
            }
        }
        let workload = self.load(uow.as_mut(), kind, id).await?;
        uow.commit().await?;
        Ok(workload)
    }

    /// Deletes a workload: it is deactivated if it is not already, then
    /// marked Deleted, which erases its name and takes it out of every
    /// group and organization; its owners are forgotten and every token
    /// issued for it is revoked, all in one unit of work.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `identity.workload_not_found` for a workload
    /// of `kind` that does not exist or is deleted.
    pub async fn delete(
        &self,
        tenant: &TenantContext,
        kind: UserKind,
        id: UserId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let workload = self.load(uow.as_mut(), kind, id).await?;
        if workload.user().status() != UserStatus::Deactivated {
            self.deactivate(uow.as_mut(), workload.user(), caller)
                .await?;
        }
        self.identity
            .mark_deleted_in(uow.as_mut(), id, caller)
            .await?;
        self.workloads.forget_owners(uow.as_mut(), id).await?;
        self.access
            .revoke_access(uow.as_mut(), id, WORKLOAD_DELETED, caller)
            .await?;
        uow.commit().await
    }

    async fn deactivate(
        &self,
        uow: &mut dyn UnitOfWork,
        user: &User,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let now = self.clock.now();
        self.identity
            .change_in(uow, user.id(), caller, |user| {
                Ok(vec![user.deactivate(now)?])
            })
            .await?;
        Ok(())
    }

    /// Every owner must be a person of the tenant who is not Deleted.
    async fn check_owners(
        &self,
        uow: &mut dyn UnitOfWork,
        owners: &[UserId],
    ) -> Result<(), DomainError> {
        for owner in owners {
            let user = self.identity.get_in(uow, *owner).await?;
            if user.status() == UserStatus::Deleted {
                return Err(DomainError::not_found(
                    "identity.user_not_found",
                    "the user does not exist",
                ));
            }
            if user.kind() != UserKind::Human {
                return Err(DomainError::invalid(
                    "identity.workload_owner_invalid",
                    "an owner of a service account or an agent is a person",
                ));
            }
        }
        Ok(())
    }

    async fn load(
        &self,
        uow: &mut dyn UnitOfWork,
        kind: UserKind,
        id: UserId,
    ) -> Result<Workload, DomainError> {
        let user = match self.identity.get_in(uow, id).await {
            Ok(user) => user,
            Err(error) if error.kind() == ErrorKind::NotFound => return Err(workload_not_found()),
            Err(error) => return Err(error),
        };
        if !(user.kind() == kind && kind.is_workload()) || user.status() == UserStatus::Deleted {
            return Err(workload_not_found());
        }
        let owners = self.workloads.owners(uow, id).await?;
        Workload::of(user, kind, owners).ok_or_else(workload_not_found)
    }
}
