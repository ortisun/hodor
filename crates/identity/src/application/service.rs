//! The use cases of the identity context.

use crate::application::groups::leave_every_group;
use crate::application::organizations::leave_every_organization;
use crate::application::ports::{GroupRepository, OrganizationRepository, UserRepository};
use crate::domain::event::UserEvent;
use crate::domain::identifier::{IdentifierId, IdentifierKind, NormalizedIdentifier};
use crate::domain::user::{Profile, User, UserKind};
use hodor_kernel::{
    Caller, Clock, Cursor, DomainError, EventEnvelope, EventMetadata, Page, PageRequest,
    TenantContext, UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;

/// What is needed to create a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUser {
    /// What sort of principal the user is.
    pub kind: UserKind,
    /// The login identifiers, as typed.
    pub identifiers: Vec<(IdentifierKind, String)>,
    /// Display name and locale.
    pub profile: Profile,
    /// Whether the user is already confirmed and starts active.
    pub confirmed: bool,
}

/// The use cases of the identity context.
#[derive(Clone)]
pub struct IdentityService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    users: Arc<dyn UserRepository>,
    clock: Arc<dyn Clock>,
    groups: Option<Arc<dyn GroupRepository>>,
    organizations: Option<Arc<dyn OrganizationRepository>>,
}

impl std::fmt::Debug for IdentityService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityService").finish_non_exhaustive()
    }
}

impl IdentityService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        users: Arc<dyn UserRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            users,
            clock,
            groups: None,
            organizations: None,
        }
    }

    /// Ends every membership of a user of organizations when the user is
    /// marked Deleted.
    #[must_use]
    pub fn with_organizations(mut self, organizations: Arc<dyn OrganizationRepository>) -> Self {
        self.organizations = Some(organizations);
        self
    }

    /// Takes a user out of every group when the user is marked Deleted.
    #[must_use]
    pub fn with_groups(mut self, groups: Arc<dyn GroupRepository>) -> Self {
        self.groups = Some(groups);
        self
    }

    /// Creates a user with its login identifiers.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if an identifier or the profile breaks a rule, and
    /// `Conflict` with code `identity.identifier_taken` if another user of
    /// the tenant has one of the identifiers.
    pub async fn create(
        &self,
        tenant: &TenantContext,
        command: CreateUser,
        caller: Caller,
    ) -> Result<User, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let user = self.create_in(uow.as_mut(), command, false, caller).await?;
        uow.commit().await?;
        Ok(user)
    }

    /// Creates a user inside the caller's unit of work, so that the user
    /// is stored together with whatever else the caller is doing, or not
    /// at all. With `verified`, every identifier that can be verified
    /// starts verified: for a caller that has proof the person controls
    /// them.
    ///
    /// # Errors
    ///
    /// As [`IdentityService::create`]. After an error the unit of work
    /// must be abandoned.
    pub async fn create_in(
        &self,
        uow: &mut dyn UnitOfWork,
        command: CreateUser,
        verified: bool,
        caller: Caller,
    ) -> Result<User, DomainError> {
        let identifiers = command
            .identifiers
            .iter()
            .map(|(kind, value)| NormalizedIdentifier::parse(*kind, value))
            .collect::<Result<Vec<_>, _>>()?;
        let now = self.clock.now();
        let (mut user, mut events) = User::create(
            command.kind,
            identifiers,
            command.profile,
            command.confirmed,
            now,
        )?;
        if verified {
            let verifiable: Vec<_> = user
                .snapshot()
                .identifiers
                .iter()
                .filter(|identifier| identifier.value.kind().needs_verification())
                .map(|identifier| identifier.id)
                .collect();
            for id in verifiable {
                events.extend(user.verify_identifier(id, now)?);
            }
        }
        self.users.insert(uow, &user).await?;
        self.record(uow, caller, &events)?;
        Ok(user)
    }

    /// Returns a user of the tenant.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such user.
    pub async fn get(&self, tenant: &TenantContext, id: UserId) -> Result<User, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), id).await
    }

    /// Returns the tenant's users in the order they were created, a page
    /// at a time.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` with code `request.cursor_invalid` if the cursor
    /// is not one this use case gave out.
    pub async fn list(
        &self,
        tenant: &TenantContext,
        page: &PageRequest,
    ) -> Result<Page<User>, DomainError> {
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
        let mut items = self
            .users
            .list(uow.as_mut(), after, page.limit() + 1)
            .await?;
        let more = items.len() > page.limit() as usize;
        items.truncate(page.limit() as usize);
        let next_cursor = more
            .then(|| items.last().map(|user| Cursor::new(user.id().to_string())))
            .flatten();
        Ok(Page { items, next_cursor })
    }

    /// Returns the user that a typed login identifier belongs to.
    ///
    /// A value that is not a well-formed identifier matches nobody.
    ///
    /// # Errors
    ///
    /// Returns an error only if storage fails.
    pub async fn find_by_login(
        &self,
        tenant: &TenantContext,
        typed: &str,
    ) -> Result<Option<User>, DomainError> {
        let Some(identifier) = NormalizedIdentifier::from_login(typed) else {
            return Ok(None);
        };
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.users
            .find_by_identifier(uow.as_mut(), &identifier)
            .await
    }

    /// Confirms a pending user.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` unless the user is pending.
    pub async fn activate(
        &self,
        tenant: &TenantContext,
        id: UserId,
        caller: Caller,
    ) -> Result<User, DomainError> {
        let now = self.clock.now();
        self.change(tenant, id, caller, |user| Ok(vec![user.activate(now)?]))
            .await
    }

    /// Blocks a user, recording why.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` unless the user is active, and `Invalid` if the
    /// reason is empty.
    pub async fn suspend(
        &self,
        tenant: &TenantContext,
        id: UserId,
        reason: &str,
        caller: Caller,
    ) -> Result<User, DomainError> {
        let now = self.clock.now();
        self.change(tenant, id, caller, |user| {
            Ok(vec![user.suspend(reason, now)?])
        })
        .await
    }

    /// Unblocks a suspended user.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` unless the user is suspended.
    pub async fn reactivate(
        &self,
        tenant: &TenantContext,
        id: UserId,
        caller: Caller,
    ) -> Result<User, DomainError> {
        let now = self.clock.now();
        self.change(tenant, id, caller, |user| Ok(vec![user.reactivate(now)?]))
            .await
    }

    /// Closes a user's account.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if the account is already closed or erased.
    pub async fn deactivate(
        &self,
        tenant: &TenantContext,
        id: UserId,
        caller: Caller,
    ) -> Result<User, DomainError> {
        let now = self.clock.now();
        self.change(tenant, id, caller, |user| Ok(vec![user.deactivate(now)?]))
            .await
    }

    /// Reopens a closed account.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` unless the user is deactivated.
    pub async fn restore(
        &self,
        tenant: &TenantContext,
        id: UserId,
        caller: Caller,
    ) -> Result<User, DomainError> {
        let now = self.clock.now();
        self.change(tenant, id, caller, |user| Ok(vec![user.restore(now)?]))
            .await
    }

    /// Erases a deactivated user.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` unless the user is deactivated.
    pub async fn mark_deleted(
        &self,
        tenant: &TenantContext,
        id: UserId,
        caller: Caller,
    ) -> Result<User, DomainError> {
        let now = self.clock.now();
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut user = self.load(uow.as_mut(), id).await?;
        let event = user.mark_deleted(now)?;
        self.users.update(uow.as_mut(), &user).await?;
        self.record(uow.as_mut(), caller, &[event])?;
        if let Some(groups) = &self.groups {
            leave_every_group(
                groups.as_ref(),
                uow.as_mut(),
                id,
                &caller,
                self.clock.as_ref(),
            )
            .await?;
        }
        if let Some(organizations) = &self.organizations {
            leave_every_organization(
                organizations.as_ref(),
                uow.as_mut(),
                id,
                &caller,
                self.clock.as_ref(),
            )
            .await?;
        }
        uow.commit().await?;
        Ok(user)
    }

    /// Adds a login identifier to a user.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the value breaks a rule, and `Conflict` if the
    /// user or another user of the tenant already has it.
    pub async fn add_identifier(
        &self,
        tenant: &TenantContext,
        id: UserId,
        kind: IdentifierKind,
        value: &str,
        caller: Caller,
    ) -> Result<User, DomainError> {
        let identifier = NormalizedIdentifier::parse(kind, value)?;
        let now = self.clock.now();
        self.change(tenant, id, caller, |user| {
            Ok(vec![user.add_identifier(identifier, now)?])
        })
        .await
    }

    /// Records that a user proved control of a login identifier.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the user has no such identifier.
    pub async fn verify_identifier(
        &self,
        tenant: &TenantContext,
        id: UserId,
        identifier: IdentifierId,
        caller: Caller,
    ) -> Result<User, DomainError> {
        let now = self.clock.now();
        self.change(tenant, id, caller, |user| {
            Ok(user
                .verify_identifier(identifier, now)?
                .into_iter()
                .collect())
        })
        .await
    }

    /// Makes a login identifier the primary one of its kind.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if it needs verification and has none.
    pub async fn choose_primary(
        &self,
        tenant: &TenantContext,
        id: UserId,
        identifier: IdentifierId,
        caller: Caller,
    ) -> Result<User, DomainError> {
        let now = self.clock.now();
        self.change(tenant, id, caller, |user| {
            Ok(user.choose_primary(identifier, now)?.into_iter().collect())
        })
        .await
    }

    /// Removes a login identifier from a user.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if it is the last identifier of a usable user.
    pub async fn remove_identifier(
        &self,
        tenant: &TenantContext,
        id: UserId,
        identifier: IdentifierId,
        caller: Caller,
    ) -> Result<User, DomainError> {
        let now = self.clock.now();
        self.change(tenant, id, caller, |user| {
            user.remove_identifier(identifier, now)
        })
        .await
    }

    /// Replaces a user's display name and locale.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the profile breaks a rule.
    pub async fn change_profile(
        &self,
        tenant: &TenantContext,
        id: UserId,
        profile: Profile,
        caller: Caller,
    ) -> Result<User, DomainError> {
        let now = self.clock.now();
        self.change(tenant, id, caller, |user| {
            Ok(vec![user.change_profile(profile, now)?])
        })
        .await
    }

    /// Loads the user, applies one change and stores the result with its
    /// events, all in one unit of work. A change that produces no event
    /// changed nothing and is not stored.
    async fn change(
        &self,
        tenant: &TenantContext,
        id: UserId,
        caller: Caller,
        apply: impl FnOnce(&mut User) -> Result<Vec<UserEvent>, DomainError> + Send,
    ) -> Result<User, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut user = self.load(uow.as_mut(), id).await?;
        let events = apply(&mut user)?;
        if events.is_empty() {
            return Ok(user);
        }
        self.users.update(uow.as_mut(), &user).await?;
        self.record(uow.as_mut(), caller, &events)?;
        uow.commit().await?;
        Ok(user)
    }

    async fn load(&self, uow: &mut dyn UnitOfWork, id: UserId) -> Result<User, DomainError> {
        self.users.get(uow, id).await?.ok_or_else(|| {
            DomainError::not_found("identity.user_not_found", "the user does not exist")
        })
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        events: &[UserEvent],
    ) -> Result<(), DomainError> {
        let tenant_id = uow.tenant().tenant_id();
        for event in events {
            let metadata = EventMetadata::new(
                tenant_id,
                caller.actor,
                caller.correlation_id,
                self.clock.as_ref(),
            );
            uow.record_event(EventEnvelope::new(metadata, event)?);
        }
        Ok(())
    }
}
