//! The use cases of groups.

use crate::application::ports::{GroupPolicy, GroupRepository, UserRepository};
use crate::domain::group::{
    Group, GroupEvent, GroupMember, GroupName, check_nesting, effective_groups,
};
use crate::domain::user::UserStatus;
use hodor_kernel::{
    Caller, Clock, Cursor, DomainError, DomainEvent, EventEnvelope, EventMetadata, GroupId, Page,
    PageRequest, TenantContext, UnitOfWork, UnitOfWorkFactory, UserId,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::Arc;

/// The use cases of groups.
#[derive(Clone)]
pub struct GroupService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    groups: Arc<dyn GroupRepository>,
    users: Arc<dyn UserRepository>,
    policy: Arc<dyn GroupPolicy>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for GroupService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupService").finish_non_exhaustive()
    }
}

fn group_not_found() -> DomainError {
    DomainError::not_found("identity.group_not_found", "the group does not exist")
}

fn cursor_invalid() -> DomainError {
    DomainError::invalid("request.cursor_invalid", "the cursor is not valid")
}

impl GroupService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        groups: Arc<dyn GroupRepository>,
        users: Arc<dyn UserRepository>,
        policy: Arc<dyn GroupPolicy>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            groups,
            users,
            policy,
            clock,
        }
    }

    /// Creates a group.
    ///
    /// # Errors
    ///
    /// `Invalid` if the name or the description breaks a rule, and
    /// `Conflict` with code `identity.group_name_taken` if another group
    /// of the tenant has the name.
    pub async fn create(
        &self,
        tenant: &TenantContext,
        name: &str,
        description: Option<String>,
        caller: Caller,
    ) -> Result<Group, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let group = self
            .create_in(uow.as_mut(), name, description, caller)
            .await?;
        uow.commit().await?;
        Ok(group)
    }

    /// As [`GroupService::create`], in the caller's unit of work.
    ///
    /// # Errors
    ///
    /// As [`GroupService::create`]. After an error the unit of work must
    /// be abandoned.
    pub async fn create_in(
        &self,
        uow: &mut dyn UnitOfWork,
        name: &str,
        description: Option<String>,
        caller: Caller,
    ) -> Result<Group, DomainError> {
        let name = GroupName::parse(name)?;
        let (group, event) = Group::create(name, description, self.clock.now())?;
        self.groups.insert(uow, &group).await?;
        record(uow, &caller, self.clock.as_ref(), &[event])?;
        Ok(group)
    }

    /// Returns a group of the tenant.
    ///
    /// # Errors
    ///
    /// `NotFound` if the tenant has no such group.
    pub async fn get(&self, tenant: &TenantContext, id: GroupId) -> Result<Group, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), id).await
    }

    /// As [`GroupService::get`], in the caller's unit of work.
    ///
    /// # Errors
    ///
    /// `NotFound` if the tenant has no such group.
    pub async fn get_in(
        &self,
        uow: &mut dyn UnitOfWork,
        id: GroupId,
    ) -> Result<Group, DomainError> {
        self.load(uow, id).await
    }

    /// Returns the tenant's groups in the order they were created, a page
    /// at a time.
    ///
    /// # Errors
    ///
    /// `Invalid` with code `request.cursor_invalid` for a cursor this use
    /// case did not give out.
    pub async fn list(
        &self,
        tenant: &TenantContext,
        page: &PageRequest,
    ) -> Result<Page<Group>, DomainError> {
        let after = page
            .cursor()
            .map(|cursor| {
                cursor
                    .as_str()
                    .parse::<GroupId>()
                    .map_err(|_| cursor_invalid())
            })
            .transpose()?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut items = self
            .groups
            .list(uow.as_mut(), after, page.limit() + 1)
            .await?;
        let more = items.len() > page.limit() as usize;
        items.truncate(page.limit() as usize);
        let next_cursor = more
            .then(|| {
                items
                    .last()
                    .map(|group| Cursor::new(group.id().to_string()))
            })
            .flatten();
        Ok(Page { items, next_cursor })
    }

    /// Replaces a group's name and description.
    ///
    /// # Errors
    ///
    /// As [`GroupService::create`], `NotFound` if the group does not
    /// exist, and `Conflict` with code `identity.group_modified_concurrently`
    /// if it changed since it was read.
    pub async fn change(
        &self,
        tenant: &TenantContext,
        id: GroupId,
        name: &str,
        description: Option<String>,
        caller: Caller,
    ) -> Result<Group, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let changed = self
            .change_in(uow.as_mut(), id, name, description, caller)
            .await?;
        if !changed {
            return self.load(uow.as_mut(), id).await;
        }
        uow.commit().await?;
        self.get(tenant, id).await
    }

    /// As [`GroupService::change`], in the caller's unit of work. Says
    /// whether anything changed.
    ///
    /// # Errors
    ///
    /// As [`GroupService::change`]. After an error the unit of work must
    /// be abandoned.
    pub async fn change_in(
        &self,
        uow: &mut dyn UnitOfWork,
        id: GroupId,
        name: &str,
        description: Option<String>,
        caller: Caller,
    ) -> Result<bool, DomainError> {
        let name = GroupName::parse(name)?;
        let mut group = self.load(uow, id).await?;
        let Some(event) = group.change(name, description, self.clock.now())? else {
            return Ok(false);
        };
        self.groups.update(uow, &group).await?;
        record(uow, &caller, self.clock.as_ref(), &[event])?;
        Ok(true)
    }

    /// Deletes a group, taking it out of every group it was in and every
    /// member out of it.
    ///
    /// # Errors
    ///
    /// `NotFound` if the group does not exist.
    pub async fn delete(
        &self,
        tenant: &TenantContext,
        id: GroupId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.delete_in(uow.as_mut(), id, caller).await?;
        uow.commit().await
    }

    /// As [`GroupService::delete`], in the caller's unit of work.
    ///
    /// # Errors
    ///
    /// `NotFound` if the group does not exist. After an error the unit of
    /// work must be abandoned.
    pub async fn delete_in(
        &self,
        uow: &mut dyn UnitOfWork,
        id: GroupId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        // A deleted group leaves the nesting: it waits for changes to it.
        self.groups.lock_nesting(uow).await?;
        let members = self
            .groups
            .delete(uow, id)
            .await?
            .ok_or_else(group_not_found)?;
        let event = GroupEvent::Deleted {
            group_id: id,
            members,
        };
        record(uow, &caller, self.clock.as_ref(), &[event])
    }

    /// Adds a user or a group to a group. Adding a member that is one
    /// already changes nothing.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `identity.group_not_found` or
    /// `identity.user_not_found` for a group or a user the tenant does
    /// not have, a Deleted user included; `Conflict` with code
    /// `identity.group_cycle` or `identity.group_nesting_too_deep` for a
    /// group that cannot go there.
    pub async fn add_member(
        &self,
        tenant: &TenantContext,
        group: GroupId,
        member: GroupMember,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        if self
            .add_member_in(uow.as_mut(), group, member, caller)
            .await?
        {
            uow.commit().await?;
        }
        Ok(())
    }

    /// As [`GroupService::add_member`], in the caller's unit of work. Says
    /// whether the member was not one already.
    ///
    /// # Errors
    ///
    /// As [`GroupService::add_member`]. After an error the unit of work
    /// must be abandoned.
    pub async fn add_member_in(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
        member: GroupMember,
        caller: Caller,
    ) -> Result<bool, DomainError> {
        self.load(uow, group).await?;
        match member {
            GroupMember::User(user) => {
                let found = self.users.get(uow, user).await?;
                if found.is_none_or(|found| found.status() == UserStatus::Deleted) {
                    return Err(DomainError::not_found(
                        "identity.user_not_found",
                        "the user does not exist",
                    ));
                }
            }
            GroupMember::Group(inner) => {
                self.groups.lock_nesting(uow).await?;
                // Read again under the lock: a group deleted meanwhile is gone.
                self.load(uow, group).await?;
                self.load(uow, inner).await?;
                let nesting = self.groups.nesting(uow).await?;
                let max_depth = self.policy.max_depth(uow).await?;
                if !nesting.contains(&(group, inner)) {
                    check_nesting(group, inner, &nesting, max_depth)?;
                }
            }
        }
        let now = self.clock.now();
        let added = self.groups.add_member(uow, group, member, now).await?;
        if added {
            let event = GroupEvent::added(group, member);
            record(uow, &caller, self.clock.as_ref(), &[event])?;
        }
        Ok(added)
    }

    /// Takes a user or a group out of a group. Taking out what is not a
    /// member changes nothing.
    ///
    /// # Errors
    ///
    /// `NotFound` if the group does not exist.
    pub async fn remove_member(
        &self,
        tenant: &TenantContext,
        group: GroupId,
        member: GroupMember,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        if self
            .remove_member_in(uow.as_mut(), group, member, caller)
            .await?
        {
            uow.commit().await?;
        }
        Ok(())
    }

    /// As [`GroupService::remove_member`], in the caller's unit of work.
    /// Says whether it was a member.
    ///
    /// # Errors
    ///
    /// `NotFound` if the group does not exist. After an error the unit of
    /// work must be abandoned.
    pub async fn remove_member_in(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
        member: GroupMember,
        caller: Caller,
    ) -> Result<bool, DomainError> {
        self.load(uow, group).await?;
        let removed = self.groups.remove_member(uow, group, member).await?;
        if removed {
            let event = GroupEvent::removed(group, member);
            record(uow, &caller, self.clock.as_ref(), &[event])?;
        }
        Ok(removed)
    }

    /// Every direct member of a group, users first, then groups, in the
    /// caller's unit of work.
    ///
    /// # Errors
    ///
    /// `NotFound` if the group does not exist.
    pub async fn all_members_in(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
    ) -> Result<Vec<GroupMember>, DomainError> {
        const PAGE: u32 = 1000;
        self.load(uow, group).await?;
        let mut members = Vec::new();
        loop {
            let page = self
                .groups
                .members(uow, group, members.last().copied(), PAGE)
                .await?;
            let done = page.len() < PAGE as usize;
            members.extend(page);
            if done {
                return Ok(members);
            }
        }
    }

    /// The direct members of a group, a page at a time: users first, then
    /// groups.
    ///
    /// # Errors
    ///
    /// `NotFound` if the group does not exist, and `Invalid` for a cursor
    /// this use case did not give out.
    pub async fn members(
        &self,
        tenant: &TenantContext,
        group: GroupId,
        page: &PageRequest,
    ) -> Result<Page<GroupMember>, DomainError> {
        let after = page
            .cursor()
            .map(|cursor| parse_member(cursor.as_str()))
            .transpose()?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), group).await?;
        let mut items = self
            .groups
            .members(uow.as_mut(), group, after, page.limit() + 1)
            .await?;
        let more = items.len() > page.limit() as usize;
        items.truncate(page.limit() as usize);
        let next_cursor = more
            .then(|| {
                items
                    .last()
                    .map(|member| Cursor::new(member_cursor(*member)))
            })
            .flatten();
        Ok(Page { items, next_cursor })
    }

    /// Every group a user is in, directly or through other groups. A user
    /// the tenant does not have is in none.
    ///
    /// # Errors
    ///
    /// Returns an error only if storage fails.
    pub async fn effective_groups(
        &self,
        tenant: &TenantContext,
        user: UserId,
    ) -> Result<BTreeSet<GroupId>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.effective_groups_in(uow.as_mut(), user).await
    }

    /// The groups a user is directly in, not through another group.
    ///
    /// # Errors
    ///
    /// Returns an error only if storage fails.
    pub async fn direct_groups(
        &self,
        tenant: &TenantContext,
        user: UserId,
    ) -> Result<BTreeSet<GroupId>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        Ok(self
            .groups
            .groups_of(uow.as_mut(), user)
            .await?
            .into_iter()
            .collect())
    }

    /// As [`GroupService::direct_groups`], in the caller's unit of work.
    ///
    /// # Errors
    ///
    /// Returns an error only if storage fails.
    pub async fn direct_groups_in(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
    ) -> Result<Vec<GroupId>, DomainError> {
        self.groups.groups_of(uow, user).await
    }

    /// As [`GroupService::effective_groups`], in the caller's unit of work.
    ///
    /// # Errors
    ///
    /// Returns an error only if storage fails.
    pub async fn effective_groups_in(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
    ) -> Result<BTreeSet<GroupId>, DomainError> {
        let direct = self.groups.groups_of(uow, user).await?;
        if direct.is_empty() {
            return Ok(BTreeSet::new());
        }
        let nesting = self.groups.nesting(uow).await?;
        Ok(effective_groups(&direct, &nesting))
    }

    async fn load(&self, uow: &mut dyn UnitOfWork, id: GroupId) -> Result<Group, DomainError> {
        self.groups.get(uow, id).await?.ok_or_else(group_not_found)
    }
}

/// Takes a user out of every group, in the caller's unit of work: what
/// marking a user Deleted does.
///
/// # Errors
///
/// Returns an error only if storage fails.
pub(crate) async fn leave_every_group(
    groups: &dyn GroupRepository,
    uow: &mut dyn UnitOfWork,
    user: UserId,
    caller: &Caller,
    clock: &dyn Clock,
) -> Result<(), DomainError> {
    let member = GroupMember::User(user);
    let mut events = Vec::new();
    for group in groups.groups_of(uow, user).await? {
        if groups.remove_member(uow, group, member).await? {
            events.push(GroupEvent::removed(group, member));
        }
    }
    record(uow, caller, clock, &events)
}

fn member_cursor(member: GroupMember) -> String {
    format!("{}:{}", member.kind(), member.id_text())
}

fn parse_member(cursor: &str) -> Result<GroupMember, DomainError> {
    match cursor.split_once(':') {
        Some(("user", id)) => id
            .parse()
            .map(GroupMember::User)
            .map_err(|_| cursor_invalid()),
        Some(("group", id)) => id
            .parse()
            .map(GroupMember::Group)
            .map_err(|_| cursor_invalid()),
        _ => Err(cursor_invalid()),
    }
}

pub(crate) fn record<E: DomainEvent + Serialize>(
    uow: &mut dyn UnitOfWork,
    caller: &Caller,
    clock: &dyn Clock,
    events: &[E],
) -> Result<(), DomainError> {
    let tenant_id = uow.tenant().tenant_id();
    for event in events {
        let metadata = EventMetadata::new(tenant_id, caller.actor, caller.correlation_id, clock);
        uow.record_event(EventEnvelope::new(metadata, event)?);
    }
    Ok(())
}
