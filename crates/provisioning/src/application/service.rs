//! The use cases of the provisioning context.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`,
//! "Operations". Each use case runs in one unit of work: the identity
//! context's use cases and what this context keeps change together, or
//! not at all.

use crate::application::ports::{ProvisionedGroupRepository, ProvisionedUserRepository};
use crate::domain::attribute::{GroupAttribute, UserAttribute};
use crate::domain::error::{group_not_found, invalid_value, user_not_found};
use crate::domain::event::ProvisioningEvent;
use crate::domain::query::ListQuery;
use crate::domain::replace::replace_user;
use crate::domain::resource::{
    GroupRequest, GroupResource, GroupSupplement, MemberKind, MemberReference, MemberView,
    SUSPENDED_THROUGH_SCIM, StoredGroupSupplement, StoredUserSupplement, UserRequest, UserResource,
    shown,
};
use hodor_identity::api::{
    CreateUser, GroupMember, GroupService, IdentityService, Profile, UserKind,
};
use hodor_kernel::{
    Caller, Clock, DomainError, ErrorKind, EventEnvelope, EventMetadata, GroupId, TenantContext,
    UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;

/// The ports [`ProvisioningService`] works through.
#[derive(Clone)]
pub struct ProvisioningPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// The identity context's users.
    pub identity: IdentityService,
    /// The identity context's groups.
    pub groups: GroupService,
    /// What this context keeps of users.
    pub users: Arc<dyn ProvisionedUserRepository>,
    /// What this context keeps of groups.
    pub provisioned_groups: Arc<dyn ProvisionedGroupRepository>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ProvisioningPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisioningPorts").finish_non_exhaustive()
    }
}

/// A page of a list: how many match, where the page starts, and what it
/// holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed<R> {
    /// How many resources match the filter, whatever the page.
    pub total: u64,
    /// Where the page starts, the first resource being 1.
    pub start_index: u64,
    /// The resources on the page.
    pub resources: Vec<R>,
}

/// The use cases of the provisioning context.
#[derive(Clone)]
pub struct ProvisioningService {
    ports: ProvisioningPorts,
}

impl std::fmt::Debug for ProvisioningService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisioningService")
            .finish_non_exhaustive()
    }
}

fn not_found_as(error: DomainError, instead: fn() -> DomainError) -> DomainError {
    if error.kind() == ErrorKind::NotFound {
        instead()
    } else {
        error
    }
}

impl ProvisioningService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub const fn new(ports: ProvisioningPorts) -> Self {
        Self { ports }
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &ProvisioningEvent,
    ) -> Result<(), DomainError> {
        let metadata = EventMetadata::new(
            uow.tenant().tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.ports.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }

    /// Creates a user with its identifiers, display name and status, and
    /// what this context keeps of it, in one unit of work. Every address
    /// starts verified.
    ///
    /// # Errors
    ///
    /// What the identity context refuses: `Conflict` with code
    /// `identity.identifier_taken` for an identifier another user has,
    /// `Invalid` for a value that breaks its rules.
    pub async fn create_user(
        &self,
        tenant: &TenantContext,
        request: &UserRequest,
        caller: Caller,
    ) -> Result<UserResource, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let command = CreateUser {
            kind: UserKind::Human,
            identifiers: request
                .identifiers()
                .iter()
                .map(|identifier| (identifier.kind(), identifier.display().to_owned()))
                .collect(),
            profile: Profile {
                display_name: request.display_name.clone(),
                locale: None,
            },
            confirmed: true,
        };
        let user = self
            .ports
            .identity
            .create_in(uow.as_mut(), command, true, caller)
            .await?;
        let id = user.id();
        if !request.active {
            let now = self.ports.clock.now();
            self.ports
                .identity
                .change_in(uow.as_mut(), id, caller, |user| {
                    Ok(vec![user.suspend(SUSPENDED_THROUGH_SCIM, now)?])
                })
                .await?;
        }
        if !request.supplement.is_empty() {
            let now = self.ports.clock.now();
            self.ports
                .users
                .put(
                    uow.as_mut(),
                    &StoredUserSupplement {
                        user_id: id,
                        supplement: request.supplement.clone(),
                        created_at: now,
                        updated_at: now,
                    },
                )
                .await?;
            self.record(
                uow.as_mut(),
                caller,
                &ProvisioningEvent::UserSupplementChanged { user_id: id },
            )?;
        }
        uow.commit().await?;
        self.get_user(tenant, id).await
    }

    /// A user SCIM shows, with what this context keeps of it and the
    /// groups it is directly in.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `provisioning.user_not_found` when the tenant
    /// has no such user, or one SCIM does not show.
    pub async fn get_user(
        &self,
        tenant: &TenantContext,
        id: UserId,
    ) -> Result<UserResource, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.user_in(uow.as_mut(), id).await
    }

    async fn user_in(
        &self,
        uow: &mut dyn UnitOfWork,
        id: UserId,
    ) -> Result<UserResource, DomainError> {
        let user = self
            .ports
            .identity
            .get_in(uow, id)
            .await
            .map_err(|error| not_found_as(error, user_not_found))?;
        if !shown(&user) {
            return Err(user_not_found());
        }
        let stored = self.ports.users.get(uow, id).await?;
        let mut groups = Vec::new();
        for group in self.ports.groups.direct_groups_in(uow, id).await? {
            let found = self.ports.groups.get_in(uow, group).await?;
            groups.push((group, found.name().as_str().to_owned()));
        }
        Ok(UserResource {
            user,
            stored,
            groups,
        })
    }

    /// Replaces what SCIM says of a user, in one unit of work.
    ///
    /// # Errors
    ///
    /// As [`ProvisioningService::get_user`] and
    /// [`ProvisioningService::create_user`].
    pub async fn replace_user(
        &self,
        tenant: &TenantContext,
        id: UserId,
        request: &UserRequest,
        caller: Caller,
    ) -> Result<UserResource, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.user_in(uow.as_mut(), id).await?;
        let now = self.ports.clock.now();
        self.ports
            .identity
            .change_in(uow.as_mut(), id, caller, |user| {
                replace_user(user, request, now)
            })
            .await?;
        let stored = self.ports.users.get(uow.as_mut(), id).await?;
        let unchanged = match &stored {
            Some(stored) => stored.supplement == request.supplement,
            None => request.supplement.is_empty(),
        };
        if !unchanged {
            self.ports
                .users
                .put(
                    uow.as_mut(),
                    &StoredUserSupplement {
                        user_id: id,
                        supplement: request.supplement.clone(),
                        created_at: stored.as_ref().map_or(now, |stored| stored.created_at),
                        updated_at: now,
                    },
                )
                .await?;
            self.record(
                uow.as_mut(),
                caller,
                &ProvisioningEvent::UserSupplementChanged { user_id: id },
            )?;
        }
        uow.commit().await?;
        self.get_user(tenant, id).await
    }

    /// A page of the users that match the query, and how many match.
    ///
    /// # Errors
    ///
    /// Returns an error only if storage fails.
    pub async fn list_users(
        &self,
        tenant: &TenantContext,
        query: &ListQuery<UserAttribute>,
    ) -> Result<Listed<UserResource>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let found = self.ports.users.find(uow.as_mut(), query).await?;
        let mut resources = Vec::with_capacity(found.ids.len());
        for id in found.ids {
            resources.push(self.user_in(uow.as_mut(), id).await?);
        }
        Ok(Listed {
            total: found.total,
            start_index: query.start_index,
            resources,
        })
    }

    /// The member a request names: a user SCIM shows, or a group of the
    /// tenant.
    async fn member_of(
        &self,
        uow: &mut dyn UnitOfWork,
        reference: &MemberReference,
    ) -> Result<GroupMember, DomainError> {
        let refused = || {
            invalid_value(format!(
                "the member {} is not a user or a group of the tenant",
                reference.value
            ))
        };
        if reference.kind != Some(MemberKind::Group) {
            let user: UserId = reference.value.parse().map_err(|_| refused())?;
            match self.ports.identity.get_in(uow, user).await {
                Ok(found) if shown(&found) => return Ok(GroupMember::User(user)),
                Ok(_) => return Err(refused()),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            if reference.kind == Some(MemberKind::User) {
                return Err(refused());
            }
        }
        let group: GroupId = reference.value.parse().map_err(|_| refused())?;
        match self.ports.groups.get_in(uow, group).await {
            Ok(_) => Ok(GroupMember::Group(group)),
            Err(error) if error.kind() == ErrorKind::NotFound => Err(refused()),
            Err(error) => Err(error),
        }
    }

    /// Creates a group with its members and what this context keeps of
    /// it, in one unit of work.
    ///
    /// # Errors
    ///
    /// `Invalid` with code `provisioning.invalid_value` for a member that
    /// is not a user or a group of the tenant, and what the identity
    /// context refuses: a name another group has, a cycle, a group too
    /// deep.
    pub async fn create_group(
        &self,
        tenant: &TenantContext,
        request: &GroupRequest,
        caller: Caller,
    ) -> Result<GroupResource, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let group = self
            .ports
            .groups
            .create_in(uow.as_mut(), &request.display_name, None, caller)
            .await?;
        let id = group.id();
        for reference in &request.members {
            let member = self.member_of(uow.as_mut(), reference).await?;
            self.ports
                .groups
                .add_member_in(uow.as_mut(), id, member, caller)
                .await?;
        }
        let now = self.ports.clock.now();
        self.ports
            .provisioned_groups
            .put(
                uow.as_mut(),
                &StoredGroupSupplement {
                    group_id: id,
                    supplement: request.supplement.clone(),
                    created_at: now,
                    updated_at: now,
                },
            )
            .await?;
        if request.supplement != GroupSupplement::default() {
            self.record(
                uow.as_mut(),
                caller,
                &ProvisioningEvent::GroupSupplementChanged { group_id: id },
            )?;
        }
        uow.commit().await?;
        self.get_group(tenant, id).await
    }

    /// A group with its members and what this context keeps of it.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `provisioning.group_not_found` when the tenant
    /// has no such group.
    pub async fn get_group(
        &self,
        tenant: &TenantContext,
        id: GroupId,
    ) -> Result<GroupResource, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.group_in(uow.as_mut(), id).await
    }

    async fn group_in(
        &self,
        uow: &mut dyn UnitOfWork,
        id: GroupId,
    ) -> Result<GroupResource, DomainError> {
        let group = self
            .ports
            .groups
            .get_in(uow, id)
            .await
            .map_err(|error| not_found_as(error, group_not_found))?;
        let stored = self.ports.provisioned_groups.get(uow, id).await?;
        let mut members = Vec::new();
        for member in self.ports.groups.all_members_in(uow, id).await? {
            let display = match member {
                GroupMember::User(user) => {
                    UserResource::display(&self.ports.identity.get_in(uow, user).await?)
                }
                GroupMember::Group(group) => self
                    .ports
                    .groups
                    .get_in(uow, group)
                    .await?
                    .name()
                    .as_str()
                    .to_owned(),
            };
            members.push(MemberView { member, display });
        }
        Ok(GroupResource {
            group,
            stored,
            members,
        })
    }

    /// Replaces a group's name, members and what this context keeps of it,
    /// in one unit of work. The group's description stays as it is.
    ///
    /// # Errors
    ///
    /// As [`ProvisioningService::get_group`] and
    /// [`ProvisioningService::create_group`].
    pub async fn replace_group(
        &self,
        tenant: &TenantContext,
        id: GroupId,
        request: &GroupRequest,
        caller: Caller,
    ) -> Result<GroupResource, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let group = self
            .ports
            .groups
            .get_in(uow.as_mut(), id)
            .await
            .map_err(|error| not_found_as(error, group_not_found))?;
        self.ports
            .groups
            .change_in(
                uow.as_mut(),
                id,
                &request.display_name,
                group.description().map(str::to_owned),
                caller,
            )
            .await?;
        let mut desired = Vec::with_capacity(request.members.len());
        for reference in &request.members {
            desired.push(self.member_of(uow.as_mut(), reference).await?);
        }
        let current = self.ports.groups.all_members_in(uow.as_mut(), id).await?;
        let mut members_changed = false;
        for member in current.iter().filter(|member| !desired.contains(member)) {
            members_changed |= self
                .ports
                .groups
                .remove_member_in(uow.as_mut(), id, *member, caller)
                .await?;
        }
        for member in desired.iter().filter(|member| !current.contains(member)) {
            members_changed |= self
                .ports
                .groups
                .add_member_in(uow.as_mut(), id, *member, caller)
                .await?;
        }
        let stored = self.ports.provisioned_groups.get(uow.as_mut(), id).await?;
        let supplement_changed = match &stored {
            Some(stored) => stored.supplement != request.supplement,
            None => request.supplement != GroupSupplement::default(),
        };
        if members_changed || supplement_changed {
            let now = self.ports.clock.now();
            self.ports
                .provisioned_groups
                .put(
                    uow.as_mut(),
                    &StoredGroupSupplement {
                        group_id: id,
                        supplement: request.supplement.clone(),
                        created_at: stored.as_ref().map_or(now, |stored| stored.created_at),
                        updated_at: now,
                    },
                )
                .await?;
        }
        if supplement_changed {
            self.record(
                uow.as_mut(),
                caller,
                &ProvisioningEvent::GroupSupplementChanged { group_id: id },
            )?;
        }
        uow.commit().await?;
        self.get_group(tenant, id).await
    }

    /// Deletes a group as the identity context does, and what this context
    /// keeps of it, in one unit of work.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `provisioning.group_not_found` when the tenant
    /// has no such group.
    pub async fn delete_group(
        &self,
        tenant: &TenantContext,
        id: GroupId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.ports
            .groups
            .delete_in(uow.as_mut(), id, caller)
            .await
            .map_err(|error| not_found_as(error, group_not_found))?;
        self.ports
            .provisioned_groups
            .remove(uow.as_mut(), id)
            .await?;
        uow.commit().await
    }

    /// A page of the groups that match the query, and how many match.
    ///
    /// # Errors
    ///
    /// Returns an error only if storage fails.
    pub async fn list_groups(
        &self,
        tenant: &TenantContext,
        query: &ListQuery<GroupAttribute>,
    ) -> Result<Listed<GroupResource>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let found = self
            .ports
            .provisioned_groups
            .find(uow.as_mut(), query)
            .await?;
        let mut resources = Vec::with_capacity(found.ids.len());
        for id in found.ids {
            resources.push(self.group_in(uow.as_mut(), id).await?);
        }
        Ok(Listed {
            total: found.total,
            start_index: query.start_index,
            resources,
        })
    }
}
