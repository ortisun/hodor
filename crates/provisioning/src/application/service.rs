//! The use cases of the provisioning context.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`,
//! "Operations". Each use case runs in one unit of work: the identity
//! context's use cases, what this context keeps, and when a person is
//! deprovisioned the end of their sessions and grants, change together, or
//! not at all.

use crate::application::ports::{
    AccessRevoker, Deprovisioning, DeprovisioningPolicy, ProvisionedGroupRepository,
    ProvisionedUserRepository,
};
use crate::domain::attribute::{GroupAttribute, UserAttribute};
use crate::domain::error::{group_not_found, invalid_value, user_not_found, version_mismatch};
use crate::domain::event::ProvisioningEvent;
use crate::domain::patch::{PatchRequest, apply_patch};
use crate::domain::query::ListQuery;
use crate::domain::replace::replace_user;
use crate::domain::resource::{
    DEPROVISIONED, GROUP_SHAPE, GroupRequest, GroupResource, GroupSupplement,
    MAX_MEMBERS_PER_REQUEST, MemberKind, MemberReference, MemberView, StoredGroupSupplement,
    StoredUserSupplement, USER_SHAPE, UserRequest, UserResource, UserSupplement,
    read_group_bounded, read_user, shown,
};
use crate::domain::version::Precondition;
use hodor_identity::api::{
    CreateUser, Group, GroupMember, GroupService, IdentityService, Profile, UserKind, UserStatus,
};
use hodor_kernel::{
    Caller, Clock, DomainError, ErrorKind, EventEnvelope, EventMetadata, GroupId, TenantContext,
    UnitOfWork, UnitOfWorkFactory, UserId,
};
use serde_json::Value;
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
    /// The tenant's deprovisioning policy.
    pub deprovisioning: Arc<dyn DeprovisioningPolicy>,
    /// Ends a deprovisioned person's sessions and grants.
    pub access: Arc<dyn AccessRevoker>,
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

/// Checks that a resource at `version` is one `precondition` names.
fn check(
    precondition: Option<&Precondition>,
    version: impl FnOnce() -> String,
) -> Result<(), DomainError> {
    match precondition {
        Some(precondition) if !precondition.admits(&version()) => Err(version_mismatch()),
        _ => Ok(()),
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
    /// starts verified. `active: false` creates the user Deactivated.
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
                    Ok(vec![user.deactivate(now)?])
                })
                .await?;
        }
        self.keep_user(uow.as_mut(), id, &request.supplement, None, caller)
            .await?;
        uow.commit().await?;
        self.get_user(tenant, id).await
    }

    /// Stores `supplement` for a user when it differs from what is kept,
    /// with its event.
    async fn keep_user(
        &self,
        uow: &mut dyn UnitOfWork,
        id: UserId,
        supplement: &UserSupplement,
        stored: Option<StoredUserSupplement>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let unchanged = match &stored {
            Some(stored) => stored.supplement == *supplement,
            None => supplement.is_empty(),
        };
        if unchanged {
            return Ok(());
        }
        let now = self.ports.clock.now();
        self.ports
            .users
            .put(
                uow,
                &StoredUserSupplement {
                    user_id: id,
                    supplement: supplement.clone(),
                    created_at: stored.as_ref().map_or(now, |stored| stored.created_at),
                    updated_at: now,
                    removed_at: stored.as_ref().and_then(|stored| stored.removed_at),
                },
            )
            .await?;
        self.record(
            uow,
            caller,
            &ProvisioningEvent::UserSupplementChanged { user_id: id },
        )
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
        let stored = self.ports.users.get(uow, id).await?;
        if !shown(&user, stored.as_ref()) {
            return Err(user_not_found());
        }
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

    /// Replaces what SCIM says of a user, in one unit of work. With
    /// `precondition`, only if the user is at one of its versions. Answers
    /// the user as it is now, or `None` when the change deprovisioned the
    /// user and the tenant's policy deletes.
    ///
    /// # Errors
    ///
    /// As [`ProvisioningService::get_user`] and
    /// [`ProvisioningService::create_user`], and `Conflict` with code
    /// `provisioning.version_mismatch` for a version the user no longer
    /// has.
    pub async fn replace_user(
        &self,
        tenant: &TenantContext,
        id: UserId,
        request: &UserRequest,
        precondition: Option<&Precondition>,
        caller: Caller,
    ) -> Result<Option<UserResource>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let current = self.user_in(uow.as_mut(), id).await?;
        check(precondition, || current.version())?;
        self.replace_user_in(uow.as_mut(), current, request, caller)
            .await?;
        uow.commit().await?;
        self.after_change(tenant, id).await
    }

    /// Changes part of a user with the operations of a `PATCH`, applied to
    /// the user as it is, then replaces the user with the result.
    ///
    /// # Errors
    ///
    /// As [`ProvisioningService::replace_user`], and the refusals of the
    /// operations.
    pub async fn patch_user(
        &self,
        tenant: &TenantContext,
        id: UserId,
        patch: &PatchRequest,
        precondition: Option<&Precondition>,
        caller: Caller,
    ) -> Result<Option<UserResource>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let current = self.user_in(uow.as_mut(), id).await?;
        check(precondition, || current.version())?;
        let mut document = current.patchable();
        apply_patch(&mut document, patch, &USER_SHAPE)?;
        let request = read_user(&Value::Object(document))?;
        self.replace_user_in(uow.as_mut(), current, &request, caller)
            .await?;
        uow.commit().await?;
        self.after_change(tenant, id).await
    }

    /// The user after a change; `None` when the change deprovisioned them
    /// under a policy that deletes.
    async fn after_change(
        &self,
        tenant: &TenantContext,
        id: UserId,
    ) -> Result<Option<UserResource>, DomainError> {
        match self.get_user(tenant, id).await {
            Ok(resource) => Ok(Some(resource)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn replace_user_in(
        &self,
        uow: &mut dyn UnitOfWork,
        current: UserResource,
        request: &UserRequest,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let id = current.user.id();
        let now = self.ports.clock.now();
        let mut deprovision = false;
        self.ports
            .identity
            .change_in(uow, id, caller, |user| {
                let replaced = replace_user(user, request, now)?;
                deprovision = replaced.deprovision;
                Ok(replaced.events)
            })
            .await?;
        self.keep_user(uow, id, &request.supplement, current.stored, caller)
            .await?;
        if deprovision {
            self.deprovision_in(uow, id, false, caller).await?;
        }
        Ok(())
    }

    /// Deprovisions a user as the tenant's policy says, as a `DELETE`
    /// does: from then on SCIM does not show them.
    ///
    /// # Errors
    ///
    /// As [`ProvisioningService::replace_user`].
    pub async fn delete_user(
        &self,
        tenant: &TenantContext,
        id: UserId,
        precondition: Option<&Precondition>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let current = self.user_in(uow.as_mut(), id).await?;
        check(precondition, || current.version())?;
        self.deprovision_in(uow.as_mut(), id, true, caller).await?;
        uow.commit().await
    }

    /// Deactivates, or deletes, a user as the tenant's policy says, and
    /// ends their sessions and grants, in the caller's unit of work.
    /// `removed` marks a user deactivated by a `DELETE`, whom SCIM no
    /// longer shows.
    async fn deprovision_in(
        &self,
        uow: &mut dyn UnitOfWork,
        id: UserId,
        removed: bool,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let policy = self.ports.deprovisioning.deprovisioning(uow).await?;
        let now = self.ports.clock.now();
        let user = self.ports.identity.get_in(uow, id).await?;
        if user.status() != UserStatus::Deactivated {
            self.ports
                .identity
                .change_in(uow, id, caller, |user| Ok(vec![user.deactivate(now)?]))
                .await?;
        }
        match policy {
            Deprovisioning::Delete => {
                self.ports.identity.mark_deleted_in(uow, id, caller).await?;
                self.ports.users.remove(uow, id).await?;
            }
            Deprovisioning::Deactivate if removed => {
                let stored = self.ports.users.get(uow, id).await?;
                self.ports
                    .users
                    .put(
                        uow,
                        &StoredUserSupplement {
                            user_id: id,
                            supplement: stored
                                .as_ref()
                                .map(|stored| stored.supplement.clone())
                                .unwrap_or_default(),
                            created_at: stored.as_ref().map_or(now, |stored| stored.created_at),
                            updated_at: now,
                            removed_at: Some(now),
                        },
                    )
                    .await?;
            }
            Deprovisioning::Deactivate => {}
        }
        self.ports
            .access
            .revoke_access(uow, id, DEPROVISIONED, caller)
            .await
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

    /// The member a request names: a member the group has already, a user
    /// SCIM shows, or a group of the tenant.
    async fn member_of(
        &self,
        uow: &mut dyn UnitOfWork,
        reference: &MemberReference,
        current: &[GroupMember],
    ) -> Result<GroupMember, DomainError> {
        let refused = || {
            invalid_value(format!(
                "the member {} is not a user or a group of the tenant",
                reference.value
            ))
        };
        if let Some(known) = current
            .iter()
            .find(|member| member.id_text() == reference.value)
        {
            let kind = match known {
                GroupMember::User(_) => MemberKind::User,
                GroupMember::Group(_) => MemberKind::Group,
            };
            return match reference.kind {
                Some(said) if said != kind => Err(refused()),
                _ => Ok(*known),
            };
        }
        if reference.kind != Some(MemberKind::Group) {
            let user: UserId = reference.value.parse().map_err(|_| refused())?;
            match self.ports.identity.get_in(uow, user).await {
                Ok(found) => {
                    let stored = self.ports.users.get(uow, user).await?;
                    if shown(&found, stored.as_ref()) {
                        return Ok(GroupMember::User(user));
                    }
                    return Err(refused());
                }
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
            let member = self.member_of(uow.as_mut(), reference, &[]).await?;
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
    /// [`ProvisioningService::create_group`], and `Conflict` with code
    /// `provisioning.version_mismatch` for a version the group no longer
    /// has.
    pub async fn replace_group(
        &self,
        tenant: &TenantContext,
        id: GroupId,
        request: &GroupRequest,
        precondition: Option<&Precondition>,
        caller: Caller,
    ) -> Result<GroupResource, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let current = self.group_in(uow.as_mut(), id).await?;
        check(precondition, || current.version())?;
        self.replace_group_in(uow.as_mut(), &current.group, request, caller)
            .await?;
        uow.commit().await?;
        self.get_group(tenant, id).await
    }

    /// Changes part of a group with the operations of a `PATCH`, applied
    /// to the group as it is, then replaces the group with the result.
    ///
    /// # Errors
    ///
    /// As [`ProvisioningService::replace_group`], the refusals of the
    /// operations, and `provisioning.invalid_value` for operations that
    /// name more than [`MAX_MEMBERS_PER_REQUEST`] members.
    pub async fn patch_group(
        &self,
        tenant: &TenantContext,
        id: GroupId,
        patch: &PatchRequest,
        precondition: Option<&Precondition>,
        caller: Caller,
    ) -> Result<GroupResource, DomainError> {
        if patch.values_named("members") > MAX_MEMBERS_PER_REQUEST {
            return Err(invalid_value(format!(
                "the operations of a PATCH name at most {MAX_MEMBERS_PER_REQUEST} members"
            )));
        }
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let current = self.group_in(uow.as_mut(), id).await?;
        check(precondition, || current.version())?;
        let mut document = current.patchable();
        apply_patch(&mut document, patch, &GROUP_SHAPE)?;
        let request = read_group_bounded(&Value::Object(document), None)?;
        self.replace_group_in(uow.as_mut(), &current.group, &request, caller)
            .await?;
        uow.commit().await?;
        self.get_group(tenant, id).await
    }

    async fn replace_group_in(
        &self,
        uow: &mut dyn UnitOfWork,
        group: &Group,
        request: &GroupRequest,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let id = group.id();
        self.ports
            .groups
            .change_in(
                uow,
                id,
                &request.display_name,
                group.description().map(str::to_owned),
                caller,
            )
            .await?;
        let current = self.ports.groups.all_members_in(uow, id).await?;
        let mut desired = Vec::with_capacity(request.members.len());
        for reference in &request.members {
            desired.push(self.member_of(uow, reference, &current).await?);
        }
        let mut members_changed = false;
        for member in current.iter().filter(|member| !desired.contains(member)) {
            members_changed |= self
                .ports
                .groups
                .remove_member_in(uow, id, *member, caller)
                .await?;
        }
        for member in desired.iter().filter(|member| !current.contains(member)) {
            members_changed |= self
                .ports
                .groups
                .add_member_in(uow, id, *member, caller)
                .await?;
        }
        let stored = self.ports.provisioned_groups.get(uow, id).await?;
        let supplement_changed = match &stored {
            Some(stored) => stored.supplement != request.supplement,
            None => request.supplement != GroupSupplement::default(),
        };
        if members_changed || supplement_changed {
            let now = self.ports.clock.now();
            self.ports
                .provisioned_groups
                .put(
                    uow,
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
                uow,
                caller,
                &ProvisioningEvent::GroupSupplementChanged { group_id: id },
            )?;
        }
        Ok(())
    }

    /// Deletes a group as the identity context does, and what this context
    /// keeps of it, in one unit of work. With `precondition`, only if the
    /// group is at one of its versions.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `provisioning.group_not_found` when the tenant
    /// has no such group, and `provisioning.version_mismatch` for a version
    /// it no longer has.
    pub async fn delete_group(
        &self,
        tenant: &TenantContext,
        id: GroupId,
        precondition: Option<&Precondition>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        if precondition.is_some() {
            let current = self.group_in(uow.as_mut(), id).await?;
            check(precondition, || current.version())?;
        }
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
