//! The use cases of organizations, their units and their members.

use crate::application::groups::record;
use crate::application::ports::{InvitationRepository, OrganizationRepository, UserRepository};
use crate::domain::identifier::{IdentifierKind, NormalizedIdentifier};
use crate::domain::organization::{
    INVITATION_LIFETIME, Invitation, InvitationId, InvitationStatus, Membership, Organization,
    OrganizationEvent, OrganizationName, Tree, Unit, UnitChange, UnitId, UnitKind, check_placement,
};
use crate::domain::user::UserStatus;
use hodor_kernel::{
    Caller, Clock, Cursor, DomainError, OrganizationId, Page, PageRequest, TenantContext,
    UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::collections::BTreeSet;
use std::sync::Arc;

/// The use cases of organizations.
#[derive(Clone)]
pub struct OrganizationService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    organizations: Arc<dyn OrganizationRepository>,
    invitations: Arc<dyn InvitationRepository>,
    users: Arc<dyn UserRepository>,
    clock: Arc<dyn Clock>,
}

/// What an invitation says, for whoever holds its link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationFound {
    /// The invitation.
    pub invitation: Invitation,
    /// The organization it is to.
    pub organization: Organization,
}

impl std::fmt::Debug for OrganizationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrganizationService")
            .finish_non_exhaustive()
    }
}

fn organization_not_found() -> DomainError {
    DomainError::not_found(
        "identity.organization_not_found",
        "the organization does not exist",
    )
}

fn unit_not_found() -> DomainError {
    DomainError::not_found(
        "identity.unit_not_found",
        "the unit does not exist in this organization",
    )
}

fn invitation_invalid() -> DomainError {
    DomainError::not_found(
        "identity.invitation_invalid",
        "the invitation is unknown, accepted, withdrawn or expired",
    )
}

fn cursor_invalid() -> DomainError {
    DomainError::invalid("request.cursor_invalid", "the cursor is not valid")
}

fn page_after<T: std::str::FromStr>(page: &PageRequest) -> Result<Option<T>, DomainError> {
    page.cursor()
        .map(|cursor| cursor.as_str().parse::<T>().map_err(|_| cursor_invalid()))
        .transpose()
}

fn page_of<T>(mut items: Vec<T>, page: &PageRequest, key: impl Fn(&T) -> String) -> Page<T> {
    let more = items.len() > page.limit() as usize;
    items.truncate(page.limit() as usize);
    let next_cursor = more
        .then(|| items.last().map(|item| Cursor::new(key(item))))
        .flatten();
    Page { items, next_cursor }
}

impl OrganizationService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        organizations: Arc<dyn OrganizationRepository>,
        invitations: Arc<dyn InvitationRepository>,
        users: Arc<dyn UserRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            organizations,
            invitations,
            users,
            clock,
        }
    }

    /// Makes an invitation of an organization to an email address, with
    /// the hash of the secret its link carries, in the caller's unit of
    /// work. A pending invitation of the organization to the same address
    /// is withdrawn.
    ///
    /// # Errors
    ///
    /// `NotFound` for an organization or a unit it does not have, and
    /// `Invalid` with code `identity.email_invalid` for an address that is
    /// not one.
    pub async fn invite_in(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        email: &str,
        units: BTreeSet<UnitId>,
        token_hash: [u8; 32],
        caller: Caller,
    ) -> Result<(Invitation, Organization), DomainError> {
        let email = NormalizedIdentifier::parse(IdentifierKind::Email, email)?;
        let found = self.load(uow, organization).await?;
        self.check_units(uow, organization, &units).await?;
        let now = self.clock.now();
        let mut events = Vec::new();
        if let Some(earlier) = self
            .invitations
            .withdraw_pending(uow, organization, email.normalized(), now)
            .await?
        {
            events.push(OrganizationEvent::InvitationWithdrawn {
                organization_id: organization,
                invitation_id: earlier,
            });
        }
        let invitation = Invitation {
            id: InvitationId::generate(),
            organization,
            email: email.normalized().to_owned(),
            units,
            token_hash,
            status: InvitationStatus::Pending,
            created_at: now,
            expires_at: now + INVITATION_LIFETIME,
            accepted: None,
            withdrawn_at: None,
        };
        self.invitations.insert(uow, &invitation).await?;
        events.push(OrganizationEvent::InvitationCreated {
            organization_id: organization,
            invitation_id: invitation.id,
        });
        record(uow, &caller, self.clock.as_ref(), &events)?;
        Ok((invitation, found))
    }

    /// The good invitation whose token has the given hash, with its
    /// organization.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `identity.invitation_invalid` for an unknown,
    /// accepted, withdrawn or expired invitation, all alike.
    pub async fn good_invitation(
        &self,
        tenant: &TenantContext,
        token_hash: &[u8; 32],
    ) -> Result<InvitationFound, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let invitation = self
            .invitations
            .find_by_hash(uow.as_mut(), token_hash)
            .await?
            .filter(|invitation| invitation.is_good_at(self.clock.now()))
            .ok_or_else(invitation_invalid)?;
        let organization = self.load(uow.as_mut(), invitation.organization).await?;
        Ok(InvitationFound {
            invitation,
            organization,
        })
    }

    /// Uses an invitation up for `user` and makes the membership with the
    /// invitation's units that still exist, in the caller's unit of work.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `identity.invitation_invalid` if another
    /// request used it up first, or it is no longer good.
    pub async fn accept_in(
        &self,
        uow: &mut dyn UnitOfWork,
        invitation: &Invitation,
        user: UserId,
        caller: Caller,
    ) -> Result<Membership, DomainError> {
        let now = self.clock.now();
        if !self
            .invitations
            .use_up(uow, invitation.id, user, now)
            .await?
        {
            return Err(invitation_invalid());
        }
        let known: BTreeSet<UnitId> = self
            .organizations
            .units(uow, invitation.organization)
            .await?
            .into_iter()
            .map(|unit| unit.id)
            .collect();
        let units = invitation.units.intersection(&known).copied().collect();
        let event = OrganizationEvent::InvitationAccepted {
            organization_id: invitation.organization,
            invitation_id: invitation.id,
            user_id: user,
        };
        record(uow, &caller, self.clock.as_ref(), &[event])?;
        self.add_member_in(uow, invitation.organization, user, units, caller)
            .await
    }

    /// Withdraws a pending invitation of an organization.
    ///
    /// # Errors
    ///
    /// `NotFound` for an organization that does not exist, or an
    /// invitation of it that is not pending.
    pub async fn withdraw_invitation(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
        id: InvitationId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), organization).await?;
        if !self
            .invitations
            .withdraw(uow.as_mut(), organization, id, self.clock.now())
            .await?
        {
            return Err(invitation_invalid());
        }
        let event = OrganizationEvent::InvitationWithdrawn {
            organization_id: organization,
            invitation_id: id,
        };
        record(uow.as_mut(), &caller, self.clock.as_ref(), &[event])?;
        uow.commit().await
    }

    /// The pending invitations of an organization, newest first.
    ///
    /// # Errors
    ///
    /// `NotFound` if the organization does not exist.
    pub async fn pending_invitations(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
    ) -> Result<Vec<Invitation>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), organization).await?;
        self.invitations.pending(uow.as_mut(), organization).await
    }

    /// Creates an organization.
    ///
    /// # Errors
    ///
    /// `Invalid` if the name or the description breaks a rule, and
    /// `Conflict` with code `identity.organization_name_taken`.
    pub async fn create(
        &self,
        tenant: &TenantContext,
        name: &str,
        description: Option<String>,
        caller: Caller,
    ) -> Result<Organization, DomainError> {
        let name = OrganizationName::parse(name)?;
        let (organization, event) = Organization::create(name, description, self.clock.now())?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.organizations
            .insert(uow.as_mut(), &organization)
            .await?;
        record(uow.as_mut(), &caller, self.clock.as_ref(), &[event])?;
        uow.commit().await?;
        Ok(organization)
    }

    /// Returns an organization of the tenant.
    ///
    /// # Errors
    ///
    /// `NotFound` if the tenant has no such organization.
    pub async fn get(
        &self,
        tenant: &TenantContext,
        id: OrganizationId,
    ) -> Result<Organization, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), id).await
    }

    /// Returns the tenant's organizations in the order they were created.
    ///
    /// # Errors
    ///
    /// `Invalid` for a cursor this use case did not give out.
    pub async fn list(
        &self,
        tenant: &TenantContext,
        page: &PageRequest,
    ) -> Result<Page<Organization>, DomainError> {
        let after = page_after::<OrganizationId>(page)?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        let items = self
            .organizations
            .list(uow.as_mut(), after, page.limit() + 1)
            .await?;
        Ok(page_of(items, page, |organization| {
            organization.id().to_string()
        }))
    }

    /// Replaces an organization's name and description.
    ///
    /// # Errors
    ///
    /// As [`OrganizationService::create`], and `NotFound`.
    pub async fn change(
        &self,
        tenant: &TenantContext,
        id: OrganizationId,
        name: &str,
        description: Option<String>,
        caller: Caller,
    ) -> Result<Organization, DomainError> {
        let name = OrganizationName::parse(name)?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut organization = self.load(uow.as_mut(), id).await?;
        let Some(event) = organization.change(name, description, self.clock.now())? else {
            return Ok(organization);
        };
        self.organizations
            .update(uow.as_mut(), &organization)
            .await?;
        record(uow.as_mut(), &caller, self.clock.as_ref(), &[event])?;
        uow.commit().await?;
        self.get(tenant, id).await
    }

    /// Deletes an organization with its units and memberships.
    ///
    /// # Errors
    ///
    /// `NotFound` if it does not exist.
    pub async fn delete(
        &self,
        tenant: &TenantContext,
        id: OrganizationId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.organizations.lock_tree(uow.as_mut(), id).await?;
        let members = self
            .organizations
            .delete(uow.as_mut(), id)
            .await?
            .ok_or_else(organization_not_found)?;
        let event = OrganizationEvent::Deleted {
            organization_id: id,
            members,
        };
        record(uow.as_mut(), &caller, self.clock.as_ref(), &[event])?;
        uow.commit().await
    }

    /// Every unit of an organization.
    ///
    /// # Errors
    ///
    /// `NotFound` if the organization does not exist.
    pub async fn units(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
    ) -> Result<Vec<Unit>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), organization).await?;
        self.organizations.units(uow.as_mut(), organization).await
    }

    /// Creates a unit, under `parent` or at the top.
    ///
    /// # Errors
    ///
    /// `NotFound` for an organization or a parent that does not exist,
    /// `Invalid` for a name or a kind that breaks a rule, `Conflict` with
    /// code `identity.unit_tree_too_deep` past ten levels and
    /// `identity.unit_name_taken` for a name a sibling has.
    pub async fn create_unit(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
        parent: Option<UnitId>,
        name: &str,
        kind: UnitKind,
        caller: Caller,
    ) -> Result<Unit, DomainError> {
        let name = OrganizationName::parse(name)?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), organization).await?;
        self.organizations
            .lock_tree(uow.as_mut(), organization)
            .await?;
        let tree = self.tree(uow.as_mut(), organization).await?.1;
        let id = UnitId::generate();
        check_placement(id, parent, &tree)?;
        let now = self.clock.now();
        let unit = Unit {
            id,
            organization,
            parent,
            name,
            kind,
            created_at: now,
            updated_at: now,
        };
        self.organizations.save_unit(uow.as_mut(), &unit).await?;
        let event = OrganizationEvent::UnitCreated {
            organization_id: organization,
            unit_id: id,
            parent_id: parent,
            kind: kind.as_str(),
        };
        record(uow.as_mut(), &caller, self.clock.as_ref(), &[event])?;
        uow.commit().await?;
        Ok(unit)
    }

    /// Renames a unit, changes its kind, or moves it under another parent
    /// or to the top, carrying the units below it.
    ///
    /// # Errors
    ///
    /// As [`OrganizationService::create_unit`], and `Conflict` with code
    /// `identity.unit_cycle` for a parent that is the unit or below it.
    pub async fn change_unit(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
        unit: UnitId,
        change: UnitChange,
        caller: Caller,
    ) -> Result<Unit, DomainError> {
        let UnitChange { parent, name, kind } = change;
        let name = OrganizationName::parse(&name)?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), organization).await?;
        self.organizations
            .lock_tree(uow.as_mut(), organization)
            .await?;
        let (units, tree) = self.tree(uow.as_mut(), organization).await?;
        let mut stored = units
            .into_iter()
            .find(|candidate| candidate.id == unit)
            .ok_or_else(unit_not_found)?;
        if stored.parent == parent && stored.name == name && stored.kind == kind {
            return Ok(stored);
        }
        if stored.parent != parent {
            check_placement(unit, parent, &tree)?;
        }
        stored.parent = parent;
        stored.name = name;
        stored.kind = kind;
        stored.updated_at = self.clock.now();
        self.organizations.save_unit(uow.as_mut(), &stored).await?;
        let event = OrganizationEvent::UnitChanged {
            organization_id: organization,
            unit_id: unit,
        };
        record(uow.as_mut(), &caller, self.clock.as_ref(), &[event])?;
        uow.commit().await?;
        Ok(stored)
    }

    /// Deletes a unit with no unit below it, taking its members out of it.
    ///
    /// # Errors
    ///
    /// `NotFound` for an organization or a unit that does not exist, and
    /// `Conflict` with code `identity.unit_not_empty`.
    pub async fn delete_unit(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
        unit: UnitId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), organization).await?;
        self.organizations
            .lock_tree(uow.as_mut(), organization)
            .await?;
        if !self
            .organizations
            .delete_unit(uow.as_mut(), organization, unit)
            .await?
        {
            return Err(unit_not_found());
        }
        let event = OrganizationEvent::UnitDeleted {
            organization_id: organization,
            unit_id: unit,
        };
        record(uow.as_mut(), &caller, self.clock.as_ref(), &[event])?;
        uow.commit().await
    }

    /// Makes a user a member of an organization, in the given units. A
    /// user who is a member already stays as they are.
    ///
    /// # Errors
    ///
    /// `NotFound` for an organization, a user, a Deleted user or a unit
    /// the organization does not have.
    pub async fn add_member(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
        user: UserId,
        units: BTreeSet<UnitId>,
        caller: Caller,
    ) -> Result<Membership, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let membership = self
            .add_member_in(uow.as_mut(), organization, user, units, caller)
            .await?;
        uow.commit().await?;
        Ok(membership)
    }

    /// As [`OrganizationService::add_member`], in the caller's unit of
    /// work: accepting an invitation makes the membership together with
    /// the rest.
    ///
    /// # Errors
    ///
    /// As [`OrganizationService::add_member`].
    pub async fn add_member_in(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        user: UserId,
        units: BTreeSet<UnitId>,
        caller: Caller,
    ) -> Result<Membership, DomainError> {
        self.load(uow, organization).await?;
        self.check_user(uow, user).await?;
        if let Some(existing) = self
            .organizations
            .membership(uow, organization, user)
            .await?
        {
            return Ok(existing);
        }
        self.check_units(uow, organization, &units).await?;
        let membership = Membership {
            organization,
            user,
            units,
            added_at: self.clock.now(),
        };
        self.organizations.save_membership(uow, &membership).await?;
        let event = OrganizationEvent::MemberAdded {
            organization_id: organization,
            user_id: user,
            units: membership.units.iter().copied().collect(),
        };
        record(uow, &caller, self.clock.as_ref(), &[event])?;
        Ok(membership)
    }

    /// Replaces the units of a member.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `identity.membership_not_found` for a user who
    /// is not a member, and for a unit the organization does not have.
    pub async fn change_member_units(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
        user: UserId,
        units: BTreeSet<UnitId>,
        caller: Caller,
    ) -> Result<Membership, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), organization).await?;
        let mut membership = self
            .organizations
            .membership(uow.as_mut(), organization, user)
            .await?
            .ok_or_else(|| {
                DomainError::not_found(
                    "identity.membership_not_found",
                    "the user is not a member of the organization",
                )
            })?;
        if membership.units == units {
            return Ok(membership);
        }
        self.check_units(uow.as_mut(), organization, &units).await?;
        membership.units = units;
        self.organizations
            .save_membership(uow.as_mut(), &membership)
            .await?;
        let event = OrganizationEvent::MemberChanged {
            organization_id: organization,
            user_id: user,
            units: membership.units.iter().copied().collect(),
        };
        record(uow.as_mut(), &caller, self.clock.as_ref(), &[event])?;
        uow.commit().await?;
        Ok(membership)
    }

    /// Takes a user out of an organization. Taking out a user who is not a
    /// member changes nothing.
    ///
    /// # Errors
    ///
    /// `NotFound` if the organization does not exist.
    pub async fn remove_member(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
        user: UserId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), organization).await?;
        if self
            .organizations
            .remove_membership(uow.as_mut(), organization, user)
            .await?
        {
            let event = OrganizationEvent::MemberRemoved {
                organization_id: organization,
                user_id: user,
            };
            record(uow.as_mut(), &caller, self.clock.as_ref(), &[event])?;
            uow.commit().await?;
        }
        Ok(())
    }

    /// The members of an organization, a page at a time.
    ///
    /// # Errors
    ///
    /// `NotFound` if the organization does not exist, and `Invalid` for a
    /// cursor this use case did not give out.
    pub async fn members(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
        page: &PageRequest,
    ) -> Result<Page<Membership>, DomainError> {
        let after = page_after::<UserId>(page)?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.load(uow.as_mut(), organization).await?;
        let items = self
            .organizations
            .members(uow.as_mut(), organization, after, page.limit() + 1)
            .await?;
        Ok(page_of(items, page, |membership| {
            membership.user.to_string()
        }))
    }

    /// Every organization a user is a member of, with their units.
    ///
    /// # Errors
    ///
    /// Returns an error only if storage fails.
    pub async fn organizations_of(
        &self,
        tenant: &TenantContext,
        user: UserId,
    ) -> Result<Vec<Membership>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.organizations.memberships_of(uow.as_mut(), user).await
    }

    /// As [`OrganizationService::organizations_of`], in the caller's unit of
    /// work.
    ///
    /// # Errors
    ///
    /// Returns an error only if storage fails.
    pub async fn organizations_of_in(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
    ) -> Result<Vec<Membership>, DomainError> {
        self.organizations.memberships_of(uow, user).await
    }

    async fn load(
        &self,
        uow: &mut dyn UnitOfWork,
        id: OrganizationId,
    ) -> Result<Organization, DomainError> {
        self.organizations
            .get(uow, id)
            .await?
            .ok_or_else(organization_not_found)
    }

    async fn tree(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
    ) -> Result<(Vec<Unit>, Tree), DomainError> {
        let units = self.organizations.units(uow, organization).await?;
        let tree = units.iter().map(|unit| (unit.id, unit.parent)).collect();
        Ok((units, tree))
    }

    async fn check_user(&self, uow: &mut dyn UnitOfWork, user: UserId) -> Result<(), DomainError> {
        let found = self.users.get(uow, user).await?;
        if found.is_none_or(|found| found.status() == UserStatus::Deleted) {
            return Err(DomainError::not_found(
                "identity.user_not_found",
                "the user does not exist",
            ));
        }
        Ok(())
    }

    async fn check_units(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        units: &BTreeSet<UnitId>,
    ) -> Result<(), DomainError> {
        if units.is_empty() {
            return Ok(());
        }
        let known: BTreeSet<UnitId> = self
            .organizations
            .units(uow, organization)
            .await?
            .into_iter()
            .map(|unit| unit.id)
            .collect();
        if units.is_subset(&known) {
            Ok(())
        } else {
            Err(unit_not_found())
        }
    }
}

/// Ends every membership of a user, in the caller's unit of work: what
/// marking a user Deleted does.
///
/// # Errors
///
/// Returns an error only if storage fails.
pub(crate) async fn leave_every_organization(
    organizations: &dyn OrganizationRepository,
    uow: &mut dyn UnitOfWork,
    user: UserId,
    caller: &Caller,
    clock: &dyn Clock,
) -> Result<(), DomainError> {
    let mut events = Vec::new();
    for membership in organizations.memberships_of(uow, user).await? {
        if organizations
            .remove_membership(uow, membership.organization, user)
            .await?
        {
            events.push(OrganizationEvent::MemberRemoved {
                organization_id: membership.organization,
                user_id: user,
            });
        }
    }
    record(uow, caller, clock, &events)
}
