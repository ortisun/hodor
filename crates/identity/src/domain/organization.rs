//! Organizations, their units and their members.
//!
//! `docs/architecture/contexts/identity.md`, under "Organizations", is the
//! specification. The rules of the tree are pure functions over every
//! unit of one organization, as the rules of nesting are for groups.

use crate::domain::group::{check_description, name_fits};
use hodor_kernel::{DomainError, DomainEvent, OrganizationId, Timestamp, UserId};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// The deepest level a unit may be at; a unit at the top is at level 1.
pub const MAX_UNIT_LEVELS: usize = 10;

hodor_kernel::define_id!(
    /// Identifies a unit of an organization.
    UnitId
);

/// A name of an organization or a unit, checked as a group's name is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationName(String);

impl OrganizationName {
    /// Checks a name.
    ///
    /// # Errors
    ///
    /// `Invalid` with code `identity.organization_name_invalid`.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        if name_fits(name) {
            Ok(Self(name.to_owned()))
        } else {
            Err(DomainError::invalid(
                "identity.organization_name_invalid",
                "a name has 1 to 100 characters, no control characters and no space at either end",
            ))
        }
    }

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name compared without regard to case.
    #[must_use]
    pub fn normalized(&self) -> String {
        self.0.to_lowercase()
    }
}

/// What an organization holds, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationSnapshot {
    /// The organization.
    pub id: OrganizationId,
    /// Its name.
    pub name: OrganizationName,
    /// Its description.
    pub description: Option<String>,
    /// When it was created.
    pub created_at: Timestamp,
    /// When it last changed.
    pub updated_at: Timestamp,
    /// Incremented on every update.
    pub version: u32,
}

/// An organization of a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Organization {
    state: OrganizationSnapshot,
}

impl Organization {
    /// A new organization.
    ///
    /// # Errors
    ///
    /// `Invalid` if the description breaks a rule.
    pub fn create(
        name: OrganizationName,
        description: Option<String>,
        now: Timestamp,
    ) -> Result<(Self, OrganizationEvent), DomainError> {
        check_description(description.as_deref())?;
        let id = OrganizationId::generate();
        let organization = Self {
            state: OrganizationSnapshot {
                id,
                name,
                description,
                created_at: now,
                updated_at: now,
                version: 0,
            },
        };
        Ok((
            organization,
            OrganizationEvent::Created {
                organization_id: id,
            },
        ))
    }

    /// An organization as it was stored.
    #[must_use]
    pub const fn from_snapshot(state: OrganizationSnapshot) -> Self {
        Self { state }
    }

    /// What the organization holds.
    #[must_use]
    pub const fn snapshot(&self) -> &OrganizationSnapshot {
        &self.state
    }

    /// The organization's identifier.
    #[must_use]
    pub const fn id(&self) -> OrganizationId {
        self.state.id
    }

    /// The organization's name.
    #[must_use]
    pub const fn name(&self) -> &OrganizationName {
        &self.state.name
    }

    /// The organization's description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.state.description.as_deref()
    }

    /// Replaces the name and the description; no event when nothing
    /// changes.
    ///
    /// # Errors
    ///
    /// `Invalid` if the description breaks a rule.
    pub fn change(
        &mut self,
        name: OrganizationName,
        description: Option<String>,
        now: Timestamp,
    ) -> Result<Option<OrganizationEvent>, DomainError> {
        check_description(description.as_deref())?;
        if name == self.state.name && description == self.state.description {
            return Ok(None);
        }
        self.state.name = name;
        self.state.description = description;
        self.state.updated_at = now;
        Ok(Some(OrganizationEvent::Changed {
            organization_id: self.state.id,
        }))
    }
}

/// What a unit is called by its organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitKind {
    /// A part of the organization.
    Unit,
    /// A department: a unit the organization calls so.
    Department,
}

impl UnitKind {
    /// `unit` or `department`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Department => "department",
        }
    }

    /// Reads a kind as stored or as given.
    ///
    /// # Errors
    ///
    /// `Invalid` with code `identity.unit_kind_invalid`.
    pub fn parse(kind: &str) -> Result<Self, DomainError> {
        match kind {
            "unit" => Ok(Self::Unit),
            "department" => Ok(Self::Department),
            _ => Err(DomainError::invalid(
                "identity.unit_kind_invalid",
                "a unit is of kind unit or department",
            )),
        }
    }
}

/// A unit of an organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    /// The unit.
    pub id: UnitId,
    /// The organization it belongs to.
    pub organization: OrganizationId,
    /// The unit it is part of, or none at the top.
    pub parent: Option<UnitId>,
    /// Its name, unique among the units that share its parent.
    pub name: OrganizationName,
    /// What the organization calls it.
    pub kind: UnitKind,
    /// When it was created.
    pub created_at: Timestamp,
    /// When it last changed.
    pub updated_at: Timestamp,
}

/// What a unit becomes when it is changed: its parent, or none at the top,
/// its name and its kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitChange {
    /// The unit it is to be part of, or none at the top.
    pub parent: Option<UnitId>,
    /// Its name.
    pub name: String,
    /// What the organization calls it.
    pub kind: UnitKind,
}

/// Every unit of one organization and its parent.
pub type Tree = BTreeMap<UnitId, Option<UnitId>>;

/// The level of a unit: 1 at the top.
fn level(unit: UnitId, tree: &Tree) -> usize {
    let mut level = 1;
    let mut current = unit;
    while let Some(Some(parent)) = tree.get(&current) {
        level += 1;
        current = *parent;
        if level > tree.len() + 1 {
            break; // A cycle in what was stored; the rules never write one.
        }
    }
    level
}

/// The longest chain of units below a unit, counting it.
fn height(unit: UnitId, tree: &Tree) -> usize {
    let mut children: BTreeMap<UnitId, Vec<UnitId>> = BTreeMap::new();
    for (&child, parent) in tree {
        if let Some(parent) = parent {
            children.entry(*parent).or_default().push(child);
        }
    }
    fn walk(
        unit: UnitId,
        children: &BTreeMap<UnitId, Vec<UnitId>>,
        seen: &mut BTreeSet<UnitId>,
    ) -> usize {
        if !seen.insert(unit) {
            return 0;
        }
        1 + children.get(&unit).map_or(0, |below| {
            below
                .iter()
                .map(|&c| walk(c, children, seen))
                .max()
                .unwrap_or(0)
        })
    }
    walk(unit, &children, &mut BTreeSet::new())
}

/// Checks that `unit`, carrying the units below it, may be put under
/// `parent`, or at the top when `parent` is none. A unit not yet in the
/// tree carries nothing.
///
/// # Errors
///
/// `NotFound` with code `identity.unit_not_found` for a parent that is not
/// in the tree, `Conflict` with code `identity.unit_cycle` for a parent
/// that is the unit or below it, and `identity.unit_tree_too_deep` past
/// ten levels.
pub fn check_placement(
    unit: UnitId,
    parent: Option<UnitId>,
    tree: &Tree,
) -> Result<(), DomainError> {
    let Some(parent) = parent else {
        let carried = if tree.contains_key(&unit) {
            height(unit, tree)
        } else {
            1
        };
        return too_deep(carried);
    };
    if !tree.contains_key(&parent) {
        return Err(DomainError::not_found(
            "identity.unit_not_found",
            "the unit does not exist in this organization",
        ));
    }
    let mut current = Some(parent);
    while let Some(step) = current {
        if step == unit {
            return Err(DomainError::conflict(
                "identity.unit_cycle",
                "a unit cannot be put under itself or a unit below it",
            ));
        }
        current = tree.get(&step).copied().flatten();
    }
    let carried = if tree.contains_key(&unit) {
        height(unit, tree)
    } else {
        1
    };
    too_deep(level(parent, tree) + carried)
}

fn too_deep(levels: usize) -> Result<(), DomainError> {
    if levels > MAX_UNIT_LEVELS {
        return Err(DomainError::conflict(
            "identity.unit_tree_too_deep",
            "units of an organization go at most ten levels deep",
        ));
    }
    Ok(())
}

/// A user's membership of an organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// The organization.
    pub organization: OrganizationId,
    /// The user.
    pub user: UserId,
    /// The units of the organization the user is in.
    pub units: BTreeSet<UnitId>,
    /// When the user joined.
    pub added_at: Timestamp,
}

/// An event of organizations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum OrganizationEvent {
    /// An organization was created.
    Created {
        /// The organization.
        organization_id: OrganizationId,
    },
    /// Its name or description changed.
    Changed {
        /// The organization.
        organization_id: OrganizationId,
    },
    /// It was deleted.
    Deleted {
        /// The organization.
        organization_id: OrganizationId,
        /// How many members it had.
        members: u64,
    },
    /// A unit was created.
    UnitCreated {
        /// The organization.
        organization_id: OrganizationId,
        /// The unit.
        unit_id: UnitId,
        /// Its parent, if any.
        parent_id: Option<UnitId>,
        /// `unit` or `department`.
        kind: &'static str,
    },
    /// A unit's name, kind or parent changed.
    UnitChanged {
        /// The organization.
        organization_id: OrganizationId,
        /// The unit.
        unit_id: UnitId,
    },
    /// A unit was deleted.
    UnitDeleted {
        /// The organization.
        organization_id: OrganizationId,
        /// The unit.
        unit_id: UnitId,
    },
    /// A user became a member.
    MemberAdded {
        /// The organization.
        organization_id: OrganizationId,
        /// The user.
        user_id: UserId,
        /// The units the user is in.
        units: Vec<UnitId>,
    },
    /// The units of a membership changed.
    MemberChanged {
        /// The organization.
        organization_id: OrganizationId,
        /// The user.
        user_id: UserId,
        /// The units the user is in now.
        units: Vec<UnitId>,
    },
    /// A user stopped being a member.
    MemberRemoved {
        /// The organization.
        organization_id: OrganizationId,
        /// The user.
        user_id: UserId,
    },
}

impl DomainEvent for OrganizationEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Created { .. } => "identity.organization_created",
            Self::Changed { .. } => "identity.organization_changed",
            Self::Deleted { .. } => "identity.organization_deleted",
            Self::UnitCreated { .. } => "identity.unit_created",
            Self::UnitChanged { .. } => "identity.unit_changed",
            Self::UnitDeleted { .. } => "identity.unit_deleted",
            Self::MemberAdded { .. } => "identity.organization_member_added",
            Self::MemberChanged { .. } => "identity.organization_member_changed",
            Self::MemberRemoved { .. } => "identity.organization_member_removed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chain of `n` units, each under the one before it.
    fn chain(n: usize) -> (Vec<UnitId>, Tree) {
        let units: Vec<UnitId> = (0..n).map(|_| UnitId::generate()).collect();
        let mut tree = Tree::new();
        for (index, unit) in units.iter().enumerate() {
            tree.insert(*unit, index.checked_sub(1).map(|before| units[before]));
        }
        (units, tree)
    }

    #[test]
    fn a_unit_cannot_go_under_itself_or_below_itself() {
        let (units, tree) = chain(3);
        for parent in [units[0], units[1], units[2]] {
            let refused = check_placement(units[0], Some(parent), &tree).expect_err("a cycle");
            assert_eq!(refused.code(), "identity.unit_cycle");
        }
        assert!(check_placement(units[2], None, &tree).is_ok(), "to the top");
    }

    #[test]
    fn ten_levels_and_no_more() {
        let (units, tree) = chain(10);
        let new = UnitId::generate();
        let refused = check_placement(new, Some(units[9]), &tree).expect_err("an eleventh level");
        assert_eq!(refused.code(), "identity.unit_tree_too_deep");
        assert!(
            check_placement(new, Some(units[8]), &tree).is_ok(),
            "a tenth level"
        );

        // Moving a chain of three under the eighth level makes eleven.
        let (mut others, mut both) = chain(3);
        both.extend(tree);
        let refused =
            check_placement(others.remove(0), Some(units[7]), &both).expect_err("too deep");
        assert_eq!(refused.code(), "identity.unit_tree_too_deep");
    }

    #[test]
    fn a_parent_of_another_organization_is_not_found() {
        let (_, tree) = chain(2);
        let refused = check_placement(UnitId::generate(), Some(UnitId::generate()), &tree)
            .expect_err("not in the tree");
        assert_eq!(refused.code(), "identity.unit_not_found");
    }

    #[test]
    fn kinds_and_names_are_checked() {
        assert_eq!(
            UnitKind::parse("department").expect("a kind"),
            UnitKind::Department
        );
        assert!(UnitKind::parse("team").is_err());
        assert!(OrganizationName::parse(" Acme").is_err());
        assert_eq!(
            OrganizationName::parse("Acme")
                .expect("a name")
                .normalized(),
            "acme"
        );
    }
}
