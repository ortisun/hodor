//! Groups of users, and groups inside groups.
//!
//! `docs/architecture/contexts/identity.md`, under "Groups", is the
//! specification. The rules on nesting are pure functions over every link
//! between groups of a tenant, so that the in-memory store and PostgreSQL
//! give the same answers.

use hodor_kernel::{DomainError, DomainEvent, GroupId, Timestamp, UserId};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// The longest name of a group, in characters.
pub const MAX_NAME_CHARACTERS: usize = 100;
/// The longest description of a group, in characters.
pub const MAX_DESCRIPTION_CHARACTERS: usize = 500;

/// The name of a group, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupName(String);

impl GroupName {
    /// Checks a name: 1 to 100 characters, no control characters, no space
    /// at either end.
    ///
    /// # Errors
    ///
    /// `Invalid` with code `identity.group_name_invalid`.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        if name_fits(name) {
            Ok(Self(name.to_owned()))
        } else {
            Err(DomainError::invalid(
                "identity.group_name_invalid",
                "a group name has 1 to 100 characters, no control characters and no space at either end",
            ))
        }
    }

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name that must be unique in the tenant: the name in lower case.
    #[must_use]
    pub fn normalized(&self) -> String {
        self.0.to_lowercase()
    }
}

/// Whether a name of a group, an organization or a unit keeps the rules:
/// 1 to 100 characters, no control characters, no space at either end.
pub(crate) fn name_fits(name: &str) -> bool {
    let count = name.chars().count();
    (1..=MAX_NAME_CHARACTERS).contains(&count)
        && name.trim() == name
        && !name.chars().any(char::is_control)
}

/// Checks a description: up to 500 characters, no control characters but
/// line breaks.
///
/// # Errors
///
/// `Invalid` with code `identity.group_description_invalid`.
pub(crate) fn check_description(description: Option<&str>) -> Result<(), DomainError> {
    let Some(description) = description else {
        return Ok(());
    };
    let fits = description.chars().count() <= MAX_DESCRIPTION_CHARACTERS
        && !description
            .chars()
            .any(|character| character.is_control() && character != '\n');
    if fits {
        Ok(())
    } else {
        Err(DomainError::invalid(
            "identity.group_description_invalid",
            "a group description has up to 500 characters and no control characters but line breaks",
        ))
    }
}

/// What a group holds, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSnapshot {
    /// The group.
    pub id: GroupId,
    /// Its name.
    pub name: GroupName,
    /// Its description.
    pub description: Option<String>,
    /// When it was created.
    pub created_at: Timestamp,
    /// When it last changed.
    pub updated_at: Timestamp,
    /// Incremented on every update.
    pub version: u32,
}

/// A group of a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    state: GroupSnapshot,
}

impl Group {
    /// A new group.
    ///
    /// # Errors
    ///
    /// `Invalid` if the description breaks a rule.
    pub fn create(
        name: GroupName,
        description: Option<String>,
        now: Timestamp,
    ) -> Result<(Self, GroupEvent), DomainError> {
        check_description(description.as_deref())?;
        let id = GroupId::generate();
        let group = Self {
            state: GroupSnapshot {
                id,
                name,
                description,
                created_at: now,
                updated_at: now,
                version: 0,
            },
        };
        Ok((group, GroupEvent::Created { group_id: id }))
    }

    /// A group as it was stored.
    #[must_use]
    pub const fn from_snapshot(state: GroupSnapshot) -> Self {
        Self { state }
    }

    /// What the group holds.
    #[must_use]
    pub const fn snapshot(&self) -> &GroupSnapshot {
        &self.state
    }

    /// The group's identifier.
    #[must_use]
    pub const fn id(&self) -> GroupId {
        self.state.id
    }

    /// The group's name.
    #[must_use]
    pub const fn name(&self) -> &GroupName {
        &self.state.name
    }

    /// The group's description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.state.description.as_deref()
    }

    /// Replaces the name and the description. Nothing happens, and no
    /// event is given, when both are what they were.
    ///
    /// # Errors
    ///
    /// `Invalid` if the description breaks a rule.
    pub fn change(
        &mut self,
        name: GroupName,
        description: Option<String>,
        now: Timestamp,
    ) -> Result<Option<GroupEvent>, DomainError> {
        check_description(description.as_deref())?;
        if name == self.state.name && description == self.state.description {
            return Ok(None);
        }
        self.state.name = name;
        self.state.description = description;
        self.state.updated_at = now;
        Ok(Some(GroupEvent::Changed {
            group_id: self.state.id,
        }))
    }
}

/// A member of a group: a user, or another group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GroupMember {
    /// A user of the tenant.
    User(UserId),
    /// A group of the tenant, whose members are members through it.
    Group(GroupId),
}

impl GroupMember {
    /// `user` or `group`, as events and the interfaces name it.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Group(_) => "group",
        }
    }

    /// The member's identifier, as text.
    #[must_use]
    pub fn id_text(self) -> String {
        match self {
            Self::User(id) => id.to_string(),
            Self::Group(id) => id.to_string(),
        }
    }
}

/// Every link from a group to a group inside it, in one tenant: the
/// container first, the member second.
pub(crate) type Nesting = [(GroupId, GroupId)];

/// The groups directly inside each group.
fn inside(nesting: &Nesting) -> BTreeMap<GroupId, Vec<GroupId>> {
    let mut map: BTreeMap<GroupId, Vec<GroupId>> = BTreeMap::new();
    for &(container, member) in nesting {
        map.entry(container).or_default().push(member);
    }
    map
}

/// The groups each group is directly inside.
fn around(nesting: &Nesting) -> BTreeMap<GroupId, Vec<GroupId>> {
    let mut map: BTreeMap<GroupId, Vec<GroupId>> = BTreeMap::new();
    for &(container, member) in nesting {
        map.entry(member).or_default().push(container);
    }
    map
}

/// The longest chain of groups starting at `start` and following `links`,
/// counting `start`. The links hold no cycle, which the rules keep true.
fn longest_chain(start: GroupId, links: &BTreeMap<GroupId, Vec<GroupId>>) -> usize {
    fn walk(
        group: GroupId,
        links: &BTreeMap<GroupId, Vec<GroupId>>,
        known: &mut BTreeMap<GroupId, usize>,
    ) -> usize {
        if let Some(&length) = known.get(&group) {
            return length;
        }
        let length = 1 + links.get(&group).map_or(0, |next| {
            next.iter()
                .map(|&n| walk(n, links, known))
                .max()
                .unwrap_or(0)
        });
        known.insert(group, length);
        length
    }
    walk(start, links, &mut BTreeMap::new())
}

/// Every group reachable from `start` along `links`, `start` not counted
/// unless a link leads back to it.
fn reachable(start: GroupId, links: &BTreeMap<GroupId, Vec<GroupId>>) -> BTreeSet<GroupId> {
    let mut seen = BTreeSet::new();
    let mut waiting = vec![start];
    while let Some(group) = waiting.pop() {
        for &next in links.get(&group).into_iter().flatten() {
            if seen.insert(next) {
                waiting.push(next);
            }
        }
    }
    seen
}

/// The depth of `group`: the longest chain of groups inside it, counting
/// itself.
#[must_use]
pub fn depth(group: GroupId, nesting: &Nesting) -> usize {
    longest_chain(group, &inside(nesting))
}

/// Checks that `member` may be put inside `container`, given every link
/// the tenant has and the deepest a group may be.
///
/// # Errors
///
/// `Conflict` with code `identity.group_cycle` if `container` is `member`
/// or already inside it, and `identity.group_nesting_too_deep` if some
/// group would then be deeper than `max_depth`.
pub fn check_nesting(
    container: GroupId,
    member: GroupId,
    nesting: &Nesting,
    max_depth: u8,
) -> Result<(), DomainError> {
    let down = inside(nesting);
    if container == member || reachable(member, &down).contains(&container) {
        return Err(DomainError::conflict(
            "identity.group_cycle",
            "a group cannot be inside itself, directly or through other groups",
        ));
    }
    // The deepest group touched by the new link is at the top of the
    // longest chain that goes up from the container: the chain above it,
    // the container, and the deepest chain inside the member.
    let above = longest_chain(container, &around(nesting));
    let below = longest_chain(member, &down);
    if above + below > usize::from(max_depth) {
        return Err(DomainError::conflict(
            "identity.group_nesting_too_deep",
            "a group would be nested deeper than the tenant allows",
        ));
    }
    Ok(())
}

/// The groups a user is in: those they are directly in, and every group
/// those are inside.
#[must_use]
pub fn effective_groups(direct: &[GroupId], nesting: &Nesting) -> BTreeSet<GroupId> {
    let up = around(nesting);
    let mut found: BTreeSet<GroupId> = direct.iter().copied().collect();
    for &group in direct {
        found.extend(reachable(group, &up));
    }
    found
}

/// An event of a group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum GroupEvent {
    /// A group was created.
    Created {
        /// The group.
        group_id: GroupId,
    },
    /// Its name or description changed.
    Changed {
        /// The group.
        group_id: GroupId,
    },
    /// It was deleted.
    Deleted {
        /// The group.
        group_id: GroupId,
        /// How many direct members it had.
        members: u64,
    },
    /// A user or a group was added to it.
    MemberAdded {
        /// The group.
        group_id: GroupId,
        /// `user` or `group`.
        member_kind: &'static str,
        /// The member's identifier.
        member_id: String,
    },
    /// A user or a group was taken out of it.
    MemberRemoved {
        /// The group.
        group_id: GroupId,
        /// `user` or `group`.
        member_kind: &'static str,
        /// The member's identifier.
        member_id: String,
    },
}

impl GroupEvent {
    /// The event of adding `member` to `group`.
    #[must_use]
    pub fn added(group: GroupId, member: GroupMember) -> Self {
        Self::MemberAdded {
            group_id: group,
            member_kind: member.kind(),
            member_id: member.id_text(),
        }
    }

    /// The event of taking `member` out of `group`.
    #[must_use]
    pub fn removed(group: GroupId, member: GroupMember) -> Self {
        Self::MemberRemoved {
            group_id: group,
            member_kind: member.kind(),
            member_id: member.id_text(),
        }
    }
}

impl DomainEvent for GroupEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Created { .. } => "identity.group_created",
            Self::Changed { .. } => "identity.group_changed",
            Self::Deleted { .. } => "identity.group_deleted",
            Self::MemberAdded { .. } => "identity.group_member_added",
            Self::MemberRemoved { .. } => "identity.group_member_removed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn groups<const N: usize>() -> [GroupId; N] {
        let mut ids: Vec<GroupId> = (0..N).map(|_| GroupId::generate()).collect();
        ids.sort();
        ids.try_into().expect("N groups")
    }

    #[test]
    fn names_are_checked_and_compared_without_case() {
        assert_eq!(
            GroupName::parse("Finance").expect("a name").normalized(),
            "finance"
        );
        for bad in ["", " finance", "finance ", "fin\tance", &"x".repeat(101)] {
            assert!(GroupName::parse(bad).is_err(), "{bad:?}");
        }
        assert!(
            GroupName::parse(&"é".repeat(100)).is_ok(),
            "characters, not bytes"
        );
    }

    #[test]
    fn descriptions_allow_line_breaks_only() {
        assert!(check_description(Some("one\ntwo")).is_ok());
        assert!(check_description(Some("one\ttwo")).is_err());
        assert!(check_description(Some(&"x".repeat(501))).is_err());
        assert!(check_description(None).is_ok());
    }

    #[test]
    fn a_change_to_nothing_gives_no_event() {
        let now = Timestamp::UNIX_EPOCH;
        let name = GroupName::parse("finance").expect("a name");
        let (mut group, _) = Group::create(name.clone(), None, now).expect("a group");
        assert_eq!(group.change(name, None, now).expect("a change"), None);
        let renamed = GroupName::parse("Finance").expect("a name");
        assert!(
            group
                .change(renamed, None, now)
                .expect("a change")
                .is_some()
        );
    }

    #[test]
    fn a_group_cannot_be_inside_itself_however_far() {
        let [finance, payables, invoices] = groups();
        let nesting = [(finance, payables), (payables, invoices)];
        for (container, member) in [(finance, finance), (payables, finance), (invoices, finance)] {
            let refused = check_nesting(container, member, &nesting, 10).expect_err("a cycle");
            assert_eq!(refused.code(), "identity.group_cycle");
        }
        assert!(
            check_nesting(finance, invoices, &nesting, 10).is_ok(),
            "a second path is no cycle"
        );
    }

    #[test]
    fn depth_counts_the_longest_chain_inside_a_group() {
        let [a, b, c, d] = groups();
        assert_eq!(depth(a, &[]), 1);
        let nesting = [(a, b), (b, c), (a, d)];
        assert_eq!(depth(a, &nesting), 3);
        assert_eq!(depth(d, &nesting), 1);
    }

    #[test]
    fn nesting_past_the_bound_is_refused_wherever_the_bound_is_reached() {
        let [a, b, c, d, e] = groups();
        // a > b > c is depth 3; d > e is depth 2.
        let nesting = [(a, b), (b, c), (d, e)];
        assert!(
            check_nesting(c, d, &nesting, 5).is_ok(),
            "a > b > c > d > e is 5"
        );
        let refused = check_nesting(c, d, &nesting, 4).expect_err("too deep");
        assert_eq!(refused.code(), "identity.group_nesting_too_deep");
        // Putting a under e makes d the deepest: d > e > a > b > c.
        assert_eq!(
            check_nesting(e, a, &nesting, 4)
                .expect_err("too deep")
                .code(),
            "identity.group_nesting_too_deep"
        );
        assert!(check_nesting(e, a, &nesting, 5).is_ok());
    }

    #[test]
    fn effective_groups_follow_every_path_upward() {
        let [finance, payables, receivables, all] = groups();
        let nesting = [(finance, payables), (finance, receivables), (all, finance)];
        let found = effective_groups(&[payables], &nesting);
        assert_eq!(found, BTreeSet::from([payables, finance, all]));
        assert!(effective_groups(&[], &nesting).is_empty());
    }
}
