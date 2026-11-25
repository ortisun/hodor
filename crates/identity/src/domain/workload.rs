//! Service accounts and agents: principals of a tenant that are not people.
//!
//! A workload is a user of kind `service_account` or `agent`; this module
//! holds what only a workload has, its owners, and how its user's status
//! reads as a workload's. See `docs/architecture/contexts/identity.md`,
//! "Service accounts and agents".

use crate::domain::user::{Profile, User, UserKind, UserStatus};
use hodor_kernel::{DomainError, DomainEvent, UserId};
use serde::Serialize;

/// Most owners a workload has.
pub const MAX_WORKLOAD_OWNERS: usize = 10;

/// Where a workload is in its life, as an administrator sees it. A deleted
/// workload is never read, so it has no status here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkloadStatus {
    /// It gets tokens, and its tokens are in force.
    Active,
    /// It gets none, and none of its tokens is in force: deactivated, or
    /// suspended as a user.
    Disabled,
}

impl WorkloadStatus {
    /// The status of a workload whose user has `status`, if it is one that
    /// is read at all.
    #[must_use]
    pub const fn of(status: UserStatus) -> Option<Self> {
        match status {
            UserStatus::Active => Some(Self::Active),
            UserStatus::Pending | UserStatus::Suspended | UserStatus::Deactivated => {
                Some(Self::Disabled)
            }
            UserStatus::Deleted => None,
        }
    }

    /// The name used in the administration interface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

/// A service account or an agent, with its owners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workload {
    user: User,
    owners: Vec<UserId>,
}

impl Workload {
    /// The workload `user` is, with its `owners`, if `user` is a workload
    /// of `kind` that is not deleted.
    #[must_use]
    pub fn of(user: User, kind: UserKind, owners: Vec<UserId>) -> Option<Self> {
        (user.kind() == kind && kind.is_workload() && user.status() != UserStatus::Deleted)
            .then_some(Self { user, owners })
    }

    /// Its identifier, which its tokens name in `sub`.
    #[must_use]
    pub const fn id(&self) -> UserId {
        self.user.id()
    }

    /// `ServiceAccount` or `Agent`.
    #[must_use]
    pub const fn kind(&self) -> UserKind {
        self.user.kind()
    }

    /// Its name, which is its user's display name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.user
            .snapshot()
            .profile
            .display_name
            .as_deref()
            .unwrap_or_default()
    }

    /// Where it is in its life.
    #[must_use]
    pub fn status(&self) -> WorkloadStatus {
        WorkloadStatus::of(self.user.status()).unwrap_or(WorkloadStatus::Disabled)
    }

    /// The people responsible for it, in the order they became owners.
    #[must_use]
    pub fn owners(&self) -> &[UserId] {
        &self.owners
    }

    /// The user it is.
    #[must_use]
    pub const fn user(&self) -> &User {
        &self.user
    }
}

/// A workload's name, checked: 1 to 200 characters once the spaces at
/// either end are removed.
///
/// # Errors
///
/// `Invalid` with code `identity.display_name_invalid` for a name that is
/// empty or too long.
pub fn workload_profile(name: &str) -> Result<Profile, DomainError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > Profile::MAX_DISPLAY_NAME_LENGTH {
        return Err(DomainError::invalid(
            "identity.display_name_invalid",
            "the name of a service account or an agent has 1 to 200 characters",
        ));
    }
    Ok(Profile {
        display_name: Some(name.to_owned()),
        locale: None,
    })
}

/// The owners of a workload, checked for their number: 1 to 10, each
/// once. Repeats are dropped, keeping the first. Whether each is a person
/// of the tenant is for the use case, which loads them.
///
/// # Errors
///
/// `Invalid` with code `identity.workload_owner_required` for none, and
/// `identity.too_many_workload_owners` for more than ten.
pub fn checked_owners(owners: &[UserId]) -> Result<Vec<UserId>, DomainError> {
    let mut kept: Vec<UserId> = Vec::with_capacity(owners.len());
    for owner in owners {
        if !kept.contains(owner) {
            kept.push(*owner);
        }
    }
    if kept.is_empty() {
        return Err(DomainError::invalid(
            "identity.workload_owner_required",
            "a service account or an agent has at least one owner",
        ));
    }
    if kept.len() > MAX_WORKLOAD_OWNERS {
        return Err(DomainError::invalid(
            "identity.too_many_workload_owners",
            "a service account or an agent has at most 10 owners",
        ));
    }
    Ok(kept)
}

/// What changes the owners of a workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum WorkloadEvent {
    /// A person became an owner.
    OwnerAdded {
        /// The workload.
        workload_id: UserId,
        /// `service_account` or `agent`.
        kind: &'static str,
        /// The owner.
        owner_id: UserId,
    },
    /// A person stopped being an owner.
    OwnerRemoved {
        /// The workload.
        workload_id: UserId,
        /// `service_account` or `agent`.
        kind: &'static str,
        /// The owner.
        owner_id: UserId,
    },
}

impl WorkloadEvent {
    /// The events of replacing the owners `before` with `after`: who was
    /// added, then who was removed, each in its list's order.
    #[must_use]
    pub fn of_change(
        workload: UserId,
        kind: UserKind,
        before: &[UserId],
        after: &[UserId],
    ) -> Vec<Self> {
        let added = after
            .iter()
            .filter(|owner| !before.contains(owner))
            .map(|owner| Self::OwnerAdded {
                workload_id: workload,
                kind: kind.as_str(),
                owner_id: *owner,
            });
        let removed = before
            .iter()
            .filter(|owner| !after.contains(owner))
            .map(|owner| Self::OwnerRemoved {
                workload_id: workload,
                kind: kind.as_str(),
                owner_id: *owner,
            });
        added.chain(removed).collect()
    }
}

impl DomainEvent for WorkloadEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::OwnerAdded { .. } => "identity.workload_owner_added",
            Self::OwnerRemoved { .. } => "identity.workload_owner_removed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::Timestamp;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn workload(kind: UserKind) -> User {
        User::create(
            kind,
            vec![],
            workload_profile("Nightly export").expect("a name"),
            true,
            NOW,
        )
        .expect("a workload")
        .0
    }

    #[test]
    fn a_name_has_one_to_two_hundred_characters() {
        assert_eq!(
            workload_profile("  Nightly export  ")
                .expect("a name")
                .display_name
                .as_deref(),
            Some("Nightly export")
        );
        for name in ["", "   ", &"x".repeat(201)] {
            assert_eq!(
                workload_profile(name).expect_err("refused").code(),
                "identity.display_name_invalid"
            );
        }
        assert!(workload_profile(&"x".repeat(200)).is_ok());
    }

    #[test]
    fn a_workload_has_one_to_ten_owners_each_once() {
        let ana = UserId::generate();
        let bob = UserId::generate();
        assert_eq!(
            checked_owners(&[ana, bob, ana]).expect("owners"),
            vec![ana, bob]
        );
        assert_eq!(
            checked_owners(&[]).expect_err("none").code(),
            "identity.workload_owner_required"
        );
        let eleven: Vec<UserId> = (0..11).map(|_| UserId::generate()).collect();
        assert_eq!(
            checked_owners(&eleven).expect_err("too many").code(),
            "identity.too_many_workload_owners"
        );
        assert!(checked_owners(&eleven[..10]).is_ok());
    }

    #[test]
    fn only_a_workload_of_the_kind_asked_for_that_is_not_deleted_is_one() {
        let account = workload(UserKind::ServiceAccount);
        assert!(Workload::of(account.clone(), UserKind::ServiceAccount, vec![]).is_some());
        assert!(Workload::of(account.clone(), UserKind::Agent, vec![]).is_none());
        let person = User::create(
            UserKind::Human,
            vec![
                crate::domain::identifier::NormalizedIdentifier::parse(
                    crate::domain::identifier::IdentifierKind::Username,
                    "ana",
                )
                .expect("a username"),
            ],
            Profile::default(),
            true,
            NOW,
        )
        .expect("a person")
        .0;
        assert!(Workload::of(person, UserKind::Human, vec![]).is_none());
        let mut gone = account;
        gone.deactivate(NOW).expect("deactivate");
        let disabled = Workload::of(gone.clone(), UserKind::ServiceAccount, vec![]).expect("read");
        assert_eq!(disabled.status(), WorkloadStatus::Disabled);
        gone.mark_deleted(NOW).expect("delete");
        assert!(Workload::of(gone, UserKind::ServiceAccount, vec![]).is_none());
    }

    #[test]
    fn a_status_reads_as_a_workload_status() {
        assert_eq!(
            WorkloadStatus::of(UserStatus::Active),
            Some(WorkloadStatus::Active)
        );
        for status in [
            UserStatus::Pending,
            UserStatus::Suspended,
            UserStatus::Deactivated,
        ] {
            assert_eq!(WorkloadStatus::of(status), Some(WorkloadStatus::Disabled));
        }
        assert_eq!(WorkloadStatus::of(UserStatus::Deleted), None);
    }

    #[test]
    fn replacing_owners_announces_who_came_and_who_left() {
        let (workload, ana, bob, carla) = (
            UserId::generate(),
            UserId::generate(),
            UserId::generate(),
            UserId::generate(),
        );
        let events =
            WorkloadEvent::of_change(workload, UserKind::Agent, &[ana, bob], &[bob, carla]);
        assert_eq!(
            events,
            vec![
                WorkloadEvent::OwnerAdded {
                    workload_id: workload,
                    kind: "agent",
                    owner_id: carla
                },
                WorkloadEvent::OwnerRemoved {
                    workload_id: workload,
                    kind: "agent",
                    owner_id: ana
                },
            ]
        );
        assert_eq!(events[0].event_type(), "identity.workload_owner_added");
        assert_eq!(events[1].event_type(), "identity.workload_owner_removed");
        assert!(WorkloadEvent::of_change(workload, UserKind::Agent, &[ana], &[ana]).is_empty());
    }
}
