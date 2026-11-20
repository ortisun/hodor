//! What happens to users, as other contexts hear about it.
//!
//! Events carry identifiers of users and of login identifiers, and the
//! kind of a login identifier, but never its value: an email address is
//! personal data and stays in the identity tables.

use crate::domain::identifier::IdentifierId;
use hodor_kernel::{DomainEvent, UserId};
use serde::Serialize;

/// An event of the identity context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum UserEvent {
    /// A user was created.
    Created {
        /// The new user.
        user_id: UserId,
        /// `human`, `service_account` or `agent`.
        kind: &'static str,
        /// The status the user starts in.
        status: &'static str,
    },
    /// A pending user became active.
    Activated {
        /// The user.
        user_id: UserId,
    },
    /// The user was suspended.
    Suspended {
        /// The user.
        user_id: UserId,
        /// Why.
        reason: String,
    },
    /// A suspended user became active again.
    Reactivated {
        /// The user.
        user_id: UserId,
    },
    /// The user's account was closed.
    Deactivated {
        /// The user.
        user_id: UserId,
    },
    /// A closed account was reopened.
    Restored {
        /// The user.
        user_id: UserId,
    },
    /// The user was erased.
    Deleted {
        /// The user.
        user_id: UserId,
    },
    /// A login identifier was added.
    IdentifierAdded {
        /// The user.
        user_id: UserId,
        /// The new login identifier.
        identifier_id: IdentifierId,
        /// `username` or `email`.
        identifier_kind: &'static str,
    },
    /// A login identifier was verified for the first time.
    IdentifierVerified {
        /// The user.
        user_id: UserId,
        /// The login identifier.
        identifier_id: IdentifierId,
        /// `username` or `email`.
        identifier_kind: &'static str,
    },
    /// A login identifier was removed.
    IdentifierRemoved {
        /// The user.
        user_id: UserId,
        /// The removed login identifier.
        identifier_id: IdentifierId,
        /// `username` or `email`.
        identifier_kind: &'static str,
    },
    /// Another identifier of a kind became primary.
    PrimaryIdentifierChanged {
        /// The user.
        user_id: UserId,
        /// The login identifier that is primary now.
        identifier_id: IdentifierId,
        /// `username` or `email`.
        identifier_kind: &'static str,
    },
    /// The display name or locale changed.
    ProfileChanged {
        /// The user.
        user_id: UserId,
    },
}

impl DomainEvent for UserEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Created { .. } => "identity.user_created",
            Self::Activated { .. } => "identity.user_activated",
            Self::Suspended { .. } => "identity.user_suspended",
            Self::Reactivated { .. } => "identity.user_reactivated",
            Self::Deactivated { .. } => "identity.user_deactivated",
            Self::Restored { .. } => "identity.user_restored",
            Self::Deleted { .. } => "identity.user_deleted",
            Self::IdentifierAdded { .. } => "identity.identifier_added",
            Self::IdentifierVerified { .. } => "identity.identifier_verified",
            Self::IdentifierRemoved { .. } => "identity.identifier_removed",
            Self::PrimaryIdentifierChanged { .. } => "identity.primary_identifier_changed",
            Self::ProfileChanged { .. } => "identity.profile_changed",
        }
    }
}
