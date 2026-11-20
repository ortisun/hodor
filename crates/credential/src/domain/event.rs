//! What happens to credentials, as other contexts hear about it.
//!
//! Events carry the user's identifier and nothing derived from a password.

use hodor_kernel::{DomainEvent, UserId};
use serde::Serialize;

/// An event about a user's password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum PasswordEvent {
    /// A password was set or reset without asking for the current one.
    Set {
        /// The user.
        user_id: UserId,
        /// Whether it must be changed at the next sign-in.
        must_change: bool,
    },
    /// A user changed their own password.
    Changed {
        /// The user.
        user_id: UserId,
    },
    /// A password was removed.
    Removed {
        /// The user.
        user_id: UserId,
    },
}

impl DomainEvent for PasswordEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Set { .. } => "credential.password_set",
            Self::Changed { .. } => "credential.password_changed",
            Self::Removed { .. } => "credential.password_removed",
        }
    }
}
