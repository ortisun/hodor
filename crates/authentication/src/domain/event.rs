//! What happens during sign-ins, as other contexts hear about it.
//!
//! Events never carry the identifier that was typed or anything about a
//! password.

use hodor_kernel::{DomainEvent, Timestamp, UserId};
use serde::Serialize;

/// An event of the authentication context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AuthenticationEvent {
    /// A step of a sign-in was rejected.
    Failed {
        /// The step that was rejected.
        step: String,
        /// The user it was attempted for, when the identifier belongs to
        /// someone.
        user_id: Option<UserId>,
    },
    /// An identifier or an address reached its limit of failed attempts.
    LockedOut {
        /// `identifier` or `address`.
        subject: &'static str,
        /// When the lockout ends.
        #[serde(with = "time::serde::rfc3339")]
        until: Timestamp,
    },
}

impl DomainEvent for AuthenticationEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Failed { .. } => "authentication.failed",
            Self::LockedOut { .. } => "authentication.locked_out",
        }
    }
}
