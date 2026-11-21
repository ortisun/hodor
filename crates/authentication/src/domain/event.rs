//! What happens during sign-ins, as other contexts hear about it.
//!
//! Events never carry the identifier that was typed, an email address, a
//! token, a link or anything about a password.

use hodor_kernel::{DomainEvent, Timestamp, UserId};
use serde::Serialize;

/// An event of the authentication context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AuthenticationEvent {
    /// A sign-in completed and a session started.
    Succeeded {
        /// Who signed in.
        user_id: UserId,
        /// The session that started, by its identifier.
        session_id: String,
        /// The methods that were satisfied.
        methods: Vec<String>,
    },
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
    /// A person finished registering.
    RegistrationCompleted {
        /// The user that was created.
        user_id: UserId,
    },
    /// A recovery link was sent to a user.
    RecoveryRequested {
        /// Whose password may be chosen anew.
        user_id: UserId,
    },
    /// A person chose a new password with a recovery link.
    PasswordReset {
        /// Whose password it is.
        user_id: UserId,
    },
}

impl DomainEvent for AuthenticationEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Succeeded { .. } => "authentication.succeeded",
            Self::Failed { .. } => "authentication.failed",
            Self::LockedOut { .. } => "authentication.locked_out",
            Self::RegistrationCompleted { .. } => "authentication.registration_completed",
            Self::RecoveryRequested { .. } => "authentication.recovery_requested",
            Self::PasswordReset { .. } => "authentication.password_reset",
        }
    }
}
