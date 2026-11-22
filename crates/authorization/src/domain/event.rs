//! What happens to role assignments, as other contexts hear about it.

use hodor_kernel::{DomainEvent, UserId};
use serde::Serialize;

/// An event of the authorization context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AuthorizationEvent {
    /// A user was given a role.
    RoleAssigned {
        /// Who was given it.
        user_id: UserId,
        /// The role's name.
        role: &'static str,
    },
    /// A role was taken away from a user.
    RoleRevoked {
        /// Whose it was.
        user_id: UserId,
        /// The role's name.
        role: &'static str,
    },
}

impl DomainEvent for AuthorizationEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::RoleAssigned { .. } => "authorization.role_assigned",
            Self::RoleRevoked { .. } => "authorization.role_revoked",
        }
    }
}
