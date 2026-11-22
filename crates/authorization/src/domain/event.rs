//! What happens to role assignments and bindings, as other contexts hear
//! about it.

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
    /// A binding was made or changed.
    EngineBound {
        /// The resource server.
        namespace: String,
        /// The engine that answers for it.
        engine: String,
    },
    /// A binding was removed.
    EngineUnbound {
        /// The resource server.
        namespace: String,
    },
    /// A failure allowed, because the binding lets the action fail open.
    FailedOpen {
        /// The resource server.
        namespace: String,
        /// The action that was allowed.
        action: String,
        /// The engine that failed, if one was reached.
        engine: Option<String>,
        /// Why it failed, as a reason code.
        cause: String,
    },
}

impl DomainEvent for AuthorizationEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::RoleAssigned { .. } => "authorization.role_assigned",
            Self::RoleRevoked { .. } => "authorization.role_revoked",
            Self::EngineBound { .. } => "authorization.engine_bound",
            Self::EngineUnbound { .. } => "authorization.engine_unbound",
            Self::FailedOpen { .. } => "authorization.failed_open",
        }
    }
}
