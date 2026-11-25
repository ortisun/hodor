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
    /// A permission was declared for a resource server, or described again.
    PermissionDeclared {
        /// The resource server.
        namespace: String,
        /// The permission.
        permission: String,
    },
    /// A permission was removed, and with it from every role.
    PermissionRemoved {
        /// The resource server.
        namespace: String,
        /// The permission.
        permission: String,
    },
    /// A role was created or replaced.
    RoleDefined {
        /// The resource server.
        namespace: String,
        /// The role's name.
        name: String,
    },
    /// A role was removed, with its assignments.
    RoleRemoved {
        /// The resource server.
        namespace: String,
        /// The role's name.
        name: String,
    },
    /// A role was given to a principal, or its start and end changed.
    PrincipalRoleAssigned {
        /// `user` or `client`.
        principal_kind: &'static str,
        /// The user's or the client's identifier.
        principal: String,
        /// The role's resource server.
        namespace: String,
        /// The role's name.
        role: String,
        /// The application it is scoped to; nothing for the whole tenant.
        application: Option<String>,
    },
    /// A role was taken away from a principal.
    PrincipalRoleRevoked {
        /// `user` or `client`.
        principal_kind: &'static str,
        /// The user's or the client's identifier.
        principal: String,
        /// The role's resource server.
        namespace: String,
        /// The role's name.
        role: String,
        /// The application it was scoped to; nothing for the whole tenant.
        application: Option<String>,
    },
    /// An entry of an access control list was granted.
    AccessEntryGranted {
        /// The entry's identifier.
        entry: String,
        /// The resource server.
        namespace: String,
        /// The permission it gives.
        permission: String,
        /// The resource's identifier.
        resource: String,
        /// `user`, `client` or `group`.
        principal_kind: &'static str,
        /// The principal's identifier.
        principal: String,
    },
    /// An entry of an access control list was removed.
    AccessEntryRemoved {
        /// The entry's identifier.
        entry: String,
        /// The resource server.
        namespace: String,
        /// The permission it gave.
        permission: String,
        /// The resource's identifier.
        resource: String,
        /// `user`, `client` or `group`.
        principal_kind: &'static str,
        /// The principal's identifier.
        principal: String,
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
    /// The tenant's settings of the record of decisions changed.
    DecisionLogChanged {
        /// The mode.
        mode: &'static str,
        /// The share of allows kept, for `sampled`.
        allow_percent: Option<u8>,
        /// How many masks there are; the paths are not announced.
        masks: usize,
        /// How many days records are kept.
        retention_days: u16,
    },
}

impl DomainEvent for AuthorizationEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::RoleAssigned { .. } => "authorization.role_assigned",
            Self::RoleRevoked { .. } => "authorization.role_revoked",
            Self::EngineBound { .. } => "authorization.engine_bound",
            Self::EngineUnbound { .. } => "authorization.engine_unbound",
            Self::PermissionDeclared { .. } => "authorization.permission_declared",
            Self::PermissionRemoved { .. } => "authorization.permission_removed",
            Self::RoleDefined { .. } => "authorization.role_defined",
            Self::RoleRemoved { .. } => "authorization.role_removed",
            Self::PrincipalRoleAssigned { .. } => "authorization.principal_role_assigned",
            Self::PrincipalRoleRevoked { .. } => "authorization.principal_role_revoked",
            Self::AccessEntryGranted { .. } => "authorization.access_entry_granted",
            Self::AccessEntryRemoved { .. } => "authorization.access_entry_removed",
            Self::FailedOpen { .. } => "authorization.failed_open",
            Self::DecisionLogChanged { .. } => "authorization.decision_log_changed",
        }
    }
}
