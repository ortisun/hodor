//! Permissions, the fixed roles that hold them, and the answer to a check.

use hodor_kernel::DomainError;

/// Something that can be done: a kind of resource and an action on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    /// Seeing users and their login identifiers.
    UsersRead,
    /// Creating users and suspending them.
    UsersWrite,
    /// Seeing a user's sessions.
    SessionsRead,
    /// Ending a session.
    SessionsRevoke,
    /// Reading the audit log.
    AuditRead,
    /// Seeing identity providers, without their secrets.
    IdentityProvidersRead,
    /// Adding and changing identity providers.
    IdentityProvidersWrite,
    /// Seeing key versions, without anything of their keys.
    KeysRead,
    /// Rotating a signing key and revoking key versions.
    KeysWrite,
    /// Seeing applications, their clients and resource servers, without
    /// any secret.
    ApplicationsRead,
    /// Registering and changing applications, clients and resource
    /// servers, and giving clients secrets and keys.
    ApplicationsWrite,
    /// Seeing the tenant's assurance levels.
    AssuranceLevelsRead,
    /// Replacing the tenant's assurance levels.
    AssuranceLevelsWrite,
    /// Seeing which second factors a user has, never a secret or a code.
    CredentialsRead,
    /// Removing a user's second factors and recovery codes.
    CredentialsWrite,
}

impl Permission {
    /// Every permission.
    pub const ALL: [Self; 15] = [
        Self::UsersRead,
        Self::UsersWrite,
        Self::SessionsRead,
        Self::SessionsRevoke,
        Self::AuditRead,
        Self::IdentityProvidersRead,
        Self::IdentityProvidersWrite,
        Self::KeysRead,
        Self::KeysWrite,
        Self::ApplicationsRead,
        Self::ApplicationsWrite,
        Self::AssuranceLevelsRead,
        Self::AssuranceLevelsWrite,
        Self::CredentialsRead,
        Self::CredentialsWrite,
    ];

    /// The permission written as `resource:action`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UsersRead => "users:read",
            Self::UsersWrite => "users:write",
            Self::SessionsRead => "sessions:read",
            Self::SessionsRevoke => "sessions:revoke",
            Self::AuditRead => "audit:read",
            Self::IdentityProvidersRead => "identity-providers:read",
            Self::IdentityProvidersWrite => "identity-providers:write",
            Self::KeysRead => "keys:read",
            Self::KeysWrite => "keys:write",
            Self::ApplicationsRead => "applications:read",
            Self::ApplicationsWrite => "applications:write",
            Self::AssuranceLevelsRead => "assurance-levels:read",
            Self::AssuranceLevelsWrite => "assurance-levels:write",
            Self::CredentialsRead => "credentials:read",
            Self::CredentialsWrite => "credentials:write",
        }
    }

    /// Reads a permission written as `resource:action`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|permission| permission.as_str() == name)
    }
}

/// A named set of permissions. The roles are fixed in this version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// The people who run a tenant: every permission.
    TenantAdministrator,
    /// People who must be able to see everything and change nothing.
    TenantAuditor,
}

impl Role {
    /// Every role.
    pub const ALL: [Self; 2] = [Self::TenantAdministrator, Self::TenantAuditor];

    /// The name the role is stored and reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TenantAdministrator => "tenant_administrator",
            Self::TenantAuditor => "tenant_auditor",
        }
    }

    /// Reads a role by its name.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if there is no such role.
    pub fn from_name(name: &str) -> Result<Self, DomainError> {
        Self::ALL
            .into_iter()
            .find(|role| role.as_str() == name)
            .ok_or_else(|| {
                DomainError::invalid("authorization.unknown_role", "there is no such role")
            })
    }

    /// The permissions the role holds.
    #[must_use]
    pub const fn permissions(self) -> &'static [Permission] {
        match self {
            Self::TenantAdministrator => &Permission::ALL,
            Self::TenantAuditor => &[
                Permission::UsersRead,
                Permission::SessionsRead,
                Permission::AuditRead,
                Permission::IdentityProvidersRead,
                Permission::KeysRead,
                Permission::ApplicationsRead,
                Permission::AssuranceLevelsRead,
                Permission::CredentialsRead,
            ],
        }
    }

    /// Whether the role holds a permission.
    #[must_use]
    pub fn allows(self, permission: Permission) -> bool {
        self.permissions().contains(&permission)
    }
}

/// Whether something may be done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// It may.
    Allow,
    /// It may not. This is the answer unless something allows.
    Deny,
    /// It could not be decided: the engine failed, timed out, was not
    /// available or said so. Whoever enforces the answer treats it as deny.
    Indeterminate,
}

/// The answer to a check, with a reason that is safe to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// The answer.
    pub effect: Effect,
    /// Why: the role that allowed, or `no_matching_role`.
    pub reason: &'static str,
}

impl Decision {
    /// Decides from the roles a user holds. Deny is the default: no role,
    /// and no role holding the permission, are the same answer.
    #[must_use]
    pub fn for_roles(roles: &[Role], permission: Permission) -> Self {
        roles.iter().find(|role| role.allows(permission)).map_or(
            Self {
                effect: Effect::Deny,
                reason: "no_matching_role",
            },
            |role| Self {
                effect: Effect::Allow,
                reason: role.as_str(),
            },
        )
    }

    /// Whether the answer is allow.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.effect == Effect::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_administrator_may_do_everything_and_an_auditor_may_only_read() {
        for permission in Permission::ALL {
            assert!(Role::TenantAdministrator.allows(permission));
            let reads = permission.as_str().ends_with(":read");
            assert_eq!(
                Role::TenantAuditor.allows(permission),
                reads,
                "{}",
                permission.as_str()
            );
        }
    }

    #[test]
    fn deny_is_the_default() {
        let nobody = Decision::for_roles(&[], Permission::UsersRead);
        assert_eq!(nobody.effect, Effect::Deny);
        assert_eq!(nobody.reason, "no_matching_role");
        let auditor = Decision::for_roles(&[Role::TenantAuditor], Permission::UsersWrite);
        assert_eq!(auditor, nobody);
        assert!(!auditor.is_allowed());
    }

    #[test]
    fn any_role_holding_the_permission_allows_and_is_named() {
        let both = [Role::TenantAuditor, Role::TenantAdministrator];
        let read = Decision::for_roles(&both, Permission::AuditRead);
        assert!(read.is_allowed());
        assert_eq!(read.reason, "tenant_auditor");
        let write = Decision::for_roles(&both, Permission::UsersWrite);
        assert!(write.is_allowed());
        assert_eq!(write.reason, "tenant_administrator");
    }

    #[test]
    fn names_round_trip() {
        for role in Role::ALL {
            assert_eq!(Role::from_name(role.as_str()).ok(), Some(role));
        }
        assert!(Role::from_name("owner").is_err());
        for permission in Permission::ALL {
            assert_eq!(Permission::from_name(permission.as_str()), Some(permission));
        }
        assert_eq!(Permission::from_name("users:delete"), None);
    }
}
