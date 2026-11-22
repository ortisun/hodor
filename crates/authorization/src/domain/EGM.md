# authorization/src/domain

## Overview

The domain model of the authorization context: the fixed permissions, the
fixed roles that hold them, the answer to a check, and the context's events
(`role.rs`: "Permissions, the fixed roles that hold them, and the answer to a
check"). The code is pure. Both modules are `pub(crate)`; the public names
reach other crates through `hodor_authorization::api`.

## Interface

### Permissions and roles (`role.rs`)

- `Permission` (`role.rs:Permission`), written as `resource:action`:

  | Variant | `as_str` |
  | --- | --- |
  | `UsersRead` | `users:read` |
  | `UsersWrite` | `users:write` |
  | `SessionsRead` | `sessions:read` |
  | `SessionsRevoke` | `sessions:revoke` |
  | `AuditRead` | `audit:read` |
  | `IdentityProvidersRead` | `identity-providers:read` |
  | `IdentityProvidersWrite` | `identity-providers:write` |

  `Permission::ALL` lists all seven; `from_name(name) -> Option<Permission>`.
- `Role` (`role.rs:Role`): `TenantAdministrator` (`tenant_administrator`) and
  `TenantAuditor` (`tenant_auditor`); `Role::ALL`, `as_str`,
  `from_name(name) -> Result<Role, DomainError>`, `permissions()`,
  `allows(permission)`.
- `Effect` (`role.rs:Effect`): `Allow`, `Deny`.
- `Decision { effect, reason }` (`role.rs:Decision`):
  `for_roles(roles, permission)`, `is_allowed()`.

### Domain events (`event.rs`)

`AuthorizationEvent` (`event.rs:AuthorizationEvent`), serialized untagged,
implements `hodor_kernel::DomainEvent`:

| Variant | Fields | `event_type` |
| --- | --- | --- |
| `RoleAssigned` | `user_id`, `role` (the role's name) | `authorization.role_assigned` |
| `RoleRevoked` | `user_id`, `role` (the role's name) | `authorization.role_revoked` |

## Invariants

- The roles are fixed in this version (`role.rs:Role`).
- `TenantAdministrator` holds every permission (`Permission::ALL`);
  `TenantAuditor` holds `UsersRead`, `SessionsRead`, `AuditRead` and
  `IdentityProvidersRead` only (`role.rs:Role::permissions`).
- Deny is the default: no role, and no role holding the permission, both give
  `Effect::Deny` with reason `no_matching_role`; otherwise the answer is
  `Effect::Allow` with the allowing role's name as reason
  (`role.rs:Decision::for_roles`).
- `Role::from_name` returns `Invalid` code `authorization.unknown_role` for an
  unknown name (`role.rs:Role::from_name`).

## Side Effects

- None: no storage, network, clock or other input and output.

## Verification

- Run: `cargo test -p hodor-authorization`
