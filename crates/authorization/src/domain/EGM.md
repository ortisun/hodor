# authorization/src/domain

## Overview

The domain model of the authorization context: the fixed permissions, the
fixed roles that hold them, the answer to a check (`role.rs`); the request an
engine answers (`request.rs`); the decision (`decision.rs`); the binding of a
resource server to an engine (`binding.rs`); and the context's events
(`event.rs`). The code is pure. Both modules are `pub(crate)`; the public names
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
  | `KeysRead` | `keys:read` |
  | `KeysWrite` | `keys:write` |

  `Permission::ALL` lists all nine; `from_name(name) -> Option<Permission>`.
- `Role` (`role.rs:Role`): `TenantAdministrator` (`tenant_administrator`) and
  `TenantAuditor` (`tenant_auditor`); `Role::ALL`, `as_str`,
  `from_name(name) -> Result<Role, DomainError>`, `permissions()`,
  `allows(permission)`.
- `Effect` (`role.rs:Effect`): `Allow`, `Deny`, `Indeterminate`.
- `Decision { effect, reason }` (`role.rs:Decision`):
  `for_roles(roles, permission)`, `is_allowed()`.

### The request (`request.rs`)

- `Namespace`: `hodor:admin` (`Namespace::ADMINISTRATION`) or an
  `https://`/`urn:` audience of at most 255 characters without fragment or
  space (`authorization.namespace_invalid`).
- `Subject { kind: SubjectKind (User, Client), id }`: identifier of 1 to 255
  characters without control characters; `Subject::user(UserId)`,
  `user_id()`.
- `Attributes`: at most 64 names (`MAX_ATTRIBUTES`) with JSON values.
- `Action`, and the kind of a `Resource`: a lower-case letter, then
  lower-case letters, digits, `-`, `_`, `.`, at most 64 characters.
- `EvaluationContext { attributes, correlation_id }`.
- `AuthorizationRequest { namespace, subject, asserted, resource, action,
  context }`: never names a tenant.

### The decision (`decision.rs`)

- `DecisionId` (`define_id!`), `ReasonCode` (with the constants Hodor
  gives: `NO_ENGINE_BOUND`, `BINDING_UNAVAILABLE`, `ENGINE_UNAVAILABLE`,
  `SUBJECT_UNAVAILABLE`, `ENGINE_FAILED`, `ENGINE_TIMED_OUT`, `FAIL_OPEN`,
  `NO_MATCHING_ROLE`), `EngineId` (`native`), `PolicyRevision`,
  `PolicyReference`.
- `EngineAnswer { effect, reason, policy_version, matched_policies }`: an
  engine's part; at most 64 matched policies.
- `AuthorizationDecision { decision_id, effect, evaluated_at, engine,
  policy_version, reason, matched_policies, metadata }` with `permits()`;
  `DecisionMetadata { duration_microseconds, cache_hit, asserted_trusted }`.

### The binding (`binding.rs`)

- `BindingSettings { namespace, engine, time_limit, sensitive,
  fail_open_actions, trust_asserted }` (`new` gives the defaults:
  `DEFAULT_TIME_LIMIT` 200 milliseconds, not sensitive, nothing fails open,
  nothing trusted).
- `EngineBinding`: `new`, `changed`, `restore`, `administration()` (the
  fixed binding of `hodor:admin`), `fails_open(action)`.

### Domain events (`event.rs`)

`AuthorizationEvent` (`event.rs:AuthorizationEvent`), serialized untagged,
implements `hodor_kernel::DomainEvent`:

| Variant | Fields | `event_type` |
| --- | --- | --- |
| `RoleAssigned` | `user_id`, `role` (the role's name) | `authorization.role_assigned` |
| `RoleRevoked` | `user_id`, `role` (the role's name) | `authorization.role_revoked` |
| `EngineBound` | `namespace`, `engine` | `authorization.engine_bound` |
| `EngineUnbound` | `namespace` | `authorization.engine_unbound` |
| `FailedOpen` | `namespace`, `action`, `engine`, `cause` | `authorization.failed_open` |

## Invariants

- The roles are fixed in this version (`role.rs:Role`).
- `TenantAdministrator` holds every permission (`Permission::ALL`);
  `TenantAuditor` holds `UsersRead`, `SessionsRead`, `AuditRead`,
  `IdentityProvidersRead` and `KeysRead` only (`role.rs:Role::permissions`).
- Deny is the default: no role, and no role holding the permission, both give
  `Effect::Deny` with reason `no_matching_role`; otherwise the answer is
  `Effect::Allow` with the allowing role's name as reason
  (`role.rs:Decision::for_roles`).
- `Role::from_name` returns `Invalid` code `authorization.unknown_role` for an
  unknown name (`role.rs:Role::from_name`).
- A binding is never for `hodor:admin` (`authorization.namespace_reserved`);
  its time limit is 1 to 5000 whole milliseconds
  (`authorization.time_limit_invalid`); a sensitive binding lets nothing fail
  open (`authorization.fail_open_on_sensitive`); at most 50 actions fail open
  (`authorization.too_many_fail_open_actions`); a change keeps the namespace
  (`authorization.namespace_changed`) (`binding.rs:EngineBinding`).
- Only `Allow` permits (`decision.rs:AuthorizationDecision::permits`).

## Side Effects

- None: no storage, network, clock or other input and output.

## Verification

- Run: `cargo test -p hodor-authorization`
