# authorization/src/domain

## Overview

The domain model of the authorization context: the fixed permissions, the
fixed roles that hold them, the answer to a check (`role.rs`); the request an
engine answers (`request.rs`); the decision (`decision.rs`); the binding of a
resource server to an engine (`binding.rs`); native role-based access
control (`native.rs`); access control lists (`access_list.rs`); the record of decisions (`decision_log.rs`); and the context's events (`event.rs`). The code is pure. Both modules are `pub(crate)`; the public names
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
  | `ApplicationsRead` | `applications:read` |
  | `ApplicationsWrite` | `applications:write` |
  | `AssuranceLevelsRead` | `assurance-levels:read` (also the auditor's) |
  | `AssuranceLevelsWrite` | `assurance-levels:write` |
  | `CredentialsRead` | `credentials:read` |
  | `CredentialsWrite` | `credentials:write` |
  | `DecisionsRead` | `decisions:read` |
  | `DecisionLogWrite` | `decision-log:write` |
  | `RolesRead` | `roles:read` |
  | `RolesWrite` | `roles:write` |
  | `BindingsRead` | `bindings:read` |
  | `BindingsWrite` | `bindings:write` |
  | `PoliciesRead` | `policies:read` |
  | `PoliciesWrite` | `policies:write` |
  | `GroupsRead` | `groups:read` |
  | `GroupsWrite` | `groups:write` |
  | `OrganizationsRead` | `organizations:read` |
  | `OrganizationsWrite` | `organizations:write` |
  | `WorkloadsRead` | `workloads:read` |
  | `WorkloadsWrite` | `workloads:write` |
  | `WebhooksRead` | `webhooks:read` |
  | `WebhooksWrite` | `webhooks:write` |
  | `AccessEntriesRead` | `access-entries:read` |
  | `AccessEntriesWrite` | `access-entries:write` |
  | `CertificateAuthorityRead` | `certificate-authority:read` |
  | `CertificateAuthorityWrite` | `certificate-authority:write` |
  | `CertificateAuthoritySign` | `certificate-authority:sign` |

  `Permission::ALL` lists all thirty-six, `certificate-authority:read`, `certificate-authority:write` and `certificate-authority:sign` the last; `from_name(name) -> Option<Permission>`.
  The auditor holds every permission that ends in `:read`, and nothing else.
- `AUTHORIZATION_API_SCOPES` (`authz:evaluate`, `authz:simulate`, `authz:explain`) and `check_key_scopes(scopes, names_application)`: the rule every interface that makes an API key follows; a scope is a `Permission` name or one of those three (`authorization.scope_unknown`), and a scope of the Authorization API comes with an application, which comes with one (`authorization.scope_needs_application`, `authorization.application_without_scope`).
- `Role` (`role.rs:Role`): `TenantAdministrator` (`tenant_administrator`),
  `TenantAuditor` (`tenant_auditor`) and `CertificateSigner`
  (`certificate_signer`, holding `certificate-authority:sign` alone);
  `Role::ALL`, `as_str`,
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
- `ApplicationReference`: an application's identifier, 1 to 255 characters
  without control characters (`authorization.application_invalid`).
- `EvaluationContext { attributes, correlation_id, application }`.
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

### Native role-based access control (`native.rs`)

- `PermissionName`: `kind:action` (`authorization.permission_invalid`);
  `of(kind, action)`, `fixed(Permission)`.
- `PermissionDefinition { namespace, name, description }`.
- `RoleName` (`authorization.role_name_invalid`), `RoleKey { namespace, name
  }` with `built_in(Role)` and `reference()` (`namespace#name`).
- `RoleContents { description, permissions, includes, conditions }` with
  `unconditional(description, permissions, includes)`; a key of
  `conditions` that is not in `permissions` is
  `authorization.condition_without_permission`. `RoleDefinition` (`new`,
  `replaced`, `restore`, `built_in(Role)`).
- `RoleGraph`: `new`, `built_in`, `get`, `roles`, `including`,
  `check(candidate, declared)`, `permissions_held(start)`, and
  `holdings(start)`: each `Holding { namespace, permission, condition }`,
  the condition being the one of the role that holds the permission.
- `AssignmentScope` (`Tenant`, `Application`), `RoleAssignment` (`new`,
  `in_force_at`, `same_grant`), `Grant { namespace, permission, condition,
  assignment }`; crate-private `grants_of` and `grant_applies`.

### Access control lists (`access_list.rs`)

- `AccessEntryId` (`define_id!`).
- `AccessEntry::new(id, namespace, permission, resource_id, principal,
  granted_at)`: never `hodor:admin` (`authorization.namespace_reserved`), a
  resource identifier of 1 to 255 characters without control characters
  (`authorization.resource_invalid`); `resource_kind()` is the first half of
  the permission; `same_grant`, `reference()` (`entry:<identifier>`),
  `allows(namespace, permission, resource_id, principals)`.
- `AccessEntryFilter { namespace, resource_kind, resource_id, principal }`
  with `of(namespace)` and `passes(entry)`.
- `MATCHING_ENTRY` (`matching_entry`), `MAX_ENTRIES_PER_DECISION` (64);
  crate-private `principals_of(subject, groups)`: the subject and, for a
  user, a group principal for each resolved group.

### The record of decisions (`decision_log.rs`)

- `DecisionLogMode` (`Full`, `Sampled { allow_percent }` from 1 to 99,
  `DenyOnly`, `Off`): `parse(name, share)`, `as_str`, `allow_percent`,
  `keeps(effect, draw)`; `sampled` keeps every refusal and indeterminate
  decision and allows whose draw (0 to 99) is below the share.
- `MaskPath::parse`: `subject.attributes.…`, `asserted.…`,
  `resource.attributes.…` or `context.attributes.…`, at most 200
  characters, `*` only alone as the last segment.
- `DecisionLogSettings::new(mode, masks, retention_days)`: at most 32 masks
  (`MAX_MASKS`), kept sorted and once; retention from 1 to 400 days
  (`MIN_RETENTION_DAYS`, `MAX_RETENTION_DAYS`); `Default` is `Full`, no
  mask, 30 days. `reduced_input(request, subject_attributes,
  asserted_trusted)` gives the stored input and the masks that erased
  something.
- `DecisionRecord::of(settings, request, subject_attributes, decision)`;
  `DecisionFilter { from, to, effect, namespace, subject }` with `matches`.
- Every refusal of a setting is `authorization.decision_log_invalid`.

### Conditions (`condition.rs`)

- `Condition`: the text of a condition, 1 to 1000 characters
  (`MAX_CONDITION_LENGTH`), not blank, no control character but a line break
  or a tab (`authorization.condition_invalid`).
- `ConditionInput { subject, resource, action, context }` with
  `ConditionSubject { kind, id, attributes, asserted }`,
  `ConditionResource { kind, id, attributes }` and
  `ConditionContext { attributes, application, time }`;
  `ConditionInput::of(request, subject_attributes, now)`.
- `invalid(detail)`, `too_costly(detail)` and `failed(detail)` make the
  errors `authorization.condition_invalid`,
  `authorization.condition_too_costly` and `authorization.condition_failed`;
  `api` exports them as `condition_invalid`, `condition_too_costly` and
  `condition_failed`.

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
| `PermissionDeclared` | `namespace`, `permission` | `authorization.permission_declared` |
| `PermissionRemoved` | `namespace`, `permission` | `authorization.permission_removed` |
| `RoleDefined` | `namespace`, `name` | `authorization.role_defined` |
| `RoleRemoved` | `namespace`, `name` | `authorization.role_removed` |
| `PrincipalRoleAssigned` | `principal_kind`, `principal`, `namespace`, `role`, `application` | `authorization.principal_role_assigned` |
| `PrincipalRoleRevoked` | `principal_kind`, `principal`, `namespace`, `role`, `application` | `authorization.principal_role_revoked` |
| `AccessEntryGranted` | `entry`, `namespace`, `permission`, `resource`, `principal_kind`, `principal` | `authorization.access_entry_granted` |
| `AccessEntryRemoved` | `entry`, `namespace`, `permission`, `resource`, `principal_kind`, `principal` | `authorization.access_entry_removed` |

## Invariants

- The roles of `hodor:admin` are fixed (`role.rs:Role`); as native roles they
  are `RoleDefinition::built_in`, holding exactly `Role::permissions`.
- Nothing a tenant defines is in `hodor:admin`, and no tenant role includes
  a built-in role (`authorization.namespace_reserved`,
  `native.rs:RoleDefinition::checked`, `PermissionDefinition::new`,
  `RoleAssignment::new`).
- A role holds at most 200 permissions (`authorization.too_many_permissions`)
  and includes at most 50 roles (`authorization.too_many_included_roles`);
  a description has at most 500 characters
  (`authorization.description_invalid`).
- `RoleGraph::check`: only declared permissions of the role's namespace
  (`authorization.permission_not_declared`), included roles exist
  (`authorization.role_not_found`), no cycle anywhere
  (`authorization.role_cycle`), at most ten deep
  (`authorization.role_inclusion_too_deep`).
- An assignment ends after it starts (`authorization.validity_invalid`) and
  allows from its start up to but not at its end; one scoped to an
  application applies only to requests naming it.
- `TenantAdministrator` holds every permission (`Permission::ALL`);
  `TenantAuditor` holds `UsersRead`, `SessionsRead`, `AuditRead`,
  `IdentityProvidersRead`, `KeysRead` and `ApplicationsRead` only
  (`role.rs:Role::permissions`).
- Deny is the default: no role, and no role holding the permission, both give
  `Effect::Deny` with reason `no_matching_role`; otherwise the answer is
  `Effect::Allow` with the allowing role's name as reason
  (`role.rs:Decision::for_roles`).
- `Role::from_name` returns `Invalid` code `authorization.unknown_role` for an
  unknown name (`role.rs:Role::from_name`).
- An entry only allows, and only on its own resource of its own resource
  server, to its own principal (`access_list.rs:AccessEntry::allows`).
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
