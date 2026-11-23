# hodor-authorization

## Overview

The authorization context: it "answers whether a user may do something"
(`Cargo.toml` description). Two parts:

- the fixed roles of Milestone 1: users hold fixed roles per tenant; a check
  reads the user's roles every time and denies unless a held role allows the
  permission;
- the engine contract of Decision 0009 (Issue-72): requests about a resource
  server are answered by the engine its binding names; a missing binding
  denies; any failure is indeterminate unless the binding lets the action
  fail open; `hodor:admin` is always answered by the `NativeEngine` from
  the built-in roles;
- native role-based access control (Issue-73): permissions a tenant
  declares per resource server, roles that hold them and include other
  roles (hierarchy and composites, no cycle, at most ten deep), assignments
  to users and clients for the tenant or one application with an optional
  start and end, managed by `RoleService` and answered by `NativeEngine`.

The specification is `docs/architecture/contexts/authorization.md`
(`src/lib.rs`).

## Interface

- [src](./src/EGM.md): the public surface `hodor_authorization::api`, the
  `testing` module, and links to `application` and `domain`.
- Port traits implemented by adapters: `RoleAssignmentStore`,
  `EngineBindingStore` and `NativeRoleStore` (all in
  `crates/adapters-postgres/src/authorization.rs`); `ConditionLanguage`
  (implemented by `CelConditionLanguage` in `crates/authorization-native`);
  `SubjectAttributeSource` (no implementation yet outside `testing`).
- Engine traits implemented by engines: `AuthorizationEngine`,
  `PolicySimulator`; `NativeEngine` is the one in this crate.
- Service entry points: `AuthorizationService` (`assign`, `revoke`,
  `roles_of`, `check`), `EvaluationService` (`bind`, `unbind`, `binding`,
  `bindings`, `evaluate`, `evaluate_batch`, `simulate`) and `RoleService`
  (`declare_permission`, `remove_permission`, `permissions`, `define_role`,
  `remove_role`, `roles`, `role`, `assign`, `revoke`, `assignments_of`).
- Domain events: `AuthorizationEvent` (`authorization.role_assigned`,
  `authorization.role_revoked`, `authorization.engine_bound`,
  `authorization.engine_unbound`, `authorization.failed_open`,
  `authorization.permission_declared`, `authorization.permission_removed`,
  `authorization.role_defined`, `authorization.role_removed`,
  `authorization.principal_role_assigned`,
  `authorization.principal_role_revoked`).

### Workspace dependencies (`Cargo.toml`)

- `hodor-kernel` (`crates/kernel`): units of work, events, errors, clock.
- External: `async-trait`, `serde`, `serde_json` (attribute values);
  `time` only with the `testing` feature.

### Feature

- `testing = ["hodor-kernel/testing", "dep:time"]`: enables
  `src/testing.rs`, the in-memory stores, the stand-in engine and attribute
  source, and the contract suites.

## Invariants

- Deny is the default (`src/domain/role.rs:Decision::for_roles`).
- Nothing is cached for `hodor:admin`; roles are read on every check
  (`src/application/service.rs:AuthorizationService::check`,
  `src/application/native.rs:NativeEngine`). For other namespaces the
  native engine keeps what a principal's assignments come to per tenant and
  reads again whenever the tenant's role revision changed
  (`src/application/native.rs:NativeEngine::tenant_answer`); every change
  through `RoleService` raises the revision first, in its own transaction
  (`src/application/roles.rs:RoleService::changing`).
- Nothing a tenant defines reaches `hodor:admin`: no permission or role
  there, no role including a built-in role, no assignment of a built-in role
  through `RoleService` (`src/domain/native.rs`).
- An unchanged assignment announces nothing
  (`src/application/service.rs:AuthorizationService::assign`, `::revoke`).
- Only `Effect::Allow` permits (`src/domain/decision.rs:AuthorizationDecision::permits`).
- `EvaluationService::evaluate` always returns a decision; every failure is
  `Effect::Indeterminate` unless the binding lets the action fail open and
  the `authorization.failed_open` event was committed
  (`src/application/evaluation.rs`).
- `hodor:admin` is never stored, bound, unbound or simulated
  (`src/domain/binding.rs:EngineBinding::check`,
  `src/application/evaluation.rs:EvaluationService`).
- A simulation is never recorded, nor a decision about `hodor:admin`; a
  masked path is removed before a record is built
  (`src/application/decision_log.rs:DecisionLog::record`,
  `src/domain/decision_log.rs:DecisionLogSettings::reduced_input`).
- Details per directory are in [src](./src/EGM.md).

## Side Effects

- Storage only through `RoleAssignmentStore`, `EngineBindingStore` and
  `NativeRoleStore`,
  inside `hodor_kernel` units of work; records `AuthorizationEvent` values
  with `UnitOfWork::record_event`.
- `EvaluationService` calls the registered engines and the
  `SubjectAttributeSource`, and reads `hodor_kernel::Clock::now` to stamp and
  time decisions. `NativeEngine` reads the clock for the start and end of
  assignments and keeps an in-process cache, emptied when it holds 10,000
  principals.

## Verification

- Run: `cargo test -p hodor-authorization`
