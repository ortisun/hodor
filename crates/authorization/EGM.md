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
  fail open; `hodor:admin` is always answered by `FixedRoleEngine`.

The specification is `docs/architecture/contexts/authorization.md`
(`src/lib.rs`).

## Interface

- [src](./src/EGM.md): the public surface `hodor_authorization::api`, the
  `testing` module, and links to `application` and `domain`.
- Port traits implemented by adapters: `RoleAssignmentStore` and
  `EngineBindingStore` (both in
  `crates/adapters-postgres/src/authorization.rs`); `SubjectAttributeSource`
  (no implementation yet outside `testing`).
- Engine traits implemented by engines: `AuthorizationEngine`,
  `PolicySimulator`; `FixedRoleEngine` is the one in this crate.
- Service entry points: `AuthorizationService` (`assign`, `revoke`,
  `roles_of`, `check`) and `EvaluationService` (`bind`, `unbind`, `binding`,
  `bindings`, `evaluate`, `evaluate_batch`, `simulate`).
- Domain events: `AuthorizationEvent` (`authorization.role_assigned`,
  `authorization.role_revoked`, `authorization.engine_bound`,
  `authorization.engine_unbound`, `authorization.failed_open`).

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
- Nothing is cached; roles are read on every check
  (`src/application/service.rs:AuthorizationService::check`).
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
- Details per directory are in [src](./src/EGM.md).

## Side Effects

- Storage only through `RoleAssignmentStore` and `EngineBindingStore`,
  inside `hodor_kernel` units of work; records `AuthorizationEvent` values
  with `UnitOfWork::record_event`.
- `EvaluationService` calls the registered engines and the
  `SubjectAttributeSource`, and reads `hodor_kernel::Clock::now` to stamp and
  time decisions.

## Verification

- Run: `cargo test -p hodor-authorization`
