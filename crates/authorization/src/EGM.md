# authorization/src

## Overview

The source root of the `hodor-authorization` crate. `lib.rs` describes the
context: it "answers one question: may this subject do this? Hodor's
administration asks it through the fixed roles; applications ask it through
the engine bound to their resource server." The specification it follows is
`docs/architecture/contexts/authorization.md` (`lib.rs` crate comment).

The modules `application` and `domain` are private; other crates use only
`pub mod api`.

## Interface

### `lib.rs: pub mod api`

- Fixed roles: `RoleAssignmentStore` (port trait), `AuthorizationService`,
  `AuthorizationEvent`, `Decision`, `Effect`, `Permission`, `Role`.
- Engine contract, request: `AuthorizationRequest`, `Namespace`, `Subject`,
  `SubjectKind`, `Attributes`, `Resource`, `Action`, `EvaluationContext`.
- Engine contract, answer: `AuthorizationDecision`, `DecisionId`,
  `DecisionMetadata`, `EngineAnswer`, `EngineId`, `ReasonCode`,
  `PolicyRevision`, `PolicyReference`.
- Engines and bindings: `AuthorizationEngine`, `PolicySimulator`,
  `EngineCapabilities`, `EvaluationInput`, `PolicySelection`,
  `SimulationAnswer`, `EngineRegistry`, `FixedRoleEngine`,
  `FIXED_ROLES_REVISION`, `EngineBinding`, `BindingSettings`,
  `DEFAULT_TIME_LIMIT`, `EngineBindingStore`, `SubjectAttributeSource`,
  `EvaluationService`, `Simulation`, `MAX_BATCH`.

### `testing.rs` (public test support)

Compiled only under `#[cfg(any(test, feature = "testing"))]` (`lib.rs`), that
is, with the crate feature `testing`.

- `InMemoryRoleAssignments` (implements `RoleAssignmentStore`),
  `Ports { units_of_work, assignments }`, `run_contract(ports)`.
- `InMemoryEngineBindings` (implements `EngineBindingStore`; `fail(true)`
  makes it fail), `BindingPorts { units_of_work, bindings }`,
  `run_binding_contract(ports)`.
- `StaticSubjectAttributes` (implements `SubjectAttributeSource`; `set`,
  `fail`).
- `ScriptedEngine` (implements `AuthorizationEngine` and `PolicySimulator`):
  answers with a closure, remembers what it was given (`seen`, `batches`),
  can move a `FixedClock` forward on every call (`take`) and answer a batch
  short (`answer_short`).

### Subdirectories

- [application](./application/EGM.md): `AuthorizationService`,
  `EvaluationService`, the engine traits, `EngineRegistry`,
  `FixedRoleEngine` and the ports.
- [domain](./domain/EGM.md): `Permission`, `Role`, `Effect`, `Decision`, the
  request and decision types, `EngineBinding` and `AuthorizationEvent`.

## Invariants

- The contract suite `testing.rs:run_contract` states what every
  `RoleAssignmentStore` must do: a new user holds no roles; `assign` and
  `revoke` return `true` the first time and `false` when repeated; `roles_of`
  returns the held roles in sorted order; assignments belong to one user in
  one tenant.
- `testing.rs:run_binding_contract` states what every `EngineBindingStore`
  must do: every setting is kept as given; `list` is ordered by namespace;
  `put` replaces the binding of the same namespace; a binding belongs to its
  tenant; `remove` returns `true` once.

## Side Effects

- `lib.rs` has none.
- `InMemoryRoleAssignments` keeps assignments in an
  `Arc<Mutex<BTreeSet<..>>>` and ignores the assignment time
  (`testing.rs:InMemoryRoleAssignments`).
- Side effects of the use cases are listed in
  [application](./application/EGM.md).

## Verification

- Run: `cargo test -p hodor-authorization`
