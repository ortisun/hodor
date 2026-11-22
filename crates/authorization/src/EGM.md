# authorization/src

## Overview

The source root of the `hodor-authorization` crate. `lib.rs` describes the
context: it "answers one question: may this subject do this? Hodor's
administration asks it through the built-in roles; applications ask it
through the engine bound to their resource server, such as the native
engine over the roles the tenant defined." The specification it follows is
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
  `SimulationAnswer`, `EngineRegistry`, `NativeEngine`,
  `FIXED_ROLES_REVISION`, `MATCHING_ROLE`, `EngineBinding`,
  `BindingSettings`, `DEFAULT_TIME_LIMIT`, `EngineBindingStore`,
  `SubjectAttributeSource`, `EvaluationService`, `Simulation`, `MAX_BATCH`,
  `ApplicationReference`.
- Native role-based access control: `NativeRoleStore` (port trait),
  `RoleService`, `Validity`, `PermissionName`, `PermissionDefinition`,
  `RoleName`, `RoleKey`, `RoleContents`, `RoleDefinition`, `RoleGraph`,
  `AssignmentScope`, `RoleAssignment`, `Grant`, `MAX_DESCRIPTION_LENGTH`,
  `MAX_ROLE_PERMISSIONS`, `MAX_INCLUDED_ROLES`, `MAX_INCLUSION_DEPTH`.

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
- `InMemoryNativeRoles` (implements `NativeRoleStore`; like the database it
  refuses a role naming an undeclared permission or a missing role, an
  assignment of a missing role, and removing an included role),
  `NativeRolePorts { units_of_work, roles }`,
  `run_native_role_contract(ports)`.
- `ScriptedEngine` (implements `AuthorizationEngine` and `PolicySimulator`):
  answers with a closure, remembers what it was given (`seen`, `batches`),
  can move a `FixedClock` forward on every call (`take`) and answer a batch
  short (`answer_short`).

### Subdirectories

- [application](./application/EGM.md): `AuthorizationService`,
  `EvaluationService`, `RoleService`, the engine traits, `EngineRegistry`,
  `NativeEngine` and the ports.
- [domain](./domain/EGM.md): `Permission`, `Role`, `Effect`, `Decision`, the
  request and decision types, `EngineBinding`, `AuthorizationEvent` and the
  native role-based access control types (`native.rs`).

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
- `testing.rs:run_native_role_contract` states what every
  `NativeRoleStore` must do: the revision starts at zero and each raise adds
  one, per tenant; permissions are listed by name and putting again
  describes again; roles keep what they hold and include and are listed by
  namespace and name; a role naming an undeclared permission or a missing
  role is refused; removing a permission removes it from every role;
  assignments are keyed by principal, role and scope, putting again replaces
  the start and end, and they are listed by role and scope; an assignment of
  a missing role is refused; a role another role includes cannot be removed
  (`authorization.role_in_use`); removing a role removes its assignments;
  nothing is seen from another tenant.

## Side Effects

- `lib.rs` has none.
- `InMemoryRoleAssignments` keeps assignments in an
  `Arc<Mutex<BTreeSet<..>>>` and ignores the assignment time
  (`testing.rs:InMemoryRoleAssignments`).
- Side effects of the use cases are listed in
  [application](./application/EGM.md).

## Verification

- Run: `cargo test -p hodor-authorization`
