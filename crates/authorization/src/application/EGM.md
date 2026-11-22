# authorization/src/application

## Overview

The use cases of the authorization context, the engine contract and the
ports they need (`mod.rs`). `AuthorizationService` assigns and revokes roles,
lists a user's roles, and answers whether a user holds a permission.
`EvaluationService` keeps the bindings and evaluates requests through the
bound engine. `RoleService` declares permissions, defines roles and assigns
them for native role-based access control, which `NativeEngine` answers
from. The modules are `pub(crate)`; the public names reach other
crates only through `hodor_authorization::api` in `../lib.rs`.

## Interface

### Port trait (`ports.rs`)

`RoleAssignmentStore` (`ports.rs:RoleAssignmentStore`), implemented outside
this crate by `PgRoleAssignmentStore` in
`crates/adapters-postgres/src/authorization.rs` and, for tests, by
`InMemoryRoleAssignments` in `../testing.rs`. Every method works inside the
tenant the unit of work is bound to.

- `assign(uow, user_id, role, now) -> bool`: gives a user a role; `false` if
  the user already held it.
- `revoke(uow, user_id, role) -> bool`: takes a role away; `false` if the user
  did not hold it.
- `roles_of(uow, user_id) -> Vec<Role>`: the roles a user holds in the tenant,
  in a fixed order.

`EngineBindingStore` (`ports.rs:EngineBindingStore`), implemented by
`PgEngineBindingStore` in `crates/adapters-postgres/src/authorization.rs`
and `InMemoryEngineBindings` in `../testing.rs`: `put` (replaces the binding
of the same namespace), `find`, `list` (ordered by namespace), `remove`
(returns whether there was one).

`NativeRoleStore` (`ports.rs:NativeRoleStore`), implemented by
`PgNativeRoleStore` in `crates/adapters-postgres/src/authorization.rs` and
`InMemoryNativeRoles` in `../testing.rs`: `raise_revision`, `revision`,
`put_permission`, `remove_permission`, `permissions`, `put_role`, `roles`,
`remove_role` (`authorization.role_in_use` when included), `put_assignment`,
`remove_assignment`, `assignments_of` (never the built-in roles).

`SubjectAttributeSource` (`ports.rs:SubjectAttributeSource`):
`attributes_of(tenant, subject) -> Attributes`; an unknown subject has none.
Implemented only by `StaticSubjectAttributes` in `../testing.rs` so far.

### Engines (`engine.rs`, `native.rs`)

- `AuthorizationEngine`: `id`, `capabilities`, `evaluate(tenant, input)`,
  `evaluate_batch(tenant, inputs)` (by default one after the other).
- `PolicySimulator`: `simulate(tenant, input, against)`.
- `EvaluationInput { request, subject_attributes, time_limit }`,
  `EngineCapabilities { simulation, explanation }`,
  `PolicySelection` (`Published`, `Revision`, `Draft`),
  `SimulationAnswer { answer, trace }`.
- `EngineRegistry`: `register`, `register_with_simulator` (a name only
  once: `authorization.engine_registered_twice`), `engine`, `simulator`,
  `contains`.
- `NativeEngine::new(units_of_work, assignments, roles, clock)`: named
  `native`. For `hodor:admin` it answers from the built-in roles with the
  permission `<resource kind>:<action>`, revision `fixed_roles`, the first
  allowing role as reason and matched policy; a subject that is not a user
  holds no role. For any other namespace it answers from the tenant's
  roles: allow with `matching_role`, the assigned roles that led there
  written `namespace#role` (at most 64), and the tenant's role revision;
  otherwise deny with `no_matching_role`.
- `NativeEngine::administration(units_of_work, assignments)`: the same for
  `hodor:admin` only; any other namespace is an error. `EvaluationService`
  uses it for `hodor:admin`.

### Service entry points (`service.rs`)

`AuthorizationService` (`service.rs:AuthorizationService`), `Clone`:

- `new(units_of_work, assignments, clock)`.
- `assign(tenant, user_id, role, caller)`: gives a user a role in the tenant.
- `revoke(tenant, user_id, role, caller)`: takes a role away.
- `roles_of(tenant, user_id) -> Vec<Role>`.
- `check(tenant, user_id, permission) -> Decision`: answers whether a user may
  do something in the tenant.

`RoleService` (`roles.rs:RoleService`), `Clone`:

- `new(units_of_work, store, clock)`.
- `declare_permission(tenant, namespace, name, description, caller)`,
  `remove_permission(tenant, namespace, name, caller) -> bool`,
  `permissions(tenant, namespace)`.
- `define_role(tenant, key, contents, caller)`, `remove_role(tenant, key,
  caller) -> bool`, `roles(tenant)`, `role(tenant, key)`.
- `assign(tenant, principal, role, scope, validity, caller)`,
  `revoke(tenant, principal, role, scope, caller) -> bool`,
  `assignments_of(tenant, principal)`.

`EvaluationService` (`evaluation.rs:EvaluationService`), `Clone`:

- `new(units_of_work, assignments, bindings, subjects, registry, clock)`.
- `bind(tenant, settings, caller) -> EngineBinding`,
  `unbind(tenant, namespace, caller) -> bool`, `binding(tenant, namespace)`,
  `bindings(tenant)`.
- `evaluate(tenant, request) -> AuthorizationDecision`,
  `evaluate_batch(tenant, requests) -> Vec<AuthorizationDecision>` (at most
  `MAX_BATCH`, 100), `simulate(tenant, request, against) -> Simulation`.

## Invariants

- Assigning a role the user already holds, or revoking one the user does not
  hold, changes nothing and announces nothing: the event is recorded and the
  unit of work committed only when the store reports a change
  (`service.rs:AuthorizationService::assign`, `::revoke`).
- `check` caches nothing: the user's roles are read every time, and the
  answer comes from `Decision::for_roles` (deny unless a held role allows).
  A caller that cannot get an answer must refuse
  (`service.rs:AuthorizationService::check`).
- `evaluate` always returns a decision. No binding: `Deny`,
  `no_engine_bound`. The binding cannot be read (`binding_unavailable`), its
  engine is not registered (`engine_unavailable`), the subject cannot be
  resolved (`subject_unavailable`), the engine fails or answers a batch of
  the wrong length (`engine_failed`), answers after the time limit
  (`engine_timed_out`) or answers `Indeterminate` (its own reason): all
  `Indeterminate`, unless the binding fails open for the action and the
  `FailedOpen` event commits, which gives `Allow`, `fail_open`.
- `hodor:admin` is always answered by the service's own administration
  `NativeEngine`, never by a registered engine, even one named `native`.
- Every `RoleService` change raises the tenant's role revision first, in
  the same unit of work, which also serializes changes of one tenant; then
  it reads the roles, checks them with `RoleGraph::check` (included roles
  exist, declared permissions only, no cycle, at most ten deep) and stores.
  A change that changes nothing is not committed and announces nothing.
  A role another role includes is not removed (`authorization.role_in_use`).
- `NativeEngine` reads the revision on every decision and reads the
  principal's assignments and the tenant's roles again when it differs from
  what it keeps, so a change takes effect on the next decision on any
  instance.
- Asserted attributes are emptied before the engine sees them unless the
  binding trusts them (`evaluation.rs:EvaluationService::input`).
- Requests of one binding go to its engine together; a batch of n has n
  times the binding's time limit (`evaluation.rs:EvaluationService::ask`).
- Binding again with the same settings announces nothing; unbinding what is
  not bound announces nothing.

## Side Effects

- Each operation opens a unit of work through
  `hodor_kernel::UnitOfWorkFactory::begin` and calls the matching
  `RoleAssignmentStore` method (`service.rs:AuthorizationService`).
- `assign` reads `hodor_kernel::Clock::now` for the assignment time.
- On a change, records `AuthorizationEvent::RoleAssigned` or
  `AuthorizationEvent::RoleRevoked` with `UnitOfWork::record_event`, using the
  caller's actor and correlation identifier
  (`service.rs:AuthorizationService::record`).
- `EvaluationService` opens units of work to read and write bindings, calls
  engines and the `SubjectAttributeSource`, reads the clock to stamp and time
  every decision, and commits `EngineBound`, `EngineUnbound` and
  `FailedOpen` events. `NativeEngine` opens a unit of work to read roles,
  the revision and assignments, and keeps a cache in memory. `RoleService`
  commits the native role-based access control events.

## Verification

- Run: `cargo test -p hodor-authorization`
