# authorization/src/application

## Overview

The use cases of the authorization context, the engine contract and the
ports they need (`mod.rs`). `AuthorizationService` assigns and revokes roles,
lists a user's roles, and answers whether a user holds a permission.
`EvaluationService` keeps the bindings and evaluates requests through the
bound engine. The modules are `pub(crate)`; the public names reach other
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

`SubjectAttributeSource` (`ports.rs:SubjectAttributeSource`):
`attributes_of(tenant, subject) -> Attributes`; an unknown subject has none.
Implemented only by `StaticSubjectAttributes` in `../testing.rs` so far.

### Engines (`engine.rs`, `fixed_roles.rs`)

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
- `FixedRoleEngine::new(units_of_work, assignments)`: named `native`;
  answers from the fixed roles with the permission
  `<resource kind>:<action>`, revision `fixed_roles`, the allowing role as
  the matched policy; a subject that is not a user holds no role.

### Service entry points (`service.rs`)

`AuthorizationService` (`service.rs:AuthorizationService`), `Clone`:

- `new(units_of_work, assignments, clock)`.
- `assign(tenant, user_id, role, caller)`: gives a user a role in the tenant.
- `revoke(tenant, user_id, role, caller)`: takes a role away.
- `roles_of(tenant, user_id) -> Vec<Role>`.
- `check(tenant, user_id, permission) -> Decision`: answers whether a user may
  do something in the tenant.

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
- `hodor:admin` is always answered by the service's own `FixedRoleEngine`,
  never by a registered engine, even one named `native`.
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
  `FailedOpen` events. `FixedRoleEngine` opens a unit of work to read
  roles.

## Verification

- Run: `cargo test -p hodor-authorization`
