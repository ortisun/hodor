# authorization/src/application

## Overview

The use cases of the authorization context and the one storage port they need
(`mod.rs`: "Use cases of the authorization context and the port they need").
`AuthorizationService` assigns and revokes roles, lists a user's roles, and
answers whether a user holds a permission. Both modules are `pub(crate)`; the
public names reach other crates only through `hodor_authorization::api` in
`../lib.rs`.

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

### Service entry points (`service.rs`)

`AuthorizationService` (`service.rs:AuthorizationService`), `Clone`:

- `new(units_of_work, assignments, clock)`.
- `assign(tenant, user_id, role, caller)`: gives a user a role in the tenant.
- `revoke(tenant, user_id, role, caller)`: takes a role away.
- `roles_of(tenant, user_id) -> Vec<Role>`.
- `check(tenant, user_id, permission) -> Decision`: answers whether a user may
  do something in the tenant.

## Invariants

- Assigning a role the user already holds, or revoking one the user does not
  hold, changes nothing and announces nothing: the event is recorded and the
  unit of work committed only when the store reports a change
  (`service.rs:AuthorizationService::assign`, `::revoke`).
- `check` caches nothing: the user's roles are read every time, and the
  answer comes from `Decision::for_roles` (deny unless a held role allows).
  A caller that cannot get an answer must refuse
  (`service.rs:AuthorizationService::check`).

## Side Effects

- Each operation opens a unit of work through
  `hodor_kernel::UnitOfWorkFactory::begin` and calls the matching
  `RoleAssignmentStore` method (`service.rs:AuthorizationService`).
- `assign` reads `hodor_kernel::Clock::now` for the assignment time.
- On a change, records `AuthorizationEvent::RoleAssigned` or
  `AuthorizationEvent::RoleRevoked` with `UnitOfWork::record_event`, using the
  caller's actor and correlation identifier
  (`service.rs:AuthorizationService::record`).

## Verification

- Run: `cargo test -p hodor-authorization`
