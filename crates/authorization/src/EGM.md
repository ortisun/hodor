# authorization/src

## Overview

The source root of the `hodor-authorization` crate. `lib.rs` describes the
context: it "answers one question: may this user do this? Other parts of
Hodor ask it and obey the answer." The specification it follows is
`docs/architecture/contexts/authorization.md` (`lib.rs` crate comment).

The modules `application` and `domain` are private; other crates use only
`pub mod api`.

## Interface

### `lib.rs: pub mod api`

- `RoleAssignmentStore` (port trait), `AuthorizationService`,
  `AuthorizationEvent`, `Decision`, `Effect`, `Permission`, `Role`.

### `testing.rs` (public test support)

Compiled only under `#[cfg(any(test, feature = "testing"))]` (`lib.rs`), that
is, with the crate feature `testing`.

- `InMemoryRoleAssignments` (implements `RoleAssignmentStore`),
  `Ports { units_of_work, assignments }`, `run_contract(ports)`.

### Subdirectories

- [application](./application/EGM.md): `AuthorizationService` and the
  `RoleAssignmentStore` port.
- [domain](./domain/EGM.md): `Permission`, `Role`, `Effect`, `Decision` and
  `AuthorizationEvent`.

## Invariants

- The contract suite `testing.rs:run_contract` states what every
  `RoleAssignmentStore` must do: a new user holds no roles; `assign` and
  `revoke` return `true` the first time and `false` when repeated; `roles_of`
  returns the held roles in sorted order; assignments belong to one user in
  one tenant.

## Side Effects

- `lib.rs` has none.
- `InMemoryRoleAssignments` keeps assignments in an
  `Arc<Mutex<BTreeSet<..>>>` and ignores the assignment time
  (`testing.rs:InMemoryRoleAssignments`).
- Side effects of the use cases are listed in
  [application](./application/EGM.md).

## Verification

- Run: `cargo test -p hodor-authorization`
