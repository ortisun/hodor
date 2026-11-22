# hodor-authorization

## Overview

The authorization context: it "answers whether a user may do something"
(`Cargo.toml` description). Users hold fixed roles per tenant; a check reads
the user's roles every time and denies unless a held role allows the
permission. The specification is `docs/architecture/contexts/authorization.md`
(`src/lib.rs`).

## Interface

- [src](./src/EGM.md): the public surface `hodor_authorization::api`, the
  `testing` module, and links to `application` and `domain`.
- Port trait implemented by adapters: `RoleAssignmentStore` (implemented in
  `crates/adapters-postgres/src/authorization.rs`).
- Service entry points: `AuthorizationService` (`assign`, `revoke`,
  `roles_of`, `check`).
- Domain events: `AuthorizationEvent` (`authorization.role_assigned`,
  `authorization.role_revoked`).

### Workspace dependencies (`Cargo.toml`)

- `hodor-kernel` (`crates/kernel`): units of work, events, errors, clock.
- External: `async-trait`, `serde`.

### Feature

- `testing = ["hodor-kernel/testing"]`: enables `src/testing.rs`, the
  in-memory store and its contract suite.

## Invariants

- Deny is the default (`src/domain/role.rs:Decision::for_roles`).
- Nothing is cached; roles are read on every check
  (`src/application/service.rs:AuthorizationService::check`).
- An unchanged assignment announces nothing
  (`src/application/service.rs:AuthorizationService::assign`, `::revoke`).
- Details per directory are in [src](./src/EGM.md).

## Side Effects

- Storage only through `RoleAssignmentStore`, inside `hodor_kernel` units of
  work; records `AuthorizationEvent` values with `UnitOfWork::record_event`.

## Verification

- Run: `cargo test -p hodor-authorization`
