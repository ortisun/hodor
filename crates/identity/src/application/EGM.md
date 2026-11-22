# Identity application layer

## Overview

The use cases of the identity context (`IdentityService`) and the one storage
port they need (`UserRepository`). Each use case opens a unit of work bound to
the caller's tenant, loads or creates a `User` from the
[domain model](../domain/EGM.md), applies one domain operation, stores the
result and records the resulting events in the same unit of work. Both modules
are `pub(crate)` (`mod.rs`); other crates reach these types through
`hodor_identity::api` (`src/lib.rs`).

## Interface

### Port trait (`ports.rs`)

`UserRepository` (async, `Send + Sync`). Every method takes
`uow: &mut dyn UnitOfWork` and works inside the tenant that unit of work is
bound to. Implemented outside this crate by `PgUserRepository` in
`crates/adapters-postgres/src/identity.rs`, and in memory by
`InMemoryUsers` in `src/testing.rs`.

| Method | Contract (from the doc comments) |
| --- | --- |
| `insert(uow, user)` | Stores a new user. `Conflict` with code `identity.identifier_taken` if another user of the tenant already has one of its login identifiers. |
| `get(uow, id) -> Option<User>` | Loads a user of the tenant. |
| `find_by_identifier(uow, identifier: &NormalizedIdentifier) -> Option<User>` | Loads the tenant's user who has that login identifier. |
| `list(uow, after: Option<UserId>, limit: u32) -> Vec<User>` | Up to `limit` users of the tenant, in creation order, starting after `after`. |
| `update(uow, user)` | Stores changes to a user loaded earlier, identifiers included. The user's version must be the loaded one; on success the stored version is one higher. `Conflict` `identity.user_modified_concurrently` on a version mismatch, `Conflict` `identity.identifier_taken` if an identifier belongs to another user, `NotFound` if the user does not exist in the tenant. |

### Service entry points (`service.rs`)

- `CreateUser` (struct): `kind: UserKind`, `identifiers: Vec<(IdentifierKind, String)>` (as typed), `profile: Profile`, `confirmed: bool` (starts active).
- `IdentityService::new(units_of_work: Arc<dyn UnitOfWorkFactory>, users: Arc<dyn UserRepository>, clock: Arc<dyn Clock>)`. The service is `Clone`; its `Debug` output shows no fields.
- `create(tenant, command: CreateUser, caller) -> User`: runs `create_in` in its own unit of work and commits.
- `create_in(uow, command, verified: bool, caller) -> User`: parses each identifier with `NormalizedIdentifier::parse`, calls `User::create`, and, when `verified` is set, verifies every identifier whose kind `needs_verification()`. Inserts the user and records the events in the caller's unit of work; it does not commit. After an error the caller must abandon the unit of work (doc comment).
- `get(tenant, id) -> User`: `NotFound` with code `identity.user_not_found` if the tenant has no such user.
- `list(tenant, page: &PageRequest) -> Page<User>`: creation order, one page at a time. The cursor is a user identifier; a cursor that does not parse as `UserId` gives `Invalid` with code `request.cursor_invalid`. Asks the repository for `limit + 1` users to decide whether `next_cursor` is set.
- `find_by_login(tenant, typed: &str) -> Option<User>`: interprets the typed text with `NormalizedIdentifier::from_login`; a malformed value returns `Ok(None)` without touching storage.
- Lifecycle: `activate`, `suspend(…, reason, …)`, `reactivate`, `deactivate`, `restore`, `mark_deleted`. Each takes `(tenant, id, caller)` and returns the changed `User`.
- Login identifiers: `add_identifier(tenant, id, kind, value, caller)`, `verify_identifier(tenant, id, identifier: IdentifierId, caller)`, `choose_primary(…)`, `remove_identifier(…)`.
- `change_profile(tenant, id, profile, caller)`.

## Invariants

- Tenant scoping: every use case except `create_in` starts its unit of work with `units_of_work.begin(tenant)`; `create_in` uses the caller's unit of work. Event metadata takes the tenant from `uow.tenant().tenant_id()` (`service.rs: IdentityService::record`).
- One change per unit of work: the private `IdentityService::change` loads the user, applies one domain operation, and stores it with its events before committing. A change that produces no event (for example verifying an identifier that is already verified, or choosing the identifier that is already primary) is neither stored nor committed, and the user is returned unchanged.
- Business rules (status transitions, identifier limits, verification before an email address becomes primary, the last identifier) are enforced by `User` in the domain layer, not here. Uniqueness of an identifier across the users of a tenant is left to `UserRepository::insert` and `update`, which return `identity.identifier_taken`.
- Identifier values are parsed (`NormalizedIdentifier::parse`) before the clock is read or storage is touched, in `create_in` and `add_identifier`.

## Side Effects

- Storage through `UserRepository`: `insert` (`create_in`), `get` (`get`, `change`), `find_by_identifier` (`find_by_login`), `list` (`list`), `update` (`change`).
- Events: each `UserEvent` is wrapped in `EventEnvelope::new(EventMetadata::new(tenant_id, caller.actor, caller.correlation_id, clock), event)` and passed to `uow.record_event` in the same unit of work as the storage write (`IdentityService::record`). Nothing is recorded for reads.
- Commits: `create` and `change` call `uow.commit()`; `create_in`, `get`, `list` and `find_by_login` do not.
- Clock: `clock.now()` gives the timestamp passed to each domain operation, and the clock is passed to `EventMetadata::new`.

## Verification

- Run: `cargo test -p hodor-identity`
