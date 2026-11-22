# hodor-session

## Overview

The `hodor-session` crate (`Cargo.toml` description: "The session context:
the record that a user signed in, and for how long that remains true.").
It owns browser sessions inside a tenant: starting them, finding them by the
token a browser presents, listing, revoking and replacing tokens. Storage,
randomness, hashing and time are reached through ports and kernel traits.

## Interface

- Source and public surface: [src](./src/EGM.md).
- Port implemented elsewhere: `SessionStore`, by `PgSessionStore` in
  `crates/adapters-postgres/src/session.rs`.
- Workspace dependencies: `hodor-kernel` (`crates/kernel`), plus
  `async-trait`, `serde` and `time`.
- Feature `testing`: enables the public `testing` module and
  `hodor-kernel/testing`.
- Dev dependencies: `hodor-kernel` with `testing`, the crate itself with
  `testing`, `proptest`, `tokio`.

## Invariants

- Only the `api` module is public to other crates; see
  [src](./src/EGM.md).
- Tokens leave the crate once, from `SessionService::start` or
  `SessionService::replace_token`; only their SHA-256 hash is stored, and
  events never carry either (see [domain](./src/domain/EGM.md)).
- Every store call is scoped to the tenant of the unit of work (see
  [application](./src/application/EGM.md)).

## Side Effects

- Through `SessionStore`: reads and writes sessions. Through
  `UnitOfWork::record_event`: records `session.started` and
  `session.revoked` events in the unit of work each use case begins.

## Verification

- Run: `cargo test -p hodor-session`
