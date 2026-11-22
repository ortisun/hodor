# hodor-session source

## Overview

The session context: the record that a user signed in to a tenant from a
browser, and for how long that remains true. It does not sign anyone in; it is
told that someone did (`lib.rs` crate documentation). The specification it
follows is `docs/architecture/contexts/session.md`.

`lib.rs` keeps `application` and `domain` private and exposes the public
surface through `pub mod api`.

## Interface

- `api` re-exports:
  - Port: `SessionStore`.
  - Service: `SessionService`, `StartSession`.
  - Event: `SessionEvent`.
  - Domain: `Assurance`, `ClientInfo`, `Session`, `SessionId`,
    `SessionSnapshot`, `SessionState`, `SessionTimeouts`, `SessionToken`,
    `TokenHash`.
- `testing` (public test-support module, compiled only under
  `#[cfg(any(test, feature = "testing"))]`; the `testing` feature enables
  `hodor-kernel/testing`):
  - `InMemorySessions`: a `SessionStore` kept in a shared
    `Arc<Mutex<BTreeMap<(TenantId, SessionId), Session>>>`.
  - `SequentialRandom`: a predictable `RandomSource` for tests only.
  - `Ports<'a> { units_of_work, sessions }` and
    `run_contract(ports: Ports<'_>)`: the store contract every
    implementation must pass; it panics on a broken rule.
- Subdirectories:
  - [application](./application/EGM.md): `SessionStore` port and
    `SessionService` use cases.
  - [domain](./domain/EGM.md): `Session` aggregate, token, hash, state and
    `SessionEvent`.

## Invariants

- Other crates may use only what `api` re-exports; `application` and
  `domain` are private modules (`lib.rs`).
- The store contract (`testing.rs:run_contract`) requires that a stored
  session loads back unchanged; lookups by identifier, by token hash and
  updates never cross tenants (an update from another tenant fails with
  `session.not_found`); a replaced token stops finding the session; a revoked
  session keeps its row with `revoked_at` and reason; `list_for_user` returns
  only the user's live sessions, newest first, and drops a session once its
  absolute expiry passes.
- `InMemorySessions::list_for_user` keeps non-revoked sessions whose
  `absolute_expires_at` is after `now`, sorted newest first by
  `(started_at, id)`.

## Side Effects

- None at the crate root. The `testing` module mutates in-process memory
  only (a mutex-guarded map and an atomic counter in `SequentialRandom`).

## Verification

- Run: `cargo test -p hodor-session`
