# Session domain

## Overview

The session aggregate, its token and its lifecycle, plus the events other
contexts hear about. The domain is pure: time, randomness and hashing are
passed in by the caller. Both modules are `pub(crate)` in `mod.rs`; the types
below are re-exported through `crate::api`.

## Interface

### `session.rs`

- `SessionId`: identifier defined with `hodor_kernel::define_id!`; safe to
  show and log.
- `Assurance { SingleFactor, MultiFactor, PhishingResistant }` (ordered) with `as_str()`
  (`"single_factor"` / `"multi_factor"`) and `from_stored(&str)`.
- `SessionTimeouts { idle: Duration, absolute: Duration }`.
- `ClientInfo { address: Option<String>, description: Option<String> }`,
  `MAX_DESCRIPTION_LENGTH = 256`.
- `SessionToken`: wraps `hodor_kernel::Secret<String>`; `LENGTH = 64`,
  `expose() -> &str`, `hash(&dyn Digest) -> TokenHash`. No public
  constructor; tokens come from `Session::start` and `Session::replace_token`.
- `TokenHash([u8; 32])` with `of_presented(&str, &dyn Digest) -> Option<Self>`,
  `from_stored([u8; 32])`, `as_bytes()`.
- `SessionState { Active, Expired, Revoked }`.
- `SessionSnapshot`: the stored state (`id`, `user_id`, `token_hash`,
  `signed_in_at`, `assurance`, `methods`, `method_proven_at` (one time per method), `started_at`, `last_activity_at`,
  `idle_timeout`, `absolute_expires_at`, `client`, `revoked_at`,
  `revocation_reason`).
- `Session` methods: `start(user_id, assurance, methods, timeouts, client, now,
  random, digest) -> Result<(Session, SessionToken, SessionEvent), DomainError>`,
  `from_snapshot`, `snapshot`, `id`, `user_id`, `expires_at`,
  `state_at(now) -> SessionState`, `record_activity(now) -> bool`,
  `revoke(reason, now) -> Option<SessionEvent>`,
  `replace_token(now, random, digest) -> Result<SessionToken, DomainError>`,
  `proofs() -> Vec<(&str, Timestamp)>` (each method with when it was last proven),
  `raise(proven, assurance, now, random, digest) -> Result<(SessionToken, SessionEvent), DomainError>`
  (adds or re-times the proven methods, keeps the higher assurance, sets
  `signed_in_at`, replaces the token; `Conflict` `session.not_active` unless active);
  constant `ACTIVITY_RESOLUTION = Duration::minutes(1)`.

### `event.rs`

`SessionEvent` (`Serialize`, untagged) implements `hodor_kernel::DomainEvent`:

| Variant | Fields | `event_type()` |
| --- | --- | --- |
| `Started` | `session_id`, `user_id`, `assurance: &'static str`, `methods: Vec<String>` | `session.started` |
| `Raised` | `session_id`, `user_id`, `assurance: &'static str`, `methods: Vec<String>` (those the step-up proved) | `session.raised` |
| `Revoked` | `session_id`, `user_id`, `reason: String` | `session.revoked` |

## Invariants

- `Session::start` returns `Invalid` `session.timeouts_invalid` unless
  `0 < idle <= absolute`, and `Invalid` `session.methods_missing` if no
  method is given (`session.rs:Session::start`).
- A new session has `absolute_expires_at = now + absolute`, and its client
  description is cut to 256 characters (`session.rs:Session::start`,
  `ClientInfo::trimmed`).
- A token is 32 random bytes written as 64 lowercase hexadecimal characters;
  only its SHA-256 hash (`Digest::sha256`) is stored
  (`session.rs:SessionToken::generate`, `SessionToken::hash`).
- `TokenHash::of_presented` returns `None` unless the value is exactly 64
  characters of `0-9a-f`; nothing is hashed for a malformed value.
- `SessionToken` and `TokenHash` print as `[REDACTED]` in `Debug`; events
  carry identifiers and never a token or its hash (`event.rs` module
  documentation).
- `expires_at` is the earlier of `last_activity_at + idle_timeout` and
  `absolute_expires_at`; `state_at` gives `Revoked` if `revoked_at` is set,
  `Expired` if `now >= expires_at`, otherwise `Active`. Expiry is computed,
  never run (`session.rs:Session::state_at`).
- `record_activity` changes nothing for a session that is not active or was
  used less than one minute ago (`session.rs:Session::record_activity`).
- `revoke` is final: it returns `None` when `revoked_at` is already set. It
  checks only revocation, not expiry (`session.rs:Session::revoke`).
- `replace_token` returns `Conflict` `session.not_active` unless the session
  is active (`session.rs:Session::replace_token`).
- `Assurance::from_stored` returns an internal `session.stored_data_invalid`
  error for an unknown name.

## Side Effects

- None inside the domain. `Session::start` and `replace_token` call the
  `RandomSource::fill` and `Digest::sha256` they are given; `SessionId::generate`
  creates the identifier.

## Verification

- Run: `cargo test -p hodor-session`
