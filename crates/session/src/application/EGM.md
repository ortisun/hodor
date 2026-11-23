# Session application layer

## Overview

The use cases of the session context and the one storage port they need.
`SessionService` starts, finds, lists, revokes and re-tokens sessions; every
use case runs inside a unit of work bound to one tenant. Both modules are
declared `pub(crate)` in `mod.rs` and reach other crates only through the
re-exports in `crate::api` (`src/lib.rs`).

## Interface

### Port (`ports.rs`)

`SessionStore` (`#[async_trait]`, `Send + Sync`) stores and loads sessions.
Every method works inside the tenant the unit of work is bound to. It is
implemented by `PgSessionStore` in `crates/adapters-postgres/src/session.rs`
and by `InMemorySessions` in [the test-support module](../EGM.md).

| Method | Signature | Meaning |
| --- | --- | --- |
| `insert` | `(&self, uow: &mut dyn UnitOfWork, session: &Session) -> Result<(), DomainError>` | Stores a new session. |
| `get` | `(&self, uow, id: SessionId) -> Result<Option<Session>, DomainError>` | Loads a session of the tenant by identifier. |
| `find_by_token_hash` | `(&self, uow, hash: &TokenHash) -> Result<Option<Session>, DomainError>` | Loads the session whose token has the given hash. |
| `update` | `(&self, uow, session: &Session) -> Result<(), DomainError>` | Stores the changeable parts: token hash, last activity, revocation. Documented to return `NotFound` if the tenant has no such session. |
| `list_for_user` | `(&self, uow, user_id: UserId, now: Timestamp) -> Result<Vec<Session>, DomainError>` | A user's sessions that are not revoked and whose absolute expiry is after `now`, newest first. The caller filters out idle sessions. |

### Service (`service.rs`)

- `StartSession { user_id: UserId, assurance: Assurance, methods: Vec<String>, timeouts: SessionTimeouts, client: ClientInfo }`
  is the command for `start`.
- `SessionService::new(units_of_work: Arc<dyn UnitOfWorkFactory>, sessions: Arc<dyn SessionStore>, digest: Arc<dyn Digest>, random: Arc<dyn RandomSource>, clock: Arc<dyn Clock>)`.
  Its `Debug` prints no fields.

| Entry point | Returns | Meaning |
| --- | --- | --- |
| `start(&self, tenant: &TenantContext, command: StartSession, caller: Caller)` | `(Session, SessionToken)` | Starts a session; the token is not available again. |
| `find_by_token(&self, tenant, presented: &str)` | `Option<Session>` | The active session a presented token belongs to; records activity. |
| `list_for_user(&self, tenant, user_id: UserId)` | `Vec<Session>` | A user's active sessions, newest first. |
| `revoke(&self, tenant, id: SessionId, reason: &str, caller)` | `()` | Ends one session; repeating it changes nothing. |
| `revoke_for_user(&self, tenant, user_id, id, reason, caller)` | `()` | Ends a session only if it belongs to the user and is active (the self-service entry point). |
| `revoke_all_for_user(&self, tenant, user_id, keep: Option<SessionId>, reason, caller)` | `usize` | Ends all of a user's sessions except `keep`; returns how many ended. |
| `replace_token(&self, tenant, id: SessionId)` | `SessionToken` | Gives a session a new token; the old one stops working at once. |
| `raise(&self, tenant, user_id, id, proven: &[String], assurance, caller)` | `(Session, SessionToken)` | Raises an active session of `user_id` after a step-up and records `SessionEvent::Raised`; `NotFound` `session.not_found` for a session of another user, ended, or unknown. |

Kernel items used (`hodor_kernel`): `Caller`, `Clock`, `Digest`,
`DomainError`, `EventEnvelope`, `EventMetadata`, `RandomSource`,
`TenantContext`, `Timestamp`, `UnitOfWork`, `UnitOfWorkFactory`, `UserId`.

## Invariants

- `start` validates through `Session::start` before any unit of work begins,
  so an invalid command touches no storage; the order is build, begin,
  `insert`, record `SessionEvent::Started`, commit
  (`service.rs:SessionService::start`).
- `find_by_token` returns `Ok(None)` without reading the clock or storage when
  `TokenHash::of_presented` rejects the value; unknown, expired and revoked
  tokens also give `Ok(None)` and are not told apart
  (`service.rs:SessionService::find_by_token`).
- `find_by_token` writes and commits only when `Session::record_activity`
  returns `true` (`service.rs:SessionService::find_by_token`).
- `list_for_user` re-filters the store's result to
  `state_at(now) == SessionState::Active` with a single `now`, and never
  commits (`service.rs:SessionService::list_for_user`).
- A missing session gives `DomainError::not_found("session.not_found", ...)`
  in `revoke`, `revoke_for_user` and `replace_token`.
- `revoke_for_user` returns the same `session.not_found` error whether the
  session is missing, belongs to another user, or is not active
  (`service.rs:SessionService::revoke_for_user`).
- `revoke` and `revoke_all_for_user` write and record an event only when
  `Session::revoke` returns an event; `revoke_all_for_user` commits only when
  at least one session ended and skips the session equal to `keep`
  (`service.rs:SessionService::revoke_all_for_user`).
- `replace_token` records no event; the not-active `Conflict` comes from the
  domain (`service.rs:SessionService::replace_token`).
- Events are wrapped with `EventMetadata::new(uow.tenant().tenant_id(),
  caller.actor, caller.correlation_id, clock)`; an envelope error aborts
  before commit (`service.rs:SessionService::record`).

## Side Effects

- Reads the injected `Clock`; `start` and `replace_token` draw from the
  injected `RandomSource` and hash with the injected `Digest`.
- Begins units of work through `UnitOfWorkFactory::begin(tenant)` and reads
  and writes through `SessionStore`.
- Records `SessionEvent` envelopes with `UnitOfWork::record_event`; nothing is
  published directly from this layer.

## Verification

- Run: `cargo test -p hodor-session`
