# hodor-kernel source

## Overview

The shared kernel of Hodor holds identifiers, the tenant context, events, errors, pagination, secrets and the port traits that adapters implement. The crate documentation states the admission rule: a type belongs here only if at least three bounded contexts need it and it carries no business rule owned by a single context (`lib.rs` crate documentation, which points to `docs/decisions/0002-crate-consolidation.md`).

All twelve modules are public (`lib.rs`: `pub mod clock` through `pub mod uow`). Their main items are re-exported at the crate root, for example `hodor_kernel::HttpClient` (`lib.rs` `pub use` lines). The hidden module `__private` re-exports `serde` and `uuid` for the `define_id!` macro and is not part of the public interface (`lib.rs:__private`).

## Interface

### Port traits (implemented by adapters or by contexts)

| Trait | Methods | Defined in | Implemented in this repository by |
| --- | --- | --- | --- |
| `Clock` | `now(&self) -> Timestamp` | `clock.rs:Clock` | `SystemClock` (`clock.rs`); test double `FixedClock` |
| `RandomSource` | `fill(&self, buffer: &mut [u8])` | `random.rs:RandomSource` | `OsRandom` in `crates/adapters-crypto`; test double `CountingRandom` |
| `Digest` | `sha256(&self, data: &[u8]) -> [u8; 32]`; `sha512(&self, data: &[u8]) -> [u8; 64]`, for the `at_hash` of an EdDSA ID token | `random.rs:Digest` | `Sha256Digest` in `crates/adapters-crypto`; test double `FakeDigest` |
| `SecretBox` (asynchronous: `#[async_trait]`) | `seal`, `open`, `needs_resealing -> Result<bool>` | `sealing.rs:SecretBox` | `TenantSecretBox` in `crates/keys`; test double `FakeSecretBox` |
| `SignatureVerifier` | `verify(&self, algorithm, key, message, signature) -> bool` | `signature.rs:SignatureVerifier` | `AwsLcVerifier` in `crates/adapters-crypto` |
| `HttpClient` (asynchronous) | `send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError>` | `http.rs:HttpClient` | `GuardedHttpClient` and `ServiceHttpClient` in `crates/adapters-http`; test double `TestProvider` in `crates/adapters-crypto` |
| `DestinationCheck` (asynchronous) | `check(&self, url: &str) -> Result<(), DomainError>`: whether an address could be called now, without calling it; `http.url_invalid`, `http.destination_forbidden` or `http.unreachable` | `http.rs:DestinationCheck` | `GuardedHttpClient` in `crates/adapters-http`; test double `FakeDestinations` in `crates/webhooks` |
| `UnitOfWork` (asynchronous) | `tenant`, `record_event`, `commit(self: Box<Self>)`, `as_any_mut` | `uow.rs:UnitOfWork` | `PgUnitOfWork` in `crates/adapters-postgres` (`uow.rs`); test double `InMemoryUnitOfWork` |
| `UnitOfWorkFactory` (asynchronous) | `begin(&self, tenant) -> Result<Box<dyn UnitOfWork>, DomainError>` | `uow.rs:UnitOfWorkFactory` | `Database` in `crates/adapters-postgres` (`uow.rs`); test double `InMemoryUnitOfWorkFactory` |
| `EventHandler` (asynchronous) | `name`, `handles(&self, event_type)`, `handle(&self, uow, event)` | `event.rs:EventHandler` | event handlers in the bounded contexts |
| `DomainEvent` | `event_type(&self) -> &'static str` | `event.rs:DomainEvent` | each context's event types |

### Types and functions

- `Timestamp`: alias of `time::OffsetDateTime`, documented as always handled in Coordinated Universal Time (`clock.rs:Timestamp`). `SystemClock` implements `Clock` (`clock.rs:SystemClock`).
- `ErrorKind`: `#[non_exhaustive]` enumeration with `NotFound`, `Conflict`, `Invalid`, `Forbidden`, `Unauthenticated`, `RateLimited`, `Unavailable` and `Internal`. The HTTP layer maps it to a status code (`error.rs:ErrorKind`).
- `DomainError`: constructors `new(kind, code, message)`, `not_found`, `conflict`, `invalid` and `internal`; builders `with_retry_after(seconds)` and `with_detail(detail)`; getters `kind`, `code`, `message`, `retry_after_seconds` and `detail`. Its display text is `"{code}: {message}"` (`error.rs:DomainError`).
- `Actor`: `User(UserId)`, `Client(ClientActorId)`, `System` or `Anonymous`, serialized with `kind` and `id` tags (`event.rs:Actor`). `Caller { actor, correlation_id }`, where `Caller::system()` makes a system caller with a new correlation identifier (`event.rs:Caller`).
- `EventMetadata { event_id, tenant_id, occurred_at, actor, correlation_id }` and `EventMetadata::new(tenant_id, actor, correlation_id, clock: &dyn Clock)` (`event.rs:EventMetadata`).
- `EventEnvelope { metadata, event_type, payload: serde_json::Value }` and `EventEnvelope::new(metadata, &event)`, which packs a `DomainEvent + Serialize` for the outbox (`event.rs:EventEnvelope`).
- `HttpMethod` (`Get`, `Post`), `HttpRequest` (`get(url)`, `post(url, content_type, body)`, `header(name, value)`, and `within(limit)`, which sets the optional `time_limit` of that request alone), and `HttpResponse` (`is_success()` for status 200 to 299, and `header(name)`, which ignores letter case) (`http.rs`).
- `define_id!` (exported macro): defines a typed identifier wrapping a UUID, with `generate()`, `from_uuid()`, `as_uuid()`, serialization as the bare UUID, `Display` and `FromStr` (`id.rs:define_id`). The kernel defines `TenantId`, `UserId`, `GroupId`, `OrganizationId`, `ClientActorId`, `EventId` and `CorrelationId` with it (`id.rs`). `ParseIdError` is the parse error (`id.rs:ParseIdError`).
- `Cursor` (opaque string), `PageRequest` (`DEFAULT_LIMIT = 50`, `MAX_LIMIT = 200`, `new(limit, cursor)`, `limit()`, `cursor()`, `Default`), and `Page<T> { items, next_cursor }` with `map` (`page.rs`).
- `SealedSecret` (`from_stored(bytes)`, `as_bytes()`) and the free function `sealing::unreadable(detail)`, which builds the internal error `secret.unreadable`. That function is not re-exported at the root (`sealing.rs`).
- `Secret<T: Zeroize>`: `new(value)`, `expose()`, plus `From<String>` and `From<Vec<u8>>` (`secret.rs:Secret`).
- `SignatureAlgorithm` (`Rs256`, `Ps256`, `Es256`, `EdDsa`; `from_name(name)`; `fits(key)`) and `PublicKey` (`Rsa { modulus, exponent }`, `P256 { x, y }`, `Ed25519 { x }`) (`signature.rs`).
- `TenantContext`: `assume(tenant_id)` and `tenant_id()` (`tenant.rs:TenantContext`).

### Test support (behind the `testing` feature)

Four `testing` submodules are compiled only under `#[cfg(any(test, feature = "testing"))]`. Other crates enable them through the Cargo feature `testing`:

- `clock::testing::FixedClock`: `at(now)` and `advance(by)` (`clock.rs`).
- `random::testing::FakeDigest`, a non-cryptographic hash, and `random::testing::CountingRandom`, which yields bytes 0, 1, 2 and so on (`random.rs`).
- `sealing::testing::FakeSecretBox` (`sealing.rs`).
- `uow::testing::InMemoryUnitOfWork` and `uow::testing::InMemoryUnitOfWorkFactory`, the latter with `committed_events()` and `committed_event_types()` (`uow.rs`).

## Invariants

- Each identifier is its own type, so a `UserId` cannot be passed where a `TenantId` is expected. `generate()` always makes a UUID version 7 (`id.rs:define_id`, through `Uuid::now_v7()`). Parsing rejects any string that is not a UUID, and the error names the identifier type (`id.rs:define_id`, `FromStr`).
- `DomainError` keeps `code` stable and machine-readable. Its documentation says `message` is safe to show to the caller and never holds secrets or details about other tenants, and that `detail` is for operators: it is logged and never returned to callers. The display text leaves `detail` out (`error.rs:DomainError`). The documentation reserves `with_retry_after` for `RateLimited` and `Unavailable`, but the code does not enforce this (`error.rs:DomainError::with_retry_after`).
- `PageRequest::new` turns a missing limit into 50 and clamps any limit into the range 1 to 200 instead of rejecting it (`page.rs:PageRequest::new`). Cursor contents belong to the repository that produced them (`page.rs:Cursor`).
- `Secret<T>` prints `Secret([REDACTED])` from `Debug` and implements neither `Display` nor `Serialize`. Its contents are zeroized when it is dropped and can be read only through `expose()` (`secret.rs:Secret`). `SealedSecret` prints only its byte length (`sealing.rs:SealedSecret`).
- `SecretBox`: a secret sealed for one tenant and purpose opens for no other. `open` returns `secret.unreadable` whatever the reason, and the reason goes only into `detail` (`sealing.rs:SecretBox`, `sealing.rs:unreadable`).
- `SignatureAlgorithm::from_name` accepts exactly `RS256`, `PS256` and `ES256`, so `none` and shared-secret algorithms cannot be named, and `EdDSA` is not read from another's header: `EdDsa` is checked only for a tenant's own keys (Issue-130). `fits` pairs RS256 and PS256 only with RSA keys, ES256 only with P-256 keys, and EdDSA only with Ed25519 keys (`signature.rs:SignatureAlgorithm`). `SignatureVerifier::verify` must return `false` for anything that is not exactly a valid signature (`signature.rs:SignatureVerifier`).
- Every port method that touches tenant data takes `&TenantContext`. The documentation says only the HTTP tenant resolver, the worker's job loader and tests may call `TenantContext::assume`, and that the tenant is never read from a request body, header or query parameter. This rule is documented only, not enforced by the code (`tenant.rs:TenantContext`).
- A unit of work stores state changes and events atomically. Dropping it without committing discards both, and a failed commit applies nothing. Domain and application code never call `as_any_mut` (`uow.rs` module documentation and `uow.rs:UnitOfWork`).
- Events are written to the outbox in the same transaction as the state change. An event handler's changes through the unit of work commit together with the record that the event was delivered. Effects outside the database may repeat, so they must deduplicate on `EventMetadata::event_id`. When a handler returns an error, the event stays pending and is retried later (`event.rs` module documentation and `event.rs:EventHandler`).
- `DomainEvent::event_type` has the form `context.event` in snake case. It is part of the published language, so renaming it breaks consumers (`event.rs:DomainEvent`). `EventEnvelope::new` maps a serialization failure to the internal error `event.not_serializable` (`event.rs:EventEnvelope::new`).
- `HttpClient`: contexts never open connections themselves; the adapter decides whether a destination may be called. `send` returns every status, including redirects and errors, as a response. Its documented error codes are `http.url_invalid`, `http.destination_forbidden`, `http.unreachable`, `http.timed_out` and `http.response_too_large`, and no error message repeats the address (`http.rs:HttpClient`).
- The documentation of `random.rs` requires production `RandomSource` implementations to draw from the operating system's cryptographically secure generator. It also marks the test doubles `FakeDigest`, `CountingRandom` and `FakeSecretBox` as never for use outside tests (`random.rs`, `sealing.rs:testing::FakeSecretBox`).

## Side Effects

- `SystemClock::now` reads the system clock through `Timestamp::now_utc()` (`clock.rs:SystemClock`).
- Identifier generation reads the system clock outside the `Clock` port, through `Uuid::now_v7()` (`id.rs:define_id`). This applies to `Caller::system()` and to `EventMetadata::new`, which takes `occurred_at` from the injected clock but generates `event_id` itself, so a fixed test clock does not make `event_id` deterministic (`event.rs:Caller::system`, `event.rs:EventMetadata::new`).
- There is no file, network or logging access in this crate. The input and output ports are traits only; adapters perform their effects.
- The test doubles keep mutable state per instance (a `Mutex`, an `AtomicU8`, and an `Arc<Mutex<Vec<EventEnvelope>>>`). None of it is global (`clock.rs:testing::FixedClock`, `random.rs:testing::CountingRandom`, `uow.rs:testing::InMemoryUnitOfWorkFactory`).

## Verification

- Run: `cargo test -p hodor-kernel`
