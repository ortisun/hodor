# hodor-adapters-postgres source

## Overview

The PostgreSQL adapter. It implements the storage ports that the domain
crates declare: the unit of work and the unit of work factory from
`hodor-kernel`, and one store or repository per bounded context (audit,
authentication, authorization, credential, federation, identity,
notification, session, tenant). It also holds the outbox dispatcher, the
cleanup job for expired pending authorizations, the embedded schema
migrations, and a feature-gated test-support module.

Tenant data is reached only through a `TenantTransaction`
(`lib.rs` module documentation, `database.rs:Database::begin`). Every query
also filters on `tenant_id` explicitly; the module documentation calls
row-level security "the second line of defence".

All modules are private; the public surface is the set of re-exports in
`lib.rs`, plus `pub mod testing` behind the `testing` feature.

## Interface

### Connection, tenant transaction and unit of work

| Symbol | Source | What it is |
| --- | --- | --- |
| `connect_pool(url, max_connections)` | `database.rs` | Opens a plain `PgPool`, for connections that are not tenant-scoped. |
| `ping_pool(pool)` | `database.rs` | Runs `SELECT 1`, for readiness probes. |
| `Database` | `database.rs` | Handle to the database as the application role sees it: `connect`, `from_pool`, `begin(tenant)`, `ping`, `pool`. `pool()` is documented as "health checks only": queries on it have no tenant bound and see no tenant rows. |
| `TenantTransaction` | `database.rs` | A transaction bound to one tenant: `tenant_id`, `connection`, `commit`, `rollback`. |
| `PgUnitOfWork` | `uow.rs` | `impl UnitOfWork for PgUnitOfWork` (trait from `hodor_kernel`). Wraps a `TenantTransaction`, the `TenantContext` and the recorded `EventEnvelope`s. |
| `impl UnitOfWorkFactory for Database` | `uow.rs` | Trait from `hodor_kernel`. `begin` calls `Database::begin` and returns a boxed `PgUnitOfWork`. |
| `connection(uow)` | `uow.rs` | Returns the `PgConnection` behind a `dyn UnitOfWork`, for this crate's stores and for event handlers that write to the database. |
| `migrate(owner_pool)` | `migrate.rs` | Applies all pending migrations. |
| `OutboxDispatcher`, `DispatchReport` | `outbox.rs` | Delivers pending outbox events to `hodor_kernel::EventHandler`s. |
| `PendingAuthorizationCleanup`, `CleanupReport` | `cleanup.rs` | `new(platform, database)`; `run(now, batch)` finds, through the platform pool, up to 100 tenants (`TENANTS_PER_PASS`) that have pending authorizations expired at `now`, and in each tenant removes up to `batch` of them in its own unit of work, through `PgPendingAuthorizationStore::remove_expired`. The report counts the tenants and the rows removed. |
| `KeyRotationJob`, `RotationPass` | `key_rotation.rs` | `new(platform, keys: KeyService, policy: RotationPolicy)`; `run(now)` takes `pg_try_advisory_xact_lock` (key `0x686f646f726b6579`, "hodorkey") in a transaction of the platform pool and, without it, answers `skipped`. With it, it finds up to 100 active tenants (`platform.tenant_directory`) that have something due by the rules of `KeySet::rotation_plan`, runs `KeyService::rotate_due` in each, and records a tenant's error in `failures` and goes on. `RotationPass { skipped, tenants, failures, changes }` with `was_full()`. The lock ends with the transaction. |
| `MigrateError`, `Error`, `PgPool` | `lib.rs` | Re-exported from `sqlx`. |

### Port implementations

Each store is a unit struct (except where noted) that runs its queries on
`connection(uow)`, so it takes part in the caller's unit of work.

| Type | Port it implements (`impl ... for` line) | Tables named in its SQL |
| --- | --- | --- |
| `PgAuditLog` | `impl AuditLog for PgAuditLog` (`audit.rs`, trait from `hodor_audit::api`) | `audit.record`, `audit.chain_head` |
| `PgAttemptStore` | `impl AttemptStore for PgAttemptStore` (`authentication.rs`, `hodor_authentication::api`) | `authentication.attempt_counter` |
| `PgTransactionStore` | `impl TransactionStore for PgTransactionStore` (`authentication.rs`, `hodor_authentication::api`) | `authentication.transaction` |
| `PgVerificationTokenStore` | `impl VerificationTokenStore for PgVerificationTokenStore` (`authentication.rs`, `hodor_authentication::api`) | `authentication.verification_token` |
| `PgRoleAssignmentStore` | `impl RoleAssignmentStore for PgRoleAssignmentStore` (`authorization.rs`, `hodor_authorization::api`) | `"authorization".role_assignment` |
| `PgEngineBindingStore` | `impl EngineBindingStore for PgEngineBindingStore` (`authorization.rs`, `hodor_authorization::api`) | `"authorization".engine_binding`; `put` upserts on `(tenant_id, namespace)`; a stored row that is not a valid binding is `authorization.stored_data_invalid` |
| `PgPasswordStore` | `impl PasswordStore for PgPasswordStore` (`credential.rs`, `hodor_credential::api`) | `credential.password`, `credential.password_history` |
| `PgAccessTokenStore` | `impl AccessTokenStore for PgAccessTokenStore` (`credential.rs`, `hodor_credential::api`) | `credential.access_token` |
| `PgTotpStore` | `impl TotpStore for PgTotpStore` (`credential.rs`, `hodor_credential::api`); `activate` locks the pending row with `FOR UPDATE`, `use_step` is one conditional `UPDATE` | `credential.totp` |
| `PgWebAuthnStore` | `impl WebAuthnStore for PgWebAuthnStore` (`credential.rs`, `hodor_credential::api`) | `credential.webauthn_credential`, `credential.webauthn_registration` |
| `PgRecoveryCodeStore` | `impl RecoveryCodeStore for PgRecoveryCodeStore` (`credential.rs`, `hodor_credential::api`); `replace` deletes the user's set and inserts the new one, a second set at the same moment refused by `recovery_code_set_one_per_user` as `credential.recovery_codes_conflict`; `use_code` is one conditional `UPDATE` | `credential.recovery_code_set`, `credential.recovery_code` |
| `PgProviderStore` | `impl ProviderStore for PgProviderStore` (`federation.rs`, `hodor_federation::api`) | `federation.identity_provider` |
| `PgLinkStore` | `impl LinkStore for PgLinkStore` (`federation.rs`, `hodor_federation::api`) | `federation.external_identity` |
| `PgPendingAuthorizationStore` | `impl PendingAuthorizationStore for PgPendingAuthorizationStore` (`federation.rs`, `hodor_federation::api`) | `federation.pending_authorization` |
| `PgApplicationStore` | `impl ApplicationStore for PgApplicationStore` (`oauth.rs`, `hodor_oauth::api`) | `oauth.application` |
| `PgClientStore` | `impl ClientStore for PgClientStore` (`oauth.rs`, `hodor_oauth::api`); `update` checks the version, then replaces the client's secrets and keys | `oauth.client`, `oauth.client_secret`, `oauth.client_key` |
| `PgAuthorizationRequestStore` | `impl AuthorizationRequestStore` (`oauth_authorization.rs`); the request as `jsonb`; `authorization_request_client_fk` is `oauth.client_not_found`; `remove` deletes and answers whether a row went | `oauth.authorization_request` |
| `PgGrantStore` | `impl GrantStore` (`oauth_authorization.rs`); `authorization_grant_client_fk` is `oauth.client_not_found` | `oauth.authorization_grant` |
| `PgAuthorizationCodeStore` | `impl AuthorizationCodeStore` (`oauth_authorization.rs`); `redeem` is one `UPDATE … WHERE redeemed_at IS NULL`, so of two at once one wins; `authorization_code_grant_fk` is `oauth.grant_not_found` | `oauth.authorization_code` |
| `PgClientAssertionStore` | `impl ClientAssertionStore` (`oauth_token.rs`); `remember` is one `INSERT … ON CONFLICT DO NOTHING` on the primary key, so of two at once one is first; `client_assertion_client_fk` is `oauth.client_not_found` | `oauth.client_assertion` |
| `PgResourceServerStore` | `impl ResourceServerStore for PgResourceServerStore` (`oauth.rs`, `hodor_oauth::api`); maps the constraints `resource_server_audience_unique`, `resource_server_application_unique` and `resource_server_application_fk` to `oauth.audience_taken`, `oauth.application_has_resource_server` and `oauth.application_not_found` | `oauth.resource_server`, `oauth.resource_server_scope` |
| `PgUserRepository` | `impl UserRepository for PgUserRepository` (`identity.rs`, `hodor_identity::api`) | `identity."user"`, `identity.user_identifier` |
| `PgMessageQueue` | `impl MessageQueue for PgMessageQueue` (`notification.rs`, `hodor_notification::api`) | `notification.message` |
| `PgPendingMessages` (holds a platform `PgPool`; `new(platform)`) | `impl PendingMessages for PgPendingMessages` (`notification.rs`, `hodor_notification::api`) | `notification.message` |
| `PgKeyStore` | `impl KeyStore for PgKeyStore` (`keys.rs`, `hodor_keys::api`); an activation that would leave two active versions gives `Conflict` `keys.activation_conflict` | `keys.key_version` |
| `PgSealingStateStore` | `impl SealingStateStore for PgSealingStateStore` (`keys.rs`, `hodor_keys::api`); refusing twice changes nothing | `keys.sealing_state` |
| `reseal_tenant`, `ResealReport`, `SEALED_COLUMNS`, `SealedColumn` | `resealing.rs`: `reseal_tenant(database, &dyn SecretBox, tenant)` reads each column of `SEALED_COLUMNS` 100 rows at a time and writes a secret sealed again only if the row still holds what was read, one transaction per row. `ResealReport { resealed, current, unreadable }` with `complete()`. What `hodor-cli secrets reseal` runs | `federation.identity_provider.client_secret`, `federation.pending_authorization.code_verifier`, `credential.totp.sealed_secret` |
| `PgSessionStore` | `impl SessionStore for PgSessionStore` (`session.rs`, `hodor_session::api`) | `session.session` |
| `PgTenantRepository` | `impl TenantRepository for PgTenantRepository` (`tenant.rs`, `hodor_tenant::api`) | `tenant.tenant` |
| `PgTenantDirectory` (holds a `Database`; `new(database)`) | `impl TenantDirectory for PgTenantDirectory` (`tenant.rs`, `hodor_tenant::api`) | `platform.tenant_directory` |

The outbox and the unit of work write to `platform.outbox`
(`uow.rs:PgUnitOfWork::commit_now`, `outbox.rs`).

### Test support (`testing.rs`, feature `testing`)

Compiled only with the `testing` feature (`lib.rs`:
`#[cfg(feature = "testing")] pub mod testing`).

- `TestDatabase::start()` starts a disposable PostgreSQL container
  (`testcontainers_modules::postgres::Postgres`, image tag `17-alpine`),
  applies the migrations as the owner, creates the login roles
  `hodor_app_login` (in role `hodor_app`) and `hodor_platform_login` (in role
  `hodor_platform`), and connects. Accessors: `owner`, `app`, `platform`,
  `app_url`, `platform_url`. It panics, suggesting Docker is not running,
  after `START_ATTEMPTS` (4) failed starts; at most two starts run at once
  (`STARTS` semaphore). The container is removed when the value is dropped.
- `schema_violations(owner)` reads the catalog and returns one message per
  table that breaks the tenant isolation rules (see Invariants). Only
  `public._sqlx_migrations` and `platform.tenant_directory` are exempt
  (`PLATFORM_TABLES`).

## Invariants

### Tenant binding

- `Database::begin` runs `SELECT set_config('app.tenant_id', $1, true)` right
  after `BEGIN`. The setting is transaction-local, so it disappears at commit
  or rollback and never leaks to the next user of a pooled connection; the
  documentation says this also keeps the adapter compatible with connection
  poolers in transaction mode (`database.rs:Database::begin`).
- Dropping a `TenantTransaction` without `commit` rolls back
  (`database.rs:TenantTransaction`). `PgUnitOfWork` has no `Drop` of its own,
  so dropping it rolls back the same way.
- Every store query is scoped by `tenant_id = uow.tenant().tenant_id()`.
  Exceptions that are cross-tenant on purpose:
  `PgPendingMessages::due` and the first query of
  `OutboxDispatcher::dispatch_batch`, both on a pool that connects as a member
  of `hodor_platform`, and `PgTenantDirectory`, which reads
  `platform.tenant_directory` through `Database::pool()`.
- `PgTenantRepository::update` addresses the row by the unit of work's
  tenant, not by the aggregate's own identifier alone: "a tenant can only
  update itself" (`tenant.rs`).

### Unit of work

- `connection(uow)` downcasts with `as_any_mut().downcast_mut::<PgUnitOfWork>()`.
  A unit of work from another adapter gives
  `DomainError::internal("database.foreign_unit_of_work", ...)`, which the
  documentation calls a wiring bug (`uow.rs:connection`).
- `PgUnitOfWork::record_event` only buffers. `commit_now` inserts every
  recorded event into `platform.outbox` inside the same transaction, then
  commits, so a state change and its events are committed together or not at
  all (`uow.rs:PgUnitOfWork::commit_now`).
- Every `sqlx::Error` becomes
  `DomainError::internal("database.error", "the operation could not be completed")`;
  the driver message is kept only as operator detail (`uow.rs:database_error`).

### Outbox dispatch

- `dispatch_batch(limit)` finds pending events on the platform pool:
  `dispatched_at IS NULL AND next_attempt_at <= now()`, ordered by
  `created_at`. It then handles each one in a unit of work of the event's
  tenant, built with `TenantContext::assume` from the stored `tenant_id`
  (`outbox.rs:dispatch_batch`).
- Each event is re-read with `FOR UPDATE SKIP LOCKED`, so several dispatchers
  may run at once. A row already locked or already dispatched counts as
  `skipped` (`outbox.rs:dispatch_one`).
- Only handlers whose `handles(&event.event_type)` is true are called, in
  order, all inside one transaction, together with the update that sets
  `dispatched_at`. The first handler error stops the dispatch, and dropping
  the unit of work rolls back every handler's work for that event
  (`outbox.rs:dispatch_one`).
- On failure, `attempts` is incremented, `last_error` is stored (truncated to
  `MAX_ERROR_LENGTH`, 2,000 bytes, at a character boundary), and
  `next_attempt_at` is set to `now() + least(power(2, attempts), 3600)`
  seconds. The code sets no maximum number of attempts
  (`outbox.rs:record_failure`).
- Handler failures are counted in `DispatchReport.failed`, not returned as
  errors; only database failures return `Err` (`outbox.rs:dispatch_batch`).

### Migrations

- Migrations are embedded at compile time:
  `static MIGRATOR: Migrator = sqlx::migrate!("../../migrations")`, the
  repository's top-level `migrations/` folder (`migrate.rs`).
- `migrate` must be given a pool that connects as the schema owner, not as
  the application role. The documentation says migrations are applied by
  `hodor-cli migrate`, never by the server at startup, and that `migrate`
  fails if the database holds a migration this binary does not know
  (`migrate.rs:migrate`).

### Concurrency and single use

- Optimistic concurrency on a `version` column: `PgTransactionStore::update`,
  `PgPasswordStore::update`, `PgUserRepository::update`,
  `PgTenantRepository::update` and `PgProviderStore::update` update only
  `WHERE ... AND version = $n` and bump the version. When no row changes,
  the first four check existence to choose between a `conflict`
  (`*_modified_concurrently`) and a `not_found` error;
  `PgProviderStore::update` always returns
  `federation.provider_modified_concurrently`.
- `PgAttemptStore::lock` creates and row-locks the counter in one upsert with
  a no-op `DO UPDATE`, so a second transaction for the same subject waits
  (`authentication.rs`). `PgAuditLog` locks the per-tenant chain head the
  same way before appending (`audit.rs:lock_head`).
- `PgVerificationTokenStore::use_up` consumes a token in one `UPDATE` that
  requires `used_at IS NULL`, `replaced_at IS NULL` and `expires_at > now`
  (`authentication.rs`).
- `PgPendingAuthorizationStore::take` is one `DELETE ... RETURNING`: of
  several concurrent callers, one gets the row. `keep_response` keeps a
  posted SAML response only if none is kept yet and the authorization has not
  expired: the first response wins (`federation.rs`).
  `remove_expired` chooses its batch once, in a common table expression
  with `LIMIT` and `FOR UPDATE SKIP LOCKED`, and deletes only those rows of
  the unit of work's tenant (`federation.rs`).
- `PgMessageQueue::take` reads a `pending` message with
  `FOR UPDATE SKIP LOCKED`: a message held by another worker is skipped, not
  waited for (`notification.rs`).

### Stored data and error mapping

- Secrets are stored as hashes or sealed values only: token hashes for
  sessions, access tokens and verification tokens, password hashes for
  passwords, and `SealedSecret` bytes for provider client secrets and
  pending code verifiers. No plaintext secret column appears in the SQL.
- Named constraint violations become domain errors:
  `tenant_slug_unique` gives `tenant.slug_taken`,
  `user_identifier_value_unique` gives `identity.identifier_taken`,
  `identity_provider_alias_unique` gives `federation.alias_taken`, and
  `external_identity_provider_fk` or `pending_authorization_provider_fk`
  give `federation.provider_not_found`. A unique violation on the audit
  record insert gives `audit.already_recorded`.
- `PgPasswordStore::insert`, `PgRoleAssignmentStore::assign` and
  `PgLinkStore::insert` use `ON CONFLICT ... DO NOTHING` and report through
  the affected row count (a `credential.password_exists` conflict, or a
  `bool`). The comment in `credential.rs` gives the reason: catching the
  error instead would leave a failed statement that aborts the whole
  transaction.
- Rows that cannot be read back give `<context>.stored_data_invalid`
  internal errors (wrong hash length, negative version, unknown stored enum
  value).

## Side Effects

- PostgreSQL reads and writes on the tables listed above, all inside the
  caller's tenant transaction except the cross-tenant reads named under
  Invariants.
- `PgUnitOfWork::commit_now` inserts into `platform.outbox`;
  `OutboxDispatcher` updates `dispatched_at`, `attempts`, `last_error` and
  `next_attempt_at` there and calls the configured event handlers.
- Row locks: `authentication.attempt_counter` (upsert), `audit.chain_head`
  (upsert), `platform.outbox` and `notification.message`
  (`FOR UPDATE SKIP LOCKED`).
- `PgPasswordStore::update` and `PgUserRepository::update` delete and
  re-insert the user's password history rows or identifier rows.
- `migrate` changes the schema.
- `testing.rs` (feature `testing` only) starts a Docker container through
  `testcontainers` and creates two login roles in it.

## Verification

- Run: `cargo test -p hodor-adapters-postgres` (needs a running Docker
  daemon; see [the crate contract](../EGM.md)).
