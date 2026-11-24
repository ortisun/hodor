# hodor-worker source

## Overview

The background process, in one file, `main.rs`. It runs six loops side by
side: the outbox dispatch loop, which turns every outbox event into an audit
record, the mail delivery loop, which sends queued messages over SMTP, four
cleanup loops, one removing pending authorizations that expired, one
removing the records of access tokens that expired, one maintaining the
record of decisions, and one removing every other kind of row that stopped
being useful once its retention passed, the rotation loop,
which rotates the tenants' signing keys, and the policy check loop, which
checks, tests and simulates policy versions with `opa`. It
holds two PostgreSQL pools: one as the application role, to handle each piece
of work inside its tenant, and one as the platform role, used only to find
pending work across tenants. An operations listener serves health endpoints.

## Interface

Configuration (`Config`, clap, command name `hodor-worker`):

| Flag | Environment variable | Default |
| --- | --- | --- |
| `--database-url` | `HODOR_DATABASE_URL` (member of `hodor_app`) | required |
| `--platform-database-url` | `HODOR_PLATFORM_DATABASE_URL` (member of `hodor_platform`) | required |
| `--database-max-connections` | `HODOR_DATABASE_MAX_CONNECTIONS` | 5, for each pool |
| `--ops-addr` | `HODOR_OPS_ADDR` | `127.0.0.1:9091` |
| `--outbox-batch-size` | `HODOR_OUTBOX_BATCH_SIZE` | 100 |
| `--outbox-poll-interval-ms` | `HODOR_OUTBOX_POLL_INTERVAL_MS` | 500 |
| `--smtp-url` | `HODOR_SMTP_URL` | unset: no mail is delivered |
| `--mail-from` | `HODOR_MAIL_FROM` | unset; requires `--smtp-url` |
| `--mail-batch-size` | `HODOR_MAIL_BATCH_SIZE` | 50 |
| `--mail-poll-interval-ms` | `HODOR_MAIL_POLL_INTERVAL_MS` | 1000 |
| `--cleanup-interval-ms` | `HODOR_CLEANUP_INTERVAL_MS` | 60000 |
| `--cleanup-batch-size` | `HODOR_CLEANUP_BATCH_SIZE` (rows per tenant per pass) | 500 |
| `--cleanup-retention-days` | `HODOR_CLEANUP_RETENTION_DAYS` (`kind=days` pairs, read by `cleanup_retentions`) | empty: every kind keeps its default |
| `--secret-keys` | `HODOR_SECRET_KEYS` | unset: keys do not rotate |
| `--key-rotation-days` | `HODOR_KEY_ROTATION_DAYS` | 90 |
| `--key-publication-hours` | `HODOR_KEY_PUBLICATION_HOURS` | 24 |
| `--key-overlap-hours` | `HODOR_KEY_OVERLAP_HOURS` | 24 |
| `--key-rotation-interval-ms` | `HODOR_KEY_ROTATION_INTERVAL_MS` | 600000 |
| `--open-policy-agent-binary` | `HODOR_OPEN_POLICY_AGENT_BINARY` | unset: no version is checked; the image sets `/usr/local/bin/opa` |
| `--open-policy-agent-binary-sha256` | `HODOR_OPEN_POLICY_AGENT_BINARY_SHA256` | unset: only the version is checked |
| `--policy-check-time-limit-seconds` | `HODOR_POLICY_CHECK_TIME_LIMIT_SECONDS` | 30 |
| `--policy-check-memory-mebibytes` | `HODOR_POLICY_CHECK_MEMORY_MEBIBYTES` | 256 |
| `--policy-check-interval-ms` | `HODOR_POLICY_CHECK_INTERVAL_MS` | 2000 |
| `--log-format` (`json`, `pretty`) | `HODOR_LOG_FORMAT` | `json` |
| `--log-filter` | `HODOR_LOG_FILTER` | `info` |
| `--otlp-traces-endpoint` | `HODOR_OTLP_TRACES_ENDPOINT` | unset: no export |
| `--otlp-metrics-endpoint` | `HODOR_OTLP_METRICS_ENDPOINT` | unset: no export |

Symbols:

- `run` builds `DeliveryService` (with `PgMessageQueue`,
  `PgPendingMessages::new(platform)`, `SmtpSender`, `SystemClock`),
  `AuditService` (with `PgAuditLog`, `Sha256Digest`), and
  `PendingAuthorizationCleanup::new(platform, database)`,
  `AccessTokenCleanup::new(platform, database)`,
  `DecisionLogMaintenance::new(platform, database)`, one
  `ExpiredRowCleanup::new(kind, retention_days, platform, database)` for
  each of `ExpiredKind::ALL`, and
  `OutboxDispatcher::new(platform, database, [AuditHandler])`, and, with
  `HODOR_SECRET_KEYS`, `KeyRotationJob::new(platform, KeyService, policy)`
  over `PgKeyStore` and `LocalKeyProvider`, and, with
  `HODOR_OPEN_POLICY_AGENT_BINARY`, `OpaProcessChecker::verified` (the worker
  does not start with a binary it refuses) and
  `PolicyCheckJob::new(platform, policy_service(database), checker)`; then
  serves `ops_router(health)` and joins the eight loops.
- `dispatch_loop` calls `OutboxDispatcher::dispatch_batch(batch_size)`.
- `delivery_loop` calls `DeliveryService::deliver_pending(batch_size)`.
- `cleanup_loop` takes a slice of jobs and calls `CleanupJob::run(now,
  batch_size)` on each in turn: `CleanupJob` is
  `PendingAuthorizations(PendingAuthorizationCleanup)`,
  `AccessTokens(AccessTokenCleanup)`, `DecisionLog(DecisionLogMaintenance)`
  or `Expired(ExpiredRowCleanup)`, and `name` is its `job` attribute, the
  kind's name for `Expired`.
- `rotation_loop` calls `KeyRotationJob::run(now)`.
- `policy_check_loop` calls `PolicyCheckJob::run()`; `policy_service` builds
  `PolicyService` over the PostgreSQL stores.
- `mail_sender` builds the optional `SmtpSender`.
- `PoolCheck` implements `hodor_protocol_http::ReadinessCheck` over
  `ping_pool`; the checks are named `database` and `platform_database`.
- `LogFormatArg`, `MIN_ERROR_PAUSE`, `wait_for`, `stop_signal`, `main`.

## Invariants

- Mail settings are checked before any database connection. `HODOR_SMTP_URL`
  without a from address fails with "HODOR_MAIL_FROM is required when
  HODOR_SMTP_URL is set" (`mail_sender`); clap rejects `--mail-from` without
  `--smtp-url` (`Config.mail_from`).
- Without `HODOR_SMTP_URL` the worker logs a warning, messages wait, and
  `delivery_loop` returns at once.
- The rotation policy is checked with `RotationPolicy::new` before any
  connection: an overlap under 65 minutes, for example, stops the worker
  with `keys.rotation_policy_invalid`. Without `HODOR_SECRET_KEYS` the worker
  logs a warning and `rotation_loop` returns at once.
- The rotation loop runs at start, then after every pause; a pass skipped
  because another worker held the lock pauses like any other, and a full
  pass without failures is followed by another at once (`rotation_loop`).
- `AuditHandler` is the only outbox handler. Comment in `run`: "Every event
  becomes an audit record, in the transaction that marks the event
  delivered."
- An error never ends a loop: after a failed pass the loop pauses for the
  larger of its poll interval and `MIN_ERROR_PAUSE` (1 second), so a broken
  database is not hammered (`dispatch_loop`, `delivery_loop`,
  `cleanup_loop`).
- The outbox loop runs again at once after a pass that delivered or failed
  any event, and sleeps for the poll interval after an empty pass
  (`dispatch_loop`). The mail loop sleeps whenever nothing was sent or
  expired, because "a pass that only failed would otherwise spin"
  (`delivery_loop`). The cleanup loop runs at start, then after every pause;
  a pass in which any job removed a full batch in every tenant it looked at
  is followed by another at once, since more may be waiting, unless a job
  failed (`cleanup_loop`).
- On the stop signal the worker finishes the current batch: readiness starts
  failing (`health.begin_draining()`), the loops stop before their next
  pass, then the operations server stops (`run`, `wait_for`).

## Side Effects

- Opens two PostgreSQL pools: `Database::connect` with `HODOR_DATABASE_URL`
  and `connect_pool` with `HODOR_PLATFORM_DATABASE_URL` (`run`).
- Writes audit records through `PgAuditLog` while dispatching outbox events
  (`dispatch_loop`).
- Sends mail through `SmtpSender` when `HODOR_SMTP_URL` is set
  (`delivery_loop`).
- Deletes expired rows of `federation.pending_authorization`, inside each
  tenant, through `PendingAuthorizationCleanup` (`cleanup_loop`), and logs
  how many when any were removed; and deletes the records of access tokens
  whose token expired, from `oauth.access_token`, through
  `AccessTokenCleanup` (`cleanup_loop`); and prepares the partitions of the
  record of decisions, drops those past 400 days and removes each tenant's
  records past its retention, through `DecisionLogMaintenance`
  (`cleanup_loop`, job `decision_log`); and deletes the rows of each
  `ExpiredKind` past their retention, inside each tenant, through
  `ExpiredRowCleanup` (`cleanup_loop`, job named after the kind).
- Makes, activates and retires signing key versions inside each tenant
  through `KeyRotationJob` (`rotation_loop`), and logs what changed and
  each tenant whose step failed.
- Records metrics on the meter `hodor.worker`: the counters
  `hodor.keys.rotation.passes` (attribute `outcome`: `ok`, `skipped`,
  `error`), `hodor.keys.rotation.changes` (attribute `change`: `created`,
  `activated`, `retired`), `hodor.outbox.events`, `hodor.outbox.passes`,
  `hodor.notification.messages`, `hodor.notification.passes`,
  `hodor.cleanup.removed` and `hodor.cleanup.passes` (attribute `job` =
  `pending_authorizations`, `access_tokens`, `decision_log` or the name of
  an `ExpiredKind`), `hodor.policy.check.passes`
  (attribute `outcome`) and `hodor.policy.check.done` (attribute `kind`:
  `version`, `simulation`).
- Runs the `opa` binary as a child process for each check, test and
  simulation, through `OpaProcessChecker` (`policy_check_loop`).
- Logs and, when the endpoints are set, exports traces and metrics through
  `hodor_observability::Telemetry::init` (`main`).
- Binds a TCP listener on `HODOR_OPS_ADDR` for health endpoints (`run`).
- Handles SIGTERM and Ctrl-C (`stop_signal`).

## Verification

- Run: `cargo test -p hodor-worker`
