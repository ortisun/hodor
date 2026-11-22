# hodor-worker source

## Overview

The background process, in one file, `main.rs`. It runs three loops side by
side: the outbox dispatch loop, which turns every outbox event into an audit
record, the mail delivery loop, which sends queued messages over SMTP, and
the cleanup loop, which removes pending authorizations that expired. It
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
| `--log-format` (`json`, `pretty`) | `HODOR_LOG_FORMAT` | `json` |
| `--log-filter` | `HODOR_LOG_FILTER` | `info` |
| `--otlp-traces-endpoint` | `HODOR_OTLP_TRACES_ENDPOINT` | unset: no export |
| `--otlp-metrics-endpoint` | `HODOR_OTLP_METRICS_ENDPOINT` | unset: no export |

Symbols:

- `run` builds `DeliveryService` (with `PgMessageQueue`,
  `PgPendingMessages::new(platform)`, `SmtpSender`, `SystemClock`),
  `AuditService` (with `PgAuditLog`, `Sha256Digest`), and
  `PendingAuthorizationCleanup::new(platform, database)` and
  `OutboxDispatcher::new(platform, database, [AuditHandler])`, then serves
  `ops_router(health)` and joins the three loops.
- `dispatch_loop` calls `OutboxDispatcher::dispatch_batch(batch_size)`.
- `delivery_loop` calls `DeliveryService::deliver_pending(batch_size)`.
- `cleanup_loop` calls `PendingAuthorizationCleanup::run(now, batch_size)`.
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
  a pass that removed a full batch in every tenant it looked at is followed
  by another at once, since more may be waiting (`cleanup_loop`).
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
  how many when any were removed.
- Records metrics on the meter `hodor.worker`: the counters
  `hodor.outbox.events`, `hodor.outbox.passes`,
  `hodor.notification.messages`, `hodor.notification.passes`,
  `hodor.cleanup.removed` and `hodor.cleanup.passes` (attribute `job` =
  `pending_authorizations`).
- Logs and, when the endpoints are set, exports traces and metrics through
  `hodor_observability::Telemetry::init` (`main`).
- Binds a TCP listener on `HODOR_OPS_ADDR` for health endpoints (`run`).
- Handles SIGTERM and Ctrl-C (`stop_signal`).

## Verification

- Run: `cargo test -p hodor-worker`
