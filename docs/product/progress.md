# Progress

What has been built, issue by issue. This page is updated with every merge into `develop`; the plan it tracks is in [epics.md](epics.md).

Last updated: 2026-11-20.

## Milestone 1: Walking skeleton

| Slice | Done | Total |
|---|---|---|
| A — Foundation | 9 | 10 |
| B — Tenancy | 0 | 3 |
| C — Identity | 0 | 3 |
| D — Password credential | 0 | 3 |
| E — Authentication and session | 0 | 7 |
| F — Audit, notification, admin | 0 | 4 |
| G — Hosted UI and acceptance | 0 | 3 |

### Slice A — Foundation

| Issue | Status | What exists |
|---|---|---|
| M1-01 Workspace skeleton | Done | Cargo workspace, shared lints with `unsafe` forbidden, pinned toolchain, `deny.toml` |
| M1-02 CI pipeline | Done | GitHub Actions: format, lint, build, test, dependency checks |
| M1-03 Architecture test | Done | `tests/architecture` checks every crate against the allowed edges in [crates.md](../architecture/crates.md) |
| M1-04 Kernel | Done | Typed UUIDv7 ids, `TenantContext`, `Clock`, `RandomSource`, `Secret<T>`, `DomainError`, event types, pagination |
| M1-05 PostgreSQL base | Done | Tenant-scoped transactions, forced row-level security helper, embedded migrations, `hodor-cli migrate`, container test harness |
| M1-06 Schema rules | Done | A catalog check that fails when a table is not a proper tenant table |
| M1-07 Outbox | Done | `UnitOfWork` port, `platform.outbox`, dispatcher with `SKIP LOCKED`, rollback and backoff |
| M1-08 Observability | Done, with a gap | Logs, traces and metrics over OTLP; VictoriaMetrics verified by test. Trace export is not yet verified against a backend |
| M1-09 HTTP base | Done | Tenant resolution from the path, request ids, security headers, limits, problem documents, health endpoints, graceful shutdown; `hodor-server` wired |
| M1-10 Container image and Compose | In progress | Specified in [local setup](../development/local-setup.md) |

### Known gaps in what is done

These are recorded here so they are not forgotten; each is picked up by the issue named.

| Gap | Picked up by |
|---|---|
| `hodor-server` knows no tenants: its resolver always answers "not found" | M1-12, M1-13 |
| `hodor-worker` is a stub: the outbox dispatcher exists but nothing runs it | A worker wiring issue, before M1-27 |
| No event handlers are registered | M1-27 (email), M1-28 (audit) |
| Traces are exported but no test receives them | First issue that adds a traced database call |
| SQL is checked at run time, not at compile time (`sqlx::query!` with the offline cache is not set up) | M1-12, with the first repository |
| CI actions are pinned by tag, not by commit SHA | Hardening pass (threat G-15) |

## Where the implementation departs from the design

Each departure is reflected in the page that specifies the topic. They are collected here for a reader who knows the original design.

| Topic | Design said | What was built | Recorded in |
|---|---|---|---|
| Metrics backend and transport | OTLP plus a Prometheus endpoint | OTLP push to VictoriaMetrics, no scrape endpoint | [ADR-0015](../adr/0015-observability-stack.md) |
| Container images | One image per binary | One image with the three binaries | [deployment](../operations/deployment.md#artifacts) |
| TLS trust for the database client | Not specified | Operating system trust store, not bundled roots | [local setup](../development/local-setup.md) and `Cargo.toml` |
| Outbox delivery | A handler registry with per-handler idempotency | Delivery is atomic per event: all handlers for an event commit together with the "delivered" mark | [ADR-0003](../adr/0003-context-communication.md) |
| `UnitOfWork` | Port named, shape open | A trait object that adapters downcast to reach their transaction | [overview](../architecture/overview.md#cross-cutting-concerns) |
| Tenant lookup for HTTP | Middleware in `protocol-http` | Same, through a `TenantResolver` trait that the composition root implements, so `protocol-http` depends on no adapter | [overview](../architecture/overview.md#cross-cutting-concerns) |
