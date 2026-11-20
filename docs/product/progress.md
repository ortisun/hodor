# Progress

What has been built, issue by issue. This page is updated with every merge into `develop`; the plan it tracks is in [epics.md](epics.md).

Last updated: 2026-11-20.

## Milestone 1: Walking skeleton

| Slice | Done | Total |
|---|---|---|
| A — Foundation | 11 | 11 |
| B — Tenancy | 1 | 3 |
| C — Identity | 0 | 3 |
| D — Password credential | 0 | 3 |
| E — Authentication and session | 0 | 7 |
| F — Audit, notification, admin | 0 | 4 |
| G — Hosted user interface and acceptance | 0 | 3 |

### Slice A — Foundation

| Issue | Status | What exists |
|---|---|---|
| Issue-01 Workspace skeleton | Done | Cargo workspace, shared lints with `unsafe` forbidden, pinned toolchain, `deny.toml` |
| Issue-02 continuous integration pipeline | Done | GitHub Actions: format, lint, build, test, dependency checks |
| Issue-03 Architecture test | Done | `tests/architecture` checks every crate against the allowed edges in [crates.md](../architecture/crates.md) |
| Issue-04 Kernel | Done | Typed UUIDv7 identifiers, `TenantContext`, `Clock`, `RandomSource`, `Secret<T>`, `DomainError`, event types, pagination |
| Issue-05 PostgreSQL base | Done | Tenant-scoped transactions, forced row-level security helper, embedded migrations, `hodor-cli migrate`, container test harness |
| Issue-06 Schema rules | Done | A catalog check that fails when a table is not a proper tenant table |
| Issue-07 Outbox | Done | `UnitOfWork` port, `platform.outbox`, dispatcher with `SKIP LOCKED`, rollback and backoff |
| Issue-08 Observability | Done, with a gap | Logs, traces and metrics over OTLP; VictoriaMetrics verified by test. Trace export is not yet verified against a backend |
| Issue-09 HTTP base | Done | Tenant resolution from the path, request identifiers, security headers, limits, problem documents, health endpoints, graceful shutdown; `hodor-server` wired |
| Issue-10 Container image and Compose | Done | Distroless image with the three binaries; Compose stack with PostgreSQL, migrations, server and VictoriaMetrics; `hodor-cli probe` |
| Issue-34 Worker runs the outbox dispatcher | Done | `hodor-worker` delivers outbox events in a polling loop, with health endpoints, metrics and a clean stop; part of the Compose stack |

### Slice B — Tenancy

Specified in [the tenant context](../architecture/contexts/tenant.md).

| Issue | Status | What exists |
|---|---|---|
| Issue-11 Tenant domain | Done | `hodor-tenant` crate: slug rules, lifecycle with every transition checked, settings with defaults and bounds, events |
| Issue-12 Tenant persistence and directory | Not started | — |
| Issue-13 Tenant commands and server resolver | Not started | — |

### Known gaps in what is done

These are recorded here so they are not forgotten; each is picked up by the issue named.

| Gap | Picked up by |
|---|---|
| `hodor-server` knows no tenants: its resolver always answers "not found" | Issue-12, Issue-13 |
| The outbox metrics were not confirmed to arrive in VictoriaMetrics from the Compose stack; the export path is covered by a test | Next change to the worker |
| No event handlers are registered | Issue-27 (email), Issue-28 (audit) |
| Traces are exported but no test receives them | First issue that adds a traced database call |
| SQL is checked at run time, not at compile time (`sqlx::query!` with the offline cache is not set up) | Issue-12, with the first repository |
| Continuous integration actions are pinned by tag, not by commit SHA | Hardening pass (threat Threat-General-15) |

## Where the implementation departs from the design

Each departure is reflected in the page that specifies the topic. They are collected here for a reader who knows the original design.

| Topic | Design said | What was built | Recorded in |
|---|---|---|---|
| Metrics backend and transport | OTLP plus a Prometheus endpoint | OTLP push to VictoriaMetrics, no scrape endpoint | [Decision 0015](../decisions/0015-observability-stack.md) |
| Container images | One image per binary | One image with the three binaries | [deployment](../operations/deployment.md#artifacts) |
| TLS trust for the database client | Not specified | Operating system trust store, not bundled roots | [local setup](../development/local-setup.md) and `Cargo.toml` |
| Outbox delivery | A handler registry with per-handler idempotency | Delivery is atomic per event: all handlers for an event commit together with the "delivered" mark | [Decision 0003](../decisions/0003-context-communication.md) |
| `UnitOfWork` | Port named, shape open | A trait object that adapters downcast to reach their transaction | [overview](../architecture/overview.md#cross-cutting-concerns) |
| Tenant lookup for HTTP | Middleware in `protocol-http` | Same, through a `TenantResolver` trait that the composition root implements, so `protocol-http` depends on no adapter | [overview](../architecture/overview.md#cross-cutting-concerns) |
