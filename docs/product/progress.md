# Progress

What has been built, issue by issue. This page is updated with every merge into `develop`; the plan it tracks is in [epics.md](epics.md).

Last updated: 2026-11-20.

## Milestone 1: Walking skeleton

| Slice | Done | Total |
|---|---|---|
| A — Foundation | 11 | 11 |
| B — Tenancy | 3 | 3 |
| C — Identity | 3 | 3 |
| D — Password credential | 3 | 3 |
| E — Authentication and session | 4 | 7 |
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
| Issue-12 Tenant persistence and directory | Done | Use cases and ports in `hodor-tenant`; `tenant.tenant` and `platform.tenant_directory` with their triggers; PostgreSQL repository and directory; one contract suite passed by the in-memory fake and by PostgreSQL |
| Issue-13 Tenant commands and server resolver | Done | `hodor-cli tenant` commands; `hodor-server` resolves tenants through the directory and answers by status |

### Slice C — Identity

Specified in [the identity context](../architecture/contexts/identity.md).

| Issue | Status | What exists |
|---|---|---|
| Issue-14 Identity domain | Done | `hodor-identity` crate: users with their lifecycle, login identifiers with normalization, uniqueness within a user and primary rules, events that carry no personal data |
| Issue-15 User repository | Done | `identity.user` and `identity.user_identifier` under row-level security; PostgreSQL repository; one contract suite passed by the in-memory fake and by PostgreSQL |
| Issue-16 Identity use cases | Done | `IdentityService`: create, find by typed login, lifecycle changes, login identifier changes, profile; each change stored with its events in one unit of work |

### Slice D — Password credential

Specified in [the credential context](../architecture/contexts/credential.md).

| Issue | Status | What exists |
|---|---|---|
| Issue-17 Credential domain | Done | `hodor-credential` crate: the rules for an acceptable password, the password record with its history, events, and the hasher port |
| Issue-18 Argon2id hasher | Done | `hodor-adapters-crypto` crate: Argon2id behind the hasher port with bounded concurrency and a bounded queue, renewal of hashes made with older parameters, a check against nothing of equal cost, and the operating system random source |
| Issue-19 Credential storage and use cases | Done | `CredentialService`: set, change, verify with silent renewal, remove; `credential.password` and its history under row-level security; one contract suite passed by the in-memory store and by PostgreSQL |

### Slice E — Authentication and session

| Issue | Status | What exists |
|---|---|---|
| Issue-20 Session | Done | `hodor-session` crate: sessions with tokens stored only as hashes, idle and absolute expiry, revocation, token replacement; `session.session` under row-level security; one contract suite passed by the in-memory store and by PostgreSQL. SHA-256 behind a `Digest` port. Specified in [the session context](../architecture/contexts/session.md) |
| Issue-21 Authentication flow engine | Done | `hodor-authentication` crate: flows as data with the built-in flow, validation of a flow, the transaction that records a sign-in in progress, the `Authenticator` extension point and the engine. No real authenticators or storage yet. Specified in [the authentication context](../architecture/contexts/authentication.md) |
| Issue-22 Authenticators and lockout | Done | The identifier and password authenticators over the identity, credential and tenant contexts; the attempt guard with growing lockouts on identifiers and addresses; `authentication.attempt_counter` under row-level security |
| Issue-23 Completing a sign-in | Done | `AuthenticationService`: start, submit a step, describe, cancel; a completed sign-in starts a session exactly once; `authentication.transaction` under row-level security. A test signs a person in with nothing faked: PostgreSQL, Argon2id, SHA-256 and the operating system's random source |
| Issue-24 to Issue-26 | Not started | — |

### Known gaps in what is done

These are recorded here so they are not forgotten; each is picked up by the issue named.

| Gap | Picked up by |
|---|---|
| The outbox metrics were not confirmed to arrive in VictoriaMetrics from the Compose stack; the export path is covered by a test | Next change to the worker |
| Tenants have no routes of their own yet: an existing tenant answers `404` with `route.not_found` | Issue-24, the interaction API |
| The system tenant is not created automatically by the development stack | Issue-30, with the bootstrap administrator |
| The Argon2id hasher was not checked against a hash produced by another implementation; it relies on the library's own conformance | When a second implementation is at hand, for example password import |
| Rows of expired and revoked sessions are never removed | A cleanup job, later in Phase 1 |
| Sign-in works through the use cases only: there is no HTTP interface, no cookie and no page, and the binaries do not wire it | Issue-24 |
| No event handlers are registered | Issue-27 (email), Issue-28 (audit) |
| Traces are exported but no test receives them | First issue that adds a traced database call |
| SQL is checked at run time, not at compile time (`sqlx::query!` with the offline cache is not set up). Every query is exercised by an integration test instead | A dedicated issue, not yet scheduled |
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
