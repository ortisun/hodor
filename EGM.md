# Hodor Blueprint

## System Overview

Hodor is an identity, authentication and authorization server for many tenants, written in Rust, with TypeScript browser frontends. The human-maintained overview, flows and documentation map are in [./README.md](./README.md) and `docs/`. This file is the contract index for the code.

The repository is one Cargo workspace (`Cargo.toml`: `members = ["crates/*", "apps/*", "tests/*"]`, edition 2024, toolchain `1.98.0` pinned in `rust-toolchain.toml`, `unsafe_code = "forbid"` in `[workspace.lints.rust]`) plus three npm packages under `frontend/`.

At run time there are three processes, all built from `apps/` and wired from `crates/`:

- `hodor-server` serves a public HTTP listener (default `0.0.0.0:8080`) and an operations listener (default `127.0.0.1:9090`). It nests the routers of `hodor-protocol-http` (the interaction routes, the administration interface, the console interface, the hosted pages and console files). It connects to PostgreSQL as a member of `hodor_app`, makes outbound HTTPS calls to identity providers through `GuardedHttpClient`, and makes LDAP connections limited to `HODOR_DIRECTORY_HOSTS`. It queues email but never sends it.
- `hodor-worker` runs its loops side by side: outbox dispatch (`OutboxDispatcher::dispatch_batch`, whose handlers are `AuditHandler`, so every event becomes an audit record, `WebhookFanOut`, which makes the webhook deliveries of the published event types, and `BackChannelLogoutFanOut`, which makes a logout delivery for every client signed in to with a session that ended), webhook delivery (`WebhookSender::lease_due` and `send`, many at once, through `GuardedHttpClient`, with `HODOR_SECRET_KEYS`), logout token delivery (`BackChannelLogoutSender::lease_due` and `send`, likewise, with `HODOR_SECRET_KEYS` and `HODOR_PUBLIC_URL`), mail delivery (`DeliveryService::deliver_pending` through `SmtpSender`), cleanup of expired pending authorizations (`PendingAuthorizationCleanup::run`) and of the records of expired access tokens (`AccessTokenCleanup::run`), and, with `HODOR_SECRET_KEYS`, key rotation (`KeyRotationJob::run`). It connects as a member of `hodor_app` and of `hodor_platform`.
- `hodor-cli` is the operations tool, and the only process that applies migrations (`hodor-cli migrate`, as the schema owner). It also manages tenants, the first administrator of a tenant, identity providers, audit chain verification and secret keys.

A state change and its events are written in one PostgreSQL transaction: `PgUnitOfWork::commit_now` (`crates/adapters-postgres/src/uow.rs`) inserts the recorded events into `platform.outbox` before committing.

The root holds no source code of its own, only the manifests `Cargo.toml`, `Cargo.lock`, `deny.toml` (cargo-deny rules for advisories, licenses, bans and sources) and `rust-toolchain.toml`.

## Subdirectories & System Boundaries

- apps: [./apps/EGM.md](./apps/EGM.md) - The three binaries `hodor-server`, `hodor-worker` and `hodor-cli`, each a single `src/main.rs` composition root with its flags and environment variables (`HODOR_*`), and `hodor-ext-authz`, Envoy's external authorization over the Authorization API, which depends on no context crate; and `hodor-cert-manager-issuer`, cert-manager's outside issuer over the signing operation, which depends on no context crate either.
- crates: [./crates/EGM.md](./crates/EGM.md) - The layered library crates: the kernel, the bounded contexts (tenant, identity, credential, session, keys, authorization, audit, notification, authentication, saml, federation, webhooks, and Open Policy Agent as an authorization engine), and the adapters (PostgreSQL, crypto, HTTP client, LDAP, SMTP, observability, the HTTP protocol layer).
- migrations: [./migrations/EGM.md](./migrations/EGM.md) - Twenty-one PostgreSQL migrations embedded by `sqlx::migrate!("../../migrations")` in `crates/adapters-postgres/src/migrate.rs`: the roles `hodor_app` and `hodor_platform`, every table, row-level security per tenant, and the append-only audit tables.
- frontend: [./frontend/EGM.md](./frontend/EGM.md) - The hosted pages (`auth-ui`, which also holds the Hodor theme and the browser tests), the administration console (`admin-console`), and the design system showcase (`design-system`).
- deploy: [./deploy/EGM.md](./deploy/EGM.md) - The container image (`deploy/docker/Dockerfile`), the local development stack (`deploy/docker/compose.yaml`), the development OpenID Connect provider, SAML identity provider and directory, and the milestone demonstrations (`deploy/demo`). Not for production. The two installation packages, which hold no secret, are in `deploy/install`: a Compose file for one machine and a Helm chart.
- tests: no contract file. `tests/architecture` (package `hodor-architecture-tests`) holds only tests: it checks the crate dependency rules in `tests/architecture/src/lib.rs` (`RULES`).
- docs: no contract file. Human-written specifications, maintained by people; see [./README.md](./README.md).

## Global Invariants

- Tenants are kept apart in the database: every tenant table except `platform.tenant_directory` has row-level security enabled and forced, with the policy `tenant_isolation` on `tenant_id = platform.current_tenant_id()` (`migrations/0001_platform_foundation.sql`, `platform.enable_tenant_rls`). `Database::begin` (`crates/adapters-postgres/src/database.rs`) binds the tenant for one transaction with `set_config('app.tenant_id', $1, true)`.
- On the HTTP side, the tenant comes only from the `/t/{slug}` path prefix. A malformed, unknown or absent slug gives 404 `tenant.not_found` and a suspended tenant gives 403 `tenant.suspended` (`crates/protocol-http/src/tenant.rs`).
- Only `hodor-cli migrate` applies migrations, connected as the schema owner. The server and the worker never run them (`apps/hodor-cli/src/main.rs`, `Command::Migrate`; `crates/adapters-postgres/src/migrate.rs`).
- The crate dependency rules hold: domain and application crates stay free of infrastructure libraries, an adapter never depends on another adapter, `hodor-ext-authz` and `hodor-cert-manager-issuer` depend on `hodor-observability` alone, and only `hodor-saml` may depend on an XML library (`tests/architecture/src/lib.rs`: `RULES`, `INFRASTRUCTURE`, `XML_CRATE`).
- `audit.record` is append-only: UPDATE and DELETE are refused, and each event is recorded once (`migrations/0012_audit.sql`). The records are hash-chained per tenant (`crates/audit/src/domain/record.rs`, `AuditRecord::computed_hash`).
- Secrets do not leak through logs or events. `Secret` redacts its `Debug` output and zeroizes on drop (`crates/kernel/src/secret.rs`). Session tokens, verification tokens and access tokens are stored only as SHA-256 hashes. Domain events carry identifiers, never tokens, passwords or email addresses (the module comments of each context's `domain/event.rs`).
- `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` allows plain HTTP to private addresses for the development providers, and in the worker for webhook endpoints and back-channel logout addresses. It must never be set anywhere real (`apps/hodor-server/src/main.rs` and `apps/hodor-worker/src/main.rs`, `Config`; `deploy/docker/compose.yaml`).

## Global Side Effects

- PostgreSQL: all state, reached through `hodor-adapters-postgres` with the roles `hodor_app` (server, worker, command-line tool) and `hodor_platform` (worker), and the schema owner for migrations.
- Outbound network: HTTPS to OpenID Connect and GitHub providers and, once when a pairwise client is saved, to its sector identifier address from the server and the command-line tool, and to tenants' webhook endpoints and clients' back-channel logout addresses from the worker (`hodor-adapters-http`, `GuardedHttpClient`), LDAP to allowed directories (`hodor-adapters-ldap`), and SMTP from the worker only (`hodor-adapters-smtp`).
- Telemetry: structured logs to standard output, and traces and metrics over OTLP when their endpoints are configured (`hodor-observability`).
- Listeners: the server's public and operations listeners, and the worker's operations listener (default `127.0.0.1:9091`).

## System Verification

- Run: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings` (job `lint` in `.github/workflows/ci.yml`).
- Run: `cargo test --workspace --locked` (job `test`). Some tests start containers through testcontainers and need Docker (see [./crates/EGM.md](./crates/EGM.md)).
- Run: `cargo deny check` and `cargo machete` (job `supply-chain`).
- Frontend checks: see [./frontend/EGM.md](./frontend/EGM.md) (jobs `pages`, `console`, `showcase`).
- End to end (job `pages`): `docker compose -f deploy/docker/compose.yaml up --build --wait`, then `npm run browser-tests` in `frontend/auth-ui`, then `python3 deploy/demo/demo.py` and `python3 deploy/demo/external_identities.py`.
