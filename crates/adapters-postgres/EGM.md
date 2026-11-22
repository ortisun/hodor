# hodor-adapters-postgres

## Overview

Crate `hodor-adapters-postgres` (`Cargo.toml` description: "PostgreSQL
adapter: connection pool, tenant-scoped transactions and migrations."). It
is the PostgreSQL implementation of the storage ports that the domain
crates declare: the unit of work, one store or repository per bounded
context, the outbox dispatcher, and the embedded schema migrations.

The schema itself is not in this crate. `src/migrate.rs` embeds the
repository's top-level `migrations/` folder at compile time
(`sqlx::migrate!("../../migrations")`).

## Interface

- Source contract: [src](./src/EGM.md). It lists every public type, the
  `impl ... for` line of each port it implements, and the tables named in its
  SQL.
- Feature `testing` (`Cargo.toml`): enables `pub mod testing`
  (`TestDatabase`, `schema_violations`) and the optional dependencies
  `testcontainers`, `testcontainers-modules` and `tokio`.

### Workspace dependencies

From `[dependencies]` in `Cargo.toml`:

- Domain crates whose ports this crate implements: `hodor-audit`,
  `hodor-authentication`, `hodor-authorization`, `hodor-credential`,
  `hodor-federation`, `hodor-identity`, `hodor-notification`,
  `hodor-session`, `hodor-tenant`.
- `hodor-kernel` (the `UnitOfWork`, `UnitOfWorkFactory`, `EventHandler`,
  `TenantContext` and `DomainError` types).
- Third party: `async-trait`, `serde_json`, `sqlx`, `time`, and, behind
  `testing`, `testcontainers`, `testcontainers-modules`, `tokio`.

Development only (`[dev-dependencies]`): `hodor-adapters-crypto`, which the
`Cargo.toml` comment says is used by the full sign-in test to run the real
hasher against the real database ("Adapters never depend on each other in
production code"), `hodor-saml`, and the `testing` feature of the domain
crates and of this crate itself.

## Invariants

- No production dependency on another adapter or on a protocol crate
  (`Cargo.toml` `[dependencies]`; the comment above
  `hodor-adapters-crypto` in `[dev-dependencies]`).
- Migrations are run through `migrate` with a pool that connects as the
  schema owner, never by the server at startup (`src/migrate.rs`).
- Tenant data is reached only through a tenant-bound transaction (see the
  [source contract](./src/EGM.md)).

## Side Effects

- Reads and writes the PostgreSQL database; see the
  [source contract](./src/EGM.md) for tables, locks and the outbox.

## Verification

- Run: `cargo test -p hodor-adapters-postgres`
- Requires a running Docker daemon. All fourteen integration test files in
  `tests/` use `TestDatabase`, which starts a PostgreSQL container
  (`testcontainers_modules::postgres::Postgres`, tag `17-alpine`) through
  `testcontainers` (`src/testing.rs`). The crate depends on itself
  with `features = ["testing"]` in `[dev-dependencies]`, so the feature is on
  for tests without extra flags.
