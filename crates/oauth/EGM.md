# hodor-oauth

## Overview

The `hodor-oauth` crate (`Cargo.toml` description: "The OAuth context:
applications, clients and resource servers, and the tokens Hodor issues to
them."). Today it holds the first part of the context, Issue-53: the
applications a tenant registers, their clients with secrets and keys, and
resource servers with their scopes. It has no endpoint and issues no token
yet. Storage, randomness, hashing and time are reached through ports and
kernel traits.

## Interface

- Source and public surface: [src](./src/EGM.md).
- Ports implemented elsewhere: `ApplicationStore`, `ClientStore` and
  `ResourceServerStore`, by `PgApplicationStore`, `PgClientStore` and
  `PgResourceServerStore` in `crates/adapters-postgres/src/oauth.rs`.
- Workspace dependencies: `hodor-kernel`, plus `async-trait`, `base64`,
  `serde`, `serde_json` and `time`. The architecture rules also allow
  `hodor-identity`, `hodor-session`, `hodor-keys` and `hodor-tenant`, which
  later issues use.
- Feature `testing`: enables the public `testing` module and
  `hodor-kernel/testing`.
- Dev dependencies: `hodor-kernel` with `testing`, the crate itself with
  `testing`, `tokio`.

## Invariants

- Only the `api` module is public to other crates; see [src](./src/EGM.md).
- A client secret leaves the crate once, from
  `ApplicationService::create_client` or `rotate_client_secret`; only its
  SHA-256 hash is stored, and events never carry either (see
  [domain](./src/domain/EGM.md)).
- Every store call is scoped to the tenant of the unit of work (see
  [application](./src/application/EGM.md)).

## Side Effects

- Through the stores: reads and writes applications, clients and resource
  servers. Through `UnitOfWork::record_event`: records the `oauth.*` events.

## Verification

- Run: `cargo test -p hodor-oauth`, and
  `cargo test -p hodor-adapters-postgres --test oauth` for PostgreSQL.
