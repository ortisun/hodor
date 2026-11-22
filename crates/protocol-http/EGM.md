# hodor-protocol-http

## Overview

Crate `hodor-protocol-http` (`Cargo.toml` description: "HTTP layer:
routing, tenant resolution, error mapping, security headers and health
endpoints."). It holds the `axum` routers for the public listener (tenant
resolution, the interaction, authorization, administration and console interfaces, and the
static hosted pages and admin console) and for the operations listener
(health endpoints).

It depends on the domain crates' service types and on `hodor-kernel`, never
on an adapter (`src/lib.rs` module documentation; `[dependencies]` in
`Cargo.toml`). What it needs from outside comes in through the
`TenantResolver` and `ReadinessCheck` traits, which the composition root
implements.

## Interface

- Source contract: [src](./src/EGM.md). It lists every public symbol, every
  route declared in the routers, and the cookie, cross-site request forgery
  and error rules.
- `openapi/admin-v1.json`: the OpenAPI document of the administration
  interface. It is compiled into the crate as `ADMIN_OPENAPI`
  (`src/admin.rs`, `include_str!("../openapi/admin-v1.json")`) and served at
  `GET /openapi.json` of the administration router.

### Workspace dependencies

From `[dependencies]` in `Cargo.toml`:

- Domain crates: `hodor-audit`, `hodor-authentication`,
  `hodor-authorization`, `hodor-credential`, `hodor-federation`,
  `hodor-identity`, `hodor-oauth`, `hodor-session`.
- `hodor-kernel` (`TenantContext`, `DomainError`, `Caller`, `Digest`,
  `Clock`, `CorrelationId`).
- Third party: `async-trait`, `axum`, `form_urlencoded`, `http-body-util`, `serde`,
  `serde_json`, `tokio`, `tower-http`, `time`, `tracing`.

Development only (`[dev-dependencies]`): `hodor-adapters-crypto` and
`hodor-adapters-ldap` (both with `testing`), the `testing` feature of the
domain crates, `hodor-notification`, `hodor-tenant` and `hodor-saml`, plus
`miniz_oxide`, `base64`, `tower` and `tokio` with
`io-util` and `test-util`.

## Invariants

- No production dependency on an adapter (`src/lib.rs` module
  documentation; adapters appear only in `[dev-dependencies]`).
- `ADMIN_OPERATIONS` in `src/admin.rs` and `openapi/admin-v1.json` describe
  the same operations; the documentation of `ADMIN_OPERATIONS` says a test
  holds them together.
- The tenant of a request comes only from the `/t/{slug}` path prefix (see
  the [source contract](./src/EGM.md)).

## Side Effects

- Listens on a TCP socket (`serve`), sets and clears cookies, reads the
  static application directories, and logs through `tracing`. State changes
  happen only through the domain services; see the
  [source contract](./src/EGM.md).

## Verification

- Run: `cargo test -p hodor-protocol-http`
- Of the six files in `tests/`, only `tests/federated_sign_in.rs` starts a
  container: its LDAP directory tests
  call `hodor_adapters_ldap::testing::TestDirectory::start()`, which starts
  OpenLDAP in a container through `testcontainers`
  (`crates/adapters-ldap/src/testing.rs`), so a running Docker daemon is
  needed for the full suite. None of the tests is marked `#[ignore]`.
