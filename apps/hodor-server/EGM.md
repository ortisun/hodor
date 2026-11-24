# hodor-server

## Overview

The package `hodor-server` (`Cargo.toml`) builds the `hodor-server` binary,
the HTTP composition root. It serves the public router and the operations
router, connects to PostgreSQL as the application role, and never runs
migrations (doc comment on `Command::Migrate` in `apps/hodor-cli/src/main.rs`).

## Subdirectories & Boundaries

- src: [./src/EGM.md](./src/EGM.md) - the configuration, the wiring of the
  domain services to their adapters, the routers it nests, and the shutdown
  sequence.

## Dependencies

From `Cargo.toml`: `async-trait`, `axum`, `clap`, `time`, `tokio`, `tracing`,
and the workspace crates `hodor-adapters-crypto`, `hodor-adapters-http`,
`hodor-adapters-ldap`, `hodor-adapters-postgres`, `hodor-audit`,
`hodor-authentication`, `hodor-authorization`, `hodor-authorization-native`,
`hodor-authorization-opa`,
`hodor-credential`,
`hodor-federation`, `hodor-identity`, `hodor-kernel`, `hodor-notification`,
`hodor-observability`, `hodor-protocol-http`, `hodor-provisioning`, `hodor-session` and
`hodor-tenant`. The tests use `hodor-adapters-postgres` and `hodor-kernel`
with the `testing` feature.

## Verification

- Run: `cargo test -p hodor-server`
