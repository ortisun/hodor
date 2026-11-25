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
and the workspace crates `hodor-adapters-crypto`, `hodor-adapters-http`, `hodor-adapters-kms`,
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
- The tests that need a running server start the binary through `tests/support/mod.rs`. The server is given `127.0.0.1:0` for both listeners and chooses its own ports; the harness reads them from the line `hodor-server started`, written in JSON, and then waits for `/readyz`. A port chosen by the test and handed to the server would be free when chosen, not when the server binds it: under load another test or connection can take it in between, and the server then stops at once.
- The tests that need a database start one with `TestDatabase` of `hodor-adapters-postgres`, whose port is published on `127.0.0.1` alone and which the server is given as `127.0.0.1` too: a port published on every address may be shared, on Docker Desktop for macOS, with a server another test started on `127.0.0.1`, which would then receive the connections meant for PostgreSQL (`docs/architecture/testing.md`, "Containers in tests").
- The harness reads everything the server writes, on its standard output and its standard error, so that the server never waits on a full pipe. If the server stops before it is ready, the test fails at once with its exit status and the last lines it wrote; if it is not ready within thirty seconds, or a test fails while it runs, those lines are shown too.
