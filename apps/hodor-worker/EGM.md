# hodor-worker

## Overview

The package `hodor-worker` (`Cargo.toml`, description "Background jobs:
outbox dispatch, cleanup and scheduled tasks.") builds the `hodor-worker`
binary. Its source runs the outbox dispatch loop, the mail delivery loop and
the cleanup loop, which removes expired pending authorizations.

## Subdirectories & Boundaries

- src: [./src/EGM.md](./src/EGM.md) - the configuration, the two database
  pools, the outbox dispatch loop, the mail delivery loop, the cleanup loop
  and the shutdown sequence.

## Dependencies

From `Cargo.toml`: `async-trait`, `clap`, `opentelemetry`, `tokio`, `tracing`,
and the workspace crates `hodor-adapters-crypto`, `hodor-adapters-postgres`,
`hodor-adapters-smtp`, `hodor-audit`, `hodor-kernel`, `hodor-notification`,
`hodor-observability` and `hodor-protocol-http`. The tests use
`hodor-adapters-postgres`, `hodor-kernel` and `hodor-notification` with the
`testing` feature, and `testcontainers`.

## Verification

- Run: `cargo test -p hodor-worker`
