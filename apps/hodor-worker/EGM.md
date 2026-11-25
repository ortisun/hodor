# hodor-worker

## Overview

The package `hodor-worker` (`Cargo.toml`, description "Background jobs:
outbox dispatch, cleanup and scheduled tasks.") builds the `hodor-worker`
binary. Its source runs the outbox dispatch loop, the mail delivery loop,
the webhook delivery loop, the logout token loop, the trust bundle loop,
the cleanup loops, the key rotation loop and the policy check loop.

## Subdirectories & Boundaries

- src: [./src/EGM.md](./src/EGM.md) - the configuration, the two database
  pools, the outbox dispatch loop, the mail delivery loop, the webhook
  delivery loop, the logout token loop, the cleanup loops and the shutdown
  sequence.

## Dependencies

From `Cargo.toml`: `async-trait`, `clap`, `opentelemetry`, `tokio`, `tracing`,
and the workspace crates `hodor-adapters-crypto`, `hodor-adapters-http`,
`hodor-adapters-policy-check`, `hodor-adapters-postgres`,
`hodor-adapters-smtp`, `hodor-audit`, `hodor-authorization-opa`,
`hodor-kernel`, `hodor-keys`, `hodor-notification`, `hodor-oauth`,
`hodor-observability`, `hodor-protocol-http`, `hodor-tenant` and
`hodor-webhooks`. The tests use `hodor-adapters-postgres`, `hodor-kernel`, `hodor-keys`,
`hodor-notification` and `hodor-webhooks` with the `testing` feature,
`testcontainers`, and, in `tests/webhooks.rs`, `standardwebhooks` and `http`
to check the signature with an implementation that is not Hodor's; in
`tests/backchannel_logout.rs`, `hodor-session`, `axum` and `tower`, to read
the tenant's key set from its real route, and `jsonwebtoken`, to check the
logout tokens with a library that is not Hodor's; in
`tests/trust_bundles.rs`, `axum`, to serve a bundle endpoint on this
machine.

## Verification

- Run: `cargo test -p hodor-worker`
