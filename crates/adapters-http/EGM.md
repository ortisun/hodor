# hodor-adapters-http

## Overview

The outbound HTTP adapter crate (package `hodor-adapters-http`). Its manifest describes it as "the one guarded way out to addresses that other people chose" (`Cargo.toml` `description`).

It implements the kernel port `HttpClient` (see [the kernel contract](../kernel/EGM.md)): `impl HttpClient for GuardedHttpClient` (`src/client.rs:199`).

## Subdirectories & Boundaries

- `src`: [./src/EGM.md](./src/EGM.md) - `GuardedHttpClient`, `OutboundPolicy` and `is_public`. The client refuses addresses that are not public, pins connections to the addresses it checked, follows no redirects and caps the size of response bodies. Its side effects are name lookups and outbound HTTP requests.
- `tests`: integration tests (not documented here).

## Workspace Dependencies

From `Cargo.toml`:

- Hodor crates: `hodor-kernel`.
- Runtime: `async-trait`, `reqwest` (feature `rustls`), `tokio`, `tracing`.
- Development only: `tokio` (feature `io-util`).

## Verification

- Run: `cargo test -p hodor-adapters-http`
