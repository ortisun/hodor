# hodor-adapters-http

## Overview

The outbound HTTP adapter crate (package `hodor-adapters-http`). Its manifest describes it as "the one guarded way out to addresses that other people chose" (`Cargo.toml` `description`).

It implements the kernel port `HttpClient` (see [the kernel contract](../kernel/EGM.md)) twice:

- `impl HttpClient for GuardedHttpClient` (`src/client.rs`), for addresses other people chose;
- `impl DestinationCheck for GuardedHttpClient` (`src/client.rs`), which says whether such an address could be called now, without calling it;
- `impl HttpClient for ServiceHttpClient` (`src/service.rs`), for the services the operator configured (Open Policy Agent).

## Subdirectories & Boundaries

- `src`: [./src/EGM.md](./src/EGM.md) - `GuardedHttpClient`, `ServiceHttpClient`, `OutboundPolicy` and `is_public`.
  - The guarded client refuses addresses that are not public and pins connections to the addresses it checked.
  - The service client calls only its configured origins.
  - Both follow no redirects and cap the time of a request and the size of response bodies.
  - Their side effects are name lookups and outbound HTTP requests.
- `tests`: integration tests (not documented here).

## Workspace Dependencies

From `Cargo.toml`:

- Hodor crates: `hodor-kernel`.
- Runtime: `async-trait`, `reqwest` (feature `rustls`), `tokio`, `tracing`.
- Development only: `tokio` (feature `io-util`).

## Verification

- Run: `cargo test -p hodor-adapters-http`
