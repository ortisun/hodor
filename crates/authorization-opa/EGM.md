# hodor-authorization-opa

## Overview

The `hodor-authorization-opa` crate (`Cargo.toml` description: "Open Policy Agent as an engine of the authorization context, over its Data API."). It provides `OpenPolicyAgentEngine`, an `AuthorizationEngine` of [the authorization context](../authorization/EGM.md) named `open_policy_agent`. It asks an Open Policy Agent instance named by the operator, on a path built from the tenant and the binding alone, and turns every failure into an indeterminate answer with its own reason. The authorization context knows nothing of it (Decision 0010). Specified in `docs/architecture/contexts/authorization.md`, "Open Policy Agent as an engine".

## Interface

- Source and public surface: [src](./src/EGM.md).
- Workspace dependencies: `hodor-kernel` and `hodor-authorization`, as the architecture test allows for this crate (`tests/architecture/src/lib.rs`, layer 3), plus `async-trait`, `serde_json` and `time`. No HTTP library: requests go through the kernel's `HttpClient` port.
- Used by `apps/hodor-server`, which builds the engine with a `ServiceHttpClient` of `hodor-adapters-http` and registers it.
- Dev dependencies: `hodor-adapters-crypto` (`Sha256Digest`), `hodor-adapters-http` (`ServiceHttpClient`), `hodor-authorization` and `hodor-kernel` with `testing`, `serde_json`, `testcontainers`, `time`, `tokio`.

## Invariants

- Only the `api` module is public; see [src](./src/EGM.md).
- The address comes from `Instances`, the operator's configuration; the path from `decision_path`, the tenant and the namespace. Nothing in a request reaches either.
- Only a `result` object with a boolean `allow` decides; every other answer and every failure is `indeterminate`.

## Verification

- Run: `cargo test -p hodor-authorization-opa`. `tests/open_policy_agent.rs` and `tests/capabilities.rs` start `openpolicyagent/opa:1.10.1` containers and need Docker; `tests/engine.rs` and the unit tests do not.
