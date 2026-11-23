# hodor-adapters-policy-check

## Overview

The adapter crate (package `hodor-adapters-policy-check`) that runs the `opa` binary for the policy lifecycle. Its manifest describes it as checking, testing and simulating "Open Policy Agent policies with the opa binary, in a child process with nothing of its own" (`Cargo.toml` `description`).

It implements the port `hodor_authorization_opa::api::PolicyChecker`, from `crates/authorization-opa`: `impl PolicyChecker for OpaProcessChecker` (`src/lib.rs`). The mechanism is [Decision 0026](../../docs/decisions/0026-policy-checks-in-a-sandbox.md); what is checked is specified in `docs/architecture/contexts/authorization.md`, "The policy lifecycle".

## Subdirectories & Boundaries

- `src`: [./src/EGM.md](./src/EGM.md) - `OpaProcessChecker`, `RunLimits`, `OPA_VERSION` and `CAPABILITIES`. Its side effects are a directory under the temporary directory and a child process for each run.
- `tests`: integration tests against the real binary (not documented here).

## Workspace Dependencies

From `Cargo.toml`:

- Hodor crates: `hodor-kernel` (`Digest`, `DomainError`, `TenantId`), `hodor-authorization-opa` (the port and the types of a report), as the architecture test allows for this adapter.
- Runtime: `async-trait`, `serde_json`, `tokio` with `process`, `io-util` and `fs`, `uuid`.
- Development only: `hodor-adapters-crypto` (`Sha256Digest`).

## Verification

- Run: `cargo test -p hodor-adapters-policy-check`. `tests/opa.rs` runs the real `opa` 1.10.1: the binary `HODOR_TEST_OPA_BINARY` names, or else the release for the machine, downloaded once with `curl` into Cargo's temporary directory for tests and used only if its SHA-256 is the published one.
