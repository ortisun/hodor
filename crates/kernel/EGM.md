# hodor-kernel

## Overview

The shared kernel crate (package `hodor-kernel`). Its manifest describes it as "identifiers, tenant context, events and errors used by every bounded context" (`Cargo.toml` `description`). It also defines the port traits that the adapter crates implement: `Clock`, `RandomSource`, `Digest`, `SecretBox`, `SignatureVerifier`, `HttpClient`, `UnitOfWork`, `UnitOfWorkFactory` and `EventHandler`.

## Subdirectories & Boundaries

- `src`: [./src/EGM.md](./src/EGM.md) - identifiers, `TenantContext`, `DomainError`, events and the outbox envelope, pagination, `Secret`, and the port traits. It has no file, network or logging side effects of its own.

## Workspace Dependencies

From `Cargo.toml`, every dependency comes from the workspace (`.workspace = true`):

- Runtime: `async-trait`, `serde`, `serde_json`, `thiserror`, `time`, `uuid`, `zeroize`.
- The kernel depends on no other Hodor crate.

## Features

- `testing = []`: compiles the deterministic test doubles (`FixedClock`, `CountingRandom`, `FakeDigest`, `FakeSecretBox`, `InMemoryUnitOfWork`, `InMemoryUnitOfWorkFactory`) for tests in other crates (`Cargo.toml` `[features]`, and `#[cfg(any(test, feature = "testing"))]` in the `src` modules).

## Verification

- Run: `cargo test -p hodor-kernel`
