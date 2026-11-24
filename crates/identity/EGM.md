# hodor-identity

## Overview

The identity context: users and the login identifiers they are found by
(`Cargo.toml` description). It owns who exists inside a tenant, how they are
found and whether they may act, and does not know how a user proves who they
are (`src/lib.rs`). Storage is reached only through the `UserRepository`
port, which adapter crates implement.

## Subdirectories & Boundaries

- src: [./src/EGM.md](./src/EGM.md) - the `api` module (`IdentityService`, `UserRepository`, `User`, `UserEvent` and the identifier types) and the feature-gated `testing` module.
- tests: integration tests of the crate (not documented here).

## Workspace Dependencies

- `hodor-kernel` (`crates/kernel`): units of work, tenant context, errors, events, clock, identifiers and paging types. The `testing` feature of this crate turns on `hodor-kernel/testing`.
- Other dependencies: `async-trait`, `serde`. Test-only dependencies: `tokio`, `proptest`.
- Crates in this workspace that depend on `hodor-identity` (from their `Cargo.toml`): `crates/adapters-postgres`, `crates/authentication`, `crates/federation`, `crates/protocol-http`, `crates/provisioning`.
- The `UserRepository` port is implemented by `PgUserRepository` in `crates/adapters-postgres/src/identity.rs`.

## Verification

- Run: `cargo test -p hodor-identity`
