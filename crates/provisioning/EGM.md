# hodor-provisioning

## Overview

The provisioning context: Hodor as a SCIM 2.0 server (`Cargo.toml`
description). Other systems create, read, replace and list a tenant's users
and groups through it. It owns no users and no groups: it maps SCIM's
resources to the identity context's, reads the filters SCIM clients send, and
keeps in its own tables what SCIM carries that the identity context has no
place for (`src/lib.rs`). The specification is
`docs/architecture/contexts/provisioning.md`.

## Subdirectories & Boundaries

- src: [./src/EGM.md](./src/EGM.md) - the `api` module (`ProvisioningService`, the ports `ProvisionedUserRepository` and `ProvisionedGroupRepository`, the filter parser, the SCIM resources and the discovery documents) and the feature-gated `testing` module (in-memory stores, the contract and the corpus of filters).
- tests: integration tests of the crate: `filter_corpus.rs` (the corpus against the parser, and property tests over any text) and `service.rs` (the use cases and the contract on the in-memory stores).

## Workspace Dependencies

- `hodor-kernel` (`crates/kernel`): units of work, tenant context, errors, events, identifiers, the clock.
- `hodor-identity` (`crates/identity`): `IdentityService` and `GroupService`, whose `*_in` use cases this context runs in its own unit of work, and the `User`, `Group` and identifier types. The `testing` feature turns on `hodor-kernel/testing` and `hodor-identity/testing`.
- Other dependencies: `async-trait`, `serde`, `serde_json` (the resources are JSON values), `time` (dates of RFC 3339). Test-only: `tokio`, `proptest`.
- Depended on by `crates/adapters-postgres` (`PgProvisionedUserRepository`, `PgProvisionedGroupRepository` in `src/provisioning.rs`), `crates/protocol-http` (`src/scim.rs`) and `apps/hodor-server` (wiring). Nothing in layers 0 to 3 depends on it (`tests/architecture/src/lib.rs`, `RULES`).

## Verification

- Run: `cargo test -p hodor-provisioning`
- The contract runs on PostgreSQL in `crates/adapters-postgres/tests/provisioning.rs`.
