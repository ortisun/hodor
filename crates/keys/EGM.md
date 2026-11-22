# hodor-keys

## Overview

The `hodor-keys` crate (`Cargo.toml` description: "The keys context: the
keys a tenant signs and encrypts with, and their lifecycle."). It owns key
sets per tenant and use (`sig`, `enc`, `data`) and key versions with their
states. It holds no cryptography: keys are made, kept and used by a
`KeyProvider`. Storage, the provider and time are reached through ports and
kernel traits.

## Interface

- Source and public surface: [src](./src/EGM.md).
- Ports implemented elsewhere: `KeyStore`, by `PgKeyStore` in
  `crates/adapters-postgres/src/keys.rs`; `KeyProvider`, by
  `LocalKeyProvider` in `crates/adapters-crypto/src/keys.rs`.
- Workspace dependencies: `hodor-kernel` (`crates/kernel`), plus
  `async-trait`, `serde` and `time`.
- Feature `testing`: enables the public `testing` module and
  `hodor-kernel/testing`.
- Dev dependencies: `hodor-kernel` with `testing`, the crate itself with
  `testing`, `serde_json`, `tokio`.

## Invariants

- Only the `api` module is public to other crates; see [src](./src/EGM.md).
- One version per algorithm is active in a key set, and activation is the
  only way a version becomes active (see [domain](./src/domain/EGM.md)).
- Key material is never read by this crate and never carried by an event;
  `KeyMaterial` prints as its length only.
- Every store call is scoped to the tenant of the unit of work (see
  [application](./src/application/EGM.md)).

## Side Effects

- Through `KeyStore`: reads and writes key versions. Through `KeyProvider`:
  makes keys and signs. Rotation (`KeyService::rotate_due`) is run by
  `KeyRotationJob` in `crates/adapters-postgres/src/key_rotation.rs`, which
  `apps/hodor-worker` schedules. Through `UnitOfWork::record_event`: records
  `keys.version_created`, `keys.version_activated`, `keys.version_retired`
  and `keys.version_revoked`.

## Verification

- Run: `cargo test -p hodor-keys`
