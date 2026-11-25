# hodor-keys

## Overview

The `hodor-keys` crate (`Cargo.toml` description: "The keys context: the
keys a tenant signs and encrypts with, and their lifecycle."). It owns key
sets per tenant and use (`sig`, `enc`, `data`) and key versions with their
states. It holds no cryptography: keys are made, kept and used by a
`KeyProvider`. It also owns the SPIFFE trust domains a tenant trusts and
their bundles (Decision 0042), read, checked and refreshed here and fetched
through the kernel's `HttpClient` and `DestinationCheck`. Storage, the provider and time are reached through ports and
kernel traits.

## Interface

- Source and public surface: [src](./src/EGM.md).
- Ports implemented elsewhere: `KeyStore` and `SealingStateStore`, by
  `PgKeyStore` and `PgSealingStateStore` in
  `crates/adapters-postgres/src/keys.rs`; `KeyProvider`, by
  `LocalKeyProvider` in `crates/adapters-crypto/src/keys.rs`;
  `FirstFormatSecrets`, by `SecretKeys` in
  `crates/adapters-crypto/src/sealing.rs`; `TrustDomainStore` and
  `DueRefreshes`, by `PgTrustDomainStore` and `PgDueRefreshes` in
  `crates/adapters-postgres/src/trust_domain.rs`.
- `TenantSecretBox` implements the kernel's `SecretBox` over the tenant's
  data keys; the binaries give it to every context that keeps secrets.
- Workspace dependencies: `hodor-kernel` (`crates/kernel`), plus
  `async-trait`, `base64`, `serde`, `serde_json` and `time`.
- Feature `testing`: enables the public `testing` module and
  `hodor-kernel/testing`.
- Dev dependencies: `hodor-kernel` with `testing`, the crate itself with
  `testing`, `tokio`.

## Invariants

- Only the `api` module is public to other crates; see [src](./src/EGM.md).
- One version per algorithm is active in a key set, and activation is the
  only way a version becomes active (see [domain](./src/domain/EGM.md)).
- Key material is never read by this crate and never carried by an event;
  `KeyMaterial` prints as its length only.
- Every store call is scoped to the tenant of the unit of work (see
  [application](./src/application/EGM.md)); only `DueRefreshes` looks
  across tenants, and only the worker is given it.
- A trust bundle is read whole or refused whole, and a bundle in force is
  replaced only by one that reads and, when fetched, does not go back in
  sequence (see [domain](./src/domain/EGM.md)).

## Side Effects

- Through `KeyStore`: reads and writes key versions. Through `KeyProvider`:
  makes keys and signs. Rotation (`KeyService::rotate_due`) is run by
  `KeyRotationJob` in `crates/adapters-postgres/src/key_rotation.rs`, which
  `apps/hodor-worker` schedules. Through `UnitOfWork::record_event`: records
  `keys.version_created`, `keys.version_activated`, `keys.version_retired`
  and `keys.version_revoked`; and for trust domains
  `keys.trust_domain_added`, `keys.trust_domain_replaced`,
  `keys.trust_domain_removed`, `keys.trust_bundle_refreshed` and
  `keys.trust_bundle_refresh_failed`.
- Through `HttpClient`: `GET` of bundle endpoints, when a trust domain is
  saved and when `BundleRefresher` (scheduled by `apps/hodor-worker`)
  refreshes it. Through `DestinationCheck`: the check of a bundle endpoint
  when it is saved.

## Verification

- Run: `cargo test -p hodor-keys`
