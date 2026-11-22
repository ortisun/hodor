# hodor-keys source

## Overview

The keys context: the keys a tenant's tokens are signed with and its
secrets are encrypted under (`lib.rs` crate documentation). The
specification it follows is `docs/architecture/contexts/keys.md`.

`lib.rs` keeps `application` and `domain` private and exposes the public
surface through `pub mod api`.

## Interface

- `api` re-exports:
  - Ports: `KeyStore`, `KeyProvider`, `SealingStateStore`, `FirstFormatSecrets`.
  - Service: `KeyService`, `RotationReport`, `Signature`.
  - Secrets at rest: `TenantSecretBox`, `SEALED_FORMAT` (2), `LOST_RACE`.
  - Event: `KeyEvent`.
  - Domain: `GeneratedKey`, `KeyAlgorithm`, `KeyMaterial`, `KeyState`,
    `KeyUse`, `KeyVersion`, `KeyVersionId`, `KeyVersionSnapshot`,
    `MAX_REASON_LENGTH`, `Activation`, `KeySet`, `RotationChange`,
    `RotationPolicy`.
- `testing` (public test-support module, compiled only under
  `#[cfg(any(test, feature = "testing"))]`):
  - `InMemoryKeys`: a `KeyStore` kept in a shared
    `Arc<Mutex<BTreeMap<(TenantId, KeyVersionId), KeyVersion>>>`; its
    `update` changes only the lifecycle fields.
  - `InMemorySealingStates`: a `SealingStateStore` in memory.
  - `FakeFirstFormat`: a `FirstFormatSecrets` for tests.
  - `FakeKeyProvider`: a `KeyProvider` named `fake` whose material names the
    tenant, version and algorithm and whose "signature" is that label
    followed by the message. Not cryptography; tests only.
  - `pending_version(tenant, algorithm, at)`: a pending version made as the
    fake provider would.
  - `Ports<'a> { units_of_work, keys }` and `run_contract(ports)`: the store
    contract every implementation must pass; it panics on a broken rule.
- Subdirectories:
  - [application](./application/EGM.md): `KeyStore` and `KeyProvider` ports
    and `KeyService` use cases.
  - [domain](./domain/EGM.md): `KeyVersion`, `KeySet`, `KeyEvent` and
    the rotation policy and plan.

## Invariants

- Other crates may use only what `api` re-exports (`lib.rs`).
- The store contract (`testing.rs:run_contract`) requires that a version of
  every algorithm loads back unchanged; lookups and lists never cross
  tenants; a list holds the versions of its use only; `update` stores the
  state, times and reason and never the key material or public key; an
  update from another tenant, or of a version never stored, fails with
  `keys.version_not_found`.

## Side Effects

- None at the crate root. The `testing` module mutates in-process memory
  only.

## Verification

- Run: `cargo test -p hodor-keys`
