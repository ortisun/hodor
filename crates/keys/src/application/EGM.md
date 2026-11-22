# Keys application layer

## Overview

The use cases of the keys context and the two ports they need.
`KeyService` makes, activates, retires and revokes key versions, reads key
sets and signs; every use case runs inside a unit of work bound to one
tenant. Both modules are `pub(crate)` in `mod.rs` and reach other crates
only through `crate::api`.

## Interface

### Ports (`ports.rs`)

`KeyStore` (`#[async_trait]`, `Send + Sync`), implemented by `PgKeyStore`
(`crates/adapters-postgres/src/keys.rs`) and `InMemoryKeys`:

| Method | Meaning |
| --- | --- |
| `insert(uow, &KeyVersion)` | Stores a new version. |
| `get(uow, KeyVersionId) -> Option<KeyVersion>` | One version of the tenant. |
| `list_for_use(uow, KeyUse) -> Vec<KeyVersion>` | Every version of one use, in any order. |
| `update(uow, &KeyVersion)` | Stores state, times and revocation reason; `NotFound` `keys.version_not_found` if absent. |

`KeyProvider` (`#[async_trait]`, `Send + Sync`), implemented by
`LocalKeyProvider` (`crates/adapters-crypto/src/keys.rs`) and
`FakeKeyProvider`:

| Method | Meaning |
| --- | --- |
| `name() -> &'static str` | Stored with every version it makes. |
| `generate(tenant, KeyVersionId, KeyAlgorithm) -> GeneratedKey` | A new key: public key for signing, and material. |
| `sign(tenant, &KeyVersion, message) -> Vec<u8>` | Signs with a signing key. |
| `encrypt(tenant, &KeyVersion, associated, &Secret<Vec<u8>>) -> Vec<u8>` | Encrypts with a data key. |
| `decrypt(tenant, &KeyVersion, associated, ciphertext) -> Secret<Vec<u8>>` | Decrypts what `encrypt` made. |

A provider must refuse material made for another tenant, version or
algorithm.

### Service (`service.rs`)

- `KeyService::new(units_of_work, keys: Arc<dyn KeyStore>, provider: Arc<dyn KeyProvider>, clock)`.
- `Signature { key_version_id, algorithm, bytes }`.

| Entry point | Meaning |
| --- | --- |
| `create_version(tenant, algorithm, caller) -> KeyVersion` | Asks the provider for a key; stores it pending. |
| `activate(tenant, id, overlap: Duration, caller) -> KeyVersion` | Pending to active; the replaced version retires after `now + overlap`. |
| `retire(tenant, id, caller) -> KeyVersion` | Retiring to retired, once its time has passed. |
| `revoke(tenant, id, reason, caller) -> KeyVersion` | Revokes; again changes nothing and records nothing. |
| `key_set(tenant, KeyUse) -> KeySet` | The versions of one use. |
| `sign(tenant, algorithm, message) -> Signature` | Signs with the active version of a signing algorithm. |
| `rotate_due(tenant, &RotationPolicy, caller) -> RotationReport` | Carries out `KeySet::rotation_plan` for the signing key set, one transaction per change. |
| `rotate_now(tenant, algorithm, &RotationPolicy, caller) -> KeyVersion` | Activates the oldest pending version of a signing algorithm, or a new one, at once, with the policy's overlap. |
| `published_keys(tenant) -> Vec<KeyVersion>` | The signing versions of the published key set. |

`RotationReport { created, activated, retired }` with `changed()` and
`add(other)`.

## Invariants

- `create_version` asks the provider before beginning a unit of work, then
  inserts and records `keys.version_created` (`service.rs:create_version`).
- `activate` stores the changed versions in the order `KeySet::activate`
  gives: the replaced version first (`service.rs:activate`).
- `activate`, `retire` and `revoke` find the version's use with `get`, load
  that use's set with `list_for_use`, and give `keys.version_not_found` for a
  version the tenant does not have.
- `rotate_now` gives `Invalid` `keys.algorithm_unsuitable` for a data
  algorithm before anything is made.
- `rotate_due` keeps the changes made before an error.
- `sign` gives `Invalid` `keys.algorithm_unsuitable` for a data algorithm and
  `Conflict` `keys.no_active_version` when no version of the algorithm is
  active (`service.rs:sign`).

## Side Effects

- Reads the injected `Clock`; calls the injected `KeyProvider`; begins units
  of work and reads and writes through `KeyStore`; records `KeyEvent`
  envelopes with `UnitOfWork::record_event`.

## Verification

- Run: `cargo test -p hodor-keys`
