# Keys domain

## Overview

Key versions, the key set of one use, and the events other contexts hear
about. The domain is pure: time and the provider's answer are passed in.
The modules are `pub(crate)` in `mod.rs`; their types are re-exported
through `crate::api`.

## Interface

### `key.rs`

- `KeyVersionId`: identifier from `hodor_kernel::define_id!`; published as
  the key identifier of a signing key.
- `KeyUse { Signing, Encryption, Data }` with `as_str()` (`sig`, `enc`,
  `data`) and `from_stored`.
- `KeyAlgorithm { Es256, Rs256, Ps256, A256Gcm }` with `as_str()`,
  `from_name`, `from_stored`, `key_use()`, `signature()`, `ALL` and
  `DEFAULT_SIGNING = Es256`.
- `KeyState { Pending, Active, Retiring, Retired, Revoked }` with `as_str()`
  and `from_stored`.
- `KeyMaterial`: opaque bytes from a provider; `from_stored`, `as_bytes`;
  `Debug` prints `KeyMaterial(<n> bytes)`.
- `GeneratedKey { public_key: Option<PublicKey>, material: KeyMaterial }`.
- `KeyVersionSnapshot`: the stored state.
- `KeyVersion`: `create(id, algorithm, provider, generated, now)`,
  `from_snapshot`, `snapshot`, `id`, `algorithm`, `key_use`, `state`,
  `material`, `public_key`, `checks()`.
- `MAX_REASON_LENGTH = 200`.

### `key_set.rs`

- `KeySet`: `from_versions(key_use, versions)`, `key_use`, `versions`
  (newest first), `version(id)`, `active(algorithm)`,
  `activate(id, overlap, now) -> Activation`, `retire(id, now)`,
  `revoke(id, reason, now)`.
- `Activation { changed: Vec<KeyVersion>, event: KeyEvent }`: the replaced
  version first.

### `event.rs`

`KeyEvent` (`Serialize`, untagged) implements `DomainEvent`:

| Variant | Fields | `event_type()` |
| --- | --- | --- |
| `VersionCreated` | `version_id`, `key_use`, `algorithm` | `keys.version_created` |
| `VersionActivated` | `version_id`, `algorithm`, `replaced_version_id`, `replaced_retire_after` (RFC 3339) | `keys.version_activated` |
| `VersionRetired` | `version_id`, `algorithm` | `keys.version_retired` |
| `VersionRevoked` | `version_id`, `algorithm`, `previous_state`, `reason` | `keys.version_revoked` |

## Invariants

- The algorithm decides the use; no algorithm is for `Encryption` yet
  (`KeyAlgorithm::key_use`).
- `KeyVersion::create` gives an internal `keys.provider_failed` unless the
  provider name is 1 to 32 of `a-z0-9_`, the material is not empty, and a
  public key of the right kind is present for a signing algorithm and absent
  for a data key.
- Only a pending version activates (`keys.not_pending`); only a retiring
  version retires (`keys.not_retiring`), and not before `retire_after`
  (`keys.still_needed`); revoking needs a trimmed reason of 1 to 200
  characters (`keys.reason_invalid`) and is final; revoking again gives no
  event.
- `KeySet::activate` refuses a negative overlap (`keys.overlap_invalid`)
  and leaves one active version per algorithm; the replaced version gets
  `retire_after = now + overlap`.
- `KeySet::from_versions` gives `keys.stored_data_invalid` for a version of
  another use or two active versions of one algorithm.
- Events never carry key material or the public key.

## Side Effects

- None. `KeyVersionId::generate` creates identifiers.

## Verification

- Run: `cargo test -p hodor-keys`
