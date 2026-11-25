# Keys domain

## Overview

Key versions, the key set of one use, trust domains with their bundles,
and the events other contexts hear about. The domain is pure: time and the provider's answer are passed in.
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

### `rotation.rs`

- `RotationPolicy`: `new(period, publication, overlap)`, `period`,
  `publication`, `overlap`, `shortest_overlap()`, `DEFAULT` (90 days, 24
  hours, 24 hours), and the constants `LONGEST_SIGNED_LIFETIME` (1 hour),
  `CLOCK_ALLOWANCE` (5 minutes), `PUBLISHED_FOR` (5 minutes, the `max-age`
  of the published key set) and `PERIOD_BOUNDS` (1 to 730 days).
- `RotationChange { Retire(id), Activate(id), Prepare(algorithm),
  CreateAndActivate(algorithm) }`.
- On `KeySet`: `rotation_plan(policy, now) -> Vec<RotationChange>`,
  `oldest_pending(algorithm)`, `published()` (pending, active and retiring
  signing versions, newest first).

### `trust_domain.rs`

- `TrustDomainId`: identifier from `hodor_kernel::define_id!`.
- `TrustDomainName::parse`: 1 to 255 of `a-z0-9._-`, nothing lowered
  (`keys.trust_domain_name_invalid`); `as_str`.
- `SvidKind { X509, Jwt }` (`x509-svid`, `jwt-svid`).
- `BundleKey { kind, key_id, jwk }`: a kept element, written as compact JSON
  with its members in order.
- `TrustBundle`: `parse(bytes)`, `from_stored`, `document()` (the bundle as
  kept: `keys`, `spiffe_refresh_hint`, `spiffe_sequence` in that order),
  `sequence`, `refresh_hint`, `keys`, `authorities(kind)`, `jwt_key(kid)`,
  `refresh_interval()` (the hint between 1 minute and 1 day, 5 minutes
  without one), `may_follow(in_force)`.
- `TrustSource { Uploaded, BundleEndpoint, Mesh }` with `as_str` and
  `parse` (`keys.trust_domain_source_invalid`).
- `CheckedSource { Uploaded(bundle), BundleEndpoint { url, bundle }, Mesh }`:
  a source whose bundle was read or fetched.
- `TrustDomainSnapshot`: the stored state; `TrustDomain`: `add(name,
  source, now)`, `from_snapshot`, `snapshot`, `id`, `name`, `source`,
  `bundle`, `version`, `replace(source, now)`, `is_due(now)`,
  `bundle_endpoint_url`, `lease(now, until)` (`keys.trust_domain_not_due`),
  `record_fetch(result, now) -> FetchOutcome`.
- `FetchOutcome { Changed { previous_sequence }, Unchanged, Failed { reason,
  first } }`.
- Bounds: `MAX_TRUST_DOMAINS` (50), `MAX_NAME_LENGTH`,
  `MAX_BUNDLE_ENDPOINT_LENGTH`, `MAX_BUNDLE_BYTES`, `MAX_BUNDLE_ELEMENTS`,
  `MAX_ERROR_LENGTH`, `FETCH_TIME_LIMIT`, `DEFAULT_REFRESH`,
  `SHORTEST_REFRESH`, `LONGEST_REFRESH`, `LONGEST_RETRY`; crate-private
  `LEASE_MARGIN` (1 minute), `check_bundle_endpoint`.

### `authority.rs`

- `AuthorityId`; `AuthoritySetting { Off, On, Development }` with
  `parse(Option<&str>)` (`keys.authority_setting_invalid`);
  `AuthorityKind { Root, Intermediate }` and `AuthorityState {
  AwaitingCertificate, Active }`, each with `as_str` and `parse`.
- `authority_trust_domain(name)`: a trust domain's name that is also a DNS
  name (`keys.authority_trust_domain_invalid`).
- `AuthorityRequest::new(kind, trust_domains, common_name, lifetime_days,
  intermediate_lifetime_days, for_development)`: 1 to 10 distinct trust
  domains, a common name of 1 to 64 characters (` (development)` added for
  development), a root's lifetime of 1 to 3650 days (1826 by default, none
  for an intermediate), a bound of 1 to 365 days (30 by default) shorter
  than the root (`keys.authority_request_invalid`); `profile()`.
- `NameConstraints::for_trust_domains`: each trust domain permitted as a
  URI host and a DNS name, `0.0.0.0/0` and `::/0` excluded.
- `AuthorityKey { id, provider, material, public_key }`, `new` (a P-256
  key or an internal error), `version(now)`: the ES256 `KeyVersion` a
  provider is given to sign, never stored as one.
- `CertificateAuthority`: `root`, `intermediate`, `from_snapshot`,
  `install(facts, sha256, chain, now)` (`keys.authority_not_awaiting_certificate`,
  `keys.authority_certificate_unsuitable` with the reason), `bundle()` (a
  SPIFFE bundle with its certificate, `spiffe_sequence` the activation time
  in seconds, refresh hint 300), `name_constraints()`.
- `to_pem(label, der)`, `hexadecimal(bytes)`.
- `trust_domain.rs` gains `TrustSource::Authority` (`authority`) and
  `CheckedSource::Authority(TrustBundle)`.

### `event.rs`

`KeyEvent` (`Serialize`, untagged) implements `DomainEvent`:

| Variant | Fields | `event_type()` |
| --- | --- | --- |
| `VersionCreated` | `version_id`, `key_use`, `algorithm` | `keys.version_created` |
| `VersionActivated` | `version_id`, `algorithm`, `replaced_version_id`, `replaced_retire_after` (RFC 3339) | `keys.version_activated` |
| `VersionRetired` | `version_id`, `algorithm` | `keys.version_retired` |
| `VersionRevoked` | `version_id`, `algorithm`, `previous_state`, `reason` | `keys.version_revoked` |

`TrustDomainEvent` (`Serialize`, untagged) implements `DomainEvent`:

| Variant | Fields | `event_type()` |
| --- | --- | --- |
| `Added` | `trust_domain_id`, `name`, `source`, and a `BundleSummary` unless `mesh` | `keys.trust_domain_added` |
| `Replaced` | the same | `keys.trust_domain_replaced` |
| `BundleRefreshed` | `trust_domain_id`, `name`, a `BundleSummary`, `previous_sequence` | `keys.trust_bundle_refreshed` |
| `RefreshFailed` | `trust_domain_id`, `name`, `reason` | `keys.trust_bundle_refresh_failed` |
| `Removed` | `trust_domain_id`, `name` | `keys.trust_domain_removed` |

`AuthorityEvent` (`Serialize`, untagged) implements `DomainEvent`:

| Variant | Fields | `event_type()` |
| --- | --- | --- |
| `Created` | `authority_id`, `kind`, `trust_domains`, `key_id`, `provider`, `for_development` | `keys.authority_created` |
| `Signed` | `authority_id`, `signed` (`certificate` or `certificate_signing_request`), `signed_sha256`, `serial_number` for a certificate, `trust_domains` | `keys.authority_signed` |
| `Activated` | `authority_id`, `serial_number`, `certificate_sha256`, `not_after` (RFC 3339) | `keys.authority_activated` |
| `Removed` | `authority_id`, `key_id` | `keys.authority_removed` |

`BundleSummary` is `bundle_sha256`, `sequence`, `x509_authorities` and
`jwt_authorities`, flattened into the event.

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
- Events never carry key material or the public key; trust domain events
  never carry a bundle endpoint's address or a bundle's keys.
- `TrustBundle::parse` follows `docs/architecture/contexts/keys.md`,
  "Reading a bundle": at most 64 kibibytes and 100 elements; an element of
  an unknown `use` or key type is ignored; a known one with a private part,
  a short coordinate or modulus, an `alg` that does not fit, an `x509-svid`
  element with a `kid` or not exactly one DER certificate, or a `jwt-svid`
  element without a unique `kid` refuses the whole bundle
  (`keys.trust_bundle_invalid`, the reason as detail).
- `TrustBundle::may_follow` refuses a fetched bundle without a sequence, or
  with a smaller one, or the same one with other contents, when the bundle
  in force has one (`keys.trust_bundle_sequence_invalid`).
- `TrustDomain::record_fetch` keeps the bundle in force on every failure,
  records `failing_since` once per run of failures and the reason's code,
  and makes the next fetch due after the interval in force, at most 5
  minutes after a failure; it always clears the lease. Each source holds
  exactly what it needs: a bundle for `uploaded` and `bundle_endpoint`, an
  address and a next refresh for `bundle_endpoint` only.
- `RotationPolicy::new` gives `keys.rotation_policy_invalid` for a period
  outside 1 to 730 days, a publication time shorter than `PUBLISHED_FOR` or
  not shorter than the period, or an overlap shorter than
  `LONGEST_SIGNED_LIFETIME` plus `CLOCK_ALLOWANCE`.
- `rotation_plan` follows `docs/architecture/contexts/keys.md`, "One step
  of rotation": retires what is due, then for ES256 with nothing active
  activates the oldest pending version or makes one and activates it at
  once; for each algorithm with an active version it prepares a pending
  version once the active one is older than the period less the
  publication time, and activates it once the active one is older than the
  period and the pending one was published for the publication time. A
  data key set plans nothing and publishes nothing: no data version is made,
  activated or retired by rotation, since secrets sealed with it may remain.

## Side Effects

- None. `KeyVersionId::generate` creates identifiers.

## Verification

- Run: `cargo test -p hodor-keys`
