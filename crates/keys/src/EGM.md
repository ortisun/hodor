# hodor-keys source

## Overview

The keys context: the keys a tenant's tokens are signed with and its
secrets are encrypted under, and the SPIFFE trust domains it trusts with
their bundles (`lib.rs` crate documentation). The
specification it follows is `docs/architecture/contexts/keys.md`.

`lib.rs` keeps `application` and `domain` private and exposes the public
surface through `pub mod api`.

## Interface

- `api` re-exports:
  - Ports: `KeyStore`, `KeyProvider`, `SealingStateStore`, `FirstFormatSecrets`,
    `TrustDomainStore`, `DueRefreshes`.
  - Trust domains: `TrustDomainService`, `TrustDomainPorts`,
    `TrustSourceRequest`, `BundleRefresher`, `RefreshLease`,
    `RefreshOutcome`; `TrustDomain`, `TrustDomainId`, `TrustDomainName`,
    `TrustDomainSnapshot`, `TrustSource`, `CheckedSource`, `TrustBundle`,
    `BundleKey`, `SvidKind`, `FetchOutcome`, `TrustDomainEvent`,
    `BundleSummary`, and the bounds `MAX_TRUST_DOMAINS` (50),
    `MAX_NAME_LENGTH` (255), `MAX_BUNDLE_ENDPOINT_LENGTH` (1000),
    `MAX_BUNDLE_BYTES` (65536), `MAX_BUNDLE_ELEMENTS` (100),
    `MAX_ERROR_LENGTH` (100), `FETCH_TIME_LIMIT` (10 seconds),
    `DEFAULT_REFRESH` (5 minutes), `SHORTEST_REFRESH` (1 minute),
    `LONGEST_REFRESH` (1 day), `LONGEST_RETRY` (5 minutes).
  - Several providers as one: `KeyProviders`.
  - Service: `KeyService`, `RotationReport`, `Signature`.
  - Secrets at rest: `TenantSecretBox`, `SEALED_FORMAT` (2), `LOST_RACE`.
  - Event: `KeyEvent`.
  - Domain: `GeneratedKey`, `KeyAlgorithm`, `KeyMaterial`, `KeyState`,
    `KeyUse`, `KeyVersion`, `KeyVersionId`, `KeyVersionSnapshot`,
    `MAX_REASON_LENGTH`, `SignatureEncoding` (`Jose` or `Der`), `Activation`,
    `KeySet`, `RotationChange`, `RotationPolicy`.
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
  - `InMemoryTrustDomains`: a `TrustDomainStore` and `DueRefreshes` in
    memory; its `update` checks and increments the version.
  - `FakeBundleEndpoints`: an `HttpClient` and `DestinationCheck` whose
    addresses answer or fail as a test tells them, `404` otherwise, and
    which records every address fetched.
  - `sample_bundle(sequence, key_ids)`: a bundle with one `x509-svid`
    element and one `jwt-svid` element per identifier; never a real
    authority.
  - `TrustDomainContract<'a> { units_of_work, store, due }` and
    `run_trust_domain_contract(ports)`: the contract of trust domain
    stores.
  - `ProviderPorts<'a> { provider, verifier, signing, data }` and
    `run_provider_contract(ports)`: the contract every key provider passes
    (both encodings checked with the public key by `verifier`, two keys never
    equal, material refused for another tenant, version, algorithm, when
    changed and for another provider, one use refused for the other, data
    keys or their refusal). `made_by`, `with_material` and `der_to_jose`
    (a strict reader of an ECDSA signature in DER) help it and the adapters'
    own tests.
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

- The trust domain contract (`testing.rs:run_trust_domain_contract`)
  requires that every source loads back unchanged, a lease and a failed
  fetch included; that one name in two tenants is two trust domains, each
  found by name in its own tenant only; that a name is taken once in a
  tenant (`keys.trust_domain_name_taken`); that an update needs the version
  it read (`keys.trust_domain_changed`) and its tenant
  (`keys.trust_domain_not_found`); that lists go in the order of
  identifiers and counts are per tenant; and that the search across tenants
  finds a due bundle endpoint of any tenant, never an uploaded or mesh one,
  one not yet due, or one leased past now.

## Side Effects

- None at the crate root. The `testing` module mutates in-process memory
  only.

## Verification

- Run: `cargo test -p hodor-keys`
