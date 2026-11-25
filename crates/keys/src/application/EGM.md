# Keys application layer

## Overview

The use cases of the keys context and the ports they need.
`KeyService` makes, activates, retires and revokes key versions, reads key
sets and signs; `TenantSecretBox` seals secrets at rest under the tenant's
data key; `TrustDomainService` adds, reads, replaces and removes trust
domains, and `BundleRefresher` fetches their bundles again for the worker.
Every use case runs inside a unit of work bound to one tenant. The modules
are `pub(crate)` in `mod.rs` and reach other crates only through
`crate::api`.

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
`LocalKeyProvider` (`crates/adapters-crypto/src/keys.rs`),
`OpenBaoKeyProvider` (`crates/adapters-kms/src/openbao.rs`), `KeyProviders`
(`providers.rs`) and `FakeKeyProvider`:

| Method | Meaning |
| --- | --- |
| `name() -> &'static str` | Stored with every version it makes. |
| `name_for(KeyAlgorithm) -> &'static str` | The provider that makes keys of the algorithm; `name()` unless the provider routes. `KeyService` stores this one. |
| `generate(tenant, KeyVersionId, KeyAlgorithm) -> GeneratedKey` | A new key: public key for signing, and material. |
| `sign(tenant, &KeyVersion, message, SignatureEncoding) -> Vec<u8>` | Signs with a signing key, in the JOSE or the DER encoding (the same bytes for RSA). |
| `encrypt(tenant, &KeyVersion, associated, &Secret<Vec<u8>>) -> Vec<u8>` | Encrypts with a data key. |
| `decrypt(tenant, &KeyVersion, associated, ciphertext) -> Secret<Vec<u8>>` | Decrypts what `encrypt` made. |

A provider must refuse material made for another tenant, version or
algorithm, or by another provider, with `keys.unusable`; the contract is
`testing::run_provider_contract`.

`KeyProviders` (`providers.rs`): `new(signing, data)` makes new signing keys
with `signing` and data keys with `data`; `also(provider)` adds a provider
whose versions are still used. Every version goes to the provider named in
it and to no other; an unknown name is `keys.provider_not_configured`.
Nothing falls back.

`SealingStateStore` (`#[async_trait]`), implemented by `PgSealingStateStore`
(`crates/adapters-postgres/src/keys.rs`) and `InMemorySealingStates`:
`first_format_refused(uow) -> bool` and `refuse_first_format(uow, at)`,
final.

`FirstFormatSecrets` (`Send + Sync`), implemented by `SecretKeys`
(`crates/adapters-crypto/src/sealing.rs`) and `FakeFirstFormat`: opens and
recognizes the secrets 0.1.0 sealed directly with a root key.

`TrustDomainStore` (`#[async_trait]`), implemented by `PgTrustDomainStore`
(`crates/adapters-postgres/src/trust_domain.rs`) and `InMemoryTrustDomains`:
`insert` (`keys.trust_domain_name_taken`), `get`, `find_by_name`, `list(uow,
after, limit)` in the order of identifiers, `count` (a second count of the
tenant waits), `update` (needs the version read and increments it;
`keys.trust_domain_changed`, `keys.trust_domain_not_found`), `remove ->
bool`, `take` (skips a row another unit of work holds) and `lock` (waits).

`DueRefreshes` (`#[async_trait]`), implemented by `PgDueRefreshes` and
`InMemoryTrustDomains`: `due(now, limit) -> Vec<(TenantId, TrustDomainId)>`
across tenants, the longest waiting first.

### Service (`service.rs`)

- `KeyService::new(units_of_work, keys: Arc<dyn KeyStore>, provider: Arc<dyn KeyProvider>, clock)`.
- `Signature { key_version_id, algorithm, bytes }`.

| Entry point | Meaning |
| --- | --- |
| `create_version(tenant, algorithm, caller) -> KeyVersion` | Asks the provider for a key; stores it pending. |
| `activate(tenant, id, overlap: Duration, caller) -> KeyVersion` | Pending to active; the replaced version retires after `now + overlap`. |
| `activate_first(tenant, id, caller) -> KeyVersion` | Pending to active only if the algorithm has no active version; `Conflict` `keys.already_active` otherwise. |
| `ensure_active(tenant, algorithm, caller) -> KeyVersion` | The active version of a signing algorithm, made with `create_version` and `activate_first` when there is none; the version that loses a race is revoked with `LOST_FIRST_RACE`. Called by the `oauth` context when it signs and by `GET /oauth2/jwks`. |
| `retire(tenant, id, caller) -> KeyVersion` | Retiring to retired, once its time has passed. |
| `revoke(tenant, id, reason, caller) -> KeyVersion` | Revokes; again changes nothing and records nothing. |
| `key_set(tenant, KeyUse) -> KeySet` | The versions of one use. |
| `sign(tenant, algorithm, message) -> Signature` | Signs with the active version of a signing algorithm. |
| `sign_naming_key(tenant, algorithm, message: FnOnce(KeyVersionId) -> Vec<u8>) -> (Vec<u8>, Signature)` | Signs a message that names the key signing it, such as a JSON Web Token whose header carries the `kid`: `message` is given the active version, and the same version signs what it returns. `sign` is this with a message that ignores the version. |
| `rotate_due(tenant, &RotationPolicy, caller) -> RotationReport` | Carries out `KeySet::rotation_plan` for the signing key set, one transaction per change. |
| `rotate_now(tenant, algorithm, &RotationPolicy, caller) -> KeyVersion` | Activates the oldest pending version of a signing algorithm, or a new one, at once, with the policy's overlap. |
| `published_keys(tenant) -> Vec<KeyVersion>` | The signing versions of the published key set. |

`RotationReport { created, activated, retired }` with `changed()` and
`add(other)`.

### Secrets at rest (`secret_box.rs`)

- `TenantSecretBox::new(units_of_work, keys, provider, states: Arc<dyn SealingStateStore>, first_format: Option<Arc<dyn FirstFormatSecrets>>, clock)` implements `hodor_kernel::SecretBox`.
- `seal` uses the tenant's active `A256GCM` data version, made with `create_version` and `activate_first` when there is none; the version that loses a race is revoked with `LOST_RACE`.
- Sealed bytes: `FORMAT` (2), the 16 bytes of the version identifier, then what the provider's `encrypt` returned; the associated data names `hodor-secret-v2`, the tenant, the purpose and the version.
- `open` opens only with an active or retiring version; the first format opens through `first_format` until the tenant refuses it. Every failure is `secret.unreadable`.
- `needs_resealing` is true for the first format and for a version that is not the active one; it does not open the secret.
- `first_format_refused(tenant)` and `refuse_first_format(tenant)`.

### Trust domains (`trust_domains.rs`)

- `TrustDomainPorts { units_of_work, store, destinations: Arc<dyn
  DestinationCheck>, http: Arc<dyn HttpClient>, digest: Arc<dyn Digest>,
  clock }`; `TrustDomainService::new(ports)`.
- `TrustSourceRequest { Uploaded { bundle }, BundleEndpoint { url }, Mesh }`
  with `from_parts(source, bundle, url)`
  (`keys.trust_domain_source_invalid`).

| Entry point | Meaning |
| --- | --- |
| `add(tenant, name, source, caller) -> TrustDomain` | Reads the name, checks the source (reads a bundle, or checks a bundle endpoint with `DestinationCheck` and fetches it once), then stores it under the tenant's count; `keys.too_many_trust_domains` at 50, `keys.trust_domain_name_taken`. |
| `get(tenant, id)` | `keys.trust_domain_not_found` if absent. |
| `find_by_name(tenant, name) -> Option<TrustDomain>` | The tenant's own only. |
| `list(tenant, &PageRequest) -> Page<TrustDomain>` | In the order of identifiers; `request.cursor_invalid`. |
| `replace(tenant, id, source, caller)` | Checks the source first, then changes the trust domain under `lock`. |
| `remove(tenant, id, caller)` | Removes it. |

- `BundleRefresher::new(service, due)`, `CONCURRENCY` (8):
  `lease_due(limit) -> Vec<RefreshLease>` takes each due trust domain with
  `take`, leases it for `FETCH_TIME_LIMIT` plus one minute and commits;
  `refresh(lease) -> RefreshOutcome` fetches outside any transaction, then
  under `lock` records the result only if the version is still the leased
  one (`Skipped` otherwise). `RefreshOutcome { Changed, Unchanged, Failed,
  Skipped }` with `as_str`.
- A fetch is a `GET` with `accept: application/json` and a time limit of 10
  seconds; a status other than 2xx or more than 64 kibibytes is
  `keys.bundle_endpoint_unreachable`; the client's `http.url_invalid` is
  `keys.bundle_endpoint_invalid`, `http.destination_forbidden`
  `keys.bundle_endpoint_forbidden`, anything else unreachable. The
  destination check's `http.unreachable` is
  `keys.bundle_endpoint_unresolvable`.

### The certificate authority (`authority.rs`)

- `AuthorityPorts { units_of_work, store: Arc<dyn AuthorityStore>,
  trust_domains: Arc<dyn TrustDomainStore>, maker: Arc<dyn KeyProvider>,
  signer: Arc<dyn KeyProvider>, certificates: Arc<dyn CertificateWriter>,
  digest, clock }`; `AuthorityService::new(ports, for_development)`,
  `for_development()`. `maker` makes the authority's key
  (`KeyProviders::authorities`), `signer` signs with it (every provider).
- `NewAuthority { kind, trust_domains, common_name, lifetime_days,
  intermediate_lifetime_days }`, checked by `AuthorityRequest::new`.

| Method | Behavior |
| --- | --- |
| `create(tenant, asked, caller)` | Checks the request; refuses `keys.authority_provider_unsuitable` when `maker.signs_inside()` is false outside development; refuses `keys.authority_exists` and `keys.authority_trust_domain_taken` before a key is made; has the ES256 key made for a new identifier; for a root, writes the part to be signed with `CertificateWriter::root_to_be_signed` and signs it with `SignatureEncoding::Der`; for an intermediate, the request's. Then inserts it, records `keys.authority_created` and `keys.authority_signed`, and for a root `keys.authority_activated` and a trust domain of source `authority` for each of its trust domains. |
| `get(tenant)` | `keys.authority_not_found` if the tenant has none. |
| `install(tenant, certificate, chain, caller)` | Reads the PEM certificate and chain, then under `lock` installs it (`CertificateAuthority::install`), updates it, records `keys.authority_activated` and adds its trust domains. |
| `remove(tenant, caller)` | Under `lock`, removes the trust domains of its names that still have the source `authority`, then the authority; records `keys.trust_domain_removed` for each and `keys.authority_removed`. |
| `bundle(tenant)` | The bundle of the tenant's active authority, or `None`. |

- `TrustDomainService::replace` refuses a trust domain of source
  `authority` with `keys.trust_domain_of_authority` before anything is
  checked; `TrustSourceRequest::from_parts` never takes `authority`.

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

- Nothing is stored when a source is refused; a refused replacement leaves
  the trust domain as it was.
- Every signature of an authority's key is recorded as
  `keys.authority_signed`, with the SHA-256 of the part signed, in the
  unit of work that keeps what was signed (`authority.rs:create`).
- An authority's trust domains are added only when it is active, and none
  is added over a trust domain the tenant has from another source.
- `BundleRefresher` records `keys.trust_bundle_refreshed` only when the
  bundle in force changed, and `keys.trust_bundle_refresh_failed` only for
  the first failure of a run; its events have the system as actor.

## Side Effects

- Reads the injected `Clock`; calls the injected `KeyProvider`; begins units
  of work and reads and writes through `KeyStore`; records `KeyEvent`
  envelopes with `UnitOfWork::record_event`; fetches bundles through the
  injected `HttpClient` and records `TrustDomainEvent` envelopes.

## Verification

- Run: `cargo test -p hodor-keys`
