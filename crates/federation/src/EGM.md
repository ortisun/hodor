# hodor-federation source

## Overview

The source of the federation context (`lib.rs` crate doc comment). It lets a person sign in to a tenant with an identity they already have elsewhere: an OpenID Connect provider, GitHub, a SAML identity provider or an LDAP directory. It records which identity providers a tenant trusts and which external identity belongs to which user. The specification it follows is `docs/architecture/contexts/federation.md`. `lib.rs` declares the private modules `application` and `domain`, the public `testing` module, and the public `api` module, which is the only way other crates use this context.

## Interface

- [application](./application/EGM.md) holds the use cases and the ports.
  - Use cases: `FederationService` manages providers and links, `ExternalSignIn` and `ExternalIdentityAuthenticator` sign people in, and `OpenIdClient`, `GitHubClient` and `SamlClient` talk to providers.
  - Port traits implemented by adapters: `ProviderStore`, `LinkStore`, `PendingAuthorizationStore`, `DirectoryClient` and `LockoutPolicy`.
- [domain](./domain/EGM.md) holds the model and the events.
  - Model: `IdentityProvider`, `ProviderSettings`, `Alias`, `ProviderKind`, `ProviderStatus`, `SamlSettings`, `DirectorySettings`, `ClaimAttributes`, `Subject`, `ExternalIdentity`, `PendingAuthorization` and `SamlAnswer`.
  - Events: `FederationEvent`.
- `api` (`lib.rs`) re-exports, as the public surface:
  - from `application`: `GitHubClient`, `AuthorizationRequest`, `OpenIdClient`, `VerifiedIdentity`, `DirectoryAnswer`, `DirectoryClient`, `DirectoryEntry`, `DirectoryQuery`, `LinkStore`, `LockoutPolicy`, `PendingAuthorizationStore`, `ProviderStore`, `MAX_SAML_POSTED_BYTES`, `SamlClient`, `saml_assertion_consumer_address`, `saml_metadata_address`, `saml_service_provider`, `ChangeProvider`, `CreateProvider`, `FederationService`, `EXTERNAL_STEP`, `ExternalIdentityAuthenticator`, `ExternalSignIn`, `OfferedProvider` and `callback_address`;
  - from `domain`: `FederationEvent`, `ExternalIdentity`, `Subject`, `PendingAuthorization`, `SamlAnswer`, `Alias`, `ClaimAttributes`, `DirectorySettings`, `IdentityProvider`, `LONGEST_CLAIM_VALUE`, `ProviderId`, `ProviderKind`, `ProviderSettings`, `ProviderSnapshot`, `ProviderStatus`, `SamlSettings`, `claims_from` and `directory_host`.
- `testing` (`testing.rs`) is public test support. It is compiled under `#[cfg(any(test, feature = "testing"))]` and provides:
  - `InMemoryFederation`, one in-memory value that implements `ProviderStore`, `LinkStore` and `PendingAuthorizationStore`;
  - `Ports<'a>`, which bundles `units_of_work`, `providers`, `links` and `pending`;
  - `run_contract(ports)`, which runs every rule the stores must obey and panics when a rule is broken, among them that a kept SAML answer comes back with its standard claims. Each run uses tenants of its own, so runs can share one database.
  - `crates/adapters-postgres/tests/federation.rs` imports `hodor_federation::testing`.

## Invariants

- Other crates use only what `api` re-exports. `application` and `domain` are private modules (`lib.rs`).
- An external identity is found by provider and subject only, and it is never joined to an existing account because of an email address (`application/sign_in.rs` module doc comment, `ExternalSignIn::resolve`).
- No `FederationEvent` carries a secret or a subject (`domain/event.rs` module doc comment).
- Every store method works inside the tenant its unit of work is bound to (`application/ports.rs` doc comments).

## Side Effects

- The domain is free of input and output.
- The application layer uses network, storage, events, secrets, the clock and randomness, always through `hodor_kernel` ports and the port traits in `application/ports.rs`. See [application](./application/EGM.md#side-effects).
- `testing::InMemoryFederation` keeps its rows in `Arc<Mutex<BTreeMap<..>>>`.

## Verification

- Run: `cargo test -p hodor-federation`
