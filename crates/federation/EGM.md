# hodor-federation

## Overview

The `hodor-federation` crate, described in `Cargo.toml` as "The federation context: the identity providers a tenant trusts, and whose external identity is whose." Administrators use it to manage a tenant's identity providers. People use it to sign in through those providers: OpenID Connect, GitHub, SAML and LDAP directories. It records which external identity is linked to which user. The specification it follows is `docs/architecture/contexts/federation.md` (`src/lib.rs` doc comment).

## Interface

- [src](./src/EGM.md) exposes the public `hodor_federation::api` module and the `hodor_federation::testing` module.
  - Use cases: `FederationService`, `ExternalSignIn` and `ExternalIdentityAuthenticator`.
  - Provider clients: `OpenIdClient`, `GitHubClient` and `SamlClient`.
  - Port traits: `ProviderStore`, `LinkStore`, `PendingAuthorizationStore`, `DirectoryClient` and `LockoutPolicy`.
  - Domain types and the `FederationEvent` enum.
- Feature `testing` turns on `hodor-kernel/testing` and `hodor-saml/testing`. It compiles `hodor_federation::testing`, which holds the in-memory stores and the store contract suite `run_contract` (`Cargo.toml` comment).
- Workspace dependencies:
  - `hodor-authentication` (`crates/authentication`): `TransactionId`, `LockoutRules`, `AttemptGuard`, and the `Authenticator` trait and its step types.
  - `hodor-identity` (`crates/identity`): `IdentityService` and `CreateUser`, used to create a user on first sign-in.
  - `hodor-kernel` (`crates/kernel`): units of work, the `DomainError` error type, secrets, and the clock, random source, digest, HTTP client and signature verifier ports.
  - `hodor-saml` ([saml](../saml/EGM.md)): response checking, requests and metadata.
- External dependencies: `async-trait`, `base64`, `form_urlencoded`, `serde`, `serde_json` and `time`.
- Depended on by `crates/adapters-crypto`, `crates/adapters-ldap`, `crates/adapters-postgres` and `crates/protocol-http` (their `Cargo.toml` files). Adapters implement its ports:
  - `crates/adapters-postgres/src/federation.rs`: `ProviderStore`, `LinkStore` and `PendingAuthorizationStore`.
  - `crates/adapters-ldap/src/lib.rs`: `DirectoryClient`.
  - `apps/hodor-server/src/main.rs`: `LockoutPolicy`.

## Invariants

- The crate has no XML dependency. It works with SAML only through `hodor-saml`.
- Every store call is scoped to the tenant of its unit of work. Each event is recorded in the same unit of work as the write it describes.
- Sign-in never joins an external identity to an existing account because of an email address. See [src/application](./src/application/EGM.md#invariants).

## Side Effects

- Every effect goes through ports, and no input or output library is a dependency:
  - network: `HttpClient` and `DirectoryClient`;
  - storage: the three store traits, inside units of work;
  - secrets: `SecretBox`;
  - time and randomness: `Clock` and `RandomSource`.
- `OpenIdClient` keeps an in-memory cache of provider descriptions and keys, shared by its clones. Its field doc comment says each server instance keeps its own.

## Verification

- Run: `cargo test -p hodor-federation`
- The crate's own tests run with its `testing` feature turned on (`Cargo.toml` `[dev-dependencies]`, with `tokio` as the async runtime).
