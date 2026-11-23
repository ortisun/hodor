# hodor-oauth

## Overview

The `hodor-oauth` crate (`Cargo.toml` description: "The OAuth context:
applications, clients and resource servers, and the tokens Hodor issues to
them."). Today it holds Issue-53: the applications a tenant registers,
their clients with secrets and keys, and resource servers with their
scopes; Issue-55: the rules and use cases of the authorization
endpoint, with pending requests, grants and authorization codes; and
Issue-56: the token endpoint, which authenticates clients and exchanges a
code for a JWT access token signed through the keys context. Storage,
randomness, hashing, signature checking and time are reached through ports
and kernel traits.

## Interface

- Source and public surface: [src](./src/EGM.md).
- Ports implemented elsewhere: `ApplicationStore`, `ClientStore` and
  `ResourceServerStore`, by `PgApplicationStore`, `PgClientStore` and
  `PgResourceServerStore` in `crates/adapters-postgres/src/oauth.rs`;
  `AuthorizationRequestStore`, `GrantStore` and `AuthorizationCodeStore`,
  by `PgAuthorizationRequestStore`, `PgGrantStore` and
  `PgAuthorizationCodeStore` in
  `crates/adapters-postgres/src/oauth_authorization.rs`;
  `ClientAssertionStore`, by `PgClientAssertionStore` in
  `crates/adapters-postgres/src/oauth_token.rs`.
- Used by `crates/protocol-http/src/authorize.rs` and
  `crates/protocol-http/src/token.rs`, the two endpoints over HTTP.
- Workspace dependencies: `hodor-kernel`, `hodor-keys` (`KeyService` signs
  access tokens; `RotationPolicy::LONGEST_SIGNED_LIFETIME` bounds the token
  policy) and `hodor-session` (for `SessionId`), plus `async-trait`,
  `base64`, `serde`, `serde_json` and `time`. The architecture rules also
  allow `hodor-identity` and `hodor-tenant`, which later issues use.
- Feature `testing`: enables the public `testing` module,
  `hodor-kernel/testing` and `hodor-keys/testing`.
- Dev dependencies: `hodor-kernel` and `hodor-keys` with `testing`, the
  crate itself with `testing`, `tokio`.

## Invariants

- Only the `api` module is public to other crates; see [src](./src/EGM.md).
- A client secret leaves the crate once, from
  `ApplicationService::create_client` or `rotate_client_secret`; only its
  SHA-256 hash is stored, and events never carry either (see
  [domain](./src/domain/EGM.md)).
- An authorization code and the secret of a pending request leave the
  crate once, from `AuthorizationCodeService::issue_code` and `hold`; only
  their SHA-256 hashes are stored, and events carry neither.
- An access token leaves the crate once, from `TokenService::token`; it is
  stored nowhere, and `oauth.access_token_issued` carries only its `jti`.
- No access or ID token lifetime exceeds
  `TokenPolicy::LONGEST_SIGNED_LIFETIME`, which is
  `RotationPolicy::LONGEST_SIGNED_LIFETIME`.
- Every store call is scoped to the tenant of the unit of work (see
  [application](./src/application/EGM.md)).

## Side Effects

- Through the stores: reads and writes applications, clients, resource
  servers, pending authorization requests, grants, codes and the `jti`s of
  client assertions. Through `KeyService`: signs access tokens. Through
  `UnitOfWork::record_event`: records the `oauth.*` events.

## Verification

- Run: `cargo test -p hodor-oauth`, and
  `cargo test -p hodor-adapters-postgres --test oauth` for PostgreSQL;
  `cargo test -p hodor-server --test authorization` and
  `cargo test -p hodor-server --test token` for the endpoints on the real
  binary.
