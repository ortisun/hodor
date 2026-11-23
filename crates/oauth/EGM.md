# hodor-oauth

## Overview

The `hodor-oauth` crate (`Cargo.toml` description: "The OAuth context:
applications, clients and resource servers, and the tokens Hodor issues to
them."). Today it holds Issue-53: the applications a tenant registers,
their clients with secrets and keys, and resource servers with their
scopes; Issue-55: the rules and use cases of the authorization
endpoint, with pending requests, grants and authorization codes; and
Issue-56: the token endpoint, which authenticates clients and exchanges a
code for a JWT access token signed through the keys context;
Issue-57: refresh tokens in families that move at every use, and client
credentials; and Issue-59: the OpenID Provider, with the ID token, UserInfo
and the discovery document. Storage,
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
  `crates/adapters-postgres/src/oauth_token.rs`; `RefreshTokenStore`, by
  `PgRefreshTokenStore` in `crates/adapters-postgres/src/oauth_refresh.rs`;
  `PersonStanding`, by `ServerStanding` in `apps/hodor-server/src/standing.rs`.
- Used by `crates/protocol-http/src/authorize.rs`,
  `crates/protocol-http/src/token.rs` and
  `crates/protocol-http/src/openid.rs` (UserInfo and discovery) over HTTP.
- Workspace dependencies: `hodor-identity` (`IdentityService` reads the
  person for UserInfo), `hodor-kernel`, `hodor-keys` (`KeyService` signs
  access and ID tokens and lists the published keys;
  `RotationPolicy::LONGEST_SIGNED_LIFETIME` bounds the token policy) and
  `hodor-session` (for `SessionId`), plus `async-trait`, `base64`, `serde`,
  `serde_json` and `time`. The architecture rules also allow `hodor-tenant`,
  which later issues use.
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
- An access token and an ID token leave the crate once, from
  `TokenService::token`; neither is stored, and `oauth.access_token_issued`
  carries only the access token's `jti`.
- UserInfo uses nothing an access token says before its signature has been
  checked against a key the tenant publishes (`check_access_token`).
- A refresh token leaves the crate from `TokenService::token` only; only
  its SHA-256 hash is stored, the family's secret only sealed, and events
  carry neither.
- No access or ID token lifetime exceeds
  `TokenPolicy::LONGEST_SIGNED_LIFETIME`, which is
  `RotationPolicy::LONGEST_SIGNED_LIFETIME`.
- Every store call is scoped to the tenant of the unit of work (see
  [application](./src/application/EGM.md)).

## Side Effects

- Through the stores: reads and writes applications, clients, resource
  servers, pending authorization requests, grants, codes, the `jti`s of
  client assertions, and refresh token families with their tokens'
  hashes. Through `KeyService`: signs access and ID tokens, and lists the
  published keys. Through `SecretBox`: seals and opens the secrets of
  refresh token families. Through `IdentityService`: reads people. Through
  `UnitOfWork::record_event`: records the `oauth.*` events.

## Verification

- Run: `cargo test -p hodor-oauth`, and
  `cargo test -p hodor-adapters-postgres --test oauth` for PostgreSQL;
  `cargo test -p hodor-server --test authorization` and
  `cargo test -p hodor-server --test token` and
  `cargo test -p hodor-server --test openid` for the endpoints on the real
  binary.
