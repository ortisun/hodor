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
credentials; Issue-59: the OpenID Provider, with the ID token, UserInfo
and the discovery document; Issue-60: logout initiated by the relying
party, with post-logout redirect addresses on clients; Issue-58:
revocation, introspection and the register of access tokens they and
UserInfo ask; and Issue-62: consent, with the question asked of a person,
their answer, their consents and withdrawing one. Storage,
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
  `AccessTokenRecordStore`, by `PgAccessTokenRecordStore` in
  `crates/adapters-postgres/src/oauth_access_token.rs`;
  `ConsentStore`, by `PgConsentStore` in
  `crates/adapters-postgres/src/oauth_consent.rs`;
  `PersonStanding`, by `ServerStanding` in `apps/hodor-server/src/standing.rs`.
- Used by `crates/protocol-http/src/authorize.rs`,
  `crates/protocol-http/src/consent.rs` (the consent routes of the
  interaction interface), `crates/protocol-http/src/admin.rs` (a user's
  consents), `crates/protocol-http/src/token.rs` and
  `crates/protocol-http/src/openid.rs` (UserInfo and discovery) and
  `crates/protocol-http/src/logout.rs` (the end-session endpoint) over HTTP.
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
- UserInfo, revocation and introspection use nothing an access token says
  before its signature has been checked against a key the tenant publishes
  (`read_access_token`). UserInfo and introspection refuse a token the
  register does not say is in force.
- Revocation ends only the presenting client's own tokens, and answers the
  same whatever the token; introspection changes nothing, and answers
  `{"active": false}` and nothing more for what the caller may not learn.
- A refresh token leaves the crate from `TokenService::token` only; only
  its SHA-256 hash is stored, the family's secret only sealed, and events
  carry neither.
- No access or ID token lifetime exceeds
  `TokenPolicy::LONGEST_SIGNED_LIFETIME`, which is
  `RotationPolicy::LONGEST_SIGNED_LIFETIME`.
- A client of a third-party application gets no code until its person
  agreed, through `ConsentService::answer`, to every scope and audience of
  the request (`must_ask`); `offline_access` is asked every time and never
  kept. Withdrawing a consent revokes every active grant of the person for
  the client.
- Every store call is scoped to the tenant of the unit of work (see
  [application](./src/application/EGM.md)).

## Side Effects

- Through the stores: reads and writes applications, clients, resource
  servers, pending authorization requests, grants, codes, the `jti`s of
  client assertions, refresh token families with their tokens' hashes,
  the records of access tokens by `jti`, and consents with their history. Through `KeyService`: signs access and ID tokens, and lists the
  published keys. Through `SecretBox`: seals and opens the secrets of
  refresh token families. Through `IdentityService`: reads people. Through
  `UnitOfWork::record_event`: records the `oauth.*` events.

## Verification

- Run: `cargo test -p hodor-oauth`, and
  `cargo test -p hodor-adapters-postgres --test oauth` for PostgreSQL;
  `cargo test -p hodor-server --test authorization` and
  `cargo test -p hodor-server --test token` and
  `cargo test -p hodor-server --test openid` and
  `cargo test -p hodor-server --test consent` for the endpoints on the real
  binary.
