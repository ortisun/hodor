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
their answer, their consents and withdrawing one; and Issue-100:
back-channel logout, with the back-channel logout address of clients, the
deliveries made when a session ends and the logout tokens the worker signs
and sends; and Issue-98: pairwise subject identifiers, with the subject
type and sector identifier address of clients, the tenant's pairwise
secret, and every token and answer naming the person as the client's
sector knows them; Issue-106: a client of a service account bound to
one SPIFFE identifier, proving who it is with a JWT-SVID (`spiffe_jwt`,
draft-ietf-oauth-spiffe-client-auth-03) checked against its trust domain's
bundle, read from the keys context; Issue-120: request objects by
value at the authorization endpoint, checked with the client's keys or,
for a client that chose `none`, unsigned; Issue-123: a person's
standard claims at UserInfo, under the scopes `profile`, `address` and
`phone`, and as attributes a claim mapper reads, their names reserved; and
Issue-132: the client registration settings of a tenant, its registration
policy and its initial access tokens, with the admission the registration
endpoint asks for; and Issue-124: the `claims` parameter, which puts a
person's claims in the ID token or at UserInfo as asked when a scope
consented to for the client covers them, reads an essential `acr` as
`acr_values` and a `sub` with a value as the person expected; and Issue-133: the registration endpoint's use case,
reading a client's metadata into its settings, checking them as an
administrator's change and against the policy, and storing the client
under the bounds, never first party; and Issue-134: reading, changing and
removing a registration with its registration access token, replaced at
every change, and a client's login initiation address. Storage,
randomness, hashing, signature checking and time are reached through ports
and kernel traits.

## Interface

- Source and public surface: [src](./src/EGM.md).
- Ports implemented elsewhere: `CertificateCheck`, by
  `X509CertificateCheck` in `crates/adapters-crypto/src/certificate.rs`; `ApplicationStore`, `ClientStore` and
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
  `ClientRegistrationStore` and `InitialAccessTokenStore`, by
  `PgClientRegistrationStore` and `PgInitialAccessTokenStore` in
  `crates/adapters-postgres/src/oauth_registration.rs`;
  `PersonStanding`, by `ServerStanding` in `apps/hodor-server/src/standing.rs`;
  `SessionClients`, `LogoutDeliveryStore` and `DueLogoutDeliveries`, by
  `PgSessionClients`, `PgLogoutDeliveryStore` and `PgDueLogoutDeliveries`
  in `crates/adapters-postgres/src/oauth_logout.rs`; `TenantIssuer`, by
  `TenantIssuers` in `apps/hodor-worker/src/main.rs`.
- Used by `apps/hodor-worker/src/main.rs`: `BackChannelLogoutFanOut` among
  the outbox handlers, and `BackChannelLogoutSender` in a sending loop.
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
- A logout token leaves the crate only in the request
  `BackChannelLogoutSender::send` makes to a client's back-channel logout
  address; it is signed anew for every attempt and stored nowhere, and
  `oauth.backchannel_logout_set_aside` carries neither it nor the address.
- A pairwise client is never given a person's user identifier: every
  service that names a person to it goes through `PairwiseSubjects`, and
  a service given none refuses (`oauth.pairwise_unavailable`). A token
  that comes back is read through its record in the register, never
  through its `sub`. The pairwise secret is made once per tenant, sealed,
  and never replaced; one that does not open is an error.
- A JWT-SVID is checked only against the bundle of the client's own trust
  domain in the client's own tenant, found by the name in the client's
  SPIFFE identifier, never by anything the JWT-SVID says; its `aud` must be
  the tenant's issuer alone, and it is used once.
- Every store call is scoped to the tenant of the unit of work (see
  [application](./src/application/EGM.md)).

## Side Effects

- Through the stores: reads and writes applications, clients, resource
  servers, pending authorization requests, grants, codes, the `jti`s of
  client assertions, refresh token families with their tokens' hashes,
  the records of access tokens by `jti`, consents with their history, and
  logout deliveries, and the tenant's sealed pairwise secret. Through
  `HttpClient`: posts logout tokens, and fetches a sector identifier
  document when a client is saved with one. Through
  `KeyService`: signs access, ID and logout tokens, and lists the
  published keys. Through `TrustDomainService`: reads the tenant's trust
  domain of a name and its bundle, to check a JWT-SVID. Through `SecretBox`: seals and opens the secrets of
  refresh token families and the pairwise secret. Through `IdentityService`: reads people. Through
  `UnitOfWork::record_event`: records the `oauth.*` events.

## Verification

- Run: `cargo test -p hodor-oauth`, and
  `cargo test -p hodor-adapters-postgres --test oauth` for PostgreSQL;
  `cargo test -p hodor-server --test authorization` and
  `cargo test -p hodor-server --test token` and
  `cargo test -p hodor-server --test openid` and
  `cargo test -p hodor-server --test consent` for the endpoints on the real
  binary; `cargo test -p hodor-adapters-postgres --test backchannel_logout`,
  `cargo test -p hodor-server --test logout` and
  `cargo test -p hodor-worker --test backchannel_logout` for back-channel
  logout; `cargo test -p hodor-oauth --test pairwise` and
  `cargo test -p hodor-server --test pairwise` for pairwise subject
  identifiers; `cargo test -p hodor-oauth --test spiffe` and
  `cargo test -p hodor-server --test spiffe_jwt` for JWT-SVIDs.
