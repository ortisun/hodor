# OAuth domain

## Overview

The aggregates of the OAuth context and the rules they keep. Pure: time,
randomness and hashing are passed in. Every module is `pub(crate)` in
`mod.rs`; the types are re-exported through `crate::api`.

## Interface

- `application.rs`: `ApplicationId`; `Status { Enabled, Disabled }`;
  `ApplicationSettings { name, first_party }`; `Application` with
  `create`, `change` (returns whether anything changed), `set_status`.
- `client.rs`: `ClientId` (the `client_id` of OAuth); `ClientType`;
  `AuthenticationMethod` (`uses_secret`); `GrantType`; `IdTokenAlgorithm`
  (`Es256` by default or `Rs256`, `key_algorithm`, listed by `ALL` in
  discovery); `TokenPolicy` with
  its default and `LONGEST_SIGNED_LIFETIME`, the keys context's bound on
  access and ID token lifetimes; `ClientSettings::new` and `checked(client_type)`; `Client`
  with `create`, `change`, `rotate_secret`, `revoke_secret`, `add_key`,
  `remove_key`, `set_status`, `accepts_redirect_uri` (exact equality) and
  `accepts_secret` (hash compared in constant time with every secret that
  has not expired). Changes return their `OauthEvent`s.
- `secret.rs`: `ClientSecretId`; `ClientSecretValue` (`hodor_cs_` and 64
  hexadecimal characters, redacted in `Debug`); `ClientSecretHash` with
  `of_presented`, `from_stored`, `matches`; `ClientSecret` with its
  lifetimes (1 to 730 days, 365 by default, an overlap of at most 30 days).
- `key.rs`: `ClientKey::parse`, which keeps a public JSON Web Key (EC on
  P-256 or P-384, RSA of at least 2048 bits, Ed25519) with a `kid`, written
  with its members in order, and refuses any private part; `MAX_KEYS`;
  `ClientKey::verifying_key(algorithm)`, the key as the kernel reads it when
  it fits `ES256`, `RS256` or `PS256` and its own `alg` (P-384 and Ed25519
  keys fit none yet).
- `resource_server.rs`: `ResourceServerId`; `Audience::parse`;
  `ScopeDefinition`; `ResourceServerSettings`; `ResourceServer` with
  `create`, `change`, `defines`; `OPENID_SCOPES`.
- `authorization.rs`: the authorization endpoint. `AuthorizationParameters`
  (pairs as received, empty values dropped); `check_request(parameters,
  client, application, servers)`, the checks of the specification in their
  order, answering `NotRedirectable(code)` until the client and its
  redirect address are trusted and `Redirect(AuthorizationError)` after;
  `AuthorizationRequest` (serializable, stored while the person signs in)
  with `counting(proofs, now, received_at)`, `decide(signed_in, counting, enough) -> SessionDecision`
  (`Issue`, `SignIn`, `StepUp { carried }`, `LoginRequired`) and
  `signed_in_as_asked`; `SignedInPerson` carries the `acr` the code and its
  tokens name, and `Proof { method, proven_at }` a session's method; `PendingAuthorization`
  (`hold`, `hold_for_consent`, `belongs_to`, `is_live_at`, and `consent`,
  whom it waits for); `first_party` reads as `false` when a stored request
  lacks it, and `prompts` says whether `prompt` holds a value; `Grant` (`make`, `revoke`);
  `AuthorizationCode` (`issue`, `check_redemption`); `CodeHash`
  (`of_presented` answers `None` for a value without the shape of a code);
  `s256_challenge`. Its cases are in `authorization/tests.rs`.
- `token.rs`: the token endpoint. `TokenRequest::parse(basic, pairs)`
  (a parameter given twice, more than one way of proving who the client
  is, or a missing `grant_type`, `code` or `redirect_uri` is
  `invalid_request`; no client named is `invalid_client`; unknown grants
  are `unsupported_grant_type`; `GrantRequest` has `AuthorizationCode`,
  `RefreshToken` with the token as a `Secret` and `ClientCredentials`, each
  with the optional `scope` and `resource` where they apply);
  `PresentedClient` and its `method`; `TokenError` with `error`,
  `description` and a `reason` for logs only; `check_assertion`, the checks
  of RFC 7523 in the specification's order; `assertion_issuer`, the `iss`
  read before the signature only to find the client;
  `claims_for` over a `TokenSubject` (whose `principal_kind` is written as
  the claim of that name) and `access_token_claims` for a code
  (RFC 9068; the issuer is the audience when there is none, and one of the
  audiences when the scopes hold `openid`; no `auth_time` without a
  person); `TokenError` also has `invalid_scope` and `invalid_target`;
  `SUPPORTED_GRANT_TYPES`, the grants the discovery document names; and,
  inside the crate, `access_token_header`, `decode_json`, `signing_input`
  and `compact`. Its cases are in `token/tests.rs`.
- `openid.rs`: the OpenID Provider. `authentication_methods` (Hodor's
  method names as RFC 8176 `amr`, each once, in a fixed order, with `mfa`),
  the code's `acr` when it has one,
  `is_multi_factor`, `access_token_hash` (`at_hash`), `id_token_claims`,
  `read_access_token` (shape, header, a published key, signature, issuer
  and expiry, in order, against `PublishedKey`s; `ReadAccessToken`),
  `check_access_token` (that, then the audience, a person as `sub` and the
  `openid` scope, for UserInfo; `BearerRefusal`, `CheckedAccessToken`
  with the `jti` and `client_id` the register is asked with), `PersonClaims`
  and `userinfo_claims` (the claims of `profile` and `email`), and
  `discovery_document(issuer, acr_values)`, which names the revocation and introspection
  endpoints and their methods. Its cases are in `openid/tests.rs`.
- `introspection.rs`: revocation and introspection. `TokenQuery::parse`
  (`token` required, a parameter twice or more than one way of proving who
  the client is `invalid_request`, no client named `invalid_client`),
  `TokenTypeHint` (an unknown hint is ignored), `AccessTokenRecord` (with
  `issued` and `for_principal`), the answers `inactive`, `active_access_token`
  (with `principal_kind` when the token has it) and
  `active_refresh_token` (`ActiveRefreshToken`), and `REVOKED_BY_CLIENT`.
  Its cases are at the bottom of the file.
- `refresh.rs`: refresh tokens. `RefreshFamily` (`start` from a redeemed
  code and the client's `TokenPolicy`, `decide`, `is_newest`, `revoke`,
  `started_event`, `first_record`), `RefreshFamilyId`, `RefreshTokenHash`
  (`of_presented` answers `None` for a value without the shape of a token),
  `RefreshTokenValue`, `RefreshTokenRecord`, `FamilySecret` (`next_after`:
  the SHA-256 of the secret and the presented token, so the same token
  always leads to the same next one), `FamilyStatus`, `RefreshAsk`,
  `RefreshDecision` (`Move` or `Retry`), `RefreshRefusal` (with
  `revokes_the_family` and `revokes_the_grant`), and `OFFLINE_ACCESS`,
  `FAMILY_SECRET_PURPOSE`, `DEFAULT_RETRY_WINDOW`, `LONGEST_RETRY_WINDOW`.
  Its cases are in `refresh/tests.rs`.
- `logout.rs`: logout initiated by the relying party. `LogoutParameters`,
  `check_id_token_hint` (an ID token of the tenant, signature checked,
  expiry not), `IdTokenHint`, `check_shape` and `check_request`
  (crate-visible; the codes are in `refusal`), `LogoutRequest::decide`
  (`Finish`, `EndSession` only for a `GET` whose hint names the browser's
  session, `Ask` otherwise and always for a form), `ReturnAddress`,
  `still_returns` (crate-visible). Its cases are in `logout/tests.rs`.
- `client.rs` also keeps `post_logout_redirect_uris`: the rules of redirect
  addresses, at most 10, only with `authorization_code`
  (`oauth.client_post_logout_redirect_uri_invalid`);
  `accepts_post_logout_redirect_uri`.
- `consent.rs`: consent. `Consent` (`stands_at`, `covers`: every scope and
  audience of a request, never `offline_access`; `give`, which adds to a
  consent that stands and starts over one that does not; `withdraw`,
  `given_event`), `must_ask` (first party unless `prompt=consent`; then
  `prompt=consent` and `offline_access` always ask; otherwise unless a
  consent covers the request), `ConsentAnswer`, `ConsentWait` (whom a
  pending request waits for, in which session, and the answer),
  `ConsentActor`, `ConsentAction`, `ConsentHistoryEntry`, and
  `DEFAULT_CONSENT_LIFETIME` (365 days), `SHORTEST_CONSENT_LIFETIME`,
  `LONGEST_CONSENT_LIFETIME` (1 and 730 days). `TokenPolicy::consent` is
  the client's lifetime, checked against those bounds. Its cases are in
  `consent/tests.rs`.
- `event.rs`: `OauthEvent`, twenty-five variants, each named `oauth.*`.
- `text.rs`: the rules of names and of scopes (`is_scope`).

## Invariants

- The rules of `docs/architecture/contexts/oauth.md`, "What a client may
  be", are all in `ClientSettings::checked`, which every create and change
  goes through: a public client uses `none`, has no secret or key and uses
  PKCE; a confidential client never uses `none`; `client_credentials` is
  for confidential clients; `refresh_token` comes with
  `authorization_code`, which comes with at least one redirect address; a
  client with a `principal` has `client_credentials` and no other grant.
- A rotation keeps only the newest previous working secret, until the
  overlap ends; every other secret is dropped, so at most two work.
- Leaving a secret method drops the secrets, and leaving `private_key_jwt`
  drops the keys.
- Events carry identifiers, names, audiences and `kid`s; never a secret, a
  code or their hashes.
- Nothing is sent to a redirect address before the client, its
  application and the address are known: `client_id` must name the client
  passed in, both must be enabled, the client must have the authorization
  code grant, and the address must equal a registered one byte for byte.
- A code challenge is S256 only; a code without one refuses a verifier.
- An assertion's signature is checked over its first two parts as they
  arrived before any claim but `iss` is read; `alg` is one of `ES256`,
  `RS256` and `PS256`, so `none` and shared-secret algorithms cannot be
  named. Its audience is the issuer, the token endpoint, or the endpoint
  it was sent to (`AssertionAudience::endpoint`).
- Nothing an access token says is used before its signature has been
  checked, at UserInfo, revocation and introspection alike.

## Verification

- Run: `cargo test -p hodor-oauth --lib`
