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
  method names as RFC 8176 `amr`, each once, in a fixed order, with `mfa`;
  `enrollment`, a factor set up during the sign-in, names nothing and counts
  as something held),
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
  `issued`, `for_principal` and `exchanged_from`), the answers `inactive`,
  `active_access_token` (with `principal_kind` and `act` when the token has
  them) and
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
  expiry not; `sub` and `sid` read as text), `IdTokenHint`, `check_shape`
  and `check_request` (crate-visible; the codes are in `refusal`),
  `LogoutRequest::decide` over a `KnownSession` (`Finish`, `EndSession`
  only for a `GET` whose hint's `sub` and `sid` are the browser's session
  as the hint's client knows it, `Ask` otherwise and always for a form), `ReturnAddress`,
  `still_returns` (crate-visible). Its cases are in `logout/tests.rs`.
- `client.rs` also keeps `post_logout_redirect_uris`: the rules of redirect
  addresses, at most 10, only with `authorization_code`
  (`oauth.client_post_logout_redirect_uri_invalid`);
  `accepts_post_logout_redirect_uri`. And `backchannel_logout_uri`, only
  with `authorization_code`, its form checked by
  `check_backchannel_logout_uri`, and
  `backchannel_logout_session_required`, `true` only with an address
  (`oauth.client_backchannel_logout_uri_invalid`);
  `Client::backchannel_logout_uri`. And `subject_type`, `pairwise` only
  with `authorization_code` (`oauth.client_subject_type_invalid`), with a
  sector from `sector_of` or `oauth.client_sector_identifier_uri_required`,
  and `sector_identifier_uri`, only for a pairwise client, its form checked
  by `check_sector_identifier_uri`; `Client::subject_type` and
  `Client::sector`.
- `pairwise.rs`: pairwise subject identifiers. `SubjectType` (`public`,
  `pairwise`), `host_of` (lowercase, without the port; none for a
  private-use scheme), `sector_of(sector_identifier_uri, redirect_uris)`,
  `check_sector_identifier_uri`, `check_sector_document` (a JSON array of
  strings holding every redirect address,
  `oauth.client_sector_identifier_uri_document_invalid` and `_mismatch`),
  the port `HmacSha256`, and `PairwiseSecret` (`generate`, `from_opened`,
  32 bytes or `secret.unreadable`; `subject` and `session`, the base64url
  of the HMAC-SHA-256 of `hodor.pairwise.sub` or `hodor.pairwise.sid`, the
  tenant, the sector in lowercase and the identifier, each part separated
  by a zero byte). Its cases are in `pairwise/tests.rs`; the value of one
  identifier is pinned in the crypto adapter.
- `openid.rs` also has `IdTokenNames`, the `sub` and `sid` an ID token
  gives, and `CheckedAccessToken::subject`, the token's `sub` as text.
- `backchannel.rs`: back-channel logout. `check_backchannel_logout_uri`
  (`https://` or `http://`, a host, a valid port, no name and password, no
  fragment, printable ASCII, at most 2000 characters; whether it may be
  called is the guarded client's to say), `logout_token_header` (`typ`
  `logout+jwt`), `logout_token_claims(LogoutTokenSubject, now, jti)` (`iss`,
  `sub` and `sid` as the subject gives them, `aud`, `iat`, `exp` two minutes later, `jti`, `events`, `sid`;
  never `nonce`), `LogoutDelivery` (`make`, `is_due`, `is_leased`, `lease`,
  `is_as_leased`, `record_success`, `record_failure`, `set_aside`, the last
  two returning `OauthEvent::BackchannelLogoutSetAside`),
  `LogoutDeliverySnapshot`, `LogoutDeliveryId`, `LogoutDeliveryStatus`,
  `LogoutRetryPolicy` (1 to 20 attempts, waits doubling up to an hour,
  `oauth.logout_retry_policy_invalid`), and `BACKCHANNEL_LOGOUT_EVENT`,
  `LOGOUT_TOKEN_TYPE`, `LOGOUT_TOKEN_LIFETIME`, `SESSION_REVOKED`,
  `MAX_BACKCHANNEL_LOGOUT_URI_LENGTH`, `MAX_LOGOUT_ERROR_LENGTH`. Its cases
  are in `backchannel/tests.rs`.
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
- `event.rs`: `OauthEvent`, twenty-nine variants, each named `oauth.*`.
- `claim_mapper.rs`: claim mappers (Decision 0041). `ClaimMapperSettings`
  (`checked`: the claim written as a scope and not `is_reserved`, compared
  without regard to case against `RESERVED_CLAIMS`; one to three distinct
  `ClaimTarget`s, put in their order; a scope the client may ask for; a
  constant but `null` of at most `MAX_CONSTANT_BYTES`) and its
  `worst_case`; `check_together` (at most `MAX_CLAIM_MAPPERS`, one per
  claim without regard to case, at most `MOST_MAPPED_BYTES` per target in
  the worst case: `oauth.claim_mappers_too_many`,
  `oauth.claim_mapper_name_taken`, `oauth.claim_mapper_token_too_large`);
  `ClaimMapper` (`create`, `replace`, `deleted`, with their events);
  `ClaimSource` (`to_json`, `from_json`, each kind's largest value);
  `needs`, `mapped_claims` (by claim name, a value larger than its bound
  or more than 100 groups leaving the claim out) and `add_mapped_claims`,
  the one hook the token endpoint and UserInfo call after Hodor's own
  claims, which never replaces one. Its cases, including one that every
  claim Hodor writes is reserved, are in `claim_mapper/tests.rs`.
- `text.rs`: the rules of names and of scopes (`is_scope`).
- `exchange.rs`: token exchange. `MAX_ACTORS` (3), `chain_length` (counts
  `act` links as far as one past the bound), `actors` (the `sub` of each,
  newest first), `act_claim(agent, previous)` and `exchanged_scopes`
  (asked, or every scope held by the subject token, allowed to the client
  and defined by the audience; `invalid_scope` otherwise). Its cases are at
  the bottom of the file. `token.rs` reads the grant in `token_exchange`
  (`ACCESS_TOKEN_TYPE` for both tokens and for `requested_token_type`, one
  audience from `audience` or `resource`), and `TokenSubject` carries `act`
  and an `amr` written as given.

## Invariants

- The rules of `docs/architecture/contexts/oauth.md`, "What a client may
  be", are all in `ClientSettings::checked`, which every create and change
  goes through: a public client uses `none`, has no secret or key and uses
  PKCE; a confidential client never uses `none`; `client_credentials` is
  for confidential clients; `refresh_token` comes with
  `authorization_code`, which comes with at least one redirect address; a
  client with a `principal` has `client_credentials` and may have
  `TokenExchange` besides, and no other grant; `TokenExchange`
  (`TOKEN_EXCHANGE_GRANT`) needs a principal and 1 to `MAX_EXCHANGE_RULES`
  `ExchangeRule`s, which only it has (`oauth.client_exchange_rules_invalid`).
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
