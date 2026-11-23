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
  `AuthenticationMethod` (`uses_secret`); `GrantType`; `TokenPolicy` with
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
  with `decide` and `satisfied_after_sign_in`; `PendingAuthorization`
  (`hold`, `belongs_to`, `is_live_at`); `Grant` (`make`, `revoke`);
  `AuthorizationCode` (`issue`, `check_redemption`); `CodeHash`
  (`of_presented` answers `None` for a value without the shape of a code);
  `s256_challenge`. Its cases are in `authorization/tests.rs`.
- `token.rs`: the token endpoint. `TokenRequest::parse(basic, pairs)`
  (a parameter given twice, more than one way of proving who the client
  is, or a missing `grant_type`, `code` or `redirect_uri` is
  `invalid_request`; no client named is `invalid_client`; `refresh_token`,
  `client_credentials` and unknown grants are `unsupported_grant_type`);
  `PresentedClient` and its `method`; `TokenError` with `error`,
  `description` and a `reason` for logs only; `check_assertion`, the checks
  of RFC 7523 in the specification's order; `assertion_issuer`, the `iss`
  read before the signature only to find the client;
  `access_token_claims` (RFC 9068; the issuer is the audience when the code
  has none); and, inside the crate, `access_token_header`,
  `signing_input` and `compact`. Its cases are in `token/tests.rs`.
- `event.rs`: `OauthEvent`, seventeen variants, each named `oauth.*`.
- `text.rs`: the rules of names and of scopes (`is_scope`).

## Invariants

- The rules of `docs/architecture/contexts/oauth.md`, "What a client may
  be", are all in `ClientSettings::checked`, which every create and change
  goes through: a public client uses `none`, has no secret or key and uses
  PKCE; a confidential client never uses `none`; `client_credentials` is
  for confidential clients; `refresh_token` comes with
  `authorization_code`, which comes with at least one redirect address.
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
  named.

## Verification

- Run: `cargo test -p hodor-oauth --lib`
