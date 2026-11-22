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
  its default; `ClientSettings::new` and `checked(client_type)`; `Client`
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
  with its members in order, and refuses any private part; `MAX_KEYS`.
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
- `event.rs`: `OauthEvent`, sixteen variants, each named `oauth.*`.
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

## Verification

- Run: `cargo test -p hodor-oauth --lib`
