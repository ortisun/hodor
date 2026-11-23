# hodor-oauth source

## Overview

The OAuth context. `lib.rs` keeps `application` and `domain` private and
exposes the public surface through `pub mod api`. The specification it
follows is `docs/architecture/contexts/oauth.md`.

## Interface

- `api` re-exports:
  - Ports: `ApplicationStore`, `ClientStore`, `ResourceServerStore`,
    `AuthorizationRequestStore`, `GrantStore`, `AuthorizationCodeStore`,
    `ClientAssertionStore`, `RefreshTokenStore`, `PersonStanding`.
  - Services: `ApplicationService`, `ApplicationPorts`, `CreateClient`,
    `RotateSecret`, `CreateResourceServer`; `AuthorizationCodeService`,
    `AuthorizationCodePorts`, `ResumedRequest`, `RedeemedCode`;
    `TokenService`, `TokenPorts`, `Issuer`, `IssuedTokens`;
    `UserInfoService`, `UserInfoPorts`; `LogoutService`, `LogoutPorts`,
    `LogoutRefusal`.
  - The end-session endpoint's domain: `LogoutParameters`,
    `check_id_token_hint`, `IdTokenHint`, `LogoutRequest` (with `decide`),
    `LogoutDecision`, `CurrentSession`, `ReturnAddress`, `logout_refusal`
    (the codes of the page), `MAX_LOGOUT_STATE_LENGTH`,
    `MAX_LOGOUT_LOCALES_LENGTH`.
  - The token endpoint's domain: `TokenRequest` (with `parse`),
    `PresentedClient`, `BasicCredentials`, `GrantRequest`, `TokenError`,
    `check_assertion`, `assertion_issuer`, `AssertionAudience`,
    `CheckedAssertion`, `access_token_claims`, `claims_for`,
    `TokenSubject`, `AccessTokenClaims`, and
    `ASSERTION_TYPE`, `MAX_ASSERTION_BYTES`, `MAX_ASSERTION_ID_LENGTH`,
    `ASSERTION_LONGEST_AHEAD`, `CLOCK_ALLOWANCE`, `SUPPORTED_GRANT_TYPES`.
  - The OpenID Provider's domain: `id_token_claims`, `access_token_hash`,
    `authentication_methods`, `assurance`, `is_multi_factor`,
    `asks_for_openid`, `check_access_token`, `PublishedKey`,
    `CheckedAccessToken`, `BearerRefusal`, `PersonClaims`,
    `userinfo_claims`, `discovery_document`, and `OPENID_SCOPE`,
    `ACR_MULTI_FACTOR`, `ACR_SINGLE_FACTOR`, `UI_LOCALES`.
  - The authorization endpoint's domain: `AuthorizationParameters`,
    `check_request`, `AuthorizationRequest`, `AuthorizationRefusal`,
    `AuthorizationError`, `SignedInPerson`, `SessionDecision`,
    `PendingAuthorization`, `PendingAuthorizationId`, `BrowserSecret`,
    `Grant`, `GrantId`, `GrantStatus`, `AuthorizationCode`, `CodeHash`,
    `CodeValue`, `CodePresentation`, `CodeRefusal`, `s256_challenge`, and
    `CODE_LIFETIME`, `PENDING_LIFETIME`, `MAX_RESOURCES`.
  - Refresh tokens: `RefreshFamily`, `RefreshFamilyId`, `RefreshTokenHash`,
    `RefreshTokenValue`, `RefreshTokenRecord`, `FamilySecret`,
    `FamilyStatus`, `RefreshAsk`, `RefreshDecision`, `RefreshRefusal`, and
    `OFFLINE_ACCESS`, `FAMILY_SECRET_PURPOSE`, `DEFAULT_RETRY_WINDOW`,
    `LONGEST_RETRY_WINDOW`.
  - Event: `OauthEvent`.
  - Domain: `Application`, `ApplicationId`, `ApplicationSettings`,
    `ApplicationSnapshot`, `Status`, `Client`, `ClientId`, `ClientType`,
    `ClientSettings`, `ClientSnapshot`, `AuthenticationMethod`, `GrantType`,
    `TokenPolicy`, `ClientSecret`, `ClientSecretId`, `ClientSecretHash`,
    `ClientSecretValue`, `ClientKey`, `ResourceServer`, `ResourceServerId`,
    `ResourceServerSettings`, `ResourceServerSnapshot`, `ScopeDefinition`,
    `Audience`, `is_scope`, and the limits `MAX_APPLICATIONS`,
    `MAX_CLIENTS`, `MAX_REDIRECT_URIS`, `MAX_SCOPES`, `MAX_KEYS`,
    `MAX_SCOPE_LENGTH`, `OPENID_SCOPES`.
- `testing` (compiled only under `#[cfg(any(test, feature = "testing"))]`):
  - `InMemoryApplications`, `InMemoryClients::new(&applications)`,
    `InMemoryResourceServers::new(&applications)`, and `InMemoryStores`,
    the three wired together. The two last refuse a row of an application
    the tenant does not have, as the database does.
  - `DistinctRandom`: a `RandomSource` whose every call gives different
    bytes, for tests only.
  - `Ports<'a> { units_of_work, applications, clients, resource_servers }`
    and `run_contract(ports)`: the contract every store passes.
  - `testing/authorization.rs`: `InMemoryAuthorizationRequests::new(&clients)`,
    `InMemoryGrants::new(&clients)`,
    `InMemoryAuthorizationCodes::new(&grants)`, which refuse a row whose
    client or grant the tenant does not have; `AuthorizationStorePorts` and
    `run_authorization_contract(ports)`; `InMemoryGrants::all(tenant)` for
    tests that look behind the use cases.
  - `testing/token.rs`: `InMemoryClientAssertions::new(&clients)`;
    `FakeVerifier` and `fake_signature`, a stand-in for signature checking
    in tests only; `AssertionStorePorts` and `run_assertion_contract(ports)`.
  - `testing/refresh.rs`: `InMemoryRefreshTokens::new(&grants)`, which
    refuses a family whose grant the tenant does not have, with `all(tenant)`;
    `StandingOf`, a stand-in `PersonStanding` whose `end_session` and `bar`
    end a session or bar a person; `RefreshStorePorts` and
    `run_refresh_token_contract(ports)`: a family stored whole and found by
    its token, a move once from a generation that keeps the earlier tokens
    known, a revocation that stops moves, and tenants apart.
- Subdirectories:
  - [application](./application/EGM.md): the ports and the use cases.
  - [domain](./domain/EGM.md): the aggregates and their rules.

## Invariants

- The contract (`testing.rs:run_contract`) requires that what is stored
  loads back unchanged, secrets, keys and scopes in their order; that no
  read or change crosses tenants; that a stale version is refused with
  `oauth.*_modified_concurrently`; that a client or resource server names
  an application of its own tenant (`oauth.application_not_found`); that
  an audience is found by exact equality and is unique in a tenant
  (`oauth.audience_taken`); and that an application has at most one
  resource server (`oauth.application_has_resource_server`).
- The authorization contract requires that a pending request, a grant and
  a code load back whole; that none is seen, removed or redeemed from
  another tenant; that a pending request is removed once and a code
  redeemed once (the second call answers `false`); and that a row cannot
  name a client (`oauth.client_not_found`) or grant
  (`oauth.grant_not_found`) of another tenant.
- The assertion contract requires that a `jti` is remembered once per
  client (the second call answers `false`), that the same `jti` of another
  client is another assertion, and that a row cannot name a client of
  another tenant (`oauth.client_not_found`).

## Side Effects

- None at the crate root. `testing` mutates in-process memory only.

## Verification

- Run: `cargo test -p hodor-oauth`
