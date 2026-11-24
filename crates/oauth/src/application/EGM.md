# OAuth application layer

## Overview

The use cases of applications, clients and resource servers, those of the
authorization endpoint and of the token endpoint, and the storage ports
they need. Every use case runs in a unit of work bound to one
tenant and records its events in it.

## Interface

### Ports (`ports.rs`)

| Port | Methods |
| --- | --- |
| `ApplicationStore` | `insert`, `update` (version checked), `get`, `list` (oldest first) |
| `ClientStore` | `insert` (`oauth.application_not_found` for an application the tenant does not have), `update` (version checked; replaces secrets and keys), `get`, `list_for_application` (oldest first) |
| `ResourceServerStore` | `insert` (`oauth.audience_taken`, `oauth.application_has_resource_server`, `oauth.application_not_found`), `update` (version checked; replaces the scopes), `get`, `find_by_audience` (exact), `list` (oldest first) |
| `AuthorizationRequestStore` | `insert` (`oauth.client_not_found`), `get`, `remove` (answers whether this call removed it), `answer` (records the answer of a request that waits for consent and has none; answers whether this call recorded it) |
| `GrantStore` | `insert` (`oauth.client_not_found`), `get`, `update` (status and revocation; `oauth.grant_not_found`), `list_active_for(user, client)`, `list_active_of(user)` (every client, oldest first) |
| `ConsentStore` | `get(user, client)` (withdrawn and expired included), `save` (replaces; `oauth.client_not_found`), `list_standing(user, now)` (newest first), `record` (a history entry; `oauth.client_not_found`) |
| `AuthorizationCodeStore` | `insert` (`oauth.grant_not_found`), `find` (by hash), `redeem` (only if not redeemed; answers whether this call redeemed it) |
| `ClientAssertionStore` | `remember(client, jti, expires_at)` (`oauth.client_not_found`; answers whether this call was the first) |

### Service (`service.rs`)

`ApplicationService::new(ApplicationPorts { units_of_work, applications,
clients, resource_servers, digest, random, clock })`:

- Applications: `create_application` (at most 100,
  `oauth.too_many_applications`), `change_application`,
  `set_application_status`, `application`, `applications`.
- Clients: `create_client(CreateClient)` (the application must exist; at
  most 20 per application, `oauth.too_many_clients`; returns the first
  secret once), `change_client`, `rotate_client_secret(RotateSecret)`,
  `revoke_client_secret`, `add_client_key` (the key as JSON),
  `remove_client_key`, `set_client_status`, `client`, `clients`.
- Resource servers: `create_resource_server(CreateResourceServer)`,
  `change_resource_server`, `resource_server`,
  `resource_server_by_audience` (`oauth.resource_server_not_found` also for
  a value that cannot be an audience), `resource_server_of(application_id)`
  (the application's one, if any), `resource_servers`.

### Authorization endpoint (`authorization.rs`)

`AuthorizationCodeService::new(AuthorizationCodePorts { units_of_work,
applications, clients, resource_servers, requests, grants, codes,
memberships, digest, random, clock })`:

- `check(tenant, parameters)`: loads the client the request names in this
  tenant, its application and the tenant's resource servers, and runs
  `check_request`. The outer `Result` is storage; the inner one the refusal.
- `hold(tenant, request)`: stores a pending request for ten minutes;
  returns its identifier and the browser's secret.
- `resume(tenant, id, secret)`: `None` unless the secret is the browser's;
  removes the request (once, even when expired) and returns it while it
  lives.
- `admits(tenant, request, user)`: true when the request names no
  organization, or `PersonMemberships::is_member` says the person is in
  it; the endpoint answers `access_denied` otherwise, before consent.
- `issue_code(tenant, request, person, caller)`: stores a grant, with the
  request's organization, and a code
  in one unit of work with `oauth.authorization_code_issued`; returns the
  code once.
- `redeem_code(tenant, code, presentation, caller)`: every refusal is
  `oauth.code_refused` with the reason as its detail (`unknown`,
  `already_redeemed`, `expired`, `other_client`, ...). A second redemption,
  found as redeemed or lost in the conditional `redeem`, revokes the grant
  (`oauth.grant_revoked`, reason `code_reused`) and commits that.
- `revoke_grants_of_in(uow, user, reason, caller)`: revokes every active
  grant of a person, for every client, in the caller's unit of work, with
  `oauth.grant_revoked` for each; answers how many. Their families and
  access tokens stop being in force with them. SCIM deprovisioning uses it.

### Token endpoint (`token.rs`)

`TokenService::new(TokenPorts { units_of_work, applications, clients,
resource_servers, grants, assertions, refresh_tokens, access_tokens,
standing, memberships, secrets, codes, keys, verifier, digest, random,
clock })`, with `codes` the
`AuthorizationCodeService`, `keys` the `KeyService`, `standing` a
`PersonStanding`, `access_tokens` the `AccessTokenRecordStore` of the
register and `secrets` the kernel `SecretBox`. The retry window of
refresh tokens is `DEFAULT_RETRY_WINDOW`, 10 seconds;
`with_retry_window(window)` sets another, 0 to 60 seconds, or answers
`oauth.retry_window_invalid`.

- `token(tenant, Issuer { issuer, token_endpoint }, request,
  correlation_id)`: the outer `Result` is storage, sealing or signing; the
  inner one a `TokenError` to answer with.
  - Authentication: the client named by `client_id`, the `Basic`
    credentials or, without either, the assertion's `iss`; it and its
    application must be enabled; the request's method must be the one it
    was registered with; then the secret (`Client::accepts_secret`), or the
    assertion (`check_assertion`) whose `jti` is remembered and committed at
    once. Every failure is `invalid_client`.
  - `authorization_code`: `unauthorized_client` without that grant;
    `AuthorizationCodeService::redeem_code` (any `oauth.code_refused` is
    `invalid_grant`); the grant must still be `active`. With the
    `refresh_token` grant, a family starts: a `FamilySecret` sealed for
    `FAMILY_SECRET_PURPOSE`, `RefreshFamily::start`, stored with
    `oauth.refresh_token_family_started` in the unit of work of
    `oauth.access_token_issued`.
  - `refresh_token`: `unauthorized_client` without that grant; a malformed
    or unknown token is `invalid_grant`. `RefreshFamily::decide` in its own
    unit of work; a refusal that revokes (`OtherClient`, `Reused`) revokes
    the family, and on reuse the grant (`oauth.grant_revoked`), and commits
    that. Then the grant must be active, `PersonStanding::may_sign_in`, the
    person a member of the grant's organization, if any
    (`PersonMemberships::is_member`), and without offline access
    `session_is_active`. The family's secret is
    opened and the next token derived. A move is `RefreshTokenStore::advance`
    from the family's generation, with `oauth.refresh_token_rotated`; a move
    lost to another refresh looks the token up again, at most twice. A retry
    answers the derived token only if `RefreshFamily::is_newest`, otherwise
    it is reuse. Records `oauth.access_token_issued` with the user as actor.
  - `client_credentials`: `unauthorized_client` without that grant; a
    client with a principal is `invalid_client` unless
    `PersonStanding::workload_that_may_act` answers its kind; scopes
    from `scope`, or every scope the client is allowed that a resource
    server defines; OpenID Connect's scopes are `invalid_scope`; `resource`
    names one resource server or is `invalid_target`. The token's `sub` is
    the principal when there is one, with `principal_kind`, and the client
    otherwise. Records `oauth.client_access_token_issued` with the
    principal. No refresh token.
  - `urn:ietf:params:oauth:grant-type:token-exchange` (`exchange.rs`,
    `TokenService::exchange`): the client must have the grant and act as an
    agent that may act (`workload_that_may_act` answers `agent`); the actor
    token must be the agent's own, issued to the client, without `act`, in
    force; the subject token a person's (no `principal_kind`, `sub` not the
    client, `may_sign_in`), in force, with a chain of fewer than
    `MAX_ACTORS`; an exchange rule must pair one of its audiences with the
    one asked, which must be a resource server's; `exchanged_scopes` only
    narrows. Token refusals are `invalid_request`, the policy's
    `invalid_target`. The new token is signed with `sign_living` for the
    smaller of the client's lifetime and what is left of the subject
    token, carries `act` (`act_claim`) and the subject's `auth_time`, `acr`
    and `amr`, is recorded with the subject's grant and family, the agent as
    principal and the subject token as parent (`exchanged_from`), and
    records `oauth.token_exchanged` with the agent as actor. The answer has
    `issued_token_type`.
  - The access token: claims from `claims_for` with a `TokenSubject`,
    whose `organization` is the grant's (`org_id`) and whose `groups` are
    `PersonMemberships::effective_groups` when the scopes hold `groups`,
    read for every token and left out past `MOST_GROUPS_IN_A_TOKEN`, 100;
    signed with `KeyAlgorithm::DEFAULT_SIGNING` through
    `KeyService::sign_naming_key` so that the header's `kid` is the version
    that signs. `TokenService::signed` makes the tenant's first key of the
    algorithm with `KeyService::ensure_active` when it has none, and only
    when even then nothing signs is it `server_error`.
  - The ID token, when the scopes hold `openid`: claims from
    `id_token_claims`, signed the same way with the client's ID token
    algorithm (`ClientSettings::id_token_algorithm`, ES256 or RS256) and
    lifetime, header `typ` `JWT`.
  - The register: every access token issued is recorded with
    `AccessTokenRecordStore::record` in the unit of work of its event: the
    code's with its grant, a refresh's with its grant and family, client
    credentials' with neither and with the principal it was issued for.

### Revocation and introspection (`introspection.rs`)

`AccessTokenRegister::new(units_of_work, access_tokens, grants,
refresh_tokens, standing)`, also `TokenService::register()`:
`in_force(tenant, token_id, client_id)` is true only when the record
exists, is not revoked, names that client, its grant and family, if
any, are active, and its principal, if any, is a workload that may act
(`PersonStanding::workload_that_may_act`); and then each parent of a token
made by exchange, up to `MAX_ACTORS` deep, is in force by the same checks.
`record(tenant, token_id)` reads a record whatever its state, for an
exchange to copy its grant and family.

`WorkloadTokens::new(access_tokens, clock)`, also
`TokenService::workload_tokens()`: `revoke_in(uow, principal, reason,
caller)` revokes every record of the principal that is not revoked yet,
in the caller's unit of work, with one `oauth.access_token_revoked` each.

- `TokenService::revoke(tenant, issuer, endpoint, query, correlation_id)`:
  authenticates the client as `token` does, with `endpoint` also accepted
  as an assertion's audience. A token shaped as a refresh token
  (`RefreshTokenHash::of_presented`) of this client revokes its family and
  its grant with `REVOKED_BY_CLIENT`; anything else is read with
  `read_access_token` and, when it is this client's, its record is revoked
  with `oauth.access_token_revoked`. Any other token does nothing; the
  answer is the same.
- `TokenService::introspect(tenant, issuer, endpoint, query)`: a public
  client is `invalid_client`. A refresh token of this client is active when
  it is the newest of a standing family, its grant is active and the
  person's standing holds; an access token when `read_access_token` accepts
  it, it is this client's or its audience holds the resource server of the
  client's application, and the register says it is in force. Otherwise
  `inactive()`. Nothing is changed.

### Consent (`consent.rs`)

`ConsentService::new(ConsentPorts { units_of_work, consents, requests,
grants, clients, applications, resource_servers, digest, random, clock })`:

- `must_ask(tenant, request, person)`: `must_ask` of the domain with the
  person's consent for the client; reads nothing when nobody is asked
  whatever was agreed (a first-party client without `prompt=consent`).
- `hold(tenant, request, person)`: stores a pending request that waits for
  this person's consent in this session; returns its identifier and the
  browser's secret.
- `describe(tenant, id, secret, user, session)`: `None` unless the request
  is this browser's, waits unanswered for this person in this session and
  lives; otherwise the `ConsentQuestion`: the application's name, each
  scope as `AskedScope::OpenId` or `AskedScope::Resource` with the
  description and name of the resource server of the request that defines
  it, and whether `offline_access` was asked.
- `answer(tenant, id, secret, person, answer, caller)`: `false` under the
  same conditions as `describe`, or when another answer won; records the
  answer on the request once. `Agreed` saves the consent
  (`Consent::give` with the client's `TokenPolicy::consent`), a `given`
  history entry and `oauth.consent_given`; `Refused` a `refused` entry and
  `oauth.consent_refused`.
- `list(tenant, user)`: the person's standing consents with their
  applications' names (`ListedConsent`).
- `withdraw(tenant, user, client, by, caller)`: `oauth.consent_not_found`
  unless a consent stands; marks it withdrawn, writes a `withdrawn` entry,
  revokes every active grant of the person for the client (reason
  `consent_withdrawn`) and records `oauth.consent_withdrawn` and each
  `oauth.grant_revoked`, in one unit of work.

`AuthorizationCodeService::resume` also returns `ResumedRequest::consent`,
whom a request waited for and their answer.

### UserInfo (`userinfo.rs`)

`UserInfoService::new(UserInfoPorts { keys, verifier, identity, register,
memberships, clock })`:

- `claims(tenant, issuer, token)`: the outer `Result` is storage; the
  inner one a `BearerRefusal` (`Missing`, `InvalidToken(reason)`,
  `InsufficientScope`). Checks the token with `check_access_token` against
  the tenant's published `ES256` keys, then asks the register: a token not
  in force is `InvalidToken`. Then it reads the person through
  `IdentityService::get`: an unknown user, or one who may not sign in (not
  `Active`, or a service account or an agent), is `InvalidToken`. Answers `userinfo_claims` for the token's scopes.
- `published_keys(keys, tenant)` (crate-visible): the tenant's published
  signing keys as `PublishedKey`s, shared with logout.

### Callers of Hodor's own resource servers (`resource_access.rs`)

`ResourceAccessService::new(ResourceAccessPorts { keys, verifier, register,
applications, clock })`:

- `caller(tenant, issuer, audience, token)`: the outer `Result` is storage;
  the inner one a `BearerRefusal`. Reads the token with `read_access_token`
  against the tenant's published keys, then requires `audience` among its
  audiences, the register's `in_force`, an enabled client of the tenant and
  an enabled application; each failure is `InvalidToken`. Answers a
  `ResourceCaller` (client, application, subject, scopes, the
  application's resource server). Checks no scope: `has_scope` is for the
  resource server. The Authorization API is its caller.

### Logout (`logout.rs`)

`LogoutService::new(LogoutPorts { units_of_work, applications, clients, keys,
verifier })`:

- `check(tenant, issuer, parameters)`: the outer `Result` is storage; the
  inner one a `LogoutRefusal { code, reason }`. Checks the shape
  (`check_shape`), then the `id_token_hint` against the published keys
  (`check_id_token_hint`), then loads the client named by `client_id` or
  the hint's `aud` with its application and applies `check_request`.
- `still_returns(tenant, kept)`: whether a `ReturnAddress` kept in the
  browser while the person was asked still holds (`still_returns` of the
  domain).

## Invariants

- A change that changes nothing stores nothing and announces nothing.
- Not found is `oauth.application_not_found`, `oauth.client_not_found` or
  `oauth.resource_server_not_found`, the same for a row of another tenant.

## Verification

- Run: `cargo test -p hodor-oauth --test service`,
  `cargo test -p hodor-oauth --test authorization`,
  `cargo test -p hodor-oauth --test token`,
  `cargo test -p hodor-oauth --test refresh` and
  `cargo test -p hodor-oauth --test revocation`,
  `cargo test -p hodor-oauth --test consent`; `cargo test -p hodor-oauth
  --lib openid` for the OpenID Provider's domain and `--lib logout` for
  logout's
