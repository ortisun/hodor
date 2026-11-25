# OAuth application layer

## Overview

The use cases of applications, clients and resource servers, those of the
authorization endpoint and of the token endpoint, those of back-channel
logout, and the storage ports they need. Every use case runs in a unit of work bound to one
tenant and records its events in it.

## Interface

### Ports (`ports.rs`)

| Port | Methods |
| --- | --- |
| `ApplicationStore` | `insert`, `update` (version checked), `get`, `list` (oldest first) |
| `ClientStore` | `insert` (`oauth.application_not_found` for an application the tenant does not have), `update` (version checked; replaces secrets and keys), `get`, `list_for_application` (oldest first), `bound_to` (the clients bound to a `WorkloadIdentity`, oldest first); `insert` and `update` refuse a client whose identity a client of another principal holds (`oauth.client_spiffe_id_taken`, `oauth.client_linkerd_identity_taken`, Decision 0058) |
| `ResourceServerStore` | `insert` (`oauth.audience_taken`, `oauth.application_has_resource_server`, `oauth.application_not_found`), `update` (version checked; replaces the scopes), `get`, `find_by_audience` (exact), `find_by_application` (the application's one, if any), `list` (oldest first) |
| `AuthorizationRequestStore` | `insert` (`oauth.client_not_found`), `get`, `remove` (answers whether this call removed it; never a pushed request), `answer` (records the answer of a request that waits for consent and has none; answers whether this call recorded it), `push(uow, pushed, keep)` (removes the oldest pushed requests of its client beyond `keep - 1`, then stores it; `oauth.client_not_found`), `take_pushed(uow, client, hash)` (removes and answers the pushed request of that client with that reference hash, only if this call removed it; an expired one too) |
| `GrantStore` | `insert` (`oauth.client_not_found`), `get`, `update` (status and revocation; `oauth.grant_not_found`), `list_active_for(user, client)`, `list_active_of(user)` (every client, oldest first) |
| `ConsentStore` | `get(user, client)` (withdrawn and expired included), `save` (replaces; `oauth.client_not_found`), `list_standing(user, now)` (newest first), `record` (a history entry; `oauth.client_not_found`) |
| `AuthorizationCodeStore` | `insert` (`oauth.grant_not_found`), `find` (by hash), `redeem` (only if not redeemed; answers whether this call redeemed it) |
| `ClientAssertionStore` | `remember(client, jti, expires_at)` (`oauth.client_not_found`; answers whether this call was the first) |
| `ClaimMapperStore` | `lock_client` (locks the client's row in the unit of work; answers whether there is one), `insert` (`oauth.client_not_found`, `oauth.claim_mapper_name_taken`), `update` (version checked, `oauth.claim_mapper_modified_concurrently`), `delete` (answers whether there was one), `get(client, id)`, `list_for_client` (by claim name) |
| `ClientRegistrationStore` | `get`, `lock` (the tenant's row locked in the unit of work), `insert` (`oauth.client_registration_modified_concurrently` for a second row, `oauth.client_registration_application_invalid` for an application not of the tenant), `update` (version checked) |
| `InitialAccessTokenStore` | `insert`, `get(id)`, `lock_by_hash` (the token's row locked in the unit of work), `list` (newest first), `count_active(now)`, `record_use` (registrations and last use only), `revoke(id, at)` (answers whether this call revoked it) |
| `PersonClaimSources` | `attributes(tenant, user)` (none for an unknown user; the person's standard claims among them), `organization_name(tenant, organization)` |

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
  `remove_client_key`, `set_client_status`, `client`, `clients`,
  `service_account_of(tenant, &WorkloadIdentity)` (the principal of the
  enabled clients bound to the identity, or `None`; Decision 0058).
- `with_destinations(check)` gives it the kernel's `DestinationCheck`: a
  client's back-channel logout address is checked through it when it is
  set by `create_client`, or new or changed by `change_client`, and the
  check's `http.*` codes become `oauth.client_backchannel_logout_uri_*`.
  Without it, any address is refused with
  `oauth.client_backchannel_logout_uri_forbidden`.
- `with_sector_documents(http)` gives it the guarded outbound client: a
  pairwise client's sector identifier address is checked through the
  `DestinationCheck` and fetched with `GET` (`SECTOR_DOCUMENT_TIME_LIMIT`,
  at most `MAX_SECTOR_DOCUMENT_BYTES`, 2xx only) by `create_client`, and by
  `change_client` when the address, the redirect addresses or the subject
  type change; `check_sector_document` must find every redirect address in
  it. The codes are `oauth.client_sector_identifier_uri_*`. Without both,
  any address is refused with `oauth.client_sector_identifier_uri_forbidden`.
- Resource servers: `create_resource_server(CreateResourceServer)`,
  `change_resource_server`, `resource_server`,
  `resource_server_by_audience` (`oauth.resource_server_not_found` also for
  a value that cannot be an audience), `resource_server_of(application_id)`
  (the application's one, if any, through `find_by_application`),
  `resource_servers`.
- Read together, in one transaction: `client_with_application(client_id)`
  (a `ClientWithApplication`: the client, its application if the tenant
  still has it, and that application's resource server; `NotFound` only
  for the client) and `application_with_resource_server(application_id)`
  (`NotFound` for the application).

### Authorization endpoint (`authorization.rs`)

`AuthorizationCodeService::new(AuthorizationCodePorts { units_of_work,
applications, clients, resource_servers, requests, grants, codes,
memberships, verifier, digest, random, clock })`:

- `check(tenant, issuer, parameters, policy)`: loads the client the request
  names in this tenant and its application. With `request_uri`
  (`parameters.reference()`), the client must be trusted
  (`trusted_client`); a reference of Hodor's shape is hashed
  (`ReferenceHash::of_presented`) and its pushed request taken for that
  client (`take_pushed`), committed whatever comes next, and
  `check_reference` answers. Otherwise it loads the tenant's resource
  servers and runs `check_request`, a request object checked against
  `issuer`, the clock and `verifier`, the kernel's `SignatureVerifier`, with
  `pushed_only` when `policy` (`PushedRequestPolicy`, the tenant's) or the
  client requires pushed requests. The outer `Result` is storage; the inner
  one the refusal.
- `push(tenant, issuer, client, parameters, policy)`: for a client that
  already proved who it is, runs `check_pushed_request` against its
  application and the tenant's resource servers and `check_hint` on what
  it gives (a refused hint is `invalid_request`), then keeps the request,
  its response mode and the hint's `sub` with it,
  with `PushedAuthorization::push` for `pushed_lifetime(policy)` and
  `AuthorizationRequestStore::push` with `MAX_PUSHED_PER_CLIENT`; answers a
  `PushedAnswer` (the reference, once, and `expires_in`), or the
  `TokenError` to answer as JSON.
- `with_id_token_hints(keys)` and `with_pairwise_subjects(pairwise)`
  (Issue-125). `check_hint(tenant, issuer, request)`: when the checked
  request holds `given_hint`, the `id_token_hint` its parameters gave
  (inside its request object when it has one), takes it and checks it with `check_id_token_hint`
  against the tenant's published keys, `verifier` and `issuer` (expiry not checked)
  and keeps its `sub` through `AuthorizationRequest::hinted`; the inner
  error is `(AuthorizationRefusal, reason)`, `invalid_request` at the
  redirect address, also when no keys were given. `hint_names(tenant,
  request, user)`: true without a hint; otherwise whether `subject_for` the
  request's client names `user` as the hint's `sub` (false for a client
  gone or a pairwise client without `with_pairwise_subjects`).
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

### Client registration (`registration.rs`)

`ClientRegistrationService::new(ClientRegistrationPorts { units_of_work,
registrations, tokens, applications, digest, random, clock })`, specified
in "Client registration" of the OAuth context and Decision 0075.
`settings` answers `RegistrationInForce` (the defaults, off, when the
tenant set none); `replace` checks `RegistrationSettings::checked`, then
that the application is the tenant's and third party
(`oauth.client_registration_application_invalid`), and stores and records
`oauth.client_registration_changed` unless nothing changed.
`issue_token` locks the settings' row, refuses while off
(`oauth.client_registration_off`, `Conflict`), without the way of tokens
(`oauth.initial_access_tokens_not_allowed`) and past
`MAX_ACTIVE_INITIAL_ACCESS_TOKENS` (`oauth.too_many_initial_access_tokens`),
and records `oauth.initial_access_token_issued`; `revoke_token` records
`oauth.initial_access_token_revoked` once; `token` and `tokens` read.
`admit(uow, presented, caller)` is the registration endpoint's (Issue-133):
inside the caller's unit of work, off is `oauth.client_registration_off`
(`NotFound`); a presented token is hashed only if it has the shape, found
with `lock_by_hash`, spent with `InitialAccessToken::spend` and stored with
`record_use`, recording `oauth.initial_access_token_used`; any refusal of
a token is `oauth.initial_access_token_invalid`, and no token where open
registration is not allowed `oauth.initial_access_token_required`. It
answers `Admission { settings, allowed_by }`; nothing is committed.

### Claim mappers (`claim_mapper.rs`)

`ClaimMapperService::new(ClaimMapperPorts { units_of_work, clients,
mappers, clock })`: `create`, `replace` and `delete` lock the client
(`oauth.client_not_found`), load its mappers and check them together with
`check_together`, then store and record `oauth.claim_mapper_created`,
`_changed` or `_deleted`; `mapper` and `mappers` read.
`ClaimMapping::new(units_of_work, mappers, memberships, sources)` and
`read(tenant, MappedToken { client_id, user_id, scopes, organization },
targets)`: the client's mappers, what those that apply need read now (the
attributes, the effective groups, the organization's name), and the claims
of each target as `MappedClaims::of(target)`. The token endpoint reads the
access token and the ID token of a code and the access token of a refresh;
client credentials and token exchange pass none; UserInfo reads its own.

### Token endpoint (`token.rs`)

`TokenService::new(TokenPorts { units_of_work, applications, clients,
resource_servers, grants, assertions, refresh_tokens, access_tokens,
standing, memberships, mapping, secrets, codes, keys, verifier, digest,
random, clock })`, with `mapping` the `ClaimMapping` of the claim mappers,
`codes` the
`AuthorizationCodeService`, `keys` the `KeyService`, `standing` a
`PersonStanding`, `access_tokens` the `AccessTokenRecordStore` of the
register and `secrets` the kernel `SecretBox`. The retry window of
refresh tokens is `DEFAULT_RETRY_WINDOW`, 10 seconds;
`with_retry_window(window)` sets another, 0 to 60 seconds, or answers
`oauth.retry_window_invalid`. `with_trust_domains(TrustDomainService)`
lets it check JWT-SVIDs and forwarded identities, and
`with_certificate_check(Arc<dyn CertificateCheck>)` forwarded
certificates; without them every JWT-SVID, and every client of
`tls_client_auth`, `spiffe_x509` and `linkerd_identity`, is refused.

- `token(tenant, Issuer { issuer, token_endpoint }, request,
  correlation_id)`: the outer `Result` is storage, sealing or signing; the
  inner one a `TokenError` to answer with.
  - Certificate-bound tokens: after authentication, the thumbprint of the
    certificate `request.forwarded` holds (`presented_thumbprint`); a
    client with `certificate_bound_access_tokens` and none is
    `invalid_request` before any grant is looked at. Every access token
    of such a client is signed with `cnf` (`sign` and `sign_living` take
    the thumbprint, inserted before the mapped claims). A public client's
    family starts bound to it (`RefreshFamily::bound_to`), and `decide`
    refuses a refresh whose certificate the family does not accept
    (`accepts_certificate`) with `invalid_grant` before deciding, so it
    revokes nothing. Token exchange refuses a subject or actor token whose
    `cnf` the request's certificate does not match
    (`ReadAccessToken::check_certificate`), with `invalid_request`.
  - Authentication: the client named by `client_id`, the `Basic`
    credentials or, without either, the assertion's `iss`; it and its
    application must be enabled; the request's method must be the one it
    was registered with; then the secret (`Client::accepts_secret`), or the
    assertion (`check_assertion`) whose `jti` is remembered and committed at
    once, or the JWT-SVID: the client named by `client_id` alone, its
    SPIFFE identifier's trust domain found by name in the tenant through
    the `TrustDomainService` (in a unit of work of its own) and its bundle,
    `check_svid` against it and the tenant's issuer, and its `mark`
    remembered through the `ClientAssertionStore` until it expires and
    committed at once; or the forwarded identity (`check_forwarded`,
    `forwarded.rs`): a request with its identifier alone may be a public
    client's or one of a forwarded identity (`PresentedClient::may_be`);
    the identity must have been forwarded, be of the kind the method
    takes, name a trust domain the tenant has (found by name through the
    `TrustDomainService`, in a unit of work of its own), and match the
    client's identity by `names_match`; a certificate is checked against
    the `x509-svid` elements of the trust domain's bundle by
    `CertificateCheck::chains_to`, with the tenant's withdrawn keys read
    through `TrustDomainService::withdrawn_keys` at every such check, and
    only a trust domain of source
    `mesh` believes names or a Linkerd identity without one. Every failure
    is `invalid_client`.
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
    client), in force with a grant, whose person, found by
    `AccessTokenRegister::person_in_force` and never from the `sub`,
    `may_sign_in`, with a chain of fewer than
    `MAX_ACTORS`; an exchange rule must pair one of its audiences with the
    one asked, which must be a resource server's; `exchanged_scopes` only
    narrows. Token refusals are `invalid_request`, the policy's
    `invalid_target`. The new token is signed with `sign_living` for the
    smaller of the client's lifetime and what is left of the subject
    token, carries `act` (`act_claim`) and the subject's `auth_time`, `acr`
    and `amr`, keeps the subject token's `sub` unchanged, is recorded with
    the subject's grant and family, the agent as
    principal and the subject token as parent (`exchanged_from`), and
    records `oauth.token_exchanged` with the agent as actor. The answer has
    `issued_token_type`.
  - The access token: claims from `claims_for` with a `TokenSubject`,
    whose `organization` is the grant's (`org_id`) and whose `groups` are
    `PersonMemberships::effective_groups` when the scopes hold `groups`,
    read for every token and left out past `MOST_GROUPS_IN_A_TOKEN`, 100;
    signed with `KeyAlgorithm::DEFAULT_SIGNING` through
    `KeyService::sign_naming_key` so that the header's `kid` is the version
    that signs. `signed_with_active_key`, which UserInfo shares, makes the
    tenant's first key of the algorithm with `KeyService::ensure_active`
    when it has none, and only when even then nothing signs is it
    `server_error`.
  - The person as the client knows them: `subject_for` and `session_for`
    (`pairwise.rs`) give the user and session identifiers to a public
    client and, through the `PairwiseSubjects` given with
    `with_pairwise_subjects`, the pairwise ones to a pairwise client; the
    access token's `sub` and the ID token's `sub` and `sid` (`IdTokenNames`)
    are those, from a code and from a refresh. Without it a pairwise client
    is answered `oauth.pairwise_unavailable`, an error of storage.
  - The ID token, when the scopes hold `openid`: claims from
    `id_token_claims`, signed the same way with the client's ID token
    algorithm (`ClientSettings::id_token_algorithm`, ES256, RS256, PS256
    or EdDSA) and
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
- `TokenService::push(tenant, issuer, endpoint, request, policy)`
  (`pushed.rs`): authenticates the client of a `PushedRequest` as `token`
  does, with `endpoint`, the pushed request endpoint's address, also
  accepted as an assertion's audience, then hands the parameters to
  `AuthorizationCodeService::push`.
- `TokenService::introspect(tenant, issuer, endpoint, query)`: a public
  client is `invalid_client`. A refresh token of this client is active when
  it is the newest of a standing family, its grant is active and the
  person's standing holds; an access token when `read_access_token` accepts
  it, it is this client's or its audience holds the resource server of the
  client's application, and the register says it is in force; a bound one
  is answered with its `cnf`, never compared with the certificate of the
  introspection request. Otherwise `inactive()`. Nothing is changed.

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

`UserInfoService::new(UserInfoPorts { units_of_work, clients, keys,
verifier, identity, register, memberships, mapping, digest, clock })`:

- `answer(tenant, issuer, token, forwarded)`: the outer `Result` is
  storage, or the key provider failing to sign; the inner one a
  `BearerRefusal` (`Missing`, `InvalidToken(reason)`,
  `InsufficientScope`). Checks the token with `check_access_token` against
  the tenant's published `ES256` keys and the thumbprint of the
  certificate in `forwarded` (`presented_thumbprint`, with `digest`), so
  that a bound token without its certificate is `InvalidToken`, whichever
  the answer, then asks the register: a token not
  in force is `InvalidToken`. Then it reads the person through
  `IdentityService::get`: an unknown user, or one who may not sign in (not
  `Active`, or a service account or an agent), is `InvalidToken`. The
  person is the one of the token's grant, through
  `AccessTokenRegister::person_in_force`, never read from its `sub`.
  Answers `userinfo_claims` for the token's scopes, with the token's own
  `sub` and the person's standard claims from the snapshot, and the claims
  of the client's mappers, as
  `UserInfoAnswer::Json`; when the token's client, read through
  `ClientStore::get` in the token's tenant, has a
  `ClientSettings::userinfo_algorithm`, as `UserInfoAnswer::Signed`: the
  claims with `iss` and `aud` (`signed_userinfo_claims`), header
  `userinfo_header` (`alg`, `kid`, no `typ`), signed through
  `signed_with_active_key`; no key even then is the internal error
  `oauth.userinfo_not_signed`, never an unsigned answer.
- `published_keys(keys, tenant)` (crate-visible): the tenant's published
  signing keys as `PublishedKey`s, shared with logout.

### Callers of Hodor's own resource servers (`resource_access.rs`)

`ResourceAccessService::new(ResourceAccessPorts { keys, verifier, register,
applications, digest, clock })`:

- `caller(tenant, issuer, audience, token, forwarded)`: the outer `Result`
  is storage; the inner one a `BearerRefusal`. Reads the token with
  `read_access_token` against the tenant's published keys, then requires
  the certificate a bound token names in `forwarded`
  (`ReadAccessToken::check_certificate`), `audience` among its
  audiences, the register's `in_force`, an enabled client of the tenant and
  an enabled application, the last two read with their resource server by
  `client_with_application`; each failure is `InvalidToken`. Answers a
  `ResourceCaller` (client, application, subject, scopes, the
  application's resource server, and the token's `principal_kind` when its
  client acts as a workload). Checks no scope: `has_scope` is for the
  resource server. The Authorization API, the SCIM server and the signing
  of intermediates at the administration interface are its callers.

### Logout (`logout.rs`)

`LogoutService::new(LogoutPorts { units_of_work, applications, clients, keys,
verifier })`:

- `check(tenant, issuer, parameters)`: the outer `Result` is storage; the
  inner one a `LogoutRefusal { code, reason }`. Checks the shape
  (`check_shape`), then the `id_token_hint` against the published keys
  (`check_id_token_hint`), then loads the client named by `client_id` or
  the hint's `aud` with its application and applies `check_request`.
- `decide(tenant, request, current, by_form)`: what to do with the
  browser's session; the hint's `sub` and `sid` are compared with the
  session's person and session as the hint's client knows them
  (`KnownSession`, from `subject_for` and `session_for`). With
  `with_pairwise_subjects`; without it a pairwise hint asks the person.
- `still_returns(tenant, kept)`: whether a `ReturnAddress` kept in the
  browser while the person was asked still holds (`still_returns` of the
  domain).

### Pairwise subject identifiers (`pairwise.rs`)

`PairwiseSubjects::new(PairwisePorts { units_of_work, secrets, secret_box,
mac, random, clock })`: `subject(tenant, client, user)` and
`session(tenant, client, session)` answer the user or session identifier
for a public client, and for a pairwise client `PairwiseSecret::subject`
and `session` for its sector. The tenant's secret is read with
`PairwiseSecretStore::find` and opened for `PAIRWISE_SECRET_PURPOSE`; a
tenant without one gets one, sealed and stored with
`insert_unless_present` in its own unit of work, then read back so that
two servers use the one stored first. A secret that does not open is
`secret.unreadable`, never replaced.

### Back-channel logout (`backchannel/`)

- `ports.rs`: `SessionClients::clients_of(session)` (the clients with a
  grant made in the session whose scopes hold `openid`, each once);
  `LogoutDeliveryStore` (`insert`, unique per client and session, answers
  whether it stored, `oauth.client_not_found`; `get`; `take`, skipping one
  another unit of work holds; `lock`, waiting; `hold_client`, answering
  whether the tenant has it; `leased(client, now)`; `update`,
  `oauth.logout_delivery_not_found`); `DueLogoutDeliveries::due(now,
  limit)`, across tenants; `TenantIssuer::issuer(tenant)`.
- `fan_out.rs`: `BackChannelLogoutFanOut::new(sessions, clients,
  applications, deliveries, clock)`, an `EventHandler` named
  `oauth_backchannel_logout` for `session.revoked` only. It refuses an
  event of another tenant than its unit of work
  (`oauth.tenant_mismatch`), reads `session_id` and `user_id` from the
  event (`oauth.session_event_unreadable`), and inserts one
  `LogoutDelivery` per client of the session that has an address and is
  enabled with its application.
- `sender.rs`: `BackChannelLogoutSender::new(LogoutSenderPorts {
  units_of_work, clients, deliveries, due, issuers, keys, http, random,
  clock }, LogoutDeliverySettings { retry, time_limit, in_flight_per_client
  })`. `lease_due(limit)` looks at four times `limit` due deliveries and,
  for each in its tenant, holds the client, takes the delivery, sets it
  aside at once (with `oauth.backchannel_logout_set_aside`) if the client
  has no address or is disabled, leaves it if the client has
  `in_flight_per_client` leased, and otherwise leases it for the time limit
  and `LEASE_MARGIN`, answering `LogoutLease`s. `send(lease)` signs a
  logout token (the client's ID token algorithm, `ensure_active` when the
  tenant has no key of it, a `jti` of 16 random bytes, `sub` and `sid` as
  the client knows them, through `with_pairwise_subjects`), posts
  `logout_token=` in a form through `HttpClient` with no transaction open,
  then records the answer if the delivery `is_as_leased`, answering a
  `LogoutOutcome`; a signing failure is a failed attempt.

## Invariants

- A change that changes nothing stores nothing and announces nothing.
- A logout token is signed for each attempt and kept nowhere; no event
  carries it or the client's address.
- No event carries a pairwise identifier: events name people by their user
  identifier.
- Not found is `oauth.application_not_found`, `oauth.client_not_found` or
  `oauth.resource_server_not_found`, the same for a row of another tenant.

## Verification

- Run: `cargo test -p hodor-oauth --test service`,
  `cargo test -p hodor-oauth --test authorization`,
  `cargo test -p hodor-oauth --test token`,
  `cargo test -p hodor-oauth --test refresh` and
  `cargo test -p hodor-oauth --test revocation`,
  `cargo test -p hodor-oauth --test consent`,
  `cargo test -p hodor-oauth --test backchannel`,
  `cargo test -p hodor-oauth --test pairwise`; `cargo test -p hodor-oauth
  --lib openid` for the OpenID Provider's domain and `--lib logout` for
  logout's
