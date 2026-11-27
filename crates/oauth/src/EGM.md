# hodor-oauth source

## Overview

The OAuth context. `lib.rs` keeps `application` and `domain` private and
exposes the public surface through `pub mod api`. The specification it
follows is `docs/architecture/contexts/oauth.md`.

## Interface

- `api` re-exports:
  - Ports: `ApplicationStore`, `ClientStore`, `ResourceServerStore`,
    `AuthorizationRequestStore`, `GrantStore`, `AuthorizationCodeStore`,
    `ClientAssertionStore`, `RefreshTokenStore`, `AccessTokenRecordStore`,
    `PersonStanding`, `PersonMemberships`, `ConsentStore`, `ClaimMapperStore`,
    `PersonClaimSources`, `ClientRegistrationStore`,
    `InitialAccessTokenStore`, and those of
    back-channel logout: `SessionClients`, `LogoutDeliveryStore`,
    `DueLogoutDeliveries`, `TenantIssuer`; that of front-channel logout,
    `FrontChannelLogoutStore`; `PairwiseSecretStore`, and
    `HmacSha256`, implemented by the crypto adapter.
  - Services: `ApplicationService`, `ApplicationPorts`, `CreateClient`,
    `RotateSecret`, `CreateResourceServer`; `AuthorizationCodeService`,
    `AuthorizationCodePorts`, `ResumedRequest`, `RedeemedCode`;
    `TokenService`, `TokenPorts`, `Issuer`, `IssuedTokens`, with
    `TokenService::revoke`, `introspect`, `register` and `workload_tokens`;
    `ClientKeySets` and `MAX_KEPT_KEY_SETS`, the keys at clients' addresses,
    given to both services with `with_client_key_sets`; and the key set
    domain: `check_jwks_uri`, `MAX_JWKS_URI_LENGTH`, `MAX_KEY_SET_BYTES`,
    `KEY_SET_TIME_LIMIT`, `KEY_SET_KEPT_FOR`, `KEY_SET_REFETCH_AFTER`,
    `MAX_PUBLISHED_KEYS`, `KEY_SET_ACCEPT`;
    `AccessTokenRegister`; `WorkloadTokens`; `UserInfoService`, `UserInfoPorts`;
    `LogoutService`, `LogoutPorts`, `LogoutRefusal`; `ConsentService`,
    `ConsentPorts`, `ConsentQuestion`, `AskedScope`, `ListedConsent`;
    `BackChannelLogoutFanOut`, `BackChannelLogoutSender`,
    `LogoutSenderPorts`, `LogoutDeliverySettings`, `LogoutLease`,
    `LogoutOutcome`; `FrontChannelLogoutService`,
    `FrontChannelLogoutPorts`; `PairwiseSubjects`, `PairwisePorts`, given to
    `TokenService`, `LogoutService`, `BackChannelLogoutSender` and
    `FrontChannelLogoutService` with `with_pairwise_subjects`;
    `ApplicationService::with_sector_documents`.
  - Pushed authorization requests' domain: `PushedRequestPolicy`,
    `PushedRequest`, `PushedAnswer`, `PushedAuthorization`, `ReferenceHash`,
    `RequestReference`, `Reference`, `check_reference`,
    `check_pushed_request`, `pushed_lifetime`, `REFERENCE_PREFIX`,
    `MAX_PUSHED_PER_CLIENT`, `DEFAULT_PUSHED_LIFETIME`,
    `SHORTEST_PUSHED_LIFETIME`, `LONGEST_PUSHED_LIFETIME`; with
    `TokenService::push` and `AuthorizationCodeService::push`.
  - Request objects at a client's address: `check_request_uri`,
    `is_registered`, `address_to_fetch`, `AddressToFetch`, `fetched_object`,
    `FetchRefusal`, `refused_fetch`, `with_fetched_object`,
    `MAX_REQUEST_URIS`, `MAX_REQUEST_URI_LENGTH`, `REQUEST_OBJECT_ACCEPT`,
    `REQUEST_OBJECT_TIME_LIMIT`; with
    `AuthorizationCodeService::with_request_object_addresses`.
  - Pairwise subject identifiers' domain: `SubjectType`, `PairwiseSecret`
    (with `subject` and `session`), `host_of`, `sector_of`,
    `check_sector_identifier_uri`, `check_sector_document`,
    `PAIRWISE_SECRET_PURPOSE`, `PAIRWISE_SECRET_BYTES`,
    `MAX_SECTOR_IDENTIFIER_URI_LENGTH`, `MAX_SECTOR_DOCUMENT_BYTES`,
    `SECTOR_DOCUMENT_TIME_LIMIT`; `IdTokenNames`, how an ID token names the
    person and the session.
  - Back-channel logout's domain: `LogoutDelivery`, `LogoutDeliveryId`,
    `LogoutDeliverySnapshot`, `LogoutDeliveryStatus`, `LogoutRetryPolicy`,
    `LogoutTokenSubject`, `logout_token_claims`, `logout_token_header`,
    `check_backchannel_logout_uri`, and `BACKCHANNEL_LOGOUT_EVENT`,
    `LOGOUT_TOKEN_TYPE`, `LOGOUT_TOKEN_LIFETIME`, `SESSION_REVOKED`,
    `MAX_BACKCHANNEL_LOGOUT_URI_LENGTH`, `MAX_LOGOUT_ERROR_LENGTH`.
  - Front-channel logout's domain: `FrontChannelLogout`,
    `FrontChannelLogoutId`, `HandleHash`, `SignedOutHandle`,
    `check_frontchannel_logout_uri`, `frame_address`, `frame_sources`, and
    `FRAMES_LIFETIME`, `FRAMES_WAIT`, `MAX_FRONTCHANNEL_LOGOUT_URI_LENGTH`.
    `ClaimMapperService`, `ClaimMapperPorts`, `ClaimMapping` (read by
    `TokenPorts::mapping` and `UserInfoPorts::mapping`), `MappedToken`,
    `MappedClaims`.
  - Client registration: `ClientRegistrationService`,
    `ClientRegistrationPorts`, `RegistrationInForce`, `Admission`,
    `AllowedBy`; `RegisterClient`, `MOST_REGISTRATIONS_PER_ADDRESS`,
    `REGISTRATION_WINDOW`; `ClientMetadata`, `read_client_metadata`,
    `registration_answer`, `DEFAULT_REGISTERED_CLIENT_NAME`;
    `ApplicationType`, `SelfRegistration`, `SelfDescription`;
    `with_registration_endpoint`; `RegistrationSettings`, `RegistrationPolicy`,
    `RegistrationWay`, `RegistrationRequest`, `check_registration`,
    `check_redirect_hosts`,
    `ClientRegistration`, `ClientRegistrationSnapshot`,
    `is_policy_host`, `ways_from_stored`, `REGISTERABLE_METHODS`,
    `MOST_REGISTERED_CLIENTS`, `DEFAULT_MOST_REGISTERED_CLIENTS`,
    `MAX_POLICY_SCOPES`, `MAX_POLICY_HOSTS`; `InitialAccessToken`,
    `InitialAccessTokenId`, `InitialAccessTokenHash`,
    `InitialAccessTokenValue`, `InitialAccessTokenSnapshot`,
    `InitialAccessTokenStatus`, `NewInitialAccessToken`,
    `looks_like_initial_access_token`, `INITIAL_ACCESS_TOKEN_PREFIX`, and
    the bounds of a token's lifetime, registrations and how many are
    active.
  - Claim mappers: `ClaimMapper`, `ClaimMapperId`, `ClaimMapperSettings`,
    `ClaimMapperSnapshot`, `ClaimSource`, `ClaimTarget`, `PersonAttribute`,
    `OrganizationAttribute`, `PersonAttributes`, `PersonFacts`,
    `check_together`, `mapped_claims`, `add_mapped_claims`, `is_reserved`,
    and `RESERVED_CLAIMS`, `MAX_CLAIM_MAPPERS`, `MOST_MAPPED_BYTES`,
    `MAX_CONSTANT_BYTES`, `LONGEST_LOCALE`.
  - The end-session endpoint's domain: `LogoutParameters`,
    `check_id_token_hint`, `IdTokenHint` (its `sub` and `sid` as text),
    `LogoutRequest` (with `decide`), `LogoutDecision`, `CurrentSession`,
    `KnownSession` (the session as the hint's client knows it),
    `ReturnAddress`, `logout_refusal`
    (the codes of the page), `MAX_LOGOUT_STATE_LENGTH`,
    `MAX_LOGOUT_LOCALES_LENGTH`.
  - Certificate-bound access tokens: `CertificateThumbprint`,
    `check_confirmation`, `CONFIRMATION_CLAIM`,
    `CERTIFICATE_THUMBPRINT_MEMBER`, `presented_thumbprint`,
    `advertise_certificate_bound_tokens`.
  - Forwarded identities: `CertificateCheck`, `ForwardedIdentity`,
    `CertificateNames`, `WorkloadIdentity`, `LinkerdIdentity`, `names_match`,
    `advertise_forwarded_methods` and their bounds.
  - The token endpoint's domain: `TokenRequest` (with `parse`),
    `PresentedClient`, `BasicCredentials`, `GrantRequest`, `TokenError`,
    `check_assertion` (with the client's keys), `assertion_issuer`,
    `AssertionAudience`,
    `CheckedAssertion`, `access_token_claims`, `claims_for`,
    `TokenSubject`, `AccessTokenClaims`, and
    `ASSERTION_TYPE`, `MAX_ASSERTION_BYTES`, `MAX_ASSERTION_ID_LENGTH`,
    `ASSERTION_LONGEST_AHEAD`, `CLOCK_ALLOWANCE`, `SUPPORTED_GRANT_TYPES`.
  - SPIFFE client authentication: `SpiffeId`, `check_svid`, `CheckedSvid`,
    and `SPIFFE_ASSERTION_TYPE`, `SPIFFE_CLIENT_AUTHENTICATION_DRAFT`,
    `MAX_SPIFFE_ID_LENGTH`, `SVID_LONGEST_AHEAD`, `SVID_MARK_PREFIX`;
    `TokenService::with_trust_domains`.
  - The OpenID Provider's domain: `id_token_claims`, `id_token_claims_for`
    (any ID token, over `SignInFacts` and `IdTokenHashes`), `claims_of_scopes`,
    `left_half_hash` (of the client's algorithm, SHA-512 for EdDSA),
    `access_token_hash`, `IMPLICIT_GRANT`,
    `authentication_methods`, `assurance`, `is_multi_factor`,
    `asks_for_openid`, `check_access_token`, `read_access_token`,
    `ReadAccessToken`, `PublishedKey`, `CheckedAccessToken`, `BearerRefusal`, `PersonClaims`,
    `userinfo_claims`, `discovery_document`, and `OPENID_SCOPE`,
    `ACR_MULTI_FACTOR`, `ACR_SINGLE_FACTOR`, `UI_LOCALES`.
  - The authorization endpoint's domain: `AuthorizationParameters`,
    `check_request`, `AuthorizationRequest`, `AuthorizationRefusal`,
    `check_request_object`, `RequestObjectCheck`, `RequestObjectRefusal`,
    `MAX_REQUEST_OBJECT_BYTES`, `RequestObjectAlgorithm`,
    `AuthorizationError`, `SignedInPerson`, `SessionDecision`,
    `PendingAuthorization`, `PendingAuthorizationId`, `BrowserSecret`,
    `Grant`, `GrantId`, `GrantStatus`, `AuthorizationCode`, `CodeHash`,
    `CodeValue`, `CodePresentation`, `CodeRefusal`, `s256_challenge`, and
    `CODE_LIFETIME`, `PENDING_LIFETIME`, `MAX_RESOURCES`.
  - Response types and modes: `ResponseType` (`read` into
    `ReadResponseType`, `parse`, `returns_code`, `returns_id_token`,
    `makes_grant`, `default_mode`, `allows`), `ResponseMode` (`query`,
    `fragment`, `form_post`), `error_mode`, and `response_types_kept`.
  - Refresh tokens: `RefreshFamily`, `RefreshFamilyId`, `RefreshTokenHash`,
    `RefreshTokenValue`, `RefreshTokenRecord`, `FamilySecret`,
    `FamilyStatus`, `RefreshAsk`, `RefreshDecision`, `RefreshRefusal`, and
    `OFFLINE_ACCESS`, `FAMILY_SECRET_PURPOSE`, `DEFAULT_RETRY_WINDOW`,
    `LONGEST_RETRY_WINDOW`.
  - Revocation and introspection: `TokenQuery` (with `parse`),
    `TokenTypeHint`, `AccessTokenRecord`, `ActiveRefreshToken`, `inactive`,
    `active_access_token`, `active_refresh_token`, `REVOKED_BY_CLIENT`.
  - Consent: `Consent`, `ConsentAnswer`, `ConsentWait`, `ConsentActor`,
    `ConsentAction`, `ConsentHistoryEntry`, `must_ask`, and
    `DEFAULT_CONSENT_LIFETIME`, `SHORTEST_CONSENT_LIFETIME`,
    `LONGEST_CONSENT_LIFETIME`.
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
    `run_authorization_contract(ports)`, pushed requests taken once by
    their client only and at most five kept per client among its cases;
    `InMemoryGrants::all(tenant)` and `InMemoryAuthorizationRequests::pushed(tenant)`
    for tests that look behind the use cases.
  - `testing/token.rs`: `InMemoryClientAssertions::new(&clients)`;
    `FakeVerifier` and `fake_signature`, a stand-in for signature checking
    in tests only; `AssertionStorePorts` and `run_assertion_contract(ports)`.
  - `testing/refresh.rs`: `InMemoryRefreshTokens::new(&grants)`, which
    refuses a family whose grant the tenant does not have, with `all(tenant)`;
    `StandingOf`, a stand-in `PersonStanding` whose `end_session` and `bar`
    end a session or bar a person or a workload, and whose `workload(id,
    kind)` makes a workload that may act; `MembershipsOf`, a stand-in
    `PersonMemberships` whose `join`, `leave` and `set_groups` say what a
    person is a member of; `RefreshStorePorts` and
    `run_refresh_token_contract(ports)`: a family stored whole and found by
    its token, a move once from a generation that keeps the earlier tokens
    known, a revocation that stops moves, tenants apart, and a family found
    by its identifier.
  - `testing/register.rs`: `InMemoryAccessTokenRecords::new(&clients)`,
    which refuses a record whose client the tenant does not have, with
    `all(tenant)`; `AccessTokenRecordStorePorts` and
    `run_access_token_record_contract(ports)`, which also checks that the
    records of a principal are revoked together, once, in their tenant only.
  - `testing/consent.rs`: `InMemoryConsents::new(&clients)`, which refuses
    a consent or a history entry whose client the tenant does not have,
    with `history(tenant)`; `consent_service(units, &stores, clock)`, a
    `ConsentService` on in-memory stores for the layers above;
    `ConsentStorePorts` and `run_consent_contract(ports)`.
  - `testing/backchannel.rs`: `InMemorySessionClients::new(&grants)`;
    `InMemoryLogoutDeliveries::new(&clients)`, which implements both
    `LogoutDeliveryStore` and `DueLogoutDeliveries` and refuses a delivery
    whose client the tenant does not have, with `all(tenant)`;
    `FixedIssuer` (`of(tenant)`); `FakeDestinations`, a destination check
    without a resolver; `RecordingClients` with `ClientAnswer`, an outbound
    client that keeps the requests (`tokens_to(url)`); and
    `LogoutDeliveryStorePorts` with `run_logout_delivery_contract(ports)`.
  - `testing/frontchannel.rs`: `InMemoryFrontChannelLogouts`, keyed by
    tenant and handle hash, with `all(tenant)`;
    `FrontChannelLogoutStorePorts` and
    `run_frontchannel_logout_contract(ports)`.
  - `testing/pairwise.rs`: `FakeHmac`; `InMemoryPairwiseSecrets` (with
    `damage(tenant)`, `len`); `SectorDocuments`, an outbound client that
    answers set documents and counts fetches; `pairwise_subjects(units,
    secrets)`; `PairwiseSecretStorePorts` and
    `run_pairwise_secret_contract(ports)`, which requires one secret per
    tenant, the first stored kept.
  - `testing/request_uri.rs`: `RequestObjectAddresses` with
    `AddressAnswer` (`Content`, `Redirect`, `Failure` by the guarded
    client's code), an outbound client that serves request objects at
    clients' addresses and keeps every request made (`asked`, `fetched`).
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
- The authorization contract also requires that a request waiting for
  consent loads back with whom it waits for, and is answered once
  (`AuthorizationRequestStore::answer` answers `false` the second time, for
  a request that waits for a sign-in, and from another tenant); and that
  `GrantStore::list_active_for` lists only the active grants of that person
  for that client, in that tenant.
- The consent contract requires that a consent loads back whole and is
  replaced by the next save; that `list_standing` lists only the person's
  consents that are neither withdrawn nor expired, the most recently given
  first; that the history takes the same entry twice; and that no consent
  is read across tenants or names another tenant's client
  (`oauth.client_not_found`).
- The assertion contract requires that a `jti` is remembered once per
  client (the second call answers `false`), that the same `jti` of another
  client is another assertion, and that a row cannot name a client of
  another tenant (`oauth.client_not_found`).
- The register contract requires that a record loads back whole by its
  `jti`; that it is revoked once and only by the client it names (later
  calls answer `false`); that records of tokens expired at the moment, that
  one included, are removed a batch at a time and no other; and that no
  record is seen, revoked, removed or made for a client of another tenant.
- The front-channel logout contract requires that the frames of a sign-out
  load back whole, in their order, by the hash of their handle; that an
  unknown hash finds nothing; and that another tenant never finds them.

## Side Effects

- None at the crate root. `testing` mutates in-process memory only.

## Verification

- Run: `cargo test -p hodor-oauth`
