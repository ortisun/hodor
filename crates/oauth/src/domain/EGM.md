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
  `AuthenticationMethod` (`uses_secret`; `uses_spiffe_id` for `SpiffeJwt`
  and `SpiffeX509`; `uses_forwarded_identity` for `TlsClientAuth`,
  `SpiffeX509` and `LinkerdIdentity`; `uses_workload_identity`, either);
  `ClientSettings::workload_identity()`; `GrantType`;
  `IdTokenAlgorithm`
  (`Es256` by default, `Rs256`, `Ps256` or `EdDsa`; `key_algorithm`,
  `signature`, `from_name`, `parse` with
  `oauth.client_id_token_algorithm_invalid` and `parse_for_userinfo` with
  `oauth.client_userinfo_algorithm_invalid`; listed by `ALL` in discovery
  for ID tokens and UserInfo), kept as `ClientSettings::id_token_algorithm`
  and, for signed UserInfo answers, `ClientSettings::userinfo_algorithm`,
  none by default; `RequestObjectAlgorithm` (`Es256`, `Rs256`, `Ps256`, `None`;
  `parse`, `as_str`, `signature`, listed by `ALL` in discovery), kept as
  `ClientSettings::request_object_algorithm`, none chosen by default;
  `TokenPolicy` with
  its default and `LONGEST_SIGNED_LIFETIME`, the keys context's bound on
  access and ID token lifetimes; `ClientSettings::new` and `checked(client_type)`; `Client`
  with `create`, `change`, `rotate_secret`, `revoke_secret`, `add_key`,
  `remove_key`, `set_status`, `accepts_redirect_uri` (exact equality) and
  `accepts_secret` (hash compared in constant time with every secret that
  has not expired). Changes return their `OauthEvent`s.
- `binding.rs`: certificate-bound access tokens (RFC 8705).
  `CertificateThumbprint` (`of_certificate` through a `Digest`,
  `from_hex` for Envoy's `Hash`, `from_x5t`, `as_x5t`, `confirmation`, the
  `cnf` claim), `CONFIRMATION_CLAIM`, `CERTIFICATE_THUMBPRINT_MEMBER`, and
  `check_confirmation(cnf, presented)`: a token bound to nothing passes, a
  bound one only with the same thumbprint, and a `cnf` that does not read
  never passes.
- `forwarded.rs`: `LinkerdIdentity` (`parse`, `as_str`, `trust_domain`,
  what follows the control plane's namespace;
  `oauth.client_linkerd_identity_invalid` otherwise); `WorkloadIdentity`
  (`Spiffe` with `spiffe.rs`'s `SpiffeId`, or `Linkerd`; `parse` reads
  `spiffe://` as a SPIFFE identifier and anything else as a Linkerd
  identity), what
  `ClientSettings::workload_identity` answers; `ForwardedIdentity`
  (`Certificate { certificate, chain }`, `Names { uris, dns_names, hash }`,
  `Linkerd`) and its `thumbprint(digest)`, with `presented_thumbprint`;
  `CertificateNames`; `names_match(method, identity, names)`;
  `advertise_forwarded_methods(document, methods)` and
  `advertise_certificate_bound_tokens(document)`; the bounds
  `MAX_FORWARDED_CERTIFICATE_BYTES`, `MAX_FORWARDED_CHAIN`,
  `MAX_LINKERD_IDENTITY_LENGTH`.
- `secret.rs`: `ClientSecretId`; `ClientSecretValue` (`hodor_cs_` and 64
  hexadecimal characters, redacted in `Debug`); `ClientSecretHash` with
  `of_presented`, `from_stored`, `matches`; `ClientSecret` with its
  lifetimes (1 to 730 days, 365 by default, an overlap of at most 30 days).
- `key.rs`: `ClientKey::parse`, which keeps a public JSON Web Key (EC on
  P-256 or P-384, RSA of at least 2048 bits, Ed25519) with a `kid`, written
  with its members in order, and refuses any private part; `MAX_KEYS`;
  `ClientKey::verifying_key(algorithm)`, the key as the kernel reads it when
  it fits `ES256`, `RS256` or `PS256` and its own `alg` (P-384 and Ed25519
  keys fit none yet), over the crate-visible `verifying_key_of(jwk,
  algorithm)`, which a trust domain's bundle is read with too;
  crate-visible `ClientKey::published(value, now)`, a key of a set at a
  client's address, checked alike but kept without a `kid` (an empty
  `key_id`), `None` for anything refused.
- `key_set.rs`: a client's keys at its address (Issue-136, Decision 0079).
  `check_jwks_uri` (the form of a back-channel logout address,
  `oauth.client_jwks_uri_invalid`), `MAX_JWKS_URI_LENGTH`,
  `MAX_KEY_SET_BYTES` (64 kibibytes), `KEY_SET_TIME_LIMIT` (5 seconds),
  `KEY_SET_KEPT_FOR` (an hour), `KEY_SET_REFETCH_AFTER` (a minute),
  `MAX_PUBLISHED_KEYS` (20), `KEY_SET_ACCEPT`; inside the crate,
  `published_keys(body, now)` (a JSON object with a list `keys`, the first
  20 accepted keys, `None` for anything else), `names_unknown_key(signed,
  keys)` (a header whose `kid` no key has, or without one none fits its
  algorithm, by `client_key_for`), `KeptSet` (address, keys, `fetched_at`,
  `asked_at`; `is_fresh`, `usable`, `asked_lately`) and `next_step(kept,
  address, signed, now)`, `KeySetStep::Use(keys)` or `Fetch`: fetch when
  nothing fresh is kept for that address or the token names an unknown
  key, never when asked less than a minute ago. `client.rs` checks the
  address (`jwks_uri`, only with `private_key_jwt`); `Client::change`
  refuses one to a client with keys (`oauth.client_jwks_uri_with_keys`),
  `Client::add_key` a key to a client with one
  (`oauth.client_keys_at_address`). Its cases are in `key_set/tests.rs`.
- `spiffe.rs`: SPIFFE client authentication with a JWT-SVID (`spiffe_jwt`,
  Decision 0055). `SpiffeId::parse` (`spiffe://`, a trust domain's name by
  the keys context's `TrustDomainName`, a path of segments of letters,
  digits, `.`, `-` and `_`, never `.` or `..`, at most
  `MAX_SPIFFE_ID_LENGTH` bytes, no `*`; `oauth.client_spiffe_id_invalid`),
  `as_str` and `trust_domain`; `check_svid(svid, spiffe_id, bundle, issuer,
  now, verifier, digest)`, the checks in the specification's order (shape,
  `alg` `ES256`, `RS256` or `PS256`, `kid` required, `typ` `JWT` or `JOSE`
  when present, the bundle's `jwt-svid` key of that `kid`, the signature,
  then `sub` exactly the identifier, `aud` the issuer alone, `exp` not past
  and at most `SVID_LONGEST_AHEAD` ahead, `nbf` and `iat` not in the
  future), answering a `CheckedSvid` whose `mark` is `SVID_MARK_PREFIX` and
  the SHA-256 of the first two parts in base64url; `SPIFFE_ASSERTION_TYPE`
  and `SPIFFE_CLIENT_AUTHENTICATION_DRAFT`. Its cases are in
  `spiffe/tests.rs`.
- `resource_server.rs`: `ResourceServerId`; `Audience::parse`;
  `ScopeDefinition`; `ResourceServerSettings`; `ResourceServer` with
  `create`, `change`, `defines`; `OPENID_SCOPES`.
- `response.rs`: what the authorization endpoint answers with, and where.
  `ResponseType` (`Code` only; `read`, `as_str`, `ALL`, `default_mode`,
  `allows(mode)`), `ResponseMode` (`Query`, the default, and `FormPost`,
  serialized as `query` and `form_post`; `read` answers `None` for any
  other name; `as_str`, `ALL`, which discovery lists), and
  `error_mode(response_type, response_mode)`: the mode an error goes back
  in, the one named when offered and allowed by the type, else the type's
  default, else the query. Its cases are in the module's own tests.
- `authorization.rs`: the authorization endpoint. `AuthorizationParameters`
  (pairs as received, empty values dropped; `client_id` is the one given,
  or the request object's when none is); `check_request(parameters,
  client, application, servers, objects)`, the checks of the specification
  in their order, answering `NotRedirectable(code)` until the client and its
  redirect address are trusted and `Redirect(AuthorizationError)` after,
  whose `mode` is `error_mode` of the request's type and mode; an unknown
  `response_mode`, or one the type does not allow, is `invalid_request`
  after the type is read; a
  request with `request` is checked by `check_request_object` first, its
  refusal sent to the redirect address outside or inside it when that is
  one of the client's, in the mode named beside that address, otherwise
  `oauth.authorization_request_object_invalid`;
  `AuthorizationRequest` (serializable, stored while the person signs in;
  `response_mode` reads as `Query` when a stored request lacks it)
  with `counting(proofs, now, received_at)`, `decide(signed_in, counting, enough) -> SessionDecision`
  (`Issue`, `SignIn`, `StepUp { carried }`, `LoginRequired`) and
  `signed_in_as_asked`; `SignedInPerson` carries the `acr` the code and its
  tokens name, and `Proof { method, proven_at }` a session's method; `PendingAuthorization`
  (`hold`, `hold_for_consent`, `belongs_to`, `is_live_at`, and `consent`,
  whom it waits for); `first_party` reads as `false` when a stored request
  lacks it, and `prompts` says whether `prompt` holds a value; Issue-125:
  `prompt=create` (`asks_to_register`, counted as asking for a new sign-in,
  `registration_refusal(open)`), `display` among `DISPLAYS` (`page`,
  `popup`, `touch`), the client's `default_max_age` and
  `default_acr_values` for a request without its own, and `id_token_hint`
  (`given_hint`, the token as the checked parameters gave it, inside a
  request object when there is one, never serialized; `hinted(checked)`
  keeps the `sub` of a hint issued to the request's client,
  `names_person(subject)`; read as `None` from a request stored before
  it); Issue-124: the request keeps `claims` (a `ClaimsRequest`, read by
  `read_claims`; an essential `acr` with values becomes `acr_values`, which
  the client's `default_acr_values` then do not replace, and an `acr` with
  values beside `acr_values` is `invalid_request`) and `claims_locales`,
  both left out of a stored request that has none, and
  `names_another(subject)` says whether it asked for another `sub`; `Grant`
  (`make`, `revoke`, and `claims`, the `GrantClaims` it gives, empty from
  `make`);
  `AuthorizationCode` (`issue`, `check_redemption`); `CodeHash`
  (`of_presented` answers `None` for a value without the shape of a code);
  `s256_challenge`. Its cases are in `authorization/tests.rs`, and those of
  Issue-125 in `authorization/parameter_tests.rs`.
- `token.rs`: the token endpoint. `TokenRequest::parse(basic, pairs)`,
  then `with_forwarded(identity)`, which keeps what a trusted proxy
  forwarded in `forwarded`, for binding tokens, besides giving it to the
  client (`PresentedClient::with_forwarded`)
  (a parameter given twice, more than one way of proving who the client
  is, or a missing `grant_type`, `code` or `redirect_uri` is
  `invalid_request`; no client named is `invalid_client`; unknown grants
  are `unsupported_grant_type`; `GrantRequest` has `AuthorizationCode`,
  `RefreshToken` with the token as a `Secret` and `ClientCredentials`, each
  with the optional `scope` and `resource` where they apply);
  `PresentedClient` and its `method` (`Svid` for the `client_assertion_type`
  of a JWT-SVID, `SpiffeJwt`), `may_be(registered)`, `with_forwarded(identity)`
  (only a request with its identifier alone becomes `Forwarded`) and
  `forwarded()`; `TokenError` with `error`,
  `description` and a `reason` for logs only; `check_assertion`, the checks
  of RFC 7523 in the specification's order; `assertion_issuer`, the `iss`
  read before the signature only to find the client; inside the crate,
  `client_key_for(keys, header, algorithm)`, the one of the client's keys
  (kept by Hodor or at its address; one without a `kid` is never the one a
  `kid` names) that can have signed, which assertions and request objects
  share, with `KeyChoice`; `check_assertion` takes those keys beside the
  client;
  `claims_for` over a `TokenSubject` (whose `principal_kind` is written as
  the claim of that name) and `access_token_claims` for a code
  (RFC 9068; the issuer is the audience when there is none, and one of the
  audiences when the scopes hold `openid`; no `auth_time` without a
  person); `TokenError` also has `invalid_scope` and `invalid_target`;
  `SUPPORTED_GRANT_TYPES`, the grants the discovery document names; and,
  inside the crate, `access_token_header`, `decode_json`, `signing_input`
  and `compact`. Its cases are in `token/tests.rs`.
- `pushed.rs`: pushed authorization requests (RFC 9126).
  `PushedRequestPolicy { lifetime, required }` (the tenant's, read by the
  HTTP layer; `requires(client)` adds the client's
  `require_pushed_requests`); `pushed_lifetime` keeps it within
  `SHORTEST_PUSHED_LIFETIME` and `LONGEST_PUSHED_LIFETIME` (10 and 600
  seconds, `DEFAULT_PUSHED_LIFETIME` 60); `ReferenceHash` (`of_presented`
  only for `REFERENCE_PREFIX` followed by 43 base64url characters);
  `RequestReference`, redacted; `PushedAuthorization` with `push(request,
  lifetime, now, random, digest)` and `is_live_at`;
  `AuthorizationParameters::reference()`, a `Reference` (`Absent`,
  `Pushed`, `Address(value)` for `https://` and `http://`, `Unknown`); `check_reference(outside,
  client, taken, now)`, the pushed request as the request, with
  `invalid_request_uri`, `request_uri_not_supported` or `invalid_request`
  at the redirect address outside when it is the client's, in the
  `error_mode` of what is outside, otherwise
  `oauth.authorization_request_uri_invalid`, and `response_type` and
  `scope` repeated outside checked against the pushed request, refused in
  its own response mode;
  `PushedRequest::parse(basic, pairs)` (a parameter twice but `resource`
  is `invalid_request`; the client by `presented_client`; the
  authentication parameters left out of the request);
  `check_pushed_request(parameters, client, application, servers,
  objects)`, `check_request` for the client that proved who it is, its
  refusals as a `TokenError` (`unauthorized_client`, `invalid_request`,
  `invalid_request_object`, or the endpoint's own `error`); `PushedAnswer`
  and `MAX_PUSHED_PER_CLIENT` (5). Its cases are in `pushed/tests.rs`.
- `request_object.rs`: request objects (OpenID Connect Core, section 6,
  and RFC 9101). `check_request_object(object, client, outside, check)`:
  `request_uri` beside it, the size (`MAX_REQUEST_OBJECT_BYTES`, 16
  kibibytes) and shape, the algorithm the client's
  `request_object_algorithm` accepts (`none` only for a client that chose
  it, with an empty signature), the key by `client_key_for` among the
  `keys` of `RequestObjectCheck` and the
  signature, then `iss` (required when signed), `client_id`, `aud` (the
  issuer of `RequestObjectCheck`), `exp` and `nbf` with the clock
  allowance; it answers the object's claims as `AuthorizationParameters`
  (text as it is, numbers, booleans and objects as JSON, lists once per
  element, without `iss`, `aud`, `exp`, `nbf`, `iat` and `jti`, with the
  client's own `client_id`), after checking that `response_type` and
  `scope` outside agree. `RequestObjectRefusal` is `Invalid`
  (`invalid_request_object`) or `Contradicted` (`invalid_request`);
  `unchecked_claims` reads an object without trusting it, only to name its
  client and where an error may go. Its cases are in
  `request_object/tests.rs`.
- `request_uri.rs`: request objects at a client's address (OpenID Connect
  Core, section 6.2). `check_request_uri` (the form of a registered
  address: as a back-channel logout address, and a path after the host;
  `oauth.client_request_uri_invalid`), which `ClientSettings::checked`
  applies to `request_uris`, at most `MAX_REQUEST_URIS` (10), only with
  `authorization_code`; `is_registered(reference, client)` (the reference
  before `#`, at most 2000 printable characters, starts with a registered
  address); `address_to_fetch(outside, client, pushed_only)`, an
  `AddressToFetch { url, fragment }` or the refusal (`invalid_request` for
  `request` beside it or a client that must push, `invalid_request_uri`
  for an unregistered address); `fetched_object(status, body, address,
  digest)` (2xx, at most `MAX_REQUEST_OBJECT_BYTES`, the base64url SHA-256
  of the body equal to the fragment, UTF-8 text without the spaces around
  it) or a `FetchRefusal`; `refused_fetch`, `invalid_request_uri` where a
  refused reference is answered (`pushed::refused_reference`); and
  `with_fetched_object`, the parameters with the content as `request` in
  place of `request_uri`. Its cases are in `request_uri/tests.rs`.
- `openid.rs`: the OpenID Provider. `authentication_methods` (Hodor's
  method names as RFC 8176 `amr`, each once, in a fixed order, with `mfa`;
  `enrollment`, a factor set up during the sign-in, names nothing and counts
  as something held),
  the code's `acr` when it has one,
  `is_multi_factor`, `access_token_hash` (`at_hash`, the left half of SHA-256, or of SHA-512 for EdDSA), `id_token_claims`,
  `read_access_token` (shape, header, a published key, signature, issuer
  and expiry, in order, against `PublishedKey`s; `ReadAccessToken`, with
  its `cnf` as `confirmation` and `check_certificate(presented)`),
  `check_access_token` (that, then the certificate of a bound token, the
  audience, a person as `sub` and the
  `openid` scope, for UserInfo; `BearerRefusal`, `CheckedAccessToken`
  with the `jti` and `client_id` the register is asked with), `PersonClaims`
  (with the person's `StandardClaims` in `claims`) and `userinfo_claims`
  (the claims of `profile`, among them the standard names, page addresses,
  gender, birth date and time zone the person has; of `email`; of `address`,
  the postal address as `address_claim` writes it, an object of the parts
  the person has; and of `phone`, `phone_number` with
  `phone_number_verified`, both only when there is a number),
  `signed_userinfo_claims` and `userinfo_header` (crate-visible: a signed
  UserInfo answer adds `iss` and `aud`, and its header has `alg` and `kid`
  and no `typ`), and
  `discovery_document(issuer, acr_values)`, which names the scopes
  `address` and `phone` and every standard claim among those supported,
  the revocation and introspection endpoints and their methods, the
  response types and modes of `ResponseType::ALL` and `ResponseMode::ALL`,
  `display_values_supported`, and the four `IdTokenAlgorithm`s as
  `id_token_signing_alg_values_supported` and
  `userinfo_signing_alg_values_supported`; `with_registration(document, open)`
  and `prompt_values_supported(open)` add `create` for a tenant open to
  registration. Its cases, with `every_claim`, a person with every standard
  claim that the claim mapper cases share, are in `openid/tests.rs`. It also
  has `PERSON_CLAIMS`, the nineteen claims of a person with the scope that
  covers each, in the order they are written; `scope_of_claim`;
  `person_claim(name, person)`, one claim's value as UserInfo writes it;
  `userinfo_claims_with(subject, scopes, asked, person)`, which adds the
  claims a grant was asked for UserInfo to those of the scopes;
  `PersonClaims::from_attributes`; and `claims_parameter_supported` true in
  discovery.
- `claims_parameter.rs`: the `claims` parameter (Decisions 0047 and 0068).
  `read_claims(text)` (at most `MAX_CLAIMS_BYTES`, 4096, and
  `MAX_CLAIMS_NAMED`, 64 claims across `id_token` and `userinfo`; a member
  or a claim of the wrong JSON type is refused with the description of
  `invalid_request`; unknown names, names with a language tag and `groups`
  ignored) into `ReadClaims { request, essential_acr, acr_with_values }`;
  `ClaimsRequest { id_token, userinfo, subject }`, the person's claims in
  the order of `PERSON_CLAIMS` and the `sub` asked with a value;
  `ClaimsRequest::given(scopes, consented) -> GrantClaims`, the claims a
  consented scope covers, none without `openid`; and `add_asked_claims(claims,
  asked, person, mapped)`, which adds the claims to an ID token within
  `MOST_MAPPED_BYTES`, the mappers' claims counting first, leaving out
  whole a claim that would cross it. Its cases are in
  `claims_parameter/tests.rs`.
- `introspection.rs`: revocation and introspection. `TokenQuery::parse`
  (`token` required, a parameter twice or more than one way of proving who
  the client is `invalid_request`, no client named `invalid_client`),
  `TokenTypeHint` (an unknown hint is ignored), `AccessTokenRecord` (with
  `issued`, `for_principal` and `exchanged_from`), the answers `inactive`,
  `active_access_token` (with `principal_kind`, `act` and `cnf` when the
  token has them) and
  `active_refresh_token` (`ActiveRefreshToken`), and `REVOKED_BY_CLIENT`.
  Its cases are at the bottom of the file.
- `refresh.rs`: refresh tokens. `RefreshFamily` (`start` from a redeemed
  code and the client's `TokenPolicy`, `decide`, `is_newest`, `revoke`,
  `started_event`, `first_record`, and `certificate`, the thumbprint a
  public client's family is bound to, with `bound_to` and
  `accepts_certificate`), `RefreshFamilyId`, `RefreshTokenHash`
  (`of_presented` answers `None` for a value without the shape of a token),
  `RefreshTokenValue`, `RefreshTokenRecord`, `FamilySecret` (`next_after`:
  the SHA-256 of the secret and the presented token, so the same token
  always leads to the same next one), `FamilyStatus`, `RefreshAsk`,
  `RefreshDecision` (`Move` or `Retry`), `RefreshRefusal` (with
  `revokes_the_family` and `revokes_the_grant`), and `OFFLINE_ACCESS`,
  `FAMILY_SECRET_PURPOSE`, `DEFAULT_RETRY_WINDOW`, `LONGEST_RETRY_WINDOW`.
  Its cases are in `refresh/tests.rs`.
- `logout.rs`: logout initiated by the relying party. `LogoutParameters`,
  `check_id_token_hint` (an ID token of the tenant, `typ` `JWT` and `alg`
  one of the four `IdTokenAlgorithm`s, signature checked, expiry not; `sub` and `sid` read as text), `IdTokenHint`, `check_shape`
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
  `Client::sector`. And the defaults for a sign-in (Issue-125), only with
  `authorization_code`: `default_max_age` 0 to 31 536 000
  (`oauth.client_default_max_age_invalid`), `default_acr_values` at most 10
  printable names without spaces, 255 characters joined
  (`oauth.client_default_acr_values_invalid`), and `require_auth_time`
  (`oauth.client_require_auth_time_invalid`); `Client::default_max_age`,
  `Client::default_acr_values` (joined by spaces). And `spiffe_id`, a `SpiffeId`, with `spiffe_jwt` and
  `spiffe_x509` (`AuthenticationMethod::uses_spiffe_id`), and
  `linkerd_identity`, a `LinkerdIdentity`, with `linkerd_identity`;
  `tls_client_auth` has exactly one of the two, every other method neither,
  and either needs a principal (`check_identities`:
  `oauth.client_spiffe_id_invalid` or
  `oauth.client_linkerd_identity_invalid`). And
  `certificate_bound_access_tokens`, refused with `linkerd_identity`
  (`oauth.client_certificate_bound_access_tokens_invalid`).
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
  `ConsentActor`, `ConsentAction`, `ConsentHistoryEntry`,
  `consented_scopes(request, standing, allowed, now)` (a first-party
  client's allowed scopes, or the request's and those of a consent that
  stands, for the `claims` parameter), and
  `DEFAULT_CONSENT_LIFETIME` (365 days), `SHORTEST_CONSENT_LIFETIME`,
  `LONGEST_CONSENT_LIFETIME` (1 and 730 days). `TokenPolicy::consent` is
  the client's lifetime, checked against those bounds. Its cases are in
  `consent/tests.rs`.
- `event.rs`: `OauthEvent`, thirty-four variants, each named `oauth.*`.
- `claim_mapper.rs`: claim mappers (Decision 0041). `ClaimMapperSettings`
  (`checked`: the claim written as a scope and not `is_reserved`, compared
  without regard to case against the 46 `RESERVED_CLAIMS`, the thirteen
  standard claims of a person among them; one to three distinct
  `ClaimTarget`s, put in their order; a scope the client may ask for; a
  constant but `null` of at most `MAX_CONSTANT_BYTES`) and its
  `worst_case`; `check_together` (at most `MAX_CLAIM_MAPPERS`, one per
  claim without regard to case, at most `MOST_MAPPED_BYTES` per target in
  the worst case: `oauth.claim_mappers_too_many`,
  `oauth.claim_mapper_name_taken`, `oauth.claim_mapper_token_too_large`);
  `ClaimMapper` (`create`, `replace`, `deleted`, with their events);
  `ClaimSource` (`to_json`, `from_json`, each kind's largest value);
  `PersonAttribute`, eighteen attributes of a person by their claim names:
  `display_name`, `username`, `email`, `email_verified`, `locale`, and the
  thirteen standard claims, each with its largest value as JSON writes it
  from the bounds `hodor-identity` exports (`LARGEST_ADDRESS` for the
  address, the object of its six parts at their longest);
  `PersonAttributes`, what a mapper reads of a person, the standard claims
  in `claims` and `updated_at`, which no mapper reads; `needs`, `mapped_claims` (by claim name, a value larger than
  its bound or more than 100 groups leaving the claim out, and
  `phone_number_verified` written only with a number) and `add_mapped_claims`,
  the one hook the token endpoint and UserInfo call after Hodor's own
  claims, which never replaces one. Its cases, including one that every
  claim Hodor writes is reserved, are in `claim_mapper/tests.rs`.
- `registration.rs`: the client registration settings of a tenant
  (Decision 0075). `RegistrationWay` (`initial_access_token`,
  `software_statement`, `open`); `RegistrationPolicy` (`checked`: grants
  among `authorization_code` and `refresh_token`, response types among
  the `ResponseType`s Hodor answers, 1 to 50 scopes, the methods of
  `REGISTERABLE_METHODS`, subject types, any host or 1 to 50 hosts by
  `is_policy_host`, each value once; `to_json`, `from_json`, left-out
  members at their defaults; `allows_address` by `host_of`);
  `check_registration`, the check of Issue-133, refusing with
  `oauth.registration_*_not_allowed`; `RegistrationSettings` (`checked`,
  `allows`, off by default); `ClientRegistration` (`create`, `replace`,
  with `oauth.client_registration_changed`). Its cases are in
  `registration/tests.rs`.
- `initial_access_token.rs`: initial access tokens. `hodor_iat_` and 64
  hexadecimal characters, kept as `InitialAccessTokenHash` with a hint of
  four; `InitialAccessToken` (`create`, checking the name, a lifetime of 1
  hour to 90 days and 1 to 1000 registrations; `status`, `revoke`,
  `spend`, every refusal `oauth.initial_access_token_invalid`).
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
