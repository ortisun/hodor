# hodor-protocol-http source

## Overview

The HTTP layer of Hodor, built on `axum`. It turns HTTP requests into calls
on the bounded contexts' use-case services and turns their results back
into responses. It owns what every route shares: resolving the tenant from
the URL, request identifiers, security headers, body limits, timeouts,
error documents and the health endpoints (`lib.rs` module documentation).

The crate never depends on an adapter. It reaches the outside world through
traits that the composition root implements: `TenantResolver` and
`ReadinessCheck` (`lib.rs`). All modules are private; the public surface is
the set of re-exports in `lib.rs`.

## Interface

### Public symbols

| Symbol | Source | What it is |
| --- | --- | --- |
| `public_router(resolver, tenant_routes, site_routes, limits)` | `server.rs` | Builds the router for the public listener. |
| `serve(listener, router, shutdown)` | `server.rs` | Serves with `ConnectInfo<SocketAddr>` until `shutdown` resolves, then stops accepting and waits for in-flight requests (`with_graceful_shutdown`). |
| `Limits` | `server.rs` | `max_body_bytes` (default 64 KiB), `max_saml_response_bytes` (default `2 * hodor_federation::api::MAX_SAML_POSTED_BYTES`), `max_policy_agent_report_bytes` (default 1 MiB), `max_scim_bulk_bytes` (default twice `hodor_provisioning::api::MAX_BULK_BYTES`, for `POST /t/{slug}/scim/v2/Bulk` only), `request_timeout` (default 30 seconds). |
| `ops_router(health)`, `Health`, `ReadinessCheck` | `health.rs` | Operations listener. `Health::new(checks)`, `begin_draining`, `is_draining`. `ReadinessCheck` has `name()` and `async check() -> Result<(), String>`. |
| `TenantResolver`, `ResolvedTenant`, `TenantSlug`, `TenantStatus` | `tenant.rs` | `TenantResolver::resolve(slug) -> Result<Option<ResolvedTenant>, DomainError>`. `ResolvedTenant` holds a `TenantContext` and a `TenantStatus` (`Active` or `Suspended`). `TenantSlug(pub String)` is the slug as it appears in the path. |
| `Problem` | `problem.rs` | Error response body, `application/problem+json`. `Problem::new(status, code, detail)`, `status()`, `impl From<DomainError>`, `impl IntoResponse`. |
| `ClientAddress(pub Option<IpAddr>)` | `request.rs` | The address of the connection, or the one a trusted proxy forwarded, inserted as a request extension. |
| `TrustedProxies`, `AddressRange`, `ForwardedHeader`, `parse_ranges`, `public_router_behind` | `client_address.rs`, `server.rs` | The proxies whose forwarded header is read (`HODOR_TRUSTED_PROXIES`) and that header (`HODOR_FORWARDED_HEADER`: `XForwardedFor`, `Forwarded`, or `None`, which reads no address). `TrustedProxies::with_identity_header(Option<IdentityHeader>)` names the header of the caller's identity those proxies write, and `identity_header()` answers it. `parse_gateways` reads `HODOR_GATEWAY_IDENTITIES` into `WorkloadIdentity` values, SPIFFE identifiers or Linkerd identities, refusing one that does not read with `InvalidGateway`; `TrustedProxies::with_gateways(identities, Arc<dyn CertificateCheck>)` reads the forwarded header only from a caller that is one of them, the check reading a forwarded certificate's names, and `gateways()` answers them. `Resolved::ignored` says why a forwarded header that was there was not read: `Ignored::NoIdentity` or `Ignored::NotAGateway`. |
| `IdentityHeader` | `forwarded_identity.rs` | `ClientCert` (`client-cert` with `client-cert-chain`, RFC 9440), `XForwardedClientCert` (Envoy) or `LinkerdClientId` (`l5d-client-id`), read with `FromStr` from `HODOR_CLIENT_IDENTITY_HEADER`; `as_str()`, `methods()`, the methods of client authentication it makes usable, and `forwards_certificates()`, whether tokens can be bound to what it forwards. The header is read only from a trusted proxy, and only its nearest element, the last: a structured byte sequence with every element of the chain; a pair list read by `Cert` and `Chain` (percent-encoded PEM, the certificate itself left out of the chain) or, without `Cert`, by `URI` and `DNS` and `Hash`, the certificate's SHA-256 in 64 hexadecimal digits (`CertificateThumbprint::from_hex`; one that does not read, or given twice, is left out); a lowercase DNS name. Certificates over 16 kibibytes, more than 10 in a chain and elements that do not read give no identity. |
| `interaction_routes(state)`, `InteractionState` | `interaction.rs` | The interaction interface: browser sign-in, sessions, registration and password recovery. |
| `authorization_routes(state)`, `AuthorizationState` | `authorize.rs` | The OAuth authorization endpoint: checks a request, its request object first when it has one (`AuthorizationCodeService::check` with the tenant's issuer), issues a code to a signed-in browser whose methods that count (`max_age`) reach the tenant level `acr_values` asks for, starts a step-up of the session when they do not (`AuthenticationService::start_step_up`, giving the browser the sign-in cookie; `unmet_authentication_requirements` when it cannot be reached), or keeps the request while the person signs in, sending them to `/account/sign-in?continue=authorization` with the request's `login_hint` and `ui_locales`, or for `prompt=create` to `/account/register?continue=authorization` with `ui_locales` (Issue-125). Once the request passes `check`, `prompt=create` is refused with `invalid_request` when the tenant's registration policy is closed, and `AuthorizationCodeService::check_hint` checks `id_token_hint`; both refusals are answered in the request's response mode. A session whose person `hint_names` does not name counts as none (`login_required` with `prompt=none`), and at the resume a person other than the hint's gets `login_required`. The code carries the `acr` of the tenant's levels the counted methods reach. `AuthorizationState { authorization: AuthorizationCodeService, sessions, authentication: AuthenticationService, tenants: TenantService, public_url }`. |
| `consent_routes(state)`, `ConsentState` | `consent.rs` | The consent routes of the interaction interface, merged with `interaction_routes` under `/interaction`, behind the origin check: `GET` and `POST /consent` (what the waiting request asks for, the answer; `404 oauth.consent_request_not_found` for any request that is not this browser's, this person's and this session's, or was answered), `GET /consents` and `DELETE /consents/{client_id}` (`404 oauth.consent_not_found`). The two that change something need the session's CSRF token. `ConsentState { consents, sessions, digest }`. |
| `token_routes(state)`, `TokenState` | `token.rs` | The OAuth token, revocation, introspection and pushed request endpoints (`/token`, `/revoke`, `/introspect`, `/par`): each reads the form and the `Basic` credentials, and answers what `TokenService` decides: tokens in the JSON of RFC 6749 (with `issued_token_type` for a token exchange, RFC 8693), an empty `200` for every revocation by a client that proved who it is (RFC 7009), the JSON of RFC 7662, and `201` with `request_uri` and `expires_in` (RFC 9126) for a pushed request, read with `PushedRequest::parse` and given the tenant's `pushed_policy` of its settings. Every answer carries `no-store`. The `ForwardedIdentity` extension of the request, when a trusted proxy forwarded one, is given to the token request (`TokenRequest::with_forwarded`), for the client a request names with its identifier alone and for binding tokens to its certificate, and to the client of a revocation or introspection (`PresentedClient::with_forwarded`). `TokenState { tokens: TokenService, tenants: TenantService, public_url }`. |
| `userinfo_routes(state)`, `UserInfoState` | `openid.rs` | UserInfo at `GET` and `POST /oauth2/userinfo`, mounted under a tenant: reads `Authorization: Bearer`, or `access_token` from a `POST` whose body is `application/x-www-form-urlencoded` (RFC 6750, section 2.2; Issue-125), never the query; both ways at once, or `access_token` twice, is `400` with `WWW-Authenticate: Bearer error="invalid_request"`. It answers what `UserInfoService::answer` decides, given the request's `ForwardedIdentity` for a bound token, however the token came: JSON or, for a client with a UserInfo algorithm, the signed answer as `application/jwt`, with `Cache-Control: no-store`; a refusal is `401` with `WWW-Authenticate: Bearer` (with `error="invalid_token"` when a token was sent) or `403` with `error="insufficient_scope"`. `UserInfoState { userinfo, public_url }`. |
| `logout_routes(state)`, `LogoutState` | `logout.rs` | The end-session endpoint at `GET` and `POST /oauth2/logout` and `GET /oauth2/logout/finish`, mounted under a tenant. A refused request is the page of `error_page` (status `400`), never a redirect. A `GET` whose hint names the browser's session revokes it (`relying_party_logout`) and forgets the cookie; otherwise, and always for a form, the checked return address is kept in `__Secure-hodor_logout` (`SameSite=Strict`, 600 seconds) and the browser goes to `/account/sign-out`. The finish sends a browser still signed in to `/account`, else to the return address checked again (`LogoutService::still_returns`) with `state`, else to `/account/sign-in?notice=signed-out`. Every answer is `Cache-Control: no-store`. `LogoutState { logout, sessions, public_url }`. |
| `discovery_routes(DiscoveryState { public_url, tenants, identity_header })` | `openid.rs` | `GET /.well-known/openid-configuration` and `GET /.well-known/oauth-authorization-server`, mounted under a tenant: the same `discovery_document`, naming the tenant's assurance levels in `acr_values_supported` and its `pushed_requests.required` as `require_pushed_authorization_requests`, through `with_registration` `create` in `prompt_values_supported` when the tenant's registration policy is open, and, when a header of the caller's identity is named, the methods it makes usable (`advertise_forwarded_methods`) and, for a header that forwards certificates, `tls_client_certificate_bound_access_tokens` (`advertise_certificate_bound_tokens`), with `Cache-Control: public, max-age=300` and `Access-Control-Allow-Origin: *`. |
| `authorization_api_routes(state)`, `AuthorizationApiState`, `AUTHORIZATION_API_AUDIENCE`, `EVALUATE_SCOPE`, `SIMULATE_SCOPE`, `EXPLAIN_SCOPE`, `AUTHORIZATION_OPENAPI`, `AUTHORIZATION_OPERATIONS` | `authorization_api.rs` | The Authorization API, mounted under a tenant at `/api/v1/authorization`: `POST /evaluate`, `/batch` (at most 100; a request that cannot be read is a problem object in its place) and `/simulate` (`against`: exactly one of `published: true`, `revision`, `draft`), and `GET /openapi.json` (`include_str!("../openapi/authorization-v1.json")`; a unit test holds it and `AUTHORIZATION_OPERATIONS` together). The caller comes from `ResourceAccessService::caller` with the audience `urn:hodor:authorization` and the request's `ForwardedIdentity`, or, for a value that `looks_like_api_key`, from `ApiKeyAccess` (the key good in the tenant, its holder a workload that may act, its application an enabled one of the tenant, whose resource server is asked about), then the route's scope; the namespace is the audience of the token client's application's resource server (`authorization.no_resource_server` when it has none) and the context's application is that application. A subject `{"type": "workload_identity", "id": …}` is resolved first by `resolve_workload`, through `ApplicationService::service_account_of`, to `{"type": "user"}` naming the service account the tenant's enabled clients bound to it act as, or the identity itself when none is bound; one that `WorkloadIdentity::parse` refuses is `authorization.workload_identity_invalid` (Decision 0058). Bodies are `deny_unknown_fields` (`request.body_invalid`). Answers name `decision` (`ALLOW`, `DENY`, `INDETERMINATE`), `decision_id`, `evaluated_at`, `engine`, `policy_version`, `reason`, and with `authz:explain` `matched_policies` and a simulation's `trace`; every answer carries `no-store`. `AuthorizationApiState { access, keys: ApiKeyAccess { keys, identity, applications }, evaluation, public_url }`. |
| `scim_routes(state)`, `ScimState { access, provisioning, public_url }`, `SCIM_AUDIENCE`, `SCIM_SCOPE`, `SCIM_MEDIA_TYPE` | `scim.rs` | The SCIM 2.0 server, mounted under a tenant at `/scim/v2`: `GET /ServiceProviderConfig`, `/ResourceTypes[/{name}]`, `/Schemas[/{uri}]`; `GET`, `POST /Users` and `/Groups`; `GET`, `PUT`, `PATCH`, `DELETE` of one user or group; `POST /Bulk`; `.search` answers `501`; any other path a SCIM `404`. Every route first takes the caller from `ResourceAccessService::caller` with the audience `urn:hodor:scim` and the request's `ForwardedIdentity` (in the handlers' `Context`), then needs the scope `scim`; refusals carry the challenge of `bearer::challenge` and a SCIM error. The caller is `Actor::Client`. Every change goes through `perform`, alone or as an operation of a bulk request, so both answer alike: `If-Match` (a bulk operation's `version`) is a `Precondition`; answers carry `ETag` from `meta.version` and `Location` on `201`; `GET` of one resource answers `304` when `If-None-Match` names its version. `bulk` refuses a body past `MAX_BULK_BYTES` or more than 100 operations with `413` `tooMany`, then does each operation in order in its own transaction, resolving `bulkId:` references against what earlier `POST`s created, and stops after `failOnErrors` failures. Bodies must be `application/scim+json` or `application/json` (`415` otherwise); answers are `application/scim+json` with `no-store`, errors in the schema of RFC 7644 (`status` as text, `scimType` from the provisioning codes, `uniqueness` for `identity.identifier_taken` and `identity.group_name_taken`, `412` without one for `provisioning.version_mismatch`). Path parameters are read with `RawPathParams`, since the tenant's is among them. |
| `ClaimsBody`, `AddressBody` (crate-visible) | `claims.rs` | A person's standard claims as the administration and interaction interfaces write them, every member optional and unknown members refused (`deny_unknown_fields`). `ClaimsBody::of(claims, person)` writes those with a value and `phone_number_verified`, and nothing for a workload; `into_claims` gives the identity context the claims unchecked, `phone_number_verified` false unless given. `Debug` prints no value. |
| `bearer`, `refused`, `challenge`, `not_cached` (crate-visible) | `bearer.rs` | The token of `Authorization: Bearer`; a refusal as `401` with `WWW-Authenticate: Bearer` (`error="invalid_token"` when a token was sent) or `403` with `error="insufficient_scope", scope="…"`, logged with the surface it came from; `Cache-Control: no-store`. Shared by UserInfo and the Authorization API. |
| `admin_routes(state)`, `AdminState`, `CERTIFICATE_AUTHORITY_AUDIENCE` | `admin.rs` | The administration interface, authenticated by bearer access token or by the API key of a workload (`by_token`: a value that `looks_like_api_key` goes to `AdminState.api_keys`, its holder must be `is_workload_that_may_act`, and the route's permission must be among the key's scopes as well as in the holder's roles); the signing of intermediates alone also by an access token of the token endpoint for `urn:hodor:certificate-authority` (`admin/certificate_authority.rs`). |
| `console_routes(state)`, `ConsoleState` | `admin.rs` | The same handlers for the admin console, authenticated by session cookie, plus `/me`. |
| `ADMIN_OPENAPI` | `admin.rs` | `include_str!("../openapi/admin-v1.json")`, served at `/openapi.json`. |
| `ADMIN_OPERATIONS` | `admin.rs` | Table of `(method, path as written in the OpenAPI document, Permission)`. Every shared handler looks its permission up here; the documentation says a test holds the table and the OpenAPI document together. |
| `CONSOLE_SESSION_HOURS` | `admin.rs` | `12`: the console stops answering this many hours after `signed_in_at`, whatever the tenant allows. |
| `authority_bundle_routes(authority: AuthorityService)` | `authority_bundle.rs` | `GET /certificate-authority/bundle`, mounted under a tenant only when the installation turns the authority on: the bundle of the tenant's active authority as kept, `content-type: application/json` and `Cache-Control: public, max-age=300`; `404` `keys.authority_not_found` without one. |
| `key_set_routes(keys: KeyService)` | `key_set.rs` | `GET /oauth2/jwks`, mounted under a tenant: first `KeyService::ensure_active` for each `IdTokenAlgorithm` (ES256, RS256, PS256, EdDSA), so that the set names the key of the next token; an Ed25519 key is written `kty` `OKP`, `crv` `Ed25519`, `x`; then the published key set as a JSON Web Key Set, with `Cache-Control: public, max-age=300` (`RotationPolicy::PUBLISHED_FOR`) and `Access-Control-Allow-Origin: *`. |
| `policy_agent_routes(bundles: BundleService)` | `policy_agent.rs` | Mounted at the root, for Open Policy Agent instances, each by its bearer credential: `GET /opa/bundles/{name}` (`application/gzip`, `ETag`, `304` for a matching `If-None-Match`, `Cache-Control: no-store`; `404 authorization.bundle_not_found` for anything the instance may not pull), `POST /opa/status` and `POST /opa/logs` (`204`; a body with `Content-Encoding: gzip` is expanded). A missing, unknown or disabled credential is `401` with `WWW-Authenticate: Bearer`. |
| `Pages` | `pages.rs` | A static application read from a directory: `load` (hosted pages), `load_console` (admin console), `page_routes`, `asset_routes`. |
| `PAGE_PATHS`, `PROVIDER_CALLBACK_PAGE`, `PAGE_ASSETS_PATH`, `CONSOLE_PATHS`, `CONSOLE_ASSETS_PATH`, `PAGES_CONTENT_SECURITY_POLICY` | `pages.rs` | Paths and the content security policy of the static applications. |

`InteractionState` holds `authentication: AuthenticationService`,
`accounts: AccountService` (both `hodor_authentication::api`),
`sessions: SessionService` (`hodor_session::api`),
`factors: FactorService` (`hodor_authentication::api`),
`external: Option<ExternalSignIn>` (`hodor_federation::api`; `None` means no
provider is offered), `digest: Arc<dyn Digest>` and `clock: Arc<dyn Clock>`
(`hodor_kernel`).

`AdminState` holds `tokens: AccessTokenService` (`hodor_credential`),
`authorization: AuthorizationService` (`hodor_authorization`),
`identity: IdentityService` (`hodor_identity`), `sessions: SessionService`,
`audit: AuditService` (`hodor_audit`),
`factors: FactorService` (`hodor_authentication`; what an administrator sees
and removes of a user's factors, `admin/factors.rs`),
`decisions: DecisionLog` (`hodor_authorization`; the record of decisions and
its settings, `admin/decisions.rs`),
`roles: RoleService` and `evaluation: EvaluationService` (`hodor_authorization`;
permissions, roles, assignments and bindings, `admin/authorization.rs`, a
resource server named in the path by its identifier and standing for its
audience), `access_lists: AccessListService` (`hodor_authorization`; the
entries of access control lists, `admin/access_lists.rs`, granted under a
resource server named by its identifier and read and removed by their own
identifier at `/access-entries/{entry_id}`; granting the same entry again
answers `200` with it instead of `201`; the principal is checked to be of
the tenant by `admin/authorization.rs:principal`), `policies: Option<PolicyService>` (`hodor_authorization_opa`; policy
versions drafted, checked, tested and simulated, and the publication status;
`None` answers `404` `authorization.policies_unavailable`; publishing is not a
route, since only the command line holds the key that signs bundles),
`trust_domains: TrustDomainService` (`hodor_keys`; the five operations of
`admin/trust_domains.rs`, `/trust-domains` and
`/trust-domains/{trust_domain_id}`, under `keys:read` and `keys:write`; a
bundle is taken and answered as JSON),
`authority: Option<AuthorityService>` (`hodor_keys`; the eight operations of
`admin/certificate_authority.rs`, `/certificate-authority`,
`/certificate-authority:install`, `/certificate-authority/intermediates`
and `/certificate-authority/intermediates/{intermediate_id}` with its
`:withdraw` action in the last segment, under `certificate-authority:read`,
`certificate-authority:write` and `certificate-authority:sign` (signing
alone); a refusal of a `keys.intermediate_` code,
`keys.authority_certificate_unsuitable`, `keys.authority_request_invalid` or
`keys.authority_trust_domain_invalid` that is `Invalid` or `Conflict` is
answered with the domain error's reason as the problem's `detail`
(`refused`), every other as `Problem::from`; merged into the routes only when it is
`Some`; when `None`, `GET /openapi.json` answers the document without those
operations and their schemas, and `/me` lists neither permission),
`certificate_signing: Option<ResourceAccessService>` (`hodor_oauth`; when
`Some`, and only on the administration interface, `POST
/certificate-authority/intermediates` takes a bearer that reads as a JSON
Web Token through `ResourceAccessService::caller` with the audience
`CERTIFICATE_AUTHORITY_AUDIENCE`, `urn:hodor:certificate-authority`, the
tenant's issuer and the request's `ForwardedIdentity`: refused `401`
`admin.not_authenticated` unless good and of a client whose
`principal_kind` is `service_account`, then `403` `admin.forbidden`
without the scope `certificate-authority:sign` or the permission in the
service account's roles, the service account read again and required
active; `signing_workload` holds the rule; the actor is
`Actor::User(service account)`),
`webhooks: Option<WebhookService>` (`hodor_webhooks`; endpoints,
subscriptions, secrets shown once with `Cache-Control: no-store`,
deliveries and delivering again, `admin/webhooks.rs`; `None` answers `503`
`webhooks.not_configured`, except `GET /webhook-event-types`),
`federation: Option<FederationService>` (`None` when the installation has no
keys to keep provider secrets with), `keys: Option<KeyService>`
(`hodor_keys`; `None` makes the key routes answer `503`
`keys.not_configured`), `key_rotation: RotationPolicy` (whose overlap a
rotation by hand uses), `applications: ApplicationService`,
`tenants: TenantService` (`hodor_tenant`, for the assurance levels) and
`public_url: String`.
`ConsoleState` holds an `AdminState` plus `digest` and `clock`.

### Routes

Routes as declared by `.route(...)`, `.nest(...)` and `.nest_service(...)`
calls. The mount points of the interaction, administration and console
routers are the ones their documentation comments name; the mounting itself
happens in the composition root, outside this crate.

`public_router` (`server.rs`): `.nest("/t/{tenant}", tenant_routes)`,
`.merge(site_routes)`, and a `route_not_found` fallback on both the tenant
routes and the whole router.

`ops_router` (`health.rs`), for the operations listener:

| Method | Path | Handler |
| --- | --- | --- |
| GET | `/livez` | `livez` |
| GET | `/readyz` | `readyz` |
| GET | `/startupz` | `startupz` |

`interaction_routes` (`interaction.rs`), documented mount point
`/t/{slug}/interaction`:

| Method | Path | Handler |
| --- | --- | --- |
| POST, GET, DELETE | `/sign-in` | `start_sign_in`, `describe_sign_in`, `cancel_sign_in` |
| POST | `/sign-in/steps/identifier` | `submit_identifier` |
| POST | `/sign-in/steps/password` | `submit_password` |
| POST | `/sign-in/steps/totp` | `submit_totp` (body `{ "code" }`) |
| POST | `/sign-in/steps/webauthn/options` | `webauthn_options` (the challenge of the WebAuthn step) |
| POST | `/sign-in/steps/webauthn` | `submit_webauthn` |
| POST | `/sign-in/steps/recovery_code` | `submit_recovery_code` (body `{ "code" }`), a substitute of the `webauthn` and `totp` steps |
| POST | `/sign-in/steps/passkey/options` | `passkey_options` (the challenge of the passkey alternative) |
| POST | `/sign-in/steps/passkey` | `submit_passkey` |
| GET | `/sign-in/alternatives` | `offered_alternatives` (`AuthenticationService::alternatives`; no sign-in needed) |
| POST | `/sign-in/steps/email_code/send`, `/sign-in/steps/email_link/send` | `ask_for_code`, `ask_for_link` (body `{ "email", "locale"? }`; the challenge of the email alternative, answered `202` `{ "status": "accepted" }`) |
| POST | `/sign-in/steps/email_code`, `/sign-in/steps/email_link` | `submit_email_code` (body `{ "code" }`), `submit_email_link` (body `{ "token" }`) |
| GET | `/sign-in/steps/enrollment/kinds` | `enrollment_kinds` (`FactorService::enrollable`, `{ "kinds": [...] }`; no sign-in needed) |
| POST | `/sign-in/steps/enrollment/options` | `begin_enrollment` (body `{ "kind" }`, `422` `request.invalid_body` for anything but `authenticator_application`, `security_key` or `passkey`; the challenge of the enrollment step, `200` with its options) |
| POST | `/sign-in/steps/enrollment` | `finish_enrollment` (body `{ "code" }`, or `{ "client_data", "attestation_object", "transports"?, "discoverable"?, "name"? }`; the answer of a sign-in, with `recovery_codes` once when a set was made) |
| GET, PUT | `/profile` | `profile::read_profile`, `profile::replace_profile` (`interaction/profile.rs`; body and answer `{ "display_name", "claims" }`, the PUT with the session's CSRF token; `AccountService::own_profile` and `change_own_profile`) |
| GET | `/sign-in/providers` | `offered_providers` |
| POST | `/sign-in/providers/{alias}` | `choose_provider` |
| POST | `/sign-in/providers/{alias}/callback` | `finish_with_provider` |
| POST | `/sign-in/providers/{alias}/password` | `sign_in_with_directory` (LDAP directory sign-in) |
| GET, DELETE | `/session` | `current_session`, `sign_out` |
| GET, DELETE | `/sessions` | `list_sessions`, `end_other_sessions` |
| DELETE | `/sessions/{session_id}` | `end_session` |
| POST | `/webauthn/registrations` | `begin_webauthn_registration` (session and CSRF token; `{ "passkey": true }` asks for a passkey) |
| POST | `/webauthn/registrations/{registration_id}` | `finish_webauthn_registration` (session and CSRF token) |
| POST | `/registration` | `request_registration` |
| POST | `/registration/complete` | `complete_registration` |
| POST | `/recovery` | `request_recovery` |
| POST | `/recovery/complete` | `reset_password` |
| POST | `/sign-in/providers/{alias}/saml` | `receive_saml_response` (SAML assertion consumer; outside the origin check) |
| GET | `/sign-in/providers/{alias}/saml/metadata` | `saml_metadata` (`application/samlmetadata+xml`) |

`authorization_routes` (`authorize.rs`), documented mount point
`/t/{slug}/oauth2`:

| Method | Path | Handler |
| --- | --- | --- |
| GET | `/authorize` | `authorize_by_query` |
| POST | `/authorize` | `authorize_by_form` (only `application/x-www-form-urlencoded`; otherwise the page `oauth.authorization_form_expected`) |
| GET | `/authorize/resume` | `resume` (takes the pending request of the `__Secure-hodor_authorization` cookie once, and removes the cookie unless it keeps the request again to ask for consent) |

A request whose client or redirect address is not trusted gets Hodor's own
HTML page with status `400` and the reason's code (`error_page`). Every
answer to the client, a code or an error, goes through `answer_at(uri,
mode, parameters)`, in the request's `response_mode` (an error in its
`AuthorizationError::mode`): `Query` is a `302` with the parameters added
to the address's query (`redirect_to`, which logout uses too, is
`answer_at` in the query); `FormPost` is the page of
`form_post::form_post_page`. Every other answer is a `302`. The issuer sent as `iss` is
`{public_url}/t/{slug}`. The cookie `__Secure-hodor_authorization` is
`Path=/t/{slug}`, `SameSite=Strict`, ten minutes; a completed sign-in of
the interaction interface adds `"continue":
"/t/{slug}/oauth2/authorize/resume"` to its answer while the browser
holds it (`authorize::waiting`). When the session is enough, `proceed`
asks `ConsentService::must_ask`: a request that must ask is kept with
`ConsentService::hold` and the browser sent to `/account/consent` (with
`ui_locales`), or answered `consent_required` with `prompt=none`. A request
that waited for consent is answered by its answer at `resume`, for the
session it was asked in; any other session, or no answer, is
`access_denied`.

The page of `form_post` (`form_post.rs`, crate-visible
`form_post_page(uri, parameters)`, `SUBMIT_SCRIPT`,
`FORM_POST_CONTENT_SECURITY_POLICY`): status `200`, one form posting to
`uri`, one hidden field per parameter, every name, value and the address
written with `&`, `<`, `>`, `"` and `'` as character references, a
sentence and a button without a name in the form (not in `noscript`, so a
browser that did not run the script can still go on), and the one script
`document.forms[0].submit();`. Headers: `Content-Type: text/html;
charset=utf-8`, `Cache-Control: no-store`, `Pragma: no-cache`,
`Referrer-Policy: no-referrer`, and the policy `default-src 'none';
script-src 'sha256-…'` (the hash of `SUBMIT_SCRIPT`, which a unit test
recomputes), `base-uri 'none'; frame-ancestors 'none';
require-trusted-types-for 'script'; trusted-types 'none'`, without
`form-action`, which browsers check again at the redirects after the post.

`token_routes` (`token.rs`), merged with `authorization_routes` under the
same mount point `/t/{slug}/oauth2`:

| Method | Path | Handler |
| --- | --- | --- |
| POST | `/token` | `token` (only `application/x-www-form-urlencoded`, otherwise `invalid_request`; any other method is `405`) |
| POST | `/revoke` | `revoke` (the same form rules; `200` with an empty body for every token once the client proved who it is) |
| POST | `/introspect` | `introspect` (the same form rules; the JSON `TokenService::introspect` answers) |

`Authorization: Basic` is base64 of the form-encoded identifier and secret
(`basic_credentials`, `form_decoded`); a malformed one is `invalid_client`,
another scheme `invalid_request`. `invalid_client` is `401`, with
`WWW-Authenticate: Basic realm="{issuer}"` when `Basic` was used;
`server_error` and a failure of storage or signing are `500`; every other
refusal is `400`. Every answer carries `Cache-Control: no-store` and
`Pragma: no-cache`. The reason of a refusal is logged at `info`, never
sent. The issuer is `{public_url}/t/{slug}` and the token endpoint
`{issuer}/oauth2/token`.

Administration and console handlers, shared by both routers
(`admin.rs:shared_routes`):

| Method | Path | Handler |
| --- | --- | --- |
| GET, POST | `/users` | `list_users`, `create_user` |
| GET, POST | `/users/{user}` | `get_user`, `user_action` (`POST /users/{user_id}:suspend` arrives here) |
| PUT | `/users/{user}/claims` | `replace_user_claims` (a `ClaimsBody`; `IdentityService::change_claims`, answering the user) |
| GET | `/users/{user}/sessions` | `list_user_sessions` |
| DELETE | `/sessions/{session}` | `revoke_session` |
| GET | `/audit-records` | `list_audit_records` |
| GET, POST | `/identity-providers` | `list_providers`, `create_provider` |
| GET, PATCH, POST | `/identity-providers/{provider}` | `get_provider`, `change_provider`, `provider_action` (`:disable` and `:enable` arrive here) |
| PUT | `/identity-providers/{provider}/client-secret` | `change_provider_secret` |
| GET, POST | `/keys/{key_set}` | `list_key_versions`, `key_set_action` (`POST /keys/{key_set}:rotate` arrives here) |
| POST | `/keys/{key_set}/versions/{version}` | `key_version_action` (`:revoke` arrives here) |
| GET, POST | `/trust-domains` | `trust_domains::list_trust_domains`, `add_trust_domain` (`admin/trust_domains.rs`) |
| GET, PUT, DELETE | `/trust-domains/{trust_domain}` | `get_trust_domain`, `replace_trust_domain` (the name cannot be given), `remove_trust_domain` |
| GET, PUT | `/assurance-levels` | `read_assurance_levels`, `replace_assurance_levels` (`{ "levels": [{ "acr", "requirement" }] }`, weakest first; `tenant.settings_invalid` for levels that break a rule) |
| GET, POST | `/applications` | `applications::list_applications`, `create_application` |
| GET, PATCH, POST | `/applications/{application}` | `get_application`, `change_application`, `application_action` (`:disable` and `:enable` arrive here) |
| GET, POST | `/applications/{application}/clients` | `list_clients`, `create_client` |
| GET, PATCH, POST | `/clients/{client}` | `get_client`, `change_client`, `client_action` (`:disable` and `:enable` arrive here) |
| POST | `/clients/{client}/secrets` | `rotate_secret` (an empty body is `{}`) |
| DELETE | `/clients/{client}/secrets/{secret}` | `revoke_secret` |
| POST | `/clients/{client}/keys` | `add_key` |
| DELETE | `/clients/{client}/keys/{key}` | `remove_key` (the `kid`, percent-decoded) |
| GET, POST | `/clients/{client}/claim-mappers` | `list_mappers`, `create_mapper` (`admin/claim_mappers.rs`) |
| GET, PUT, DELETE | `/clients/{client}/claim-mappers/{mapper}` | `get_mapper`, `replace_mapper`, `delete_mapper` |
| GET, PUT | `/client-registration` | `read_settings`, `replace_settings` (`admin/client_registration.rs`) |
| GET, POST | `/client-registration/initial-access-tokens` | `list_tokens`, `create_token` |
| GET, DELETE | `/client-registration/initial-access-tokens/{token}` | `get_token`, `revoke_token` |
| GET, POST | `/resource-servers` | `list_resource_servers`, `create_resource_server` |
| GET, PATCH | `/resource-servers/{resource_server}` | `get_resource_server`, `change_resource_server` |

The application routes live in `admin/applications.rs` and are merged into
`shared_routes`; they need `ApplicationService` in `AdminState.applications`.
A client's `principal` is checked there through `AdminState.identity`
(`principal_of`, which also asks for an agent when the grants hold token exchange, and for a service account when the method is `spiffe_jwt`, the kept principal included on `PATCH`): a service account or an agent of the tenant that is not
Deleted, otherwise `422` `oauth.client_principal_invalid`; `PATCH` tells a
`principal` left out from one given as `null`, which removes it. A client's
`spiffe_id` is read with `SpiffeId::parse` (`422`
`oauth.client_spiffe_id_invalid`), answered as text or `null`, and on
`PATCH` left out, `null` (removed) or replaced alike.

`create_user` takes `email` and, optionally, `username`, `display_name`
and `locale`; a username becomes a second login identifier. A user's answer
(`UserBody`) carries `claims`, a `ClaimsBody`, empty for a workload. The
settings of a directory and of a SAML identity provider (`DirectoryBody`,
`SamlBody`) carry `claim_attributes`, a map from a standard claim to an
attribute name; left out of a change, the provider's map is kept.

`GET` and `PUT /pushed-authorization-requests` (`read_pushed_requests`,
`set_pushed_requests` in `admin.rs`, `applications:read` and
`applications:write`) read and replace the tenant's `pushed_requests` as
`{ "lifetime_seconds", "required" }`, both required and nothing else
(`422` `request.body_invalid`); a life outside 10 to 600 is
`tenant.settings_invalid`. Clients carry
`require_pushed_authorization_requests`, `false` unless given.

`GET` and `PUT /email-sign-in` (`read_email_sign_in`, `set_email_sign_in`
in `admin.rs`, `users:read` and `users:write`) read and replace the
tenant's `authentication.email_sign_in` as `{ "code", "link" }`, both
required and nothing else (`422` `request.body_invalid`).

The claim mapper routes live in `admin/claim_mappers.rs`, merged into
`shared_routes`, under the permissions of clients, and need
`ClaimMapperService` in `AdminState.claim_mappers`. A `group_member`
source's group is checked through `AdminState.groups`; another tenant's
group, or none, is `422` `oauth.claim_mapper_group_unknown`.

Client registration lives in `admin/client_registration.rs`, merged into
`shared_routes`, under `applications:read` and `applications:write`, and
needs `ClientRegistrationService` in `AdminState.client_registration`.
`PUT /client-registration` takes `enabled` and, each at its default when
left out, `application_id`, `ways`, `max_clients` and `policy` (read by
`RegistrationPolicy::from_json`); a token is answered with its hint after
an ellipsis and its status at `ClientRegistrationService::now`, and
`initial_access_token` only in the `201` that made it; `lifetime_hours` is
held far from overflow before the domain refuses it.

Service accounts and agents live in `admin/workloads.rs`, merged into
`shared_routes`, and need `WorkloadService` in `AdminState.workloads`. One
set of handlers serves both collections, `/service-accounts` and `/agents`,
each a `Collection` naming its `UserKind` and the paths its operations are
written under in `ADMIN_OPERATIONS` (`workloads:read`, `workloads:write`);
the routes are closures over the collection. `:disable` and `:enable` arrive
at the item's `POST`; any other action is authorized as `:disable` before it
is answered `route.not_found`. A workload's API keys are served there too, under `…/api-keys`, with `AdminState.api_keys` (`ApiKeyService`): the scopes checked by `hodor_authorization::api::check_key_scopes`, an application checked through `AdminState.applications`, the key itself written once in `MadeKeyBody` (no `Debug`), `:rotate` arriving at a key's `POST`.
A client's secret is written only by `create_client` (`client_secret` in
`CreatedClientBody`) and `rotate_secret` (`NewSecretBody`); neither type is
`Debug`, and `ClientBody` names secrets by identifier and expiry only.

`admin_routes` (documented mount point `/t/{slug}/api/v1/admin`) adds
`GET /openapi.json` (`openapi`, no authentication). `console_routes`
(documented mount point `/t/{slug}/console/api`) adds `GET /me` (`me`).

`Pages::page_routes` answers `GET` with the in-memory `index.html` on every
path of `PAGE_PATHS` plus `PROVIDER_CALLBACK_PAGE` (hosted pages) or of
`CONSOLE_PATHS` (console), to be mounted under `/t/{slug}`.
`Pages::asset_routes` serves the `assets` directory with
`.nest_service(PAGE_ASSETS_PATH | CONSOLE_ASSETS_PATH, ServeDir)`, at the
root, outside any tenant.

## Invariants

### Tenant resolution (`tenant.rs`)

- The tenant comes only from the path prefix `/t/{slug}`, never from a
  header, query parameter or body (module documentation). `resolve_tenant`
  reads the slug from `OriginalUri`.
- A slug must be 2 to 63 characters of lowercase letters, digits and
  hyphens, starting with a letter or digit (`is_valid_slug`); anything else
  is refused without a lookup.
- Malformed, unknown and absent slugs get the same `404 tenant.not_found`,
  so tenant names cannot be probed. A `Suspended` tenant gets
  `403 tenant.suspended`. For an `Active` tenant, `TenantContext` and
  `TenantSlug` are inserted as request extensions and the tenant identifier
  is recorded on the tracing span.

### Request context and limits (`request.rs`, `server.rs`)

- `request_context` is the outermost layer, so every response, including
  those from inner layers, carries `x-request-id` and the security headers.
  The request identifier is always generated by the server; client-sent
  identifiers are ignored. Only the path is logged, never the query string.
- Security headers added when a response does not set them:
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`,
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`,
  `Cache-Control: no-store`,
  `Strict-Transport-Security: max-age=63072000; includeSubDomains`
  (`SECURITY_HEADERS`).
- The caller's identity is read first, from the one header the operator
  named, only when the connection is from a trusted proxy, and is inserted
  as a `hodor_oauth::api::ForwardedIdentity` extension. A header that does
  not read inserts nothing and is counted by
  `hodor.http.forwarded_identity.unreadable`, by `header`.
- `ClientAddress` is the connection's address, or the address a trusted
  proxy forwarded (`TrustedProxies::resolve_with`, given the identity just
  read). With ingress gateways named, the forwarded header is read only
  when that identity is one of them; otherwise a header that was there is
  counted by `hodor.http.forwarded_address.ignored`, by `reason`.
- `limit_bodies` refuses a body over the limit with
  `413 request.body_too_large`, whether or not it declares its length.
  `POST /t/.../interaction/sign-in/providers/.../saml` gets
  `max_saml_response_bytes` (`posts_a_saml_response`); `POST /opa/status`
  and `POST /opa/logs` get `max_policy_agent_report_bytes`, 1 mebibyte
  (`posts_a_policy_agent_report`); every other request gets
  `max_body_bytes`. Requests longer than `request_timeout` get 408
  (`TimeoutLayer`).
- Unknown routes get `404 route.not_found` (`route_not_found`).

### Error documents (`problem.rs`)

- `DomainError` kinds map to statuses: `NotFound` 404, `Conflict` 409,
  `Invalid` 422, `Forbidden` 403, `Unauthenticated` 401, `RateLimited` 429,
  `Unavailable` 503, anything else 500.
- For 500, the caller gets the generic detail "the request could not be
  completed"; server errors are logged with code, message and detail.
- `type` is `urn:hodor:error:{code}`; the body carries the current
  request identifier; `retry_after_seconds` is sent as `Retry-After`.

### Interaction interface (`interaction.rs`)

- Handlers translate between HTTP and the authentication context and
  "decide nothing about a sign-in themselves" (module documentation).
- Cookies: `__Secure-hodor_signin` holds `{transaction_id}.{secret}`, with
  `Path=/t/{slug}/interaction; Max-Age=600; HttpOnly; Secure; SameSite=Strict`,
  and is cleared when a sign-in fails, completes or is cancelled.
  `__Secure-hodor_session` holds the session token, with
  `Path=/t/{slug}; HttpOnly; Secure; SameSite=Lax` and a `Max-Age` equal to
  the time left until the session's absolute expiry; it is set when a
  sign-in completes and cleared on sign-out or when the current session is
  ended.
- Cross-site request forgery: the token is the hexadecimal SHA-256 of
  `csrf:` followed by the sign-in secret or the session token
  (`csrf_token`). It must be sent in the `x-csrf-token` header on step
  submissions, provider choice, cancellation, sign-out and ending sessions,
  and is compared in constant time (`same`). A wrong or missing token gets
  `403 request.csrf_token_invalid`.
- `/profile` answers only a signed-in person (`401 session.not_authenticated`
  otherwise); its `PUT` needs the CSRF token and reads the body only once
  the person is known, `422 request.invalid_body` for one that cannot be
  read. The rules of the claims are the identity context's
  (`identity.claim_invalid`), and the person cannot vouch for a telephone
  number.
- `refuse_other_origins` refuses any request other than GET, HEAD or OPTIONS
  whose `Origin` host differs from `Host`, with `403 request.cross_origin`.
  It is layered over every interaction route except the two SAML routes,
  which are added after the layer; the code comment says another site must
  be able to post to the assertion consumer. The console router applies the
  same layer (`admin.rs:console_routes`).
- A missing, malformed or wrong sign-in cookie gets the same answer as an
  unknown sign-in (`no_sign_in`). Any session failure gets one
  `401 session.not_authenticated` (`not_authenticated`).
- `choose_provider` starts a provider sign-in only for a sign-in that is
  still pending or rejected; otherwise `409 authentication.transaction_not_active`.
- `receive_saml_response` keeps the response unread through
  `ExternalSignIn::keep_saml_response` only when the relay state is a plain
  token of 1 to 80 letters, digits, `-` or `_` (`is_plain_token`) and the
  alias parses, then always answers `303` to
  `/t/{slug}/account/providers/{alias}/callback?binding=saml`, adding
  `state` and `receipt` when a response was kept.
- Registration and recovery requests answer `202 {"status":"accepted"}`
  whether or not the address has an account (`accepted`).

### Administration and console interfaces (`admin.rs`)

- Every shared handler calls `authorize` before reading the body or the
  query, so a refused request learns nothing about what it asked for. An
  operation missing from `ADMIN_OPERATIONS` is refused with
  `403 admin.forbidden`; otherwise `AuthorizationService::check` must allow
  the operation's `Permission`.
- Administration callers present `Authorization: Bearer <token>`, checked by
  `AccessTokenService::authenticate`; the user must exist and pass
  `may_sign_in()`. Every failure gets one `401 admin.not_authenticated` with
  `WWW-Authenticate: Bearer`.
- Console callers are recognized by the `__Secure-hodor_session` cookie
  through `SessionService::find_by_token`, refused once `CONSOLE_SESSION_HOURS`
  have passed since `signed_in_at`, and must send the session's
  `x-csrf-token` on every method other than GET. Failures get
  `401 console.not_authenticated` or `403 request.csrf_token_invalid`.
- Page requests take `limit` from 1 to `PageRequest::MAX_LIMIT`, else
  `422 request.query_invalid`. Bodies that do not deserialize get
  `422 request.body_invalid`; the provider bodies reject unknown fields.
- Provider routes answer `503 federation.not_configured` when
  `AdminState.federation` is `None`. Provider responses never include the
  client secret.

### Health (`health.rs`)

- Each readiness check has 2 seconds (`CHECK_TIMEOUT`); a check that does
  not answer counts as failed. Only hard dependencies belong in
  `ReadinessCheck` (documentation names the database).
- `/livez` always answers `200 {"status":"ok"}`. `/readyz` fails with
  `503 {"status":"unavailable","failed":[...]}` while draining or when a
  check fails. `/startupz` reports the checks without the draining flag.

### Static applications (`pages.rs`)

- One `index.html`, read once at startup, answers every page of every
  tenant with `PAGES_CONTENT_SECURITY_POLICY` and `Cache-Control: no-cache`.
- Assets get `Cache-Control: public, max-age=31536000, immutable`;
  directories are never listed, and anything that is not a file gets
  `404 route.not_found` (`asset_answer`).

## Side Effects

- Network: `serve` accepts connections on the given `TcpListener`.
- Logging: a `tracing` span per request (`http.request`); error logs for
  server errors (`problem.rs`) and warnings for failed readiness checks
  (`health.rs`).
- Disk: `Pages::load` and `Pages::load_console` read `index.html`;
  `asset_routes` serves files from the `assets` directory.
- Cookies: the sign-in and session cookies set and cleared by
  `interaction.rs`. The console only reads the session cookie.
- State changes happen only through the domain services the handlers call:
  sign-in steps, sessions revoked (`sign_out`, `ended_by_user`,
  `revoked_by_administrator`), registration, recovery, a person's own
  profile, user creation, suspension and standard claims, and identity provider creation, change, secret change and
  status change. Each authenticated or anonymous `Caller` carries a freshly
  generated `CorrelationId`.

## Verification

- Run: `cargo test -p hodor-protocol-http` (one test file needs Docker; see
  [the crate contract](../EGM.md)).
