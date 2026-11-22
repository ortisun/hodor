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
| `Limits` | `server.rs` | `max_body_bytes` (default 64 KiB), `max_saml_response_bytes` (default `2 * hodor_federation::api::MAX_SAML_POSTED_BYTES`), `request_timeout` (default 30 seconds). |
| `ops_router(health)`, `Health`, `ReadinessCheck` | `health.rs` | Operations listener. `Health::new(checks)`, `begin_draining`, `is_draining`. `ReadinessCheck` has `name()` and `async check() -> Result<(), String>`. |
| `TenantResolver`, `ResolvedTenant`, `TenantSlug`, `TenantStatus` | `tenant.rs` | `TenantResolver::resolve(slug) -> Result<Option<ResolvedTenant>, DomainError>`. `ResolvedTenant` holds a `TenantContext` and a `TenantStatus` (`Active` or `Suspended`). `TenantSlug(pub String)` is the slug as it appears in the path. |
| `Problem` | `problem.rs` | Error response body, `application/problem+json`. `Problem::new(status, code, detail)`, `status()`, `impl From<DomainError>`, `impl IntoResponse`. |
| `ClientAddress(pub Option<IpAddr>)` | `request.rs` | The address of the connection, inserted as a request extension. |
| `interaction_routes(state)`, `InteractionState` | `interaction.rs` | The interaction interface: browser sign-in, sessions, registration and password recovery. |
| `admin_routes(state)`, `AdminState` | `admin.rs` | The administration interface, authenticated by bearer access token. |
| `console_routes(state)`, `ConsoleState` | `admin.rs` | The same handlers for the admin console, authenticated by session cookie, plus `/me`. |
| `ADMIN_OPENAPI` | `admin.rs` | `include_str!("../openapi/admin-v1.json")`, served at `/openapi.json`. |
| `ADMIN_OPERATIONS` | `admin.rs` | Table of `(method, path as written in the OpenAPI document, Permission)`. Every shared handler looks its permission up here; the documentation says a test holds the table and the OpenAPI document together. |
| `CONSOLE_SESSION_HOURS` | `admin.rs` | `12`: the console stops answering this many hours after `signed_in_at`, whatever the tenant allows. |
| `Pages` | `pages.rs` | A static application read from a directory: `load` (hosted pages), `load_console` (admin console), `page_routes`, `asset_routes`. |
| `PAGE_PATHS`, `PROVIDER_CALLBACK_PAGE`, `PAGE_ASSETS_PATH`, `CONSOLE_PATHS`, `CONSOLE_ASSETS_PATH`, `PAGES_CONTENT_SECURITY_POLICY` | `pages.rs` | Paths and the content security policy of the static applications. |

`InteractionState` holds `authentication: AuthenticationService`,
`accounts: AccountService` (both `hodor_authentication::api`),
`sessions: SessionService` (`hodor_session::api`),
`external: Option<ExternalSignIn>` (`hodor_federation::api`; `None` means no
provider is offered), `digest: Arc<dyn Digest>` and `clock: Arc<dyn Clock>`
(`hodor_kernel`).

`AdminState` holds `tokens: AccessTokenService` (`hodor_credential`),
`authorization: AuthorizationService` (`hodor_authorization`),
`identity: IdentityService` (`hodor_identity`), `sessions: SessionService`,
`audit: AuditService` (`hodor_audit`),
`federation: Option<FederationService>` (`None` when the installation has no
keys to keep provider secrets with) and `public_url: String`.
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
| GET | `/sign-in/providers` | `offered_providers` |
| POST | `/sign-in/providers/{alias}` | `choose_provider` |
| POST | `/sign-in/providers/{alias}/callback` | `finish_with_provider` |
| POST | `/sign-in/providers/{alias}/password` | `sign_in_with_directory` (LDAP directory sign-in) |
| GET, DELETE | `/session` | `current_session`, `sign_out` |
| GET, DELETE | `/sessions` | `list_sessions`, `end_other_sessions` |
| DELETE | `/sessions/{session_id}` | `end_session` |
| POST | `/registration` | `request_registration` |
| POST | `/registration/complete` | `complete_registration` |
| POST | `/recovery` | `request_recovery` |
| POST | `/recovery/complete` | `reset_password` |
| POST | `/sign-in/providers/{alias}/saml` | `receive_saml_response` (SAML assertion consumer; outside the origin check) |
| GET | `/sign-in/providers/{alias}/saml/metadata` | `saml_metadata` (`application/samlmetadata+xml`) |

Administration and console handlers, shared by both routers
(`admin.rs:shared_routes`):

| Method | Path | Handler |
| --- | --- | --- |
| GET, POST | `/users` | `list_users`, `create_user` |
| GET, POST | `/users/{user}` | `get_user`, `user_action` (`POST /users/{user_id}:suspend` arrives here) |
| GET | `/users/{user}/sessions` | `list_user_sessions` |
| DELETE | `/sessions/{session}` | `revoke_session` |
| GET | `/audit-records` | `list_audit_records` |
| GET, POST | `/identity-providers` | `list_providers`, `create_provider` |
| GET, PATCH, POST | `/identity-providers/{provider}` | `get_provider`, `change_provider`, `provider_action` (`:disable` and `:enable` arrive here) |
| PUT | `/identity-providers/{provider}/client-secret` | `change_provider_secret` |

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
- `ClientAddress` is the connection's address. The documentation says that
  behind a load balancer it is the balancer's address; trusting forwarded
  addresses is not built yet.
- `limit_bodies` refuses a body over the limit with
  `413 request.body_too_large`, whether or not it declares its length.
  `POST /t/.../interaction/sign-in/providers/.../saml` gets
  `max_saml_response_bytes`; every other request gets `max_body_bytes`
  (`posts_a_saml_response`). Requests longer than `request_timeout` get 408
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
  `revoked_by_administrator`), registration, recovery, user creation and
  suspension, and identity provider creation, change, secret change and
  status change. Each authenticated or anonymous `Caller` carries a freshly
  generated `CorrelationId`.

## Verification

- Run: `cargo test -p hodor-protocol-http` (one test file needs Docker; see
  [the crate contract](../EGM.md)).
