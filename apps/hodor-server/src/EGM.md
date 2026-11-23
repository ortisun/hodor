# hodor-server source

## Overview

The HTTP composition root, in one file, `main.rs`. It parses the
configuration (`Config`), starts telemetry, opens one PostgreSQL pool as the
application role, wires the domain services to their PostgreSQL, crypto,
HTTP and LDAP adapters, and serves two listeners: the public router and the
operations router. Routing itself lives in `hodor_protocol_http`; this file
only nests and merges the routers that crate builds.

## Interface

Configuration (`Config`, clap, command name `hodor-server`):

| Flag | Environment variable | Default |
| --- | --- | --- |
| `--listen-addr` | `HODOR_LISTEN_ADDR` | `0.0.0.0:8080` |
| `--ops-addr` | `HODOR_OPS_ADDR` | `127.0.0.1:9090` |
| `--database-url` | `HODOR_DATABASE_URL` | required |
| `--database-max-connections` | `HODOR_DATABASE_MAX_CONNECTIONS` | 10 |
| `--log-format` (`json`, `pretty`) | `HODOR_LOG_FORMAT` | `json` |
| `--log-filter` | `HODOR_LOG_FILTER` | `info` |
| `--otlp-traces-endpoint` | `HODOR_OTLP_TRACES_ENDPOINT` | unset: no export |
| `--otlp-metrics-endpoint` | `HODOR_OTLP_METRICS_ENDPOINT` | unset: no export |
| `--shutdown-drain-seconds` | `HODOR_SHUTDOWN_DRAIN_SECONDS` | 5 |
| `--public-url` | `HODOR_PUBLIC_URL` | `http://localhost:8080` |
| `--pages-directory` | `HODOR_PAGES_DIRECTORY` | unset |
| `--console-directory` | `HODOR_CONSOLE_DIRECTORY` | unset |
| `--secret-keys` | `HODOR_SECRET_KEYS` | unset |
| `--key-overlap-hours` | `HODOR_KEY_OVERLAP_HOURS` | 24 |
| `--refresh-retry-seconds` | `HODOR_REFRESH_RETRY_SECONDS` | 10, checked by `TokenService::with_retry_window` (0 to 60) |
| `--outbound-development-hosts` | `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` | empty, comma separated |
| `--open-policy-agent-address` | `HODOR_OPEN_POLICY_AGENT_ADDRESS` | unset |
| `--open-policy-agent-tenant-addresses` | `HODOR_OPEN_POLICY_AGENT_TENANT_ADDRESSES` | empty, comma separated `tenant-identifier=origin` |
| `--open-policy-agent-token` | `HODOR_OPEN_POLICY_AGENT_TOKEN` | unset; its value is hidden from the help text |
| `--directory-hosts` | `HODOR_DIRECTORY_HOSTS` | empty, comma separated `host:port` |
| `--password-hash-memory-kibibytes` | `HODOR_PASSWORD_HASH_MEMORY_KIBIBYTES` | `19 * 1024` |
| `--password-hash-passes` | `HODOR_PASSWORD_HASH_PASSES` | 2 |
| `--password-hash-lanes` | `HODOR_PASSWORD_HASH_LANES` | 1 |
| `--password-hash-concurrency` | `HODOR_PASSWORD_HASH_CONCURRENCY` | `HashingLimits::for_this_machine()` |
| `--password-hash-queue` | `HODOR_PASSWORD_HASH_QUEUE` | four times the concurrency |

Routers, as assembled in `run`:

- `/interaction` nests `hodor_protocol_http::interaction_routes` with the
  `InteractionState` built by `interaction`.
- `/api/v1/admin` nests `hodor_protocol_http::admin_routes` with the
  `AdminState` built by `administration`.
- `/console/api` nests `hodor_protocol_http::console_routes`.
- `/oauth2/jwks`: `hodor_protocol_http::key_set_routes(KeyService)` is merged
  into the tenant routes when `keys` built a `KeyService` (`PgKeyStore`,
  `LocalKeyProvider` over `HODOR_SECRET_KEYS`); otherwise a warning is logged
  and the address is not served.
- `/opa/…`: `hodor_protocol_http::policy_agent_routes(BundleService)` is
  merged into the site routes, with `PgInstanceStore`, `PgBundleStore`,
  `PgInstanceStatusStore` and `PgUploadedDecisionStore`. The server never
  holds the key that signs bundles: it serves them as published.
- Hosted pages and the console come from `Pages::load` and
  `Pages::load_console`, merged through `page_routes` and `asset_routes`.
- The public router is `hodor_protocol_http::public_router`; the operations
  router is `hodor_protocol_http::ops_router(Health)`. Both are served with
  `hodor_protocol_http::serve`. No other path string appears in `main.rs`.

Adapters implemented here:

- `DirectoryResolver` implements `hodor_protocol_http::TenantResolver` over
  `PgTenantDirectory`.
- `DatabaseCheck` implements `hodor_protocol_http::ReadinessCheck` under the
  name `database`, calling `Database::ping`.
- `TenantLockout` implements `hodor_federation::api::LockoutPolicy`, reading
  the tenant's lockout settings into `LockoutRules`.
- `ServerStanding` (`standing.rs`) implements
  `hodor_oauth::api::PersonStanding` over `SessionService::list_for_user`
  (a session is active when it is among the person's active sessions) and
  `IdentityService::get` (`may_sign_in`; an unknown user may not).

Wiring functions: `interaction` (Argon2id hashing, identity, credential,
WebAuthn with the relying party of `HODOR_PUBLIC_URL`, session, attempt
guard, sign-in flow, accounts and notification queue; the flow is the
built-in one with a `webauthn` step after it and a `totp` step when secrets
can be kept, both conditional on the sign-in not being multi-factor yet, and
the alternative `passkey`),
`external_sign_in` (`ExternalSignIn` with OpenID Connect, GitHub, SAML and,
through `with_directories`, `LdapDirectoryClient`), `keys`, `key_rotation`
(the default policy with `HODOR_KEY_OVERLAP_HOURS`), `token` (the token
endpoint, with `PgRefreshTokenStore`, `ServerStanding`, the secret box and
the retry window of `HODOR_REFRESH_RETRY_SECONDS`), `administration`,
`development_hosts`, `directory_hosts`, `wait_for`, `stop_signal`, `main`
and `run`.

## Invariants

- The server does not start without `HODOR_DATABASE_URL`: the flag has no
  default (`Config.database_url`).
- Without `HODOR_SECRET_KEYS` the server logs "HODOR_SECRET_KEYS is not set:
  no identity provider can be used", leaves external sign-in out of the flow
  (`external_sign_in` returns `None`) and has no identity providers to manage
  (`administration`). A malformed value aborts startup through
  `SecretKeys::parse`.
- The token endpoint is mounted only with both a key service and
  `HODOR_SECRET_KEYS`; a retry window outside 0 to 60 seconds aborts startup
  (`token`).
- Every context that keeps secrets (federation, authenticator applications,
  refresh token families)
  gets the same kind of `TenantSecretBox`, built by `secret_box` with
  `PgKeyStore`, `LocalKeyProvider` over the root keys, `PgSealingStateStore`
  and the root keys to open the first format.
- An overlap that `RotationPolicy::new` refuses, under 65 minutes, aborts
  startup (`key_rotation`, called by `administration`).
- Invalid hashing parameters or an invalid sign-in flow abort startup
  (`Argon2idHasher::new`, `AuthenticationService::new` in `interaction`).
- Failure to load a configured pages or console directory aborts startup; an
  unset directory only logs a warning (`run`).
- `DirectoryResolver` resolves `Active` tenants as active, `Suspended` and
  `PendingDeletion` as suspended, and `Provisioning` and `Deleted` as absent,
  "indistinguishable from a tenant that never existed".
- `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` is for a development stack on one
  machine; the doc comment says never set it anywhere real.
- Comments in `interaction` and `administration`: "The server only queues
  messages; the worker delivers them." and "The server reads the audit log;
  the worker writes it."
- Telemetry starts before the async runtime and shuts down after it (`main`).
- One stop signal stops both listeners: readiness starts failing
  (`health.begin_draining()`), the server waits `shutdown_drain_seconds`, then
  stops (`run`).

## Side Effects

- Binds a TCP listener on `HODOR_LISTEN_ADDR` for the public router and one on
  `HODOR_OPS_ADDR` for the operations router (`run`).
- Opens one PostgreSQL pool with `Database::connect` as the application role,
  a member of `hodor_app`, shared by every store (`run`).
- Readiness pings the database (`DatabaseCheck`).
- Logs and, when the endpoints are set, exports traces and metrics through
  `hodor_observability::Telemetry::init` (`main`).
- Outbound HTTPS to identity providers goes through `GuardedHttpClient`;
  LDAP connections go through `LdapDirectoryClient`, limited to
  `HODOR_DIRECTORY_HOSTS` (`external_sign_in`).
- Builds the engine registry with `NativeEngine` (over `PgRoleAssignmentStore`
  and `PgNativeRoleStore`) and `OpenPolicyAgentEngine` over a
  `ServiceHttpClient` limited to the configured Open Policy Agent origins,
  with a 64-kibibyte limit on answers (`authorization_engines`, called in
  `run`). A wrong origin or tenant pair stops the server at startup. No
  route evaluates through the registry yet (Issue-75).
- Queues notification messages in PostgreSQL through `PgMessageQueue`; it
  sends no mail (`interaction`).
- Reads the built pages and console from disk (`Pages::load`,
  `Pages::load_console`).
- Spawns one task that waits for SIGTERM or Ctrl-C and broadcasts stop over a
  `tokio::sync::watch` channel (`run`, `stop_signal`).

## Verification

- Run: `cargo test -p hodor-server`
