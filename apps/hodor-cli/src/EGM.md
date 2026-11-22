# hodor-cli source

## Overview

The operations tool of a Hodor installation, in one file, `main.rs`. It parses
the command line with clap (`Cli`, `Command`), connects to PostgreSQL and calls
the services of the domain crates directly. It applies migrations, manages
tenants, makes the first administrator of a tenant, verifies the audit chain,
manages identity providers, generates secret keys and probes a health endpoint.
The tool acts as the system: every mutating call passes `caller()`, which
returns `Caller { actor: Actor::System, correlation_id: CorrelationId::generate() }`.

## Interface

Commands, as typed, from the clap enums in `main.rs`:

| Command | Flags and environment variables | What it calls |
| --- | --- | --- |
| `hodor-cli migrate` | `--database-url` / `HODOR_DATABASE_OWNER_URL` (required) | `hodor_adapters_postgres::PgPool::connect`, then `hodor_adapters_postgres::migrate` (`Command::Migrate`) |
| `hodor-cli tenant create` | `--slug`, `--name`, `--open-registration` | `TenantService::create` with `CreateTenant { system: false, .. }` (`TenantCommand::Create`) |
| `hodor-cli tenant create-system` | none | `TenantService::find_by_slug("system")`; when absent, `TenantService::create` with `system: true` (`TenantCommand::CreateSystem`) |
| `hodor-cli tenant list` | none | `TenantService::list` (`TenantCommand::List`) |
| `hodor-cli tenant suspend` | `--slug`, `--reason` | `TenantService::suspend` (`TenantCommand::Suspend`) |
| `hodor-cli tenant reactivate` | `--slug` | `TenantService::reactivate` (`TenantCommand::Reactivate`) |
| `hodor-cli admin bootstrap` | `--tenant`, `--email`, `--token-minutes` (default 60) | `bootstrap_administrator` (`AdminCommand::Bootstrap`) |
| `hodor-cli audit verify` | `--tenant` | `verify_audit`, which calls `hodor_audit::api::AuditService::verify` (`AuditCommand::Verify`) |
| `hodor-cli provider add` | `--tenant`, `--alias`, `--name`, `--kind` (`openid-connect`, `github`, `ldap`, `saml`; default `openid-connect`), `--issuer`, `--client-id`, `--scope` (repeatable), `--no-create-users`, `--base`, `--filter`, `--subject-attribute` (default `entryUUID`), `--email-attribute`, `--name-attribute`, `--sign-on-address`, `--certificate`, `--trust-email`; client secret from `HODOR_PROVIDER_CLIENT_SECRET` | `FederationService::create_provider` (`ProviderCommand::Add`, `run_provider`) |
| `hodor-cli provider list` | `--tenant` | `FederationService::providers` (`ProviderCommand::List`) |
| `hodor-cli provider disable` / `enable` | `--tenant`, `--alias` | `FederationService::provider_by_alias`, then `FederationService::set_provider_status` with `ProviderStatus::Disabled` or `ProviderStatus::Enabled` |
| `hodor-cli secrets generate-key` | none | `hodor_adapters_crypto::SecretKeys::generate(&OsRandom)` (`SecretsCommand::GenerateKey`) |
| `hodor-cli probe` | `--addr` (default `127.0.0.1:9090`), `--path` (default `/readyz`) | local `probe`, over `std::net::TcpStream` (`Command::Probe`) |

Global flags of the command groups (`Command` in `main.rs`):

- `tenant`, `admin`, `audit` and `provider` take `--database-url` /
  `HODOR_DATABASE_URL`, the application role, connected with
  `Database::connect(&Secret, 2)`.
- `provider` also takes `--secret-keys` / `HODOR_SECRET_KEYS`,
  `--development-hosts` / `HODOR_OUTBOUND_DEVELOPMENT_HOSTS`,
  `--directory-hosts` / `HODOR_DIRECTORY_HOSTS` (both comma separated) and
  `--public-url` / `HODOR_PUBLIC_URL` (default `http://localhost:8080`).

Other symbols in `main.rs`: `ProviderKindArg` (maps to `ProviderKind`),
`caller`, `existing` (tenant lookup by slug), `run_tenant`, `run_provider`,
`provider_line`, `bootstrap_administrator`, `verify_audit`, `probe`, and
`main` (`#[tokio::main(flavor = "current_thread")]`).

## Invariants

- Only `migrate` connects as the schema owner. Doc comment on
  `Command::Migrate`: "The server and worker use a different, less privileged
  role and never run migrations." The `tenant` group connects "as a member of
  `hodor_app`; no cross-tenant role is needed" (`Command::Tenant`).
- `tenant`, `admin`, `audit` and `provider` fail with "HODOR_DATABASE_URL or
  --database-url is required" when no URL is given (`main`).
- An unknown slug fails with the error code `tenant.not_found` (`existing`,
  `bootstrap_administrator`, `verify_audit`).
- `bootstrap_administrator` runs in a fixed order: resolve the tenant; parse
  the address with `NormalizedIdentifier::parse(IdentifierKind::Email, ..)`;
  find the user with `IdentityService::find_by_login` or create a confirmed
  human user; refuse with `identity.user_may_not_sign_in` when
  `user.may_sign_in()` is false; assign `Role::TenantAdministrator` through
  `AuthorizationService::assign`; issue a token through
  `AccessTokenService::issue`. The doc comment on `AdminCommand::Bootstrap`
  says the token "is printed once" and running the command again issues a new
  one and leaves earlier ones as they are. The 1 to 43200 minute range is
  stated in the doc comment only; `main.rs` does not check it.
- `run_provider` refuses with `secret.keys_missing` when no secret keys are
  given, because provider secrets are kept encrypted. For every kind except
  SAML it refuses with `federation.client_secret_invalid` when
  `HODOR_PROVIDER_CLIENT_SECRET` is unset; a SAML provider gets an empty
  secret ("A SAML identity provider is not proved anything with a secret.").
- The client secret is read from the environment, never from an argument, so
  that it shows neither in the list of processes nor in a shell's history
  (doc comment on `ProviderCommand::Add`).
- Directory settings are built only when `--base` or `--filter` is given, and
  SAML settings only when `--sign-on-address` or `--certificate` is given
  (`run_provider`).
- `tenant create-system` is idempotent: when the slug `system` exists it
  prints `exists <slug> <id>` and creates nothing (`run_tenant`).
- `audit verify` exits with an error when the chain is broken and names the
  record where it breaks (`verify_audit`, `main`).
- `probe` succeeds only when the first 12 bytes of the answer are exactly
  `HTTP/1.1 200`, with a 3 second connect, read and write timeout (`probe`).
- Every error is returned from `main`, so the process exits non-zero.

## Side Effects

- `migrate` applies the pending schema migrations as the schema owner and
  prints `migrations applied` (`Command::Migrate`).
- `tenant` commands write tenant rows or change a tenant's status
  (`TenantService::create`, `suspend`, `reactivate`).
- `admin bootstrap` may create a user, assigns the administrator role and
  issues an access token; it prints the plaintext token once
  (`bootstrap_administrator`).
- `audit verify` only reads the tenant's audit chain through `PgAuditLog`
  (`verify_audit`).
- `provider add`, `disable` and `enable` write identity provider rows; the
  client secret is sealed with the keys from `HODOR_SECRET_KEYS`
  (`run_provider`).
- `secrets generate-key` prints a new key once and stores it nowhere; it opens
  no database (`SecretsCommand::GenerateKey`).
- `probe` opens one TCP connection and sends `GET <path> HTTP/1.1` (`probe`).
- `main.rs` writes no audit record itself; any audit record comes from inside
  the services it calls.

## Verification

- Run: `cargo test -p hodor-cli`
