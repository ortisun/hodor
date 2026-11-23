# hodor-cli source

## Overview

The operations tool of a Hodor installation: `main.rs`, and
`applications.rs` for the application, client and resource server commands. It parses
the command line with clap (`Cli`, `Command`), connects to PostgreSQL and calls
the services of the domain crates directly. It applies migrations, manages
tenants, makes the first administrator of a tenant, verifies the audit chain,
manages identity providers, looks at, rotates and revokes a tenant's keys,
registers Open Policy Agent instances and publishes their signed bundles,
generates secret keys and probes a health endpoint.
manages identity providers and applications, generates secret keys and probes
a health endpoint.
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
| `hodor-cli tenant second-factor` | `--slug`, `--policy` (`required`, `not-required`) | `TenantService::change_settings` with `authentication.second_factor` (`TenantCommand::SecondFactor`) |
| `hodor-cli admin bootstrap` | `--tenant`, `--email`, `--token-minutes` (default 60) | `bootstrap_administrator` (`AdminCommand::Bootstrap`) |
| `hodor-cli audit verify` | `--tenant` | `verify_audit`, which calls `hodor_audit::api::AuditService::verify` (`AuditCommand::Verify`) |
| `hodor-cli provider add` | `--tenant`, `--alias`, `--name`, `--kind` (`openid-connect`, `github`, `ldap`, `saml`; default `openid-connect`), `--issuer`, `--client-id`, `--scope` (repeatable), `--no-create-users`, `--base`, `--filter`, `--subject-attribute` (default `entryUUID`), `--email-attribute`, `--name-attribute`, `--sign-on-address`, `--certificate`, `--trust-email`; client secret from `HODOR_PROVIDER_CLIENT_SECRET` | `FederationService::create_provider` (`ProviderCommand::Add`, `run_provider`) |
| `hodor-cli provider list` | `--tenant` | `FederationService::providers` (`ProviderCommand::List`) |
| `hodor-cli provider disable` / `enable` | `--tenant`, `--alias` | `FederationService::provider_by_alias`, then `FederationService::set_provider_status` with `ProviderStatus::Disabled` or `ProviderStatus::Enabled` |
| `hodor-cli application add` | `--tenant`, `--name`, `--first-party` (third party unless given) | `ApplicationService::create_application`; prints `application <id> <name>` (`applications.rs:run_application`) |
| `hodor-cli application list` | `--tenant` | `ApplicationService::applications`; one line `<id> <status> first-party|third-party <name>` each |
| `hodor-cli application disable` / `enable` | `--tenant`, `--id` | `ApplicationService::set_application_status`; prints `application <id> <status>` |
| `hodor-cli client add` | `--tenant`, `--application`, `--name`, `--type`, `--grant` (repeatable, required), `--redirect-uri`, `--scope` (repeatable), `--method`, `--secret-days` (default 365) | `ApplicationService::create_client`; prints `client <id>` and, for a secret method, `secret <value>` and `expires <time>`, once (`applications.rs:run_client`) |
| `hodor-cli client list` | `--tenant`, `--application` | `ApplicationService::clients`; one line `<id> <status> <type> <method> <name>` each |
| `hodor-cli client rotate-secret` | `--tenant`, `--id`, `--lifetime-days` (default 365), `--keep-previous-days` (default 7) | `ApplicationService::rotate_client_secret`; prints `secret <value>` and `expires <time>`, once |
| `hodor-cli client disable` / `enable` | `--tenant`, `--id` | `ApplicationService::set_client_status`; prints `client <id> <status>` |
| `hodor-cli resource-server add` | `--tenant`, `--application`, `--audience`, `--name`, `--scope name=description` (repeatable) | `ApplicationService::create_resource_server`; prints `resource-server <id> <audience>` (`applications.rs:run_resource_server`) |
| `hodor-cli resource-server list` | `--tenant` | `ApplicationService::resource_servers`; one line `<id> <audience> <name> [<scopes>]` each |
| `hodor-cli totp enroll` | `--tenant`, `--login`; keys from `HODOR_SECRET_KEYS` | `TotpService::begin_enrollment`, issuer the tenant's display name; prints `secret <Base32>` and `address <otpauth://…>` (`TotpCommand::Enroll`, `run_totp`) |
| `hodor-cli totp confirm` | `--tenant`, `--login`, `--code` | `TotpService::confirm_enrollment`, then `RecoveryCodeService::generate_if_none`; prints `confirmed`, followed by `recovery codes, shown once: 10` and the ten codes when the person had no unused code (`TotpCommand::Confirm`) |
| `hodor-cli totp remove` | `--tenant`, `--login` | `TotpService::remove`; prints `removed` or `nothing to remove` (`TotpCommand::Remove`) |
| `hodor-cli keys list` | `--tenant`, `--key-set` (`sig`, `data`; default `sig`) | `KeyService::key_set`, one `key_line` per version (`KeysCommand::List`, `run_keys`) |
| `hodor-cli keys rotate` | `--tenant`, `--algorithm` (`es256`, `rs256`, `ps256`; default `es256`) | `KeyService::rotate_now` with the overlap of `--key-overlap-hours` (`KeysCommand::Rotate`) |
| `hodor-cli keys revoke` | `--tenant`, `--version`, `--reason` | `KeyService::revoke` (`KeysCommand::Revoke`) |
| `hodor-cli recovery-codes generate` | `--tenant`, `--login`; no keys needed | `RecoveryCodeService::generate`: a set in place of any earlier one; prints `recovery codes, shown once: 10` and the ten codes (`RecoveryCodeCommand::Generate`, `run_recovery_codes`) |
| `hodor-cli recovery-codes count` | `--tenant`, `--login` | `RecoveryCodeService::unused`; prints `unused <count>` (`RecoveryCodeCommand::Count`) |
| `hodor-cli recovery-codes remove` | `--tenant`, `--login` | `RecoveryCodeService::remove`; prints `removed` or `nothing to remove` (`RecoveryCodeCommand::Remove`) |
| `hodor-cli policy-agent signing-key` | none; no database | `BundleSigningKey::generate`; prints the private key and the public key in PEM (`PolicyAgentCommand::SigningKey`, `run_policy_agent`) |
| `hodor-cli policy-agent bundle-name` | `--tenant`, optional `--namespace` | `bundle_name`, or with a namespace the package of `decision_path` (`PolicyAgentCommand::BundleName`) |
| `hodor-cli policy-agent instance add` | `--name`, optional `--tenant` (without it, a shared instance) | `BundleService::register`; prints `<identifier>\t<name>` and the credential on the next line, once (`InstanceCommand::Add`) |
| `hodor-cli policy-agent instance list` | none | `BundleService::instances`: name, tenant or `shared`, when registered, `enabled` or `disabled <when>` (`InstanceCommand::List`) |
| `hodor-cli policy-agent instance disable` | `--name` | `BundleService::disable`; `authorization.policy_agent_instance_not_found` if no enabled instance has the name (`InstanceCommand::Disable`) |
| `hodor-cli policy-agent publish` | `--tenant`, `--directory`, `--written-by` (`operator`, `tenant`; default `tenant`), `--signing-key-file` / `HODOR_OPEN_POLICY_AGENT_SIGNING_KEY_FILE`, `--signing-key-id` / `HODOR_OPEN_POLICY_AGENT_SIGNING_KEY_ID` (default `hodor`) | every file under the directory (`bundle_files`), `BundleSigningKey::from_pem`, `BundleService::publish`; prints `<revision>\t<entity tag>` (`PolicyAgentCommand::Publish`) |
| `hodor-cli policy-agent status` | `--tenant` | `BundleService::statuses`: instance, active revision, when reported, last error (`PolicyAgentCommand::Status`) |
| `hodor-cli secrets generate-key` | none | `hodor_adapters_crypto::SecretKeys::generate(&OsRandom)` (`SecretsCommand::GenerateKey`) |
| `hodor-cli secrets reseal` | `--tenant` (optional), `HODOR_DATABASE_URL`, `HODOR_SECRET_KEYS` | `hodor_adapters_postgres::reseal_tenant` per tenant of `TenantDirectory::list`, then `TenantSecretBox::refuse_first_format` when nothing was left unreadable; one line per tenant (`SecretsCommand::Reseal`, `run_reseal`) |
| `hodor-cli probe` | `--addr` (default `127.0.0.1:9090`), `--path` (default `/readyz`) | local `probe`, over `std::net::TcpStream` (`Command::Probe`) |

Global flags of the command groups (`Command` in `main.rs`):

- `tenant`, `admin`, `audit`, `provider`, `application`, `client` and
  `resource-server` take `--database-url` /
  `HODOR_DATABASE_URL`, the application role, connected with
  `Database::connect(&Secret, 2)`.
- `keys` takes `--database-url` / `HODOR_DATABASE_URL`, `--secret-keys` /
  `HODOR_SECRET_KEYS` (required: `run_keys` refuses with
  `secret.keys_missing`) and `--key-overlap-hours` /
  `HODOR_KEY_OVERLAP_HOURS` (default 24, checked by `RotationPolicy::new`).
- `provider` also takes `--secret-keys` / `HODOR_SECRET_KEYS`,
  `--development-hosts` / `HODOR_OUTBOUND_DEVELOPMENT_HOSTS`,
  `--directory-hosts` / `HODOR_DIRECTORY_HOSTS` (both comma separated) and
  `--public-url` / `HODOR_PUBLIC_URL` (default `http://localhost:8080`).

Other symbols in `main.rs`: `ProviderKindArg` (maps to `ProviderKind`),
`caller`, `existing` (tenant lookup by slug), `run_tenant`, `run_provider`,
`provider_line`, `KeySetArg`, `SigningAlgorithmArg`, `run_keys`, `key_line`,
`written`, `bootstrap_administrator`, `verify_audit`, `probe`, and
`caller`, `existing` (tenant lookup by slug), `connect` and `print` (used by
the application commands), `run_tenant`, `run_provider`,
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
- `totp enroll` stores a sealed secret and prints it once in Base32 with its
  `otpauth://` address; `totp confirm` and `totp remove` change
  `credential.totp` and record `credential.totp_enrolled` or
  `credential.totp_removed` (`run_totp`). `tenant second-factor` changes the
  tenant's settings.
- Recovery codes are printed once, when they are made, and stored only as
  SHA-256 hashes; `recovery-codes generate` and `remove` record
  `credential.recovery_codes_generated` or `credential.recovery_codes_removed`
  (`run_recovery_codes`). `totp confirm` makes a set only when the person has
  no unused code, so confirming a new application keeps the codes already
  written down.
- `secrets generate-key` prints a new key once and stores it nowhere; it opens
  no database (`SecretsCommand::GenerateKey`).
- `secrets reseal` exits with a failure when a secret that needed sealing
  again did not open; that tenant keeps accepting the first format
  (`run_reseal`). The `totp` and `provider` commands seal through the same
  `TenantSecretBox` as the server (`secret_box`).
- `probe` opens one TCP connection and sends `GET <path> HTTP/1.1` (`probe`).
- `main.rs` writes no audit record itself; any audit record comes from inside
  the services it calls.

## Verification

- Run: `cargo test -p hodor-cli`
