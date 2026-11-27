# hodor-cli source

## Overview

The operations tool of a Hodor installation: `main.rs`, and
`applications.rs` for the application, client and resource server commands, and
`decisions.rs` for `hodor-cli authorization decision-log show|set` and
`hodor-cli authorization decisions`, and `roles.rs` for
`hodor-cli authorization permission declare|remove|list`, `role define|remove|list`,
`assign`, `revoke`, `access-entry grant|list|remove`, `bind`, `unbind` and
`bindings` (a resource server named by
its audience; `bind` knows the engine names `native` and `open_policy_agent`
through a registry of names only, since the tool never evaluates), and
`webhooks.rs` for `hodor-cli webhook`, `trust_domains.rs` for
`hodor-cli trust-domain`, `mesh.rs` for `hodor-cli mesh linkerd-policy`, and
`users.rs` for `hodor-cli user claims`. It parses
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
| `hodor-cli tenant email-sign-in` | `--slug`, `--code` and `--link` (`on`, `off`), each optional; neither to only print | `TenantService::change_settings` with `authentication.email_sign_in`, only what was given; prints `<slug> email-sign-in code <on\|off> link <on\|off>` (`TenantCommand::EmailSignIn`) |
| `hodor-cli tenant pushed-requests` | `--slug`, `--seconds` (10 to 600) and `--required` (`on`, `off`), each optional; neither to only print | `TenantService::change_settings` with `pushed_requests`, only what was given; prints `<slug> pushed-requests seconds <seconds> required <on\|off>` (`TenantCommand::PushedRequests`) |
| `hodor-cli tenant scim-deprovisioning` | `--slug`, `--policy` (`deactivate`, `delete`) | `TenantService::change_settings` with `provisioning.deprovisioning`; prints `<slug> scim-deprovisioning <policy>` (`TenantCommand::ScimDeprovisioning`) |
| `hodor-cli tenant assurance-levels` | `--slug`, `--level <acr>=<requirement>` repeated; none to only print | `AssuranceLevels::new` then `TenantService::change_settings` with `authentication.assurance_levels`; prints `<slug> <acr> <requirement>` per level, weakest first (`TenantCommand::AssuranceLevels`) |
| `hodor-cli admin bootstrap` | `--tenant`, `--email`, `--token-minutes` (default 60) | `bootstrap_administrator` (`AdminCommand::Bootstrap`) |
| `hodor-cli audit verify` | `--tenant` | `verify_audit`, which calls `hodor_audit::api::AuditService::verify` (`AuditCommand::Verify`) |
| `hodor-cli provider add` | `--tenant`, `--alias`, `--name`, `--kind` (`openid-connect`, `github`, `ldap`, `saml`; default `openid-connect`), `--issuer`, `--client-id`, `--scope` (repeatable), `--no-create-users`, `--base`, `--filter`, `--subject-attribute` (default `entryUUID`), `--email-attribute`, `--name-attribute`, `--sign-on-address`, `--certificate`, `--trust-email`, `--claim-attribute <claim>=<attribute>` (repeatable, such as `given_name=givenName` or `address.locality=l`; the `claim_attributes` of the directory or SAML settings); client secret from `HODOR_PROVIDER_CLIENT_SECRET` | `FederationService::create_provider` (`ProviderCommand::Add`, `run_provider`) |
| `hodor-cli provider list` | `--tenant` | `FederationService::providers` (`ProviderCommand::List`) |
| `hodor-cli provider disable` / `enable` | `--tenant`, `--alias` | `FederationService::provider_by_alias`, then `FederationService::set_provider_status` with `ProviderStatus::Disabled` or `ProviderStatus::Enabled` |
| `hodor-cli user claims` | `--tenant`, `--user` (its identifier, or a username or email address it has; `identity.user_not_found` otherwise), and each optional: `--given-name`, `--family-name`, `--middle-name`, `--nickname`, `--profile`, `--picture`, `--website`, `--gender`, `--birthdate`, `--zoneinfo`, `--phone-number`, `--phone-number-verified true\|false`, `--formatted-address`, `--street-address`, `--locality`, `--region`, `--postal-code`, `--country` | Without any of them, only prints. Otherwise the person's claims with each given one set through `StandardClaims::set` (an empty value removes it, the others kept), `phone_number_verified` false for a new number unless given, then `IdentityService::change_claims`. Prints `<claim> <value>` per claim the person has, in the order of `ClaimField::ALL`, the parts of the address as `address.<part>` and a line break as `\n`, then `phone_number_verified <true\|false>` when there is a number (`users.rs:run`, `UserCommand::Claims`) |
| `hodor-cli application add` | `--tenant`, `--name`, `--first-party` (third party unless given) | `ApplicationService::create_application`; prints `application <id> <name>` (`applications.rs:run_application`) |
| `hodor-cli application list` | `--tenant` | `ApplicationService::applications`; one line `<id> <status> first-party|third-party <name>` each |
| `hodor-cli application disable` / `enable` | `--tenant`, `--id` | `ApplicationService::set_application_status`; prints `application <id> <status>` |
| `hodor-cli client add` | `--tenant`, `--application`, `--name`, `--type`, `--grant` (repeatable, required), `--response-type` (repeatable; `code` alone for a client of `authorization_code` unless given, read by `ResponseType::parse`), `--redirect-uri`, `--scope` (repeatable), `--method`, `--secret-days` (default 365), `--without-pkce` (a confidential client only), `--id-token-algorithm` (`ES256` unless given, or `RS256`, `PS256` or `EdDSA`; otherwise `oauth.client_id_token_algorithm_invalid`), `--userinfo-signed-response-alg` (`ES256`, `RS256`, `PS256` or `EdDSA`; UserInfo in JSON unless given; otherwise `oauth.client_userinfo_algorithm_invalid`), `--request-object-signing-alg` (`ES256`, `RS256`, `PS256` or `none`; none chosen unless given), `--require-pushed-authorization-requests` (`ClientSettings::require_pushed_requests`), `--request-uri` (repeatable, `ClientSettings::request_uris`, checked by the same guarded client; a private address is `oauth.client_request_uri_forbidden`), `--backchannel-logout-uri` (checked by a `GuardedHttpClient` with the development exception of `HODOR_OUTBOUND_DEVELOPMENT_HOSTS`, given to `ApplicationService::with_destinations`; a private address is `oauth.client_backchannel_logout_uri_forbidden`), `--backchannel-logout-session-required`, `--frontchannel-logout-uri` (`ClientSettings::frontchannel_logout_uri`, checked by the OAuth context alone and resolved by nothing; an address on none of the sites of the client's redirect addresses is `oauth.client_frontchannel_logout_uri_invalid`), `--frontchannel-logout-session-required`, `--jwks-uri` (a key set address for `private_key_jwt`, checked by the same client and not fetched; otherwise `oauth.client_jwks_uri_*`), `--principal` (a service account or an agent of the tenant: an agent with the token exchange grant, a service account with a method of `AuthenticationMethod::uses_workload_identity`, checked by `workloads.rs:principal_of` with the kind required, otherwise `oauth.client_principal_invalid`), `--exchange-rule '<subject audience>=><audience>'` (repeatable, `exchange_rule`), `--spiffe-id` (`SpiffeId::parse`, into `ClientSettings::spiffe_id`), `--linkerd-identity` (`LinkerdIdentity::parse`, into `ClientSettings::linkerd_identity`), `--bound-tokens` (`ClientSettings::certificate_bound_access_tokens`); the rules of identities and methods are the OAuth context's, so `oauth.client_spiffe_id_invalid`, `_taken`, `oauth.client_linkerd_identity_invalid`, `_taken` and `oauth.client_certificate_bound_access_tokens_invalid` are its own | `ApplicationService::create_client`; prints `client <id>` and, for a secret method, `secret <value>` and `expires <time>`, once (`applications.rs:run_client`) |
| `hodor-cli service-account create` / `agent create` | `--tenant`, `--name`, `--owner` (repeatable, required) | `WorkloadService::create` with the kind of the command; prints `created <id> <name>` (`workloads.rs:run`) |
| `hodor-cli service-account list` / `agent list` | `--tenant` | `WorkloadService::list`, every page; one line `<id> <status> <name>` each, the deleted left out |
| `hodor-cli service-account disable` / `enable` / `delete`, and the same of `agent` | `--tenant`, `--id` | `WorkloadService::disable`, `enable` and `delete`; print `<status> <id>` or `deleted <id>`. `CommandLineAccess` implements `WorkloadAccess` with `WorkloadTokens` and, on deletion, `ApiKeyService::revoke_all_of_in`, since a workload holds no session and no grant |
| `hodor-cli service-account key create` / `agent key create` | `--tenant`, `--id`, `--name`, `--scope` (repeatable, required), `--application`, `--lifetime-days` (default 90) | `check_key_scopes`, the application through `ApplicationService::application` (`credential.api_key_application_invalid`), then `ApiKeyService::create`; prints `key <id>`, `api-key <value>` once and `expires <time>` (`workloads.rs:run_key`) |
| `hodor-cli service-account key list` / `rotate` / `revoke`, and the same of `agent` | `--tenant`, `--id`; `--key` for `rotate` and `revoke`; `--lifetime-days` and `--keep-previous-days` (default 7) for `rotate` | `ApiKeyService::list` (one line `<id> <status> <hint> <name>` each), `rotate` (prints as `create`), `revoke` (prints `revoked <id>`) |
| `hodor-cli trust-domain add` | `--tenant`, `--name`, and exactly one of `--bundle-file <path>` (`-` for the standard input, read up to `MAX_BUNDLE_BYTES` and one byte; a file that cannot be read is `keys.trust_bundle_invalid`), `--bundle-endpoint <address>` and `--mesh` (`SourceArguments`, a clap group); `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` | `TrustDomainService::add` with `TrustSourceRequest`, through a `GuardedHttpClient` of `max_response_bytes` `MAX_BUNDLE_BYTES + 1` as `DestinationCheck` and `HttpClient`; prints `added <id>` then `described` (`trust_domains.rs:run`) |
| `hodor-cli trust-domain list` | `--tenant` | `TrustDomainService::list`, every page; one `line` each: `<id> <name> <source>`, then `fetched <time>` for a bundle endpoint, or `failing-since <time> <code>` while it fails |
| `hodor-cli trust-domain show` | `--tenant`, `--name` | `TrustDomainService::find_by_name` (`keys.trust_domain_not_found` when none); prints `trust-domain <id>` then `described`: `name`, `source`, `bundle-endpoint`, `sequence`, `refresh-hint`, `x509-authorities`, `jwt-authorities`, `bundle-sha256` (`Sha256Digest` of the kept document, as events name it), `bundle-changed`, `fetched`, `next-fetch`, `failing-since`, `last-error`, each only when it applies |
| `hodor-cli trust-domain replace` | `--tenant`, `--name`, and one source as for `add` | the source read first, then `find_by_name` and `TrustDomainService::replace`; prints `replaced <id>` then `described` |
| `hodor-cli trust-domain remove` | `--tenant`, `--name` | `find_by_name`, then `TrustDomainService::remove`; prints `removed <id> <name>` |
| `hodor-cli mesh linkerd-policy` | `--tenant`, `--application`, `--namespace` (a Kubernetes label), `--server` and `--name` (Kubernetes names; `hodor-<application>` unless given), `--output` (the file, read first as the last run) | `applications::open`, `ApplicationService::application` and `resource_server_of` (`oauth.resource_server_not_found` without one); `bound_identities`: every enabled client of an enabled application with a principal and a `linkerd_identity`; `identities_let_in`: for each principal, `IdentityService::get` (an active service account only), `GroupService::effective_groups`, `OrganizationService::organizations_of`, then `RoleService::assignments_on` for the resource server's audience and the application; `render` writes the `MeshTLSAuthentication` (`NOBODY` when no one holds a role) and the `AuthorizationPolicy` as JSON documents after a comment; `read_back` and `changes` compare with the last run; `replace` writes beside and renames. Prints `added`, `removed`, `changed`, `no service account holds a role on`, then `wrote` or `unchanged` (`mesh.rs:run`) |
| `hodor-cli webhook event-types` | none; no tenant | `CATALOG`, one a line (`webhooks.rs:run`) |
| `hodor-cli webhook add` | `--tenant`, `--url`, `--event` (repeatable, required), `--description`; `HODOR_SECRET_KEYS` and `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` | `WebhookService::register`, the address checked by `GuardedHttpClient` as `DestinationCheck`; prints `created <id> <url>` and `secret <whsec_…>`, once |
| `hodor-cli webhook list` | `--tenant` | `WebhookService::list`, every page; one line `<id> <url> <type>,<type>…` each |
| `hodor-cli webhook subscribe` | `--tenant`, `--id`, `--event` (repeatable, required) | `WebhookService::replace_subscriptions`; prints `subscribed <id> <type>,<type>…` |
| `hodor-cli webhook rotate-secret` | `--tenant`, `--id`, `--overlap-hours` (24 unless given); `HODOR_SECRET_KEYS` | `WebhookService::rotate_secret`; prints `secret <whsec_…>` once and `previous-until <time>` |
| `hodor-cli webhook remove` | `--tenant`, `--id` | `WebhookService::remove`; prints `removed <id>` |
| `hodor-cli webhook deliveries` | `--tenant`, `--endpoint`, `--status` (`pending`, `delivered`, `set_aside`) | `WebhookService::deliveries`, the latest 100; one line `<id> <status> <attempts> <event type> <event id>` each |
| `hodor-cli webhook redeliver` | `--tenant`, `--delivery` | `WebhookService::redeliver`; prints `pending <id>` |
| `hodor-cli admin grant` / `revoke` | `--tenant`, `--user`, `--role` (`tenant_administrator`, `tenant_auditor` or `certificate_signer`) | `AuthorizationService::assign` or `revoke` for a user who exists and is not Deleted; prints `granted <role> <id>` or `revoked <role> <id>` (`built_in_role`) |
| `hodor-cli client list` | `--tenant`, `--application` | `ApplicationService::clients`; one line `<id> <status> <type> <method> <name>` each |
| `hodor-cli client rotate-secret` | `--tenant`, `--id`, `--lifetime-days` (default 365), `--keep-previous-days` (default 7) | `ApplicationService::rotate_client_secret`; prints `secret <value>` and `expires <time>`, once |
| `hodor-cli client disable` / `enable` | `--tenant`, `--id` | `ApplicationService::set_client_status`; prints `client <id> <status>` |
| `hodor-cli client mapper add` | `--tenant`, `--client`, `--claim`, `--target` (repeatable, required), `--source`, `--attribute`, `--group`, `--value` (JSON), `--scope` | The group of `group_member` through `GroupService::get` (`memberships::groups`), then `ClaimMapperService::create`; prints `mapper <id>` (`applications.rs:run_mapper`) |
| `hodor-cli client mapper list` | `--tenant`, `--client` | `ClaimMapperService::mappers`; one line `<id> <claim> <targets, comma-separated> <source> <scope or ->` each, the source as `attribute:<name>`, `groups`, `group_member:<group>`, `organization:<attribute>` or `constant` |
| `hodor-cli client mapper remove` | `--tenant`, `--client`, `--id` | `ClaimMapperService::delete`; prints `removed <id>` |
| `hodor-cli client-registration show` | `--tenant` | `ClientRegistrationService::settings`; one fact a line: `registration on|off`, `application`, `ways`, `most-clients`, `grants`, `response-types`, `scopes`, `methods`, `subject-types`, `hosts` (`any` or comma-separated) (`registration.rs:run`) |
| `hodor-cli client-registration on` | `--tenant`, `--application`, `--way`, `--most-clients` (100), `--grant`, `--response-type`, `--scope`, `--method`, `--subject-type`, `--host` (each repeatable, left out at its default) | The policy read by `RegistrationPolicy::from_json`, then `ClientRegistrationService::replace` with registration on; prints what `show` prints |
| `hodor-cli client-registration off` | `--tenant` | The settings in force with `enabled` false, through `replace`; prints what `show` prints |
| `hodor-cli client-registration token add` | `--tenant`, `--name`, `--hours` (168), `--registrations` (1) | `ClientRegistrationService::issue_token`; prints `token <id>`, `initial-access-token <token>`, once, and `expires <time>` |
| `hodor-cli client-registration token list` | `--tenant` | `ClientRegistrationService::tokens`; one line `<id> <status> <used>/<allowed> <expires> …<hint> <name>` each, newest first |
| `hodor-cli client-registration token revoke` | `--tenant`, `--id` | `ClientRegistrationService::revoke_token`; prints `revoked <id>` |
| `hodor-cli resource-server add` | `--tenant`, `--application`, `--audience`, `--name`, `--scope name=description` (repeatable) | `ApplicationService::create_resource_server`; prints `resource-server <id> <audience>` (`applications.rs:run_resource_server`) |
| `hodor-cli resource-server list` | `--tenant` | `ApplicationService::resource_servers`; one line `<id> <audience> <name> [<scopes>]` each |
| `hodor-cli totp enroll` | `--tenant`, `--login`; keys from `HODOR_SECRET_KEYS` | `TotpService::begin_enrollment`, issuer the tenant's display name; prints `secret <Base32>` and `address <otpauth://…>` (`TotpCommand::Enroll`, `run_totp`) |
| `hodor-cli totp confirm` | `--tenant`, `--login`, `--code` | `TotpService::confirm_enrollment`, then `RecoveryCodeService::generate_if_none`; prints `confirmed`, followed by `recovery codes, shown once: 10` and the ten codes when the person had no unused code (`TotpCommand::Confirm`) |
| `hodor-cli totp remove` | `--tenant`, `--login` | `TotpService::remove`; prints `removed` or `nothing to remove` (`TotpCommand::Remove`) |
| `hodor-cli keys list` | `--tenant`, `--key-set` (`sig`, `data`; default `sig`) | `KeyService::key_set`, one `key_line` per version (`KeysCommand::List`, `run_keys`) |
| `hodor-cli keys rotate` | `--tenant`, `--algorithm` (`es256`, `rs256`, `ps256`; default `es256`) | `KeyService::rotate_now` with the overlap of `--key-overlap-hours` (`KeysCommand::Rotate`) |
| `hodor-cli keys revoke` | `--tenant`, `--version`, `--reason` | `KeyService::revoke` (`KeysCommand::Revoke`) |
| `hodor-cli authority sign` | `--tenant`, `--request` (a file, or `-` for standard input), `--lifetime-days`; `HODOR_SECRET_KEYS`, `HODOR_CERTIFICATE_AUTHORITY` (`on` or `development`, else `keys.authority_setting_invalid`) and the key provider's settings | `AuthorityService::sign` (`authority.rs`), acting as the system; prints the certificate then the chain in PEM, and `signed <line>` on standard error; a refusal prints its code, message and detail |
| `hodor-cli authority intermediates` | `--tenant` | `AuthorityService::intermediates`, every page; one line each: identifier, state, serial number, end of validity, subject |
| `hodor-cli authority withdraw` | `--tenant`, `--intermediate`, `--reason` | `AuthorityService::withdraw`; `withdrawn <line>` for each intermediate of the key |
| `hodor-cli recovery-codes generate` | `--tenant`, `--login`; no keys needed | `RecoveryCodeService::generate`: a set in place of any earlier one; prints `recovery codes, shown once: 10` and the ten codes (`RecoveryCodeCommand::Generate`, `run_recovery_codes`) |
| `hodor-cli recovery-codes count` | `--tenant`, `--login` | `RecoveryCodeService::unused`; prints `unused <count>` (`RecoveryCodeCommand::Count`) |
| `hodor-cli recovery-codes remove` | `--tenant`, `--login` | `RecoveryCodeService::remove`; prints `removed` or `nothing to remove` (`RecoveryCodeCommand::Remove`) |
| `hodor-cli policy-agent signing-key` | none; no database | `BundleSigningKey::generate`; prints the private key and the public key in PEM (`PolicyAgentCommand::SigningKey`, `run_policy_agent`) |
| `hodor-cli policy-agent bundle-name` | `--tenant`, optional `--namespace` | `bundle_name`, or with a namespace the package of `decision_path` (`PolicyAgentCommand::BundleName`) |
| `hodor-cli policy-agent instance add` | `--name`, optional `--tenant` (without it, a shared instance) | `BundleService::register`; prints `<identifier>\t<name>` and the credential on the next line, once (`InstanceCommand::Add`) |
| `hodor-cli policy-agent instance list` | none | `BundleService::instances`: name, tenant or `shared`, when registered, `enabled` or `disabled <when>` (`InstanceCommand::List`) |
| `hodor-cli policy-agent instance disable` | `--name` | `BundleService::disable`; `authorization.policy_agent_instance_not_found` if no enabled instance has the name (`InstanceCommand::Disable`) |
| `hodor-cli policy draft` | `--tenant`, `--directory`, `--written-by` (`operator`, `tenant`; default `tenant`) | every file under the directory (`bundle_files`), `PolicyService::draft`; prints `<version>\t<digest>` (`policies.rs`) |
| `hodor-cli policy validate`, `policy test` | `--tenant`, `--version`, `--wait` (seconds, default 60; 0 does not wait) | `PolicyService::validate` or `test`, then polls the version every 500 milliseconds until the worker moved it; `authorization.policy_check_pending` when it did not in time, `authorization.policy_version_rejected` with the report when it was rejected |
| `hodor-cli policy simulate` | `--tenant`, `--version`, `--namespace`, `--inputs` (a JSON file holding a list), `--wait` | `PolicyService::simulate`, then polls the simulation; prints each input's position, `same` or `differs`, the version's answer and the published one |
| `hodor-cli policy publish`, `policy rollback` | `--tenant`, `--version` or `--revision`, `--signing-key-file` / `HODOR_OPEN_POLICY_AGENT_SIGNING_KEY_FILE`, `--signing-key-id` / `HODOR_OPEN_POLICY_AGENT_SIGNING_KEY_ID` (default `hodor`) | `PolicyService::publish` or `roll_back`; prints `<revision>\t<version>\t<entity tag>` |
| `hodor-cli policy status`, `policy versions`, `policy show` | `--tenant`, and `--version` for `show` | `PolicyService::status`, `versions` (the latest 50) or `version` |
| `hodor-cli policy-agent status` | `--tenant` | `BundleService::statuses`: instance, active revision, when reported, last error (`PolicyAgentCommand::Status`) |
| `hodor-cli secrets generate-key` | none | `hodor_adapters_crypto::SecretKeys::generate(&OsRandom)` (`SecretsCommand::GenerateKey`) |
| `hodor-cli secrets reseal` | `--tenant` (optional), `HODOR_DATABASE_URL`, `HODOR_SECRET_KEYS` | `hodor_adapters_postgres::reseal_tenant` per tenant of `TenantDirectory::list`, then `TenantSecretBox::refuse_first_format` when nothing was left unreadable; one line per tenant (`SecretsCommand::Reseal`, `run_reseal`) |
| `hodor-cli probe` | `--addr` (default `127.0.0.1:9090`), `--path` (default `/readyz`) | local `probe`, over `std::net::TcpStream` (`Command::Probe`) |

Global flags of the command groups (`Command` in `main.rs`):

- `tenant`, `admin`, `audit`, `provider`, `user`, `application`, `client`,
  `resource-server` and `mesh` take `--database-url` /
  `HODOR_DATABASE_URL`, the application role, connected with
  `Database::connect(&Secret, 2)`.
- `trust-domain` takes `--database-url` / `HODOR_DATABASE_URL` and
  `--development-hosts` / `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` (comma
  separated), as `webhook` does. The bundle endpoint's certificate is checked
  against the machine's authorities, which `SSL_CERT_FILE` replaces.
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
- `webhooks.rs:run` builds `WebhookService` with `NoKeys` in place of the
  tenants' secret box when `HODOR_SECRET_KEYS` is not given: it refuses to
  seal or open with `secret.keys_missing`, so `add` and `rotate-secret` are
  refused and the other commands work.
- `run_provider` refuses with `secret.keys_missing` when no secret keys are
  given, because provider secrets are kept encrypted. For every kind except
  SAML it refuses with `federation.client_secret_invalid` when
  `HODOR_PROVIDER_CLIENT_SECRET` is unset; a SAML provider gets an empty
  secret ("A SAML identity provider is not proved anything with a secret.").
- A `--claim-attribute` without `=` is refused with
  `federation.claim_attribute_invalid`, and so are claim attributes given
  for a provider that is neither a directory nor a SAML identity provider
  (`run_provider`).
- `user claims` checks nothing itself: the identity context does, so a
  value the administration interface refuses is refused with the same code,
  `identity.claim_invalid` or, for a service account or an agent,
  `identity.workload_claims_refused` (`users.rs` module documentation).
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
- `user claims` replaces a person's standard claims when one is given,
  recording `identity.profile_changed` when they changed (`users.rs:run`).
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
