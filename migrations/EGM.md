# migrations

## Overview

The PostgreSQL schema, as thirty numbered SQL files. A number is
reserved when a piece of work starts, so a number can be missing until that
work merges; every file not yet applied is applied, in order. They are
embedded in the binaries by `static MIGRATOR: Migrator = sqlx::migrate!("../../migrations")`
in `crates/adapters-postgres/src/migrate.rs` and applied by
`hodor_adapters_postgres::migrate`, which `hodor-cli migrate` calls with a
pool connected as the schema owner. The doc comment on `migrate` says
migrations are applied by `hodor-cli migrate`, never by the server at
startup, and that a database holding a migration the binary does not know is
an error.

## Interface

Tables created, by file:

| File | Schema, table or other object |
| --- | --- |
| `0001_platform_foundation.sql` | roles `hodor_app` and `hodor_platform` (`NOLOGIN`); schema `platform`; functions `platform.current_tenant_id()` and `platform.enable_tenant_rls(regclass)` |
| `0002_outbox.sql` | `platform.outbox` |
| `0003_tenant.sql` | schema `tenant`; `tenant.tenant`; `platform.tenant_directory`; function `platform.sync_tenant_directory()` with trigger `tenant_directory_sync`; function `tenant.forbid_slug_change()` with trigger `tenant_slug_is_immutable` |
| `0004_identity.sql` | schema `identity`; `identity."user"`; `identity.user_identifier` |
| `0005_credential.sql` | schema `credential`; `credential.password`; `credential.password_history` |
| `0006_session.sql` | schema `session`; `session.session` |
| `0007_authentication.sql` | schema `authentication`; `authentication.attempt_counter` |
| `0008_authentication_transaction.sql` | `authentication.transaction` |
| `0009_authentication_transaction_binding.sql` | adds the column `binding` to `authentication.transaction` |
| `0010_notification.sql` | schema `notification`; `notification.message` |
| `0011_authentication_verification_token.sql` | `authentication.verification_token` |
| `0012_audit.sql` | schema `audit`; `audit.record`; `audit.chain_head`; function `audit.refuse_change()` with triggers `record_is_append_only` and `record_is_never_emptied` |
| `0013_authorization.sql` | schema `"authorization"`; `"authorization".role_assignment` |
| `0014_credential_access_token.sql` | `credential.access_token` |
| `0015_federation.sql` | schema `federation`; `federation.identity_provider`; `federation.external_identity` |
| `0016_federation_pending_authorization.sql` | `federation.pending_authorization` |
| `0017_federation_development_issuer.sql` | replaces the issuer check of `federation.identity_provider` |
| `0018_federation_github_and_trusted_email.sql` | adds the kind `github` and the column `trusts_email` to `federation.identity_provider` |
| `0019_federation_directories.sql` | adds the kind `ldap` and the `directory_*` columns to `federation.identity_provider` |
| `0020_federation_saml.sql` | adds the kind `saml` and the `saml_*` columns to `federation.identity_provider`; adds `saml_response` and `saml_receipt_hash` to `federation.pending_authorization` |
| `0021_federation_pending_authorization_expiry.sql` | adds the index `pending_authorization_expiry_idx` on `federation.pending_authorization (expires_at)`, for the cleanup job of `hodor-worker` |
| `0022_federation_saml_answer.sql` | keeps only the answer of a SAML response in `federation.pending_authorization`, never the response |
| `0023_keys.sql` | schema `keys`; table `keys.key_version` with the partial unique index `key_version_one_active` (one `active` row per tenant, use and algorithm) |
| `0024_oauth_clients.sql` | schema `oauth`; `oauth.application`; `oauth.client`; `oauth.client_secret`; `oauth.client_key`; `oauth.resource_server`; `oauth.resource_server_scope` |
| `0026_credential_totp.sql` | `credential.totp`: authenticator applications, with the secret sealed (`totp_one_per_status`, `totp_confirmed_when_active`) |
| `0027_credential_webauthn.sql` | `credential.webauthn_credential` (unique `webauthn_credential_id_unique` on tenant and credential identifier); `credential.webauthn_registration`; adds the column `challenge` to `authentication.transaction` |
| `0029_oauth_authorization.sql` | `oauth.authorization_request`; `oauth.authorization_grant`; `oauth.authorization_code` (a code lives at most 60 seconds; an S256 challenge is 43 base64url characters) |
| `0030_authorization_engine_binding.sql` | `"authorization".engine_binding`: which engine answers for a resource server, never `hodor:admin` |
| `0031_credential_recovery_codes.sql` | `credential.recovery_code_set` (`recovery_code_set_one_per_user`) and `credential.recovery_code`, with only the SHA-256 of each code (`recovery_code_hash_length`, `recovery_code_unique_in_set`) |
| `0032_keys_sealing_state.sql` | `keys.sealing_state`: whether a tenant refuses secrets of the first format; `hodor_app` may insert and read, never update or delete |
| `0035_oauth_client_assertion.sql` | `oauth.client_assertion`: the `jti` of every client assertion until it expires, once per client (`client_assertion_jti_shape`) |

No migration creates a type, an extension or seed rows; enumerations are text
columns with `CHECK ... IN (...)` constraints.

## Invariants

- Every table except `platform.tenant_directory` is put under row-level
  security by `platform.enable_tenant_rls`: it enables and forces row-level
  security, adds the policy `tenant_isolation` (`tenant_id =
  platform.current_tenant_id()`), adds the policy `platform_access` for
  `hodor_platform`, and grants `SELECT, INSERT, UPDATE, DELETE` to
  `hodor_app` and `hodor_platform` (`0001_platform_foundation.sql`).
- `platform.current_tenant_id()` reads `current_setting('app.tenant_id',
  true)`; an unset tenant matches no row (`0001_platform_foundation.sql`).
- `platform.tenant_directory` is deliberately outside row-level security,
  because a request is resolved from a slug before any tenant is known. The
  application roles may only read it; the trigger `tenant_directory_sync`,
  running with the owner's rights, is its only writer (`0003_tenant.sql`).
- A tenant's slug never changes (trigger `tenant_slug_is_immutable`) and is
  unique across tenants (constraint `tenant_slug_unique`) (`0003_tenant.sql`).
- Contexts do not reference each other's tables: user identifiers outside
  `identity` are deliberately not foreign keys (comments in
  `0005_credential.sql` and later files).
- `audit.record` is append-only: `UPDATE` and `DELETE` are revoked from
  `hodor_app` and `hodor_platform`, and the triggers `record_is_append_only`
  and `record_is_never_emptied` refuse changes from any role
  (`0012_audit.sql`). Each event is recorded once (constraint
  `record_event_once`).
- Secrets are stored as digests or sealed values, checked by constraints such
  as `session_token_hash_is_sha256`, `access_token_hash_is_sha256`,
  `verification_token_hash_is_sha256` and
  `identity_provider_secret_is_sealed`. Every access token expires
  (constraint `access_token_expires` in `0014_credential_access_token.sql`).
- The role names allowed in `"authorization".role_assignment` are
  `tenant_administrator` and `tenant_auditor` (constraint
  `role_assignment_role_known`).
- Each identity provider kind carries only its own settings: the
  `directory_*` columns are set only for `ldap`
  (`identity_provider_directory_settings`), and the `saml_*` columns only for
  `saml` (`identity_provider_saml_settings`).
- `keys.key_version` holds key material only as a provider sealed it
  (constraint `key_version_material_present`); the algorithm fits the use
  and the public key fits the algorithm, each state has the times it needs
  (`key_version_times_fit_state`), and `DELETE` is revoked from `hodor_app`
  (`0023_keys.sql`).

## Side Effects

- `0001_platform_foundation.sql` creates the cluster-wide roles `hodor_app`
  and `hodor_platform` when they do not exist.
- Each schema grants `USAGE` to `hodor_app` and `hodor_platform`.
- At run time, every insert into `tenant.tenant` and every change of its
  status upserts a row of `platform.tenant_directory`
  (`platform.sync_tenant_directory`).
- `0009_authentication_transaction_binding.sql` deletes every row of
  `authentication.transaction` before adding the required `binding` column.

## Verification

- Run: `cargo test -p hodor-adapters-postgres` (the crate embeds this
  directory through `sqlx::migrate!` in
  `crates/adapters-postgres/src/migrate.rs`).
