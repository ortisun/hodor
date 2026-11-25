# migrations

## Overview

The PostgreSQL schema, as forty-five numbered SQL files. A number is
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
| `0033_authorization_native_roles.sql` | `"authorization".permission`, `role`, `role_permission`, `role_inclusion`, `role_revision`; changes `"authorization".role_assignment` to hold users and clients, roles of any namespace, a scope and a start and end, with the earlier rows as built-in assignments of `hodor:admin` |
| `0035_oauth_client_assertion.sql` | `oauth.client_assertion`: the `jti` of every client assertion until it expires, once per client (`client_assertion_jti_shape`) |
| `0036_credential_passkey_registration.sql` | adds the column `passkey` to `credential.webauthn_registration` |
| `0037_authorization_policy_bundles.sql` | `platform.policy_agent_instance` (a platform table: Open Policy Agent instances with the digest of each credential; the application role may not delete); `"authorization".policy_bundle` (append only for the application role); `"authorization".policy_agent_status`; `"authorization".policy_agent_decision` |
| `0038_oauth_refresh_token.sql` | `oauth.refresh_token_family`: each family of refresh tokens with its grant, scopes, sealed secret, generation, the hash of its newest token, what its last move asked for and its lifetimes, under the bounds of the token policy; `oauth.refresh_token`: the hash of every token a family has had, one per generation |
| `0040_authorization_role_conditions.sql` | Adds `condition` to `"authorization".role_permission`: the text of a role's condition on the permission, or `NULL`, 1 to 1000 characters (`role_permission_condition_length`) |
| `0042_oauth_post_logout_redirect_uris.sql` | adds `post_logout_redirect_uris` to `oauth.client`, compared byte for byte, at most 10 (`client_post_logout_at_most_ten`) and only with `authorization_code` (`client_post_logout_needs_code`) |
| `0043_assurance_levels_and_step_up.sql` | lets `session.session` be `phishing_resistant` and adds `method_proven_at`; adds `carried_methods`, `demanded_assurance` and `raised_session_id` to `authentication.transaction`; adds `acr` to `oauth.authorization_code` and `oauth.refresh_token_family` |
| `0044_authorization_policy_lifecycle.sql` | `"authorization".policy_version` (a tenant's policy versions: files as JSON, digest, state, last report; never deleted by the application role), `"authorization".policy_publication` (the version each bundle revision came from; append only), `"authorization".policy_simulation` (inputs only while waiting, results once done); all under row-level security, with partial indexes on what waits for the worker |
| `0045_oauth_access_token.sql` | `oauth.access_token`: the register of access tokens, a record of each one by its `jti` with its client, grant and refresh token family (referenced with the tenant), when it expires and whether and why it was revoked; never the token; the index `access_token_expiry_idx` on `expires_at`, for the cleanup job |
| `0046_oauth_consent.sql` | `oauth.consent`: what a person agreed to for a client (never `offline_access`, at most 730 days); `oauth.consent_history`, which the application role may add to and read, never change or remove; adds `consent_seconds` to `oauth.client` (1 to 730 days) and to `oauth.authorization_request` whom a request waits for consent for and the answer (`authorization_request_consent_whole`, `authorization_request_consent_answer_known`) |
| `0047_oauth_client_id_token_algorithm.sql` | `oauth.client.id_token_algorithm`: how a client's ID tokens are signed, `ES256` (the default, and the value of every client made before it) or `RS256`, by the check constraint `client_id_token_algorithm_known` |
| `0048_authorization_decision_log.sql` | `"authorization".decision_log_setting` (a tenant's mode, share of allows, masks and retention) and `"authorization".decision_log`, partitioned by day on `decided_at` with a default partition, under row-level security on the partitioned table only, never updated; `"authorization".maintain_decision_log_partitions(today, days_ahead, keep_days)`, `SECURITY DEFINER`, executable by `hodor_platform` only, which prepares partitions (moving their day's rows out of the default one first) and drops the old; partitions for the week of the migration; an index for the retention of uploaded decisions |
| `0054_provisioning.sql` | schema `provisioning`; `provisioning.user_attribute` and `provisioning.group_attribute`: what SCIM carries of a user or a group that the identity context has no place for, keyed by the user or the group with the tenant first, without a foreign key to another context's tables; every text 1 to 256 characters (`user_attribute_text_length`, `group_attribute_text_length`); an index on each `external_id` |
| `0055_provisioning_changes.sql` | adds to `provisioning.user_attribute` `email_types` (`jsonb`, an object of the type of each address, `user_attribute_email_types_object`) and `removed_at`, when a `DELETE` deprovisioned the user under the policy that deactivates |
| `0056_workloads.sql` | `identity.workload_owner`: the owners of a service account or an agent, both referencing `identity."user"` with the tenant, never the workload itself, with `workload_owner_owner_idx`; `oauth.client.principal_id`, the workload a client acts as, allowed only with the `client_credentials` grant alone (`client_principal_only_client_credentials`); `oauth.access_token.principal_id`, the workload a token was issued for, with `access_token_principal_idx` |
| `0057_credential_api_key.sql` | `credential.api_key`: the API keys of service accounts and agents, each the SHA-256 of the key (`api_key_hash_unique` per tenant, `api_key_hash_is_sha256`), a hint of four hexadecimal characters, a name, 1 to 50 scopes, an optional application, an expiry after its making, a last use, a revocation complete with its reason, and the key that replaced it; the holder and the application are deliberately not references; indexes on the holder and on the expiry, for the cleanup job |
| `0058_oauth_token_exchange.sql` | replaces `client_principal_only_client_credentials` with `client_principal_grants` (a client with a principal has `client_credentials` and may have the token exchange grant besides) and `client_token_exchange_needs_principal`; adds `oauth.client.exchange_rules` (`jsonb`, an array of at most 20, empty exactly when the client lacks the grant, `client_exchange_rules_shape`); adds `oauth.access_token.parent_token_id`, the token an exchanged token came from, referenced with the tenant and removed with it (`access_token_parent_fk`), with `access_token_parent_idx` |
| `0060_webhooks.sql` | schema `webhooks`; `webhooks.endpoint` (address of 1 to 1000 characters, HTTP or HTTPS); `webhooks.subscription` (an endpoint's event types, indexed by tenant and type for the fan-out); `webhooks.signing_secret` (the sealed secret, `expires_at` `NULL` for the current one); `webhooks.delivery` (one per endpoint and event, `delivery_once_per_endpoint_and_event`; a body of at most 65536 bytes; `pending`, `delivered` or `set_aside`, finished exactly when not pending, leased only while pending); partial indexes for the due search, the leases of an endpoint and the cleanup. Numbers 0053 to 0059 are left to other work |
| `0061_authorization_access_entries.sql` | `authorization.access_entry`: the entries of access control lists, one principal (`user`, `client` or `group`, not a reference), one declared permission (a reference to `authorization.permission` with the tenant and the namespace, `ON DELETE CASCADE`) and one resource identifier of 1 to 255 characters, never `hodor:admin`; `resource_kind` generated from the permission; unique per principal, permission and resource (`access_entry_once`); `access_entry_resource_idx` for decisions and listings of a resource, `access_entry_principal_idx` for those of a principal |
| `0063_authentication_email_sign_in.sql` | `authentication.email_sign_in`: what was sent to sign in by email, one row per transaction (`PRIMARY KEY (tenant_id, transaction_id)`, the transaction not a foreign key), `method` `email_code` or `email_link`, `secret_hash` and `identifier_key` of 32 bytes, `user_id` null for nobody, never used without one (`email_sign_in_used_by_someone`); row-level security; an index on `expires_at` for the cleanup |
| `0065_oauth_backchannel_logout.sql` | adds to `oauth.client` `backchannel_logout_uri` (`COLLATE "C"`, 1 to 2000 characters, HTTP or HTTPS, `client_backchannel_logout_uri_form`; only with `authorization_code`, `client_backchannel_logout_needs_code`) and `backchannel_logout_session_required` (`false` by default; `true` only with an address, `client_backchannel_logout_session_needs_uri`); indexes `oauth.authorization_grant` by tenant and session (`authorization_grant_session_idx`); `oauth.logout_delivery` (a client, a session and a person, unique per client and session, `logout_delivery_once_per_client_and_session`; status, attempts, next attempt, lease, last answer and error as `webhooks.delivery` has them, with the same checks), under row-level security, with partial indexes for the due search, the leases of a client and the cleanup |
| `0068_authentication_transaction_enrollment.sql` | `authentication.transaction` gains `enrollment_kind` (`authenticator_application`, `security_key` or `passkey`, `transaction_enrollment_kind_known`) and `enrollment_id`, the credential context's enrollment or registration, not a foreign key; both null or both set (`transaction_enrollment_whole`) |
| `0070_oauth_pairwise_subjects.sql` | adds to `oauth.client` `subject_type` (`public` by default, `public` or `pairwise`, `client_subject_type_known`; `pairwise` only with `authorization_code`, `client_pairwise_needs_code`) and `sector_identifier_uri` (`COLLATE "C"`, 1 to 2000 characters, HTTP or HTTPS, `client_sector_identifier_uri_form`; only for a pairwise client, `client_sector_identifier_uri_needs_pairwise`); `oauth.pairwise_secret` (the tenant's sealed pairwise secret, one per tenant, `pairwise_secret_one_per_tenant`), under row-level security |
| `0072_oauth_claim_mappers.sql` | `oauth.claim_mapper`: the claim mappers of a client, referencing it with the tenant and going with it; one per claim and client without regard to case (`claim_mapper_claim_once` on `claim_normalized`, kept the lowercase of `claim`); targets among `id_token`, `access_token` and `userinfo`; the source an object of a known `kind`, a constant at most 2048 bytes as PostgreSQL writes it. |
| `0073_keys_trust_domains.sql` | `keys.trust_domain`: a tenant's SPIFFE trust domains, unique per tenant by name (`trust_domain_name_unique`, `trust_domain_name_shape` `^[a-z0-9._-]{1,255}$`); the source `uploaded`, `bundle_endpoint` or `mesh`, with an address exactly for `bundle_endpoint`, a bundle of at most 65536 bytes exactly unless `mesh`, a next refresh exactly for `bundle_endpoint` and a fetch, lease and failure only for it; the partial index `trust_domain_due_idx` on `next_refresh_at` of the `bundle_endpoint` rows for the worker |
| `0077_webhooks_subscription_since.sql` | adds `since` to `webhooks.subscription`: when the endpoint began to receive the type, so that the fan-out skips an event that happened before; existing subscriptions count from the migration |
| `0078_oauth_client_spiffe_id.sql` | adds `spiffe_jwt` to `client_method_known` and `oauth.client.spiffe_id` (`COLLATE "C"`, `client_spiffe_id_shape`: `spiffe://`, a trust domain's name and a path without `.` or `..` segments nor `*`, at most 2048 bytes; exactly with `spiffe_jwt`, `client_spiffe_id_with_spiffe_jwt`; only with a principal, `client_spiffe_id_needs_principal`), unique per tenant by the partial index `client_spiffe_id_unique`. Numbers 0074 to 0077 are left to other work |
| `0080_oauth_forwarded_client_identity.sql` | `oauth.client`: `client_method_known` widened to `spiffe_jwt`, `tls_client_auth`, `spiffe_x509` and `linkerd_identity`; `client_spiffe_id_with_spiffe_jwt` replaced by `client_identity_of_its_method`, which holds `spiffe_jwt` and `spiffe_x509` to a SPIFFE identifier, `linkerd_identity` to a Linkerd identity, `tls_client_auth` to one of the two and every other method to none; `linkerd_identity`, `COLLATE "C"`, shaped by `client_linkerd_identity_shape`, needing a principal (`client_linkerd_identity_needs_principal`), unique per tenant (`client_linkerd_identity_unique`) |
| `0082_oauth_certificate_bound_tokens.sql` | `oauth.client`: `certificate_bound_access_tokens`, `false` by default, refused with `linkerd_identity` by `client_certificate_bound_not_linkerd`; `oauth.refresh_token_family`: `certificate_thumbprint`, 32 bytes or null (`refresh_token_family_certificate_thumbprint_shape`), the certificate a public client's family is bound to |
| `0084_oauth_identity_binds_one_service_account.sql` | drops the unique indexes `client_spiffe_id_unique` and `client_linkerd_identity_unique` of `oauth.client` and creates the plain partial indexes `client_spiffe_id_bound` and `client_linkerd_identity_bound` on the tenant and the identity: an identity may bind several clients of the tenant acting as one principal, which the client store checks under a transaction-scoped advisory lock (Decision 0058) |
| `0094_keys_certificate_authority.sql` | `keys.certificate_authority`: the certificate authority of a tenant, one per tenant (primary key `tenant_id`), `root` or `intermediate`, `awaiting_certificate` (an intermediate only) or `active`; 1 to 10 trust domains, a root's lifetime exactly for a root, the key's provider, material and P-256 point, a request exactly for an intermediate, and the certificate with its serial number, validity, SHA-256 and activation time exactly when active; a chain of at most 5 for an intermediate only. Adds `authority` to `trust_domain_source_known` of `keys.trust_domain` |
| `0096_oauth_client_request_object_algorithm.sql` | `oauth.client.request_object_signing_alg`: how a client signs its request objects, `ES256`, `RS256`, `PS256` or `none` by the check constraint `client_request_object_signing_alg_known`, or null (none chosen, the value of every client made before it) |

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
- In `"authorization".role_assignment`, the namespace `hodor:admin` holds
  only `tenant_administrator` and `tenant_auditor`, given to users for the
  whole tenant without a start or end (constraint `role_assignment_built_in`);
  any other assignment names a role of `"authorization".role` through the
  generated column `role_namespace` (constraint `role_assignment_role_exists`,
  deleted with the role). No tenant table of native roles names
  `hodor:admin`, and a role cannot be removed while another includes it
  (constraint `role_inclusion_included_exists`).
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
