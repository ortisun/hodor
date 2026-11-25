# hodor-adapters-postgres source

## Overview

The PostgreSQL adapter. It implements the storage ports that the domain
crates declare: the unit of work and the unit of work factory from
`hodor-kernel`, and one store or repository per bounded context (audit,
authentication, authorization, credential, federation, identity,
notification, session, tenant). It also holds the outbox dispatcher, the
cleanup jobs for expired pending authorizations, records of access
tokens and every other kind of row that stopped being useful, the embedded schema
migrations, and a feature-gated test-support module.

Tenant data is reached only through a `TenantTransaction`
(`lib.rs` module documentation, `database.rs:Database::begin`). Every query
also filters on `tenant_id` explicitly; the module documentation calls
row-level security "the second line of defence".

All modules are private; the public surface is the set of re-exports in
`lib.rs`, plus `pub mod testing` behind the `testing` feature.

## Interface

### Connection, tenant transaction and unit of work

| Symbol | Source | What it is |
| --- | --- | --- |
| `connect_pool(url, max_connections)` | `database.rs` | Opens a plain `PgPool`, for connections that are not tenant-scoped. `Database::connect` uses it too. sqlx checks a connection with a ping when it is handed back; the pool pings it again before handing it out only when it has been idle for more than `CHECKED_IF_IDLE_FOR` (one second), not on every acquire. |
| `ping_pool(pool)` | `database.rs` | Runs `SELECT 1`, for readiness probes. |
| `Database` | `database.rs` | Handle to the database as the application role sees it: `connect`, `from_pool`, `begin(tenant)`, `ping`, `pool`. `pool()` is documented as "health checks only": queries on it have no tenant bound and see no tenant rows. |
| `TenantTransaction` | `database.rs` | A transaction bound to one tenant: `tenant_id`, `connection`, `commit`, `rollback`. |
| `PgUnitOfWork` | `uow.rs` | `impl UnitOfWork for PgUnitOfWork` (trait from `hodor_kernel`). Wraps a `TenantTransaction`, the `TenantContext` and the recorded `EventEnvelope`s. |
| `impl UnitOfWorkFactory for Database` | `uow.rs` | Trait from `hodor_kernel`. `begin` calls `Database::begin` and returns a boxed `PgUnitOfWork`. |
| `connection(uow)` | `uow.rs` | Returns the `PgConnection` behind a `dyn UnitOfWork`, for this crate's stores and for event handlers that write to the database. |
| `migrate(owner_pool)` | `migrate.rs` | Applies all pending migrations. |
| `OutboxDispatcher`, `DispatchReport` | `outbox.rs` | Delivers pending outbox events to `hodor_kernel::EventHandler`s. |
| `PendingAuthorizationCleanup`, `CleanupReport` | `cleanup.rs` | `new(platform, database)`; `run(now, batch)` finds, through the platform pool, up to 100 tenants (`TENANTS_PER_PASS`) that have pending authorizations expired at `now`, and in each tenant removes up to `batch` of them in its own unit of work, through `PgPendingAuthorizationStore::remove_expired`. The report counts the tenants and the rows removed. |
| `AccessTokenCleanup` | `cleanup.rs` | The same for the register: `new(platform, database)`; `run(now, batch)` finds up to 100 tenants with records of access tokens expired at `now`, and in each removes up to `batch` through `PgAccessTokenRecordStore::remove_expired`. |
| `ExpiredKind`, `ExpiredRowCleanup` | `cleanup.rs` | `ExpiredKind` names the fourteen kinds of row of the cleanup in `docs/operations/deployment.md` (`name`, `default_retention_days`, `FromStr`); each has two SQL statements written whole with `concat!` in `queries`, never assembled at run time. `ExpiredRowCleanup::new(kind, retention_days, platform, database)`; `run(now, batch)` finds up to 100 tenants with rows that stopped being useful before `now` less the retention, and in each removes up to `batch` of them, chosen with `FOR UPDATE SKIP LOCKED` by `ctid`, in a transaction of that tenant as the application role. |
| `DecisionLogMaintenance`, `DecisionLogMaintenanceReport` | `decision_log.rs` | `new(platform, database)`; `run(now, batch)` calls `"authorization".maintain_decision_log_partitions(now, DAYS_PREPARED_AHEAD = 7, 400)` through the platform pool (partitions created and dropped), then finds up to 100 tenants with records or uploaded decisions older than their retention and, in each, removes up to `batch` of each through the application role. |
| `KeyRotationJob`, `RotationPass` | `key_rotation.rs` | `new(platform, keys: KeyService, policy: RotationPolicy)`; `run(now)` takes `pg_try_advisory_xact_lock` (key `0x686f646f726b6579`, "hodorkey") in a transaction of the platform pool and, without it, answers `skipped`. With it, it finds up to 100 active tenants (`platform.tenant_directory`) that have something due by the rules of `KeySet::rotation_plan`, runs `KeyService::rotate_due` in each, and records a tenant's error in `failures` and goes on. `RotationPass { skipped, tenants, failures, changes }` with `was_full()`. The lock ends with the transaction. |
| `PolicyCheckJob`, `PolicyCheckPass` | `policy_lifecycle.rs` | `new(platform, policies: PolicyService, checker)`; `run()` takes `pg_try_advisory_xact_lock` (key `0x686f646f72706f6c`, "hodorpol"), finds up to 100 tenants with a version in `validating` or `testing` or a simulation `waiting`, through the platform pool, and calls `PolicyService::run_waiting` in each; a tenant whose run could not start is a failure of the pass |
| `MigrateError`, `Error`, `PgPool` | `lib.rs` | Re-exported from `sqlx`. |

### Port implementations

Each store is a unit struct (except where noted) that runs its queries on
`connection(uow)`, so it takes part in the caller's unit of work.

| Type | Port it implements (`impl ... for` line) | Tables named in its SQL |
| --- | --- | --- |
| `PgAuditLog` | `impl AuditLog for PgAuditLog` (`audit.rs`, trait from `hodor_audit::api`) | `audit.record`, `audit.chain_head` |
| `PgAttemptStore` | `impl AttemptStore for PgAttemptStore` (`authentication.rs`, `hodor_authentication::api`) | `authentication.attempt_counter` |
| `PgTransactionStore` | `impl TransactionStore for PgTransactionStore` (`authentication.rs`, `hodor_authentication::api`) | `authentication.transaction` |
| `PgVerificationTokenStore` | `impl VerificationTokenStore for PgVerificationTokenStore` (`authentication.rs`, `hodor_authentication::api`) | `authentication.verification_token` |
| `PgEmailSignInStore` | `impl EmailSignInStore for PgEmailSignInStore` (`authentication.rs`, `hodor_authentication::api`) | `authentication.email_sign_in` (`replace` is an upsert on the tenant and the transaction) |
| `PgRoleAssignmentStore` | `impl RoleAssignmentStore for PgRoleAssignmentStore` (`authorization.rs`, `hodor_authorization::api`) | `"authorization".role_assignment`, only the built-in roles of `hodor:admin` given to users (`principal_kind` `user`, `application` empty) |
| `PgNativeRoleStore` | `impl NativeRoleStore for PgNativeRoleStore` (`authorization.rs`, `hodor_authorization::api`) | `"authorization".permission`, `role`, `role_permission`, `role_inclusion`, `role_revision` and the assignments of `role_assignment` outside `hodor:admin`; `raise_revision` upserts and returns the new revision, locking the row until commit; `put_role` replaces what the role holds and includes; a removal blocked by `role_inclusion_included_exists` gives `authorization.role_in_use` |
| `PgAccessListStore` | `impl AccessListStore for PgAccessListStore` (`access_list.rs`, `hodor_authorization::api`) | `"authorization".access_entry` (migration 0061); `insert` is `ON CONFLICT ON CONSTRAINT access_entry_once DO NOTHING`; `allowing` matches the principals given as two arrays through `unnest`, on `access_entry_resource_idx`; `list` pages by identifier, the cursor the last one; a removed permission takes its entries with it (`ON DELETE CASCADE`) |
| `PgEngineBindingStore` | `impl EngineBindingStore for PgEngineBindingStore` (`authorization.rs`, `hodor_authorization::api`) | `"authorization".engine_binding`; `put` upserts on `(tenant_id, namespace)`; a stored row that is not a valid binding is `authorization.stored_data_invalid` |
| `PgInstanceStore` | `impl InstanceStore for PgInstanceStore` (`policy_bundles.rs`, `hodor_authorization_opa::api`); `new(Database)`, queries through the pool, not a unit of work; a taken name or credential is `authorization.policy_agent_instance_exists` | `platform.policy_agent_instance` |
| `PgBundleStore` | `impl BundleStore for PgBundleStore` (`policy_bundles.rs`); a taken revision is `authorization.bundle_revision_taken`; `latest_revision` reads the revision and its time without the archive | `"authorization".policy_bundle` |
| `PgInstanceStatusStore` | `impl InstanceStatusStore for PgInstanceStatusStore` (`policy_bundles.rs`); `record` upserts on `(tenant_id, instance_id)` | `"authorization".policy_agent_status` |
| `PgUploadedDecisionStore` | `impl UploadedDecisionStore for PgUploadedDecisionStore` (`policy_bundles.rs`); `record` inserts with `ON CONFLICT DO NOTHING` and counts the new rows | `"authorization".policy_agent_decision` |
| `PgDecisionLogStore` | `impl DecisionLogStore for PgDecisionLogStore` (`decision_log.rs`); `append` is one multi-row insert with `ON CONFLICT DO NOTHING`; `page` is keyset on `(decided_at, decision_id)`, its cursor `<microseconds>.<uuid>` | `"authorization".decision_log`, `"authorization".decision_log_setting` |
| `PgPolicyVersionStore` | `impl PolicyVersionStore for PgPolicyVersionStore` (`policy_lifecycle.rs`); files as JSON text, `list` without them; a taken number is `authorization.policy_version_taken`; `transition` updates only from the state it names | `"authorization".policy_version` |
| `PgPublicationStore` | `impl PublicationStore for PgPublicationStore` (`policy_lifecycle.rs`); a taken revision is `authorization.policy_publication_taken` | `"authorization".policy_publication` |
| `PgSimulationStore` | `impl SimulationStore for PgSimulationStore` (`policy_lifecycle.rs`); `finish` sets the inputs to `NULL` | `"authorization".policy_simulation` |
| `PgPasswordStore` | `impl PasswordStore for PgPasswordStore` (`credential.rs`, `hodor_credential::api`) | `credential.password`, `credential.password_history` |
| `PgAccessTokenStore` | `impl AccessTokenStore for PgAccessTokenStore` (`credential.rs`, `hodor_credential::api`) | `credential.access_token` |
| `PgTotpStore` | `impl TotpStore for PgTotpStore` (`credential.rs`, `hodor_credential::api`); `activate` locks the pending row with `FOR UPDATE`, `use_step` is one conditional `UPDATE` | `credential.totp` |
| `PgWebAuthnStore` | `impl WebAuthnStore for PgWebAuthnStore` (`credential.rs`, `hodor_credential::api`) | `credential.webauthn_credential`, `credential.webauthn_registration` |
| `PgRecoveryCodeStore` | `impl RecoveryCodeStore for PgRecoveryCodeStore` (`credential.rs`, `hodor_credential::api`); `replace` deletes the user's set and inserts the new one, a second set at the same moment refused by `recovery_code_set_one_per_user` as `credential.recovery_codes_conflict`; `use_code` is one conditional `UPDATE` | `credential.recovery_code_set`, `credential.recovery_code` |
| `PgProviderStore` | `impl ProviderStore for PgProviderStore` (`federation.rs`, `hodor_federation::api`) | `federation.identity_provider` |
| `PgLinkStore` | `impl LinkStore for PgLinkStore` (`federation.rs`, `hodor_federation::api`) | `federation.external_identity` |
| `PgPendingAuthorizationStore` | `impl PendingAuthorizationStore for PgPendingAuthorizationStore` (`federation.rs`, `hodor_federation::api`) | `federation.pending_authorization` |
| `PgApplicationStore` | `impl ApplicationStore for PgApplicationStore` (`oauth.rs`, `hodor_oauth::api`) | `oauth.application` |
| `PgClientStore` | `impl ClientStore for PgClientStore` (`oauth.rs`, `hodor_oauth::api`); `update` checks the version, then replaces the client's secrets and keys | `oauth.client` (with `backchannel_logout_uri` and `backchannel_logout_session_required`, migration 0065, `subject_type` and `sector_identifier_uri`, migration 0070, `spiffe_id`, migration 0078, `linkerd_identity`, migration 0080, `certificate_bound_access_tokens`, migration 0082, and `request_object_signing_alg`, migration 0096; `insert` and `update` take an advisory lock on the tenant and the identity and refuse a client whose identity a client of another principal holds, `oauth.client_spiffe_id_taken` or `oauth.client_linkerd_identity_taken`, migration 0084; `bound_to` reads through `client_spiffe_id_bound` and `client_linkerd_identity_bound`), `oauth.client_secret`, `oauth.client_key` |
| `PgAuthorizationRequestStore` | `impl AuthorizationRequestStore` (`oauth_authorization.rs`); the request as `jsonb`, whom it waits for consent for in `consent_user_id` and `consent_session_id`; `authorization_request_client_fk` is `oauth.client_not_found`; `remove` deletes and answers whether a row went; `answer` is one `UPDATE … WHERE consent_user_id IS NOT NULL AND consent_answer IS NULL` | `oauth.authorization_request` |
| `PgGrantStore` | `impl GrantStore` (`oauth_authorization.rs`); `authorization_grant_client_fk` is `oauth.client_not_found`; `list_active_for` oldest first | `oauth.authorization_grant` |
| `PgConsentStore` | `impl ConsentStore` (`oauth_consent.rs`); `save` is an `INSERT … ON CONFLICT DO UPDATE` on the person and the client; `record` inserts a history row with a new UUIDv7; `consent_client_fk` and `consent_history_client_fk` are `oauth.client_not_found` | `oauth.consent`, `oauth.consent_history` |
| `PgAuthorizationCodeStore` | `impl AuthorizationCodeStore` (`oauth_authorization.rs`); `redeem` is one `UPDATE … WHERE redeemed_at IS NULL`, so of two at once one wins; `authorization_code_grant_fk` is `oauth.grant_not_found` | `oauth.authorization_code` |
| `PgRefreshTokenStore` | `impl RefreshTokenStore` (`oauth_refresh.rs`); `start` inserts the family and its first token; `find` joins a token's hash to its family; `advance` is one `UPDATE … WHERE generation = $3 AND status = 'active'`, so of two at once one moves the family, then inserts the next token; `get` reads a family by its identifier; a family's `certificate_thumbprint` (migration 0082) is read and written with it; `refresh_token_family_grant_fk` and `refresh_token_family_client_fk` are `oauth.grant_not_found` | `oauth.refresh_token_family`, `oauth.refresh_token` |
| `PgAccessTokenRecordStore` | `impl AccessTokenRecordStore` (`oauth_access_token.rs`); `record` inserts a record; `access_token_client_fk`, `access_token_grant_fk` and `access_token_family_fk` are `oauth.client_not_found`, `oauth.grant_not_found` and `oauth.refresh_token_family_not_found`; `revoke` is one `UPDATE … WHERE client_id = $3 AND revoked_at IS NULL`, so of two at once one revokes; `revoke_for_principal` is one `UPDATE … WHERE principal_id = $2 AND revoked_at IS NULL RETURNING client_id, token_id`, on the index `access_token_principal_idx` (migration 0056); `parent_token_id` is kept (migration 0058), and `access_token_parent_fk` is `oauth.access_token_not_found`; `remove_expired` removes a locked batch chosen once | `oauth.access_token` |
| `PgClaimMapperStore` | `impl ClaimMapperStore` (`oauth_claim_mapper.rs`); `lock_client` is a `SELECT … FOR UPDATE` of the client's row; `claim_normalized` is written as `lower(claim)`; `claim_mapper_client_fk` is `oauth.client_not_found` and `claim_mapper_claim_once` `oauth.claim_mapper_name_taken`; `update` checks the version and the client; `list_for_client` orders by claim | `oauth.claim_mapper` |
| `PgClientAssertionStore` | `impl ClientAssertionStore` (`oauth_token.rs`); `remember` is one `INSERT … ON CONFLICT DO NOTHING` on the primary key, so of two at once one is first; `client_assertion_client_fk` is `oauth.client_not_found`. It remembers the mark of a JWT-SVID (`jwt-svid:` and its hash) as it remembers a `jti` | `oauth.client_assertion` |
| `PgResourceServerStore` | `impl ResourceServerStore for PgResourceServerStore` (`oauth.rs`, `hodor_oauth::api`); maps the constraints `resource_server_audience_unique`, `resource_server_application_unique` and `resource_server_application_fk` to `oauth.audience_taken`, `oauth.application_has_resource_server` and `oauth.application_not_found` | `oauth.resource_server`, `oauth.resource_server_scope` |
| `PgUserRepository` | `impl UserRepository for PgUserRepository` (`identity.rs`, `hodor_identity::api`) | `identity."user"`, `identity.user_identifier` |
| `PgApiKeyStore` | `impl ApiKeyStore` (`api_key.rs`); `api_key_hash_unique` is `credential.api_key_taken`; `update` writes only the expiry, the revocation and the successor; `record_use` is one `UPDATE … WHERE last_used_at IS NULL OR last_used_at <= now - precision`, so a busy key is written once a minute; `list_of` orders by identifier, newest first | `credential.api_key` (migration 0057) |
| `PgWorkloadRepository` | `impl WorkloadRepository` (`identity.rs`); `list` reads the users of one kind that are not `deleted`; `replace_owners` deletes the owners not kept and inserts the others with `ON CONFLICT DO NOTHING`, so the kept ones keep `added_at`, and maps a foreign key violation (a user of no such tenant) to `identity.user_not_found`; `owners` orders by `added_at`, then `owner_id` | `identity.workload_owner` (migration 0056) |
| `PgGroupRepository`, `PgGroupPolicy` | `group.rs` | Groups on `identity."group"` and `identity.group_member` (migration 0049): a name unique per tenant by `group_name_unique`, members keyed by `member_id`, the column the database makes from `user_id` or `member_group_id`; `lock_nesting` takes `pg_advisory_xact_lock` on a key made from the tenant. `PgGroupPolicy` reads `settings -> 'groups' ->> 'max_depth'` of `tenant.tenant`, the default when absent. |
| `PgProvisionedUserRepository`, `PgProvisionedGroupRepository`, `PgDeprovisioningPolicy` | `provisioning.rs` | What SCIM keeps on `provisioning.user_attribute` (with `email_types` and `removed_at`, migration 0055) and `provisioning.group_attribute` (migration 0054); users removed by a `DELETE` while Deactivated are never found. `PgDeprovisioningPolicy` reads `settings -> 'provisioning' ->> 'deprovisioning'` of `tenant.tenant` in the change's transaction, `deactivate` when absent. What is kept is put with `INSERT … ON CONFLICT DO UPDATE`. `find` compiles a filter into SQL over `identity."user"`, `identity.user_identifier`, `identity."group"` and `identity.group_member` joined with those tables, read only: every value a bound parameter, every attribute a fixed expression, text folded with `translate` of `A` to `Z`, ordered with `COLLATE "C"`, each comparison `COALESCE(…, false)`; one `count(*)` and one page with `LIMIT` and `OFFSET`, ordered by the sort key then the identifier. |
| `PgOrganizationRepository` | `organization.rs` | Organizations on `identity.organization`, `identity.organization_unit`, `identity.organization_member` and `identity.organization_member_unit` (migration 0050). Foreign keys over `(tenant_id, organization_id, …)` keep a parent and the units of a membership inside one organization; `organization_unit_parent_fk`, checked at the end of the statement, refuses a unit with units below (`identity.unit_not_empty`) while deleting an organization takes its tree; sibling names are unique with `NULLS NOT DISTINCT`; `lock_tree` takes `pg_advisory_xact_lock` on a key made from the tenant and the organization. |
| `PgMessageQueue` | `impl MessageQueue for PgMessageQueue` (`notification.rs`, `hodor_notification::api`) | `notification.message` |
| `PgEndpointStore` | `impl EndpointStore for PgEndpointStore` (`webhooks.rs`, `hodor_webhooks::api`) | `webhooks.endpoint`, `webhooks.subscription` (rewritten whole on every change), `webhooks.signing_secret`; `count` takes `pg_advisory_xact_lock` on a key made from the tenant; `lock` is `FOR UPDATE` (migration 0060) |
| `PgDeliveryStore` | `impl DeliveryStore for PgDeliveryStore` (`webhooks.rs`) | `webhooks.delivery`; `insert` is `ON CONFLICT ON CONSTRAINT delivery_once_per_endpoint_and_event DO NOTHING`; `take` is `FOR UPDATE SKIP LOCKED`, `lock` `FOR UPDATE`; a foreign key naming an endpoint the tenant does not have answers `webhooks.endpoint_not_found` |
| `PgDueDeliveries` (holds a platform `PgPool`; `new(platform)`) | `impl DueDeliveries for PgDueDeliveries` (`webhooks.rs`) | `webhooks.delivery`, across tenants |
| `PgPairwiseSecretStore` | `impl PairwiseSecretStore for PgPairwiseSecretStore` (`oauth_pairwise.rs`, `hodor_oauth::api`); `find` reads the tenant's sealed secret; `insert_unless_present` is `ON CONFLICT (tenant_id) DO NOTHING`, so of two at once the second changes nothing | `oauth.pairwise_secret` (migration 0070) |
| `PgSessionClients` | `impl SessionClients for PgSessionClients` (`oauth_logout.rs`, `hodor_oauth::api`): the distinct clients of the grants of a session whose scopes hold `openid` | `oauth.authorization_grant`, by `authorization_grant_session_idx` (migration 0065) |
| `PgLogoutDeliveryStore` | `impl LogoutDeliveryStore for PgLogoutDeliveryStore` (`oauth_logout.rs`); `insert` is `ON CONFLICT ON CONSTRAINT logout_delivery_once_per_client_and_session DO NOTHING`, and a foreign key naming a client the tenant does not have answers `oauth.client_not_found`; `take` is `FOR UPDATE SKIP LOCKED`, `lock` `FOR UPDATE`; `hold_client` is `FOR NO KEY UPDATE` on the client, which a delivery being inserted for it does not wait for | `oauth.logout_delivery` (migration 0065) |
| `PgDueLogoutDeliveries` (holds a platform `PgPool`; `new(platform)`) | `impl DueLogoutDeliveries for PgDueLogoutDeliveries` (`oauth_logout.rs`) | `oauth.logout_delivery`, across tenants |
| `PgPendingMessages` (holds a platform `PgPool`; `new(platform)`) | `impl PendingMessages for PgPendingMessages` (`notification.rs`, `hodor_notification::api`) | `notification.message` |
| `PgKeyStore` | `impl KeyStore for PgKeyStore` (`keys.rs`, `hodor_keys::api`); an activation that would leave two active versions gives `Conflict` `keys.activation_conflict` | `keys.key_version` |
| `PgSealingStateStore` | `impl SealingStateStore for PgSealingStateStore` (`keys.rs`, `hodor_keys::api`); refusing twice changes nothing | `keys.sealing_state` |
| `PgTrustDomainStore` | `impl TrustDomainStore for PgTrustDomainStore` (`trust_domain.rs`, `hodor_keys::api`); a name taken in the tenant gives `Conflict` `keys.trust_domain_name_taken` from `trust_domain_name_unique`; `count` takes a transaction advisory lock per tenant; `update` needs the version read and increments it; `take` is `FOR UPDATE SKIP LOCKED`, `lock` `FOR UPDATE`; the bundle is stored as kept, with its sequence and refresh hint beside it | `keys.trust_domain` |
| `PgAuthorityStore` | `impl AuthorityStore for PgAuthorityStore` (`certificate_authority.rs`, `hodor_keys::api`); one row per tenant, a second giving `Conflict` `keys.authority_exists` from `certificate_authority_pkey`; `lock` is `FOR UPDATE`; `update` needs the version read and increments it (`keys.authority_changed`, `keys.authority_not_found`), and changes only the state, the certificate, the chain and the times | `keys.certificate_authority` |
| `PgIntermediateStore` | `impl IntermediateStore for PgIntermediateStore` (`intermediates.rs`, `hodor_keys::api`); `list` is of one authority by descending identifier before a cursor; `of_key` finds every intermediate of the tenant by `public_key_sha256`; `update` changes only the withdrawal and needs the version read (`keys.intermediate_changed`, `keys.intermediate_not_found`); `withdrawn_keys` is the distinct hashes of withdrawn intermediates whose `not_after` is still ahead | `keys.intermediate` |
| `PgDueRefreshes` (holds a platform `PgPool`; `new(platform)`) | `impl DueRefreshes for PgDueRefreshes` (`trust_domain.rs`) | `keys.trust_domain`, across tenants: `bundle_endpoint` rows due and not leased, by `next_refresh_at` |
| `reseal_tenant`, `ResealReport`, `SEALED_COLUMNS`, `SealedColumn` | `resealing.rs`: `reseal_tenant(database, &dyn SecretBox, tenant)` reads each column of `SEALED_COLUMNS` 100 rows at a time and writes a secret sealed again only if the row still holds what was read, one transaction per row. `ResealReport { resealed, current, unreadable }` with `complete()`. What `hodor-cli secrets reseal` runs | `federation.identity_provider.client_secret`, `federation.pending_authorization.code_verifier`, `credential.totp.sealed_secret`, `oauth.refresh_token_family.sealed_secret`, `oauth.pairwise_secret.sealed_secret`, `webhooks.signing_secret.sealed_secret` |
| `PgSessionStore` | `impl SessionStore for PgSessionStore` (`session.rs`, `hodor_session::api`) | `session.session` |
| `PgTenantRepository` | `impl TenantRepository for PgTenantRepository` (`tenant.rs`, `hodor_tenant::api`) | `tenant.tenant` |
| `PgTenantDirectory` (holds a `Database`; `new(database)`) | `impl TenantDirectory for PgTenantDirectory` (`tenant.rs`, `hodor_tenant::api`) | `platform.tenant_directory` |

The outbox and the unit of work write to `platform.outbox`
(`uow.rs:PgUnitOfWork::commit_now`, `outbox.rs`).

### Test support (`testing.rs`, feature `testing`)

Compiled only with the `testing` feature (`lib.rs`:
`#[cfg(feature = "testing")] pub mod testing`).

- `TestDatabase::start()` starts a disposable PostgreSQL container
  (`testcontainers_modules::postgres::Postgres`, image tag `17-alpine`)
  through `hodor_test_containers::start_checked`, which publishes port 5432
  on `127.0.0.1` alone; every address it gives connects to `127.0.0.1`. It
  waits up to thirty seconds for the first connection as the owner
  (`first_connection`), applies the migrations as the owner, creates the
  login roles `hodor_app_login` (in role `hodor_app`) and
  `hodor_platform_login` (in role `hodor_platform`), and connects.
  Accessors: `owner`, `app`, `platform`, `app_url`, `platform_url`. A
  container that does not start, stops before its port is given, or never
  accepts the first connection is replaced, three containers at most, after
  which it panics with the reason each one failed; at most two starts run at
  once (`STARTS` semaphore). The container is removed when the value is
  dropped.
- `schema_violations(owner)` reads the catalog and returns one message per
  table that breaks the tenant isolation rules (see Invariants). Only
  `public._sqlx_migrations`, `platform.tenant_directory` and
  `platform.policy_agent_instance` are exempt (`PLATFORM_TABLES`).

## Invariants

### Tenant binding

- `Database::begin` sends `BEGIN; SELECT set_config('app.tenant_id',
  '<uuid>', true)` as one simple query, one round trip (`begin_statement`,
  the tenant's UUID written in). The setting is transaction-local, so it disappears at commit
  or rollback and never leaks to the next user of a pooled connection; the
  documentation says this also keeps the adapter compatible with connection
  poolers in transaction mode (`database.rs:Database::begin`).
- Dropping a `TenantTransaction` without `commit` rolls back
  (`database.rs:TenantTransaction`). `PgUnitOfWork` has no `Drop` of its own,
  so dropping it rolls back the same way.
- Every store query is scoped by `tenant_id = uow.tenant().tenant_id()`.
  Exceptions that are cross-tenant on purpose:
  `PgPendingMessages::due` and the first query of
  `OutboxDispatcher::dispatch_batch`, both on a pool that connects as a member
  of `hodor_platform`, and `PgTenantDirectory`, which reads
  `platform.tenant_directory` through `Database::pool()`.
- `PgTenantRepository::update` addresses the row by the unit of work's
  tenant, not by the aggregate's own identifier alone: "a tenant can only
  update itself" (`tenant.rs`).

### Unit of work

- `connection(uow)` downcasts with `as_any_mut().downcast_mut::<PgUnitOfWork>()`.
  A unit of work from another adapter gives
  `DomainError::internal("database.foreign_unit_of_work", ...)`, which the
  documentation calls a wiring bug (`uow.rs:connection`).
- `PgUnitOfWork::record_event` only buffers. `commit_now` inserts every
  recorded event into `platform.outbox` inside the same transaction, then
  commits, so a state change and its events are committed together or not at
  all (`uow.rs:PgUnitOfWork::commit_now`).
- Every `sqlx::Error` becomes
  `DomainError::internal("database.error", "the operation could not be completed")`;
  the driver message is kept only as operator detail (`uow.rs:database_error`).

### Outbox dispatch

- `dispatch_batch(limit)` finds pending events on the platform pool:
  `dispatched_at IS NULL AND next_attempt_at <= now()`, ordered by
  `created_at`. It then handles each one in a unit of work of the event's
  tenant, built with `TenantContext::assume` from the stored `tenant_id`
  (`outbox.rs:dispatch_batch`).
- Each event is re-read with `FOR UPDATE SKIP LOCKED`, so several dispatchers
  may run at once. A row already locked or already dispatched counts as
  `skipped` (`outbox.rs:dispatch_one`).
- Only handlers whose `handles(&event.event_type)` is true are called, in
  order, all inside one transaction, together with the update that sets
  `dispatched_at`. The first handler error stops the dispatch, and dropping
  the unit of work rolls back every handler's work for that event
  (`outbox.rs:dispatch_one`).
- On failure, `attempts` is incremented, `last_error` is stored (truncated to
  `MAX_ERROR_LENGTH`, 2,000 bytes, at a character boundary), and
  `next_attempt_at` is set to `now() + least(power(2, attempts), 3600)`
  seconds. The code sets no maximum number of attempts
  (`outbox.rs:record_failure`).
- Handler failures are counted in `DispatchReport.failed`, not returned as
  errors; only database failures return `Err` (`outbox.rs:dispatch_batch`).

### Migrations

- Migrations are embedded at compile time:
  `static MIGRATOR: Migrator = sqlx::migrate!("../../migrations")`, the
  repository's top-level `migrations/` folder (`migrate.rs`).
- `migrate` must be given a pool that connects as the schema owner, not as
  the application role. The documentation says migrations are applied by
  `hodor-cli migrate`, never by the server at startup, and that `migrate`
  fails if the database holds a migration this binary does not know
  (`migrate.rs:migrate`).

### Concurrency and single use

- Optimistic concurrency on a `version` column: `PgTransactionStore::update`,
  `PgPasswordStore::update`, `PgUserRepository::update`,
  `PgTenantRepository::update` and `PgProviderStore::update` update only
  `WHERE ... AND version = $n` and bump the version. When no row changes,
  the first four check existence to choose between a `conflict`
  (`*_modified_concurrently`) and a `not_found` error;
  `PgProviderStore::update` always returns
  `federation.provider_modified_concurrently`.
- `PgAttemptStore::lock` creates and row-locks the counter in one upsert with
  a no-op `DO UPDATE`, so a second transaction for the same subject waits
  (`authentication.rs`). `PgAuditLog` locks the per-tenant chain head the
  same way before appending (`audit.rs:lock_head`).
- `PgVerificationTokenStore::use_up` consumes a token in one `UPDATE` that
  requires `used_at IS NULL`, `replaced_at IS NULL` and `expires_at > now`
  (`authentication.rs`).
- `PgEmailSignInStore::use_up` uses a code or a link in one `UPDATE` that
  requires the hash and the method, `used_at IS NULL`, `user_id IS NOT NULL`
  and `expires_at > now`; when it changes nothing, a `SELECT` tells a
  secret just used by another request (`AlreadyUsed`) from anything else
  (`authentication.rs`).
- `PgPendingAuthorizationStore::take` is one `DELETE ... RETURNING`: of
  several concurrent callers, one gets the row. `keep_response` keeps a
  posted SAML response only if none is kept yet and the authorization has not
  expired: the first response wins (`federation.rs`).
  `remove_expired` chooses its batch once, in a common table expression
  with `LIMIT` and `FOR UPDATE SKIP LOCKED`, and deletes only those rows of
  the unit of work's tenant (`federation.rs`).
- `PgMessageQueue::take` reads a `pending` message with
  `FOR UPDATE SKIP LOCKED`: a message held by another worker is skipped, not
  waited for (`notification.rs`).

### Stored data and error mapping

- Secrets are stored as hashes or sealed values only: token hashes for
  sessions, access tokens and verification tokens, password hashes for
  passwords, and `SealedSecret` bytes for provider client secrets and
  pending code verifiers. No plaintext secret column appears in the SQL.
- Named constraint violations become domain errors:
  `tenant_slug_unique` gives `tenant.slug_taken`,
  `user_identifier_value_unique` gives `identity.identifier_taken`,
  `identity_provider_alias_unique` gives `federation.alias_taken`, and
  `external_identity_provider_fk` or `pending_authorization_provider_fk`
  give `federation.provider_not_found`. A unique violation on the audit
  record insert gives `audit.already_recorded`.
- `PgPasswordStore::insert`, `PgRoleAssignmentStore::assign` and
  `PgLinkStore::insert` use `ON CONFLICT ... DO NOTHING` and report through
  the affected row count (a `credential.password_exists` conflict, or a
  `bool`). The comment in `credential.rs` gives the reason: catching the
  error instead would leave a failed statement that aborts the whole
  transaction.
- Rows that cannot be read back give `<context>.stored_data_invalid`
  internal errors (wrong hash length, negative version, unknown stored enum
  value).

## Side Effects

- PostgreSQL reads and writes on the tables listed above, all inside the
  caller's tenant transaction except the cross-tenant reads named under
  Invariants.
- `PgUnitOfWork::commit_now` inserts into `platform.outbox`;
  `OutboxDispatcher` updates `dispatched_at`, `attempts`, `last_error` and
  `next_attempt_at` there and calls the configured event handlers.
- Row locks: `authentication.attempt_counter` (upsert), `audit.chain_head`
  (upsert), `platform.outbox` and `notification.message`
  (`FOR UPDATE SKIP LOCKED`).
- `PgPasswordStore::update` and `PgUserRepository::update` delete and
  re-insert the user's password history rows or identifier rows.
- `migrate` changes the schema.
- `testing.rs` (feature `testing` only) starts a Docker container through
  `hodor-test-containers` and creates two login roles in it.

## Verification

- Run: `cargo test -p hodor-adapters-postgres` (needs a running Docker
  daemon; see [the crate contract](../EGM.md)).
