# hodor-federation application

## Overview

The use cases of the federation context. `FederationService` (`service.rs`) manages a tenant's identity providers and the links from external identities to users. `ExternalSignIn` (`sign_in.rs`) signs a person in through a provider. It uses one client per kind of provider: OpenID Connect (`openid.rs`), GitHub (`github.rs`), SAML (`saml.rs`), and LDAP directories through the `DirectoryClient` port. The port traits in `ports.rs` are implemented by adapter crates. Every module is `pub(crate)` (`mod.rs`), and the public items are re-exported in `hodor_federation::api` (`crates/federation/src/lib.rs`). The domain types used here are described in [domain](../domain/EGM.md).

## Interface

### Ports (`ports.rs`), implemented outside this crate

All ports are `async_trait` traits that are `Send + Sync`. Each store method takes `uow: &mut dyn UnitOfWork` and works inside the tenant the unit of work is bound to (doc comments).

| Trait | Methods | Implemented by |
| --- | --- | --- |
| `ProviderStore` | `insert`, `update`, `get`, `find_by_alias`, `list` (ordered by alias) | `PgProviderStore` in `crates/adapters-postgres/src/federation.rs`; `InMemoryFederation` in `crates/federation/src/testing.rs` |
| `LinkStore` | `insert -> bool`, `find`, `mark_used -> bool`, `list_for_user` (oldest first), `remove -> Option<UserId>` | `PgLinkStore` in `crates/adapters-postgres/src/federation.rs`; `InMemoryFederation` |
| `PendingAuthorizationStore` | `put`, `take`, `keep_response -> bool`, `remove_expired(now, limit) -> u64` | `PgPendingAuthorizationStore` in `crates/adapters-postgres/src/federation.rs`; `InMemoryFederation` |
| `DirectoryClient` | `verify(query, password) -> DirectoryAnswer` | `LdapDirectoryClient` in `crates/adapters-ldap/src/lib.rs` |
| `LockoutPolicy` | `rules(tenant) -> LockoutRules` | `TenantLockout` in `apps/hodor-server/src/main.rs` |

The value types that go with them:

- `DirectoryQuery` has the fields `address`, `bind_name`, `bind_password: Secret<String>`, `base`, `filter` and `attributes`. The filter arrives with the person's input already escaped.
- `DirectoryEntry` has the fields `name` and `attributes: Vec<(String, Vec<Vec<u8>>)>`. `first(attribute)` returns the first value of an attribute, matching the name case-insensitively.
- `DirectoryAnswer` is either `Verified(DirectoryEntry)` or `Refused(&'static str)`. The documented reasons for a refusal are `not_found`, `ambiguous` and `wrong_password`.

### Provider and link management (`service.rs`)

- `CreateProvider` has the fields `alias`, `kind`, `settings` and `client_secret`.
- `ChangeProvider` has the fields `id` and `settings`.
- `FederationService` is set up with these functions:
  - `new(units_of_work, providers, links, secrets, clock)`.
  - `allowing_directory_hosts(hosts)`: the `host:port` values this installation may connect to as directories.
  - `allowing_development_hosts(hosts)`: hosts whose issuer may use plain HTTP.
- Administration methods, each of which opens and commits its own unit of work:
  - `create_provider`
  - `change_provider`
  - `change_provider_secret`
  - `set_provider_status`
  - `unlink`
- Read methods, each of which opens a unit of work and never commits:
  - `provider(id)`
  - `provider_by_alias(alias)`
  - `providers()`
  - `links_of(user_id)`
- Methods that run in the caller's unit of work and do not commit:
  - `find_user(uow, provider_id, subject)`
  - `link(uow, provider_id, subject, user_id, caller)`
  - `mark_used(uow, provider_id, subject)`
- `client_secret(tenant, provider) -> Secret<String>` (asynchronous) opens the sealed client secret. Its doc comment says it is only for code that talks to the provider, and that the secret is never returned through an interface.

### Signing in (`sign_in.rs`)

- `ExternalSignIn` is set up with `new(federation, openid, github, saml, identity, pending, units_of_work, secrets, digest, clock, public_url)`. `with_directories(client, guard: AttemptGuard, policy)` adds directory sign-in. Its public methods are:
  - `offered(tenant) -> Vec<OfferedProvider>`: the enabled providers, by alias.
  - `callback_address(tenant_slug, alias)`.
  - `begin(tenant, tenant_slug, transaction_id, alias) -> String`: the address at the provider to send the person to.
  - `saml_metadata(tenant, tenant_slug, alias) -> String`: Hodor's metadata as XML, from `hodor_saml::metadata`.
  - `keep_saml_response(tenant, alias, relay_state, response) -> String`: stores a posted SAML response and returns a receipt for the browser.
- `ExternalIdentityAuthenticator::new(sign_in)` implements `hodor_authentication::api::Authenticator`:
  - `kind()` is `EXTERNAL_STEP` (`"external"`).
  - `traits()` sets `identifies: true`, `factor: Some(Factor::Knowledge)` and `method: Some("external")`.
  - `perform` returns `StepOutcome::Authenticated { user }` or `StepOutcome::Rejected`.
- `OfferedProvider` has the fields `alias`, `display_name` and `kind`.
- `callback_address(public_url, tenant_slug, alias)` returns `{public_url}/t/{tenant_slug}/account/providers/{alias}/callback`.

### Provider clients

- `OpenIdClient` (`openid.rs`):
  - `new(http, verifier, digest, random, clock)` and `allowing_development_hosts(hosts)` set it up.
  - `begin(provider, redirect_uri) -> AuthorizationRequest`.
  - `finish(provider, client_secret, redirect_uri, code, code_verifier, nonce) -> VerifiedIdentity`.
- `GitHubClient` (`github.rs`):
  - `new(http, random)` sets it up.
  - `begin(provider, redirect_uri) -> AuthorizationRequest`.
  - `finish(provider, client_secret, redirect_uri, code) -> VerifiedIdentity`.
- `SamlClient` (`saml.rs`):
  - `new(random)` sets it up. Its `receipt`, `begin` and `finish` methods are crate-private.
  - The public address helpers are `saml_assertion_consumer_address(public_url, tenant_slug, alias)`, which returns `{public_url}/t/{tenant_slug}/interaction/sign-in/providers/{alias}/saml`, and `saml_metadata_address(...)`, which returns that address followed by `/metadata`. The metadata address is also Hodor's entity identifier.
  - `saml_service_provider(...)` returns a `hodor_saml::ServiceProvider` built from those two addresses.
  - `MAX_SAML_POSTED_BYTES` equals `hodor_saml::MAX_POSTED_BYTES`.
- `AuthorizationRequest` (`openid.rs`) has the fields `url`, `state`, `nonce` and `code_verifier: Secret<String>`.
- `VerifiedIdentity` (`openid.rs`) has the fields `subject`, `email`, `email_verified`, `name` and `locale`.

## Invariants

### Managing providers and links (`service.rs`)

- `create_provider` validates before it opens a unit of work. In order, it calls `Alias::parse`, `ProviderSettings::checked_for(kind, development_hosts)` and `check_directory`, then seals the secret.
- `check_directory` applies to `Ldap` providers only. The `directory_host(issuer)` must be on the `allowing_directory_hosts` list, compared case-insensitively. Otherwise the call fails with `Forbidden` `federation.directory_not_allowed`. The list is empty by default.
- Client secrets are 1 to 4096 bytes (`MAX_SECRET_BYTES`); otherwise the call fails with `federation.client_secret_invalid`. They are sealed for the purpose `federation.client_secret`.
- A SAML provider must be created with an empty secret, and an empty value is sealed in its place. `change_provider_secret` refuses a SAML provider.
- A tenant may have at most `MAX_PROVIDERS` = 20 providers. `create_provider` counts them with `ProviderStore::list` in the same unit of work, and fails with `Conflict` `federation.too_many_providers` when the limit is reached.
- Missing records return `NotFound` errors:
  - A missing provider is `federation.provider_not_found`. `provider_by_alias` returns the same error for an alias that does not parse.
  - A missing link in `mark_used` or `unlink` is `federation.link_not_found`.
  - A subject that is already linked is `Conflict` `federation.identity_already_linked`, raised by `link`.
- `change_with` stores and commits only when the change produces an event. `change_provider` and `set_provider_status` therefore store nothing and announce nothing when nothing changed.
- Each event is recorded in the same unit of work as the write it describes, through `record` and `UnitOfWork::record_event`. Events and the methods that record them:
  - `ProviderCreated`: `create_provider`.
  - `ProviderChanged`: `change_provider`.
  - `ProviderSecretChanged`: `change_provider_secret`.
  - `ProviderEnabled` and `ProviderDisabled`: `set_provider_status`.
  - `IdentityLinked`: `link`.
  - `IdentityUnlinked`: `unlink`.
  - `SignInRefused`: `ExternalSignIn::record_refusal`.
  - `mark_used` records no event.

### Port contracts (`ports.rs` doc comments)

Adapters must keep these rules:

- `ProviderStore`:
  - `insert` returns `federation.alias_taken` for an alias the tenant already uses.
  - `update` succeeds only if the stored version is the version that was read. It then increments the version by one. Otherwise it returns `federation.provider_modified_concurrently`.
- `LinkStore`:
  - `insert` returns `false` and stores nothing when the subject is already linked.
  - `find` looks a link up by the provider and the subject only.
- `PendingAuthorizationStore`:
  - `put` replaces any previous pending authorization of the sign-in.
  - `take` is atomic: when several callers take at the same moment, only one gets it.
  - `keep_response` keeps a response only for an unexpired pending authorization that has no response yet, so the first response wins.
  - `remove_expired` removes up to `limit` of the tenant's pending authorizations that had expired at `now`, and returns how many; nobody can finish one of them any more.
- `DirectoryClient::verify` must refuse an empty password, and returns `federation.provider_unavailable` when the directory cannot be reached or refuses Hodor's bind.

### Signing in (`sign_in.rs`)

- A disabled provider is treated as one that does not exist (`ExternalSignIn::enabled`).
- `begin` refuses an `Ldap` provider with `federation.provider_not_found`, because nobody is sent to a directory.
- `begin` stores a `PendingAuthorization` with:
  - the SHA-256 hash of the state, not the state itself;
  - the code verifier, sealed for the purpose `federation.code_verifier`;
  - an expiry of `PENDING_LIFETIME` = 10 minutes.
- `finish` takes the pending authorization before it checks anything, so a sign-in cannot be finished twice. It then checks, in order:
  - the expiry;
  - that `provider` and `state` fields are present;
  - that the hash of the state matches;
  - that the provider is enabled and is the one the pending authorization names.
- A SAML sign-in finishes only with a stored response, and only when the browser presents a `receipt` whose SHA-256 hash matches the stored receipt hash (`finish_with_saml`).
- `keep_saml_response` returns a receipt in every case, so the caller always answers the same way. It stores the response only if all of these hold:
  - the provider is an enabled SAML provider;
  - the response is non-empty base64, at most `hodor_saml::MAX_POSTED_BYTES`;
  - the relay state is non-empty.
- Directory sign-in (`finish_with_directory`) happens when the submitted input has a `password` field (`ExternalIdentityAuthenticator::perform`). The rules, in order:
  - The identifier is trimmed and must be 1 to 255 characters with no control characters.
  - The attempt is counted with `AttemptGuard::admit` before the directory is asked. The lockout key is the SHA-256 hash of `directory:<provider id>:<lowercased identifier>`.
  - An empty password is refused before the directory is asked.
  - The identifier is escaped for the filter (RFC 4515 escaping in `escaped_for_filter`) and placed at `{identifier}`.
  - A subject value that is not text is written in hexadecimal.
  - `AttemptGuard::succeeded` is called only when the sign-in succeeds.
- `resolve` finds the user by provider and subject only. An external identity is never let into an existing account because of an email address (module doc comment):
  - If the identity is linked, the user must be able to sign in (`may_sign_in`), and the link is marked as used.
  - If it is not linked, a user is created only when `creates_users` is set, and only with an email address the provider vouched for (`email_verified`) or one the administrator trusts (`trusts_email`).
  - If the email address belongs to an existing user, the sign-in is refused with `email_belongs_to_a_user`, and the existing account is left unchanged.
  - The new user and the link are committed in one unit of work.
- Refusals are recorded as `SignInRefused` and never shown to the person. The authenticator returns only `Rejected`. The reason names are:
  - `no_pending_authorization`, `authorization_expired`, `answer_incomplete`, `state_mismatch`, `another_provider`, `provider_not_offered` and `another_kind`;
  - `answer_refused`, with the provider client's error detail;
  - `no_response` and `receipt_mismatch`;
  - `identifier_not_usable` and `empty_password`, plus the directory's own reasons;
  - `no_subject`, `user_may_not_sign_in`, `not_linked`, `no_vouched_email`, `email_belongs_to_a_user`, `profile_not_usable` and `linked_meanwhile`;
  - for SAML, the `hodor_saml::Reason` names, `certificate_unusable` and `subject`.

### Provider clients

- `OpenIdClient`, discovery and keys:
  - Discovery reads `{issuer}/.well-known/openid-configuration`, which must name exactly the configured issuer.
  - Endpoints must be `https://` (or plain HTTP at a development host) and at most 2048 bytes long.
  - The client secret goes in the HTTP Basic header by default. It goes in the request body only when the provider supports `client_secret_post` and not `client_secret_basic`.
  - The description and keys are kept for `KEPT_FOR_SECONDS` = 3600.
  - A token that names an unknown key causes the keys to be fetched again, at most once every `REFETCH_AFTER_SECONDS` = 60 per provider.
- `OpenIdClient`, `begin` and the token exchange:
  - `begin` makes a random hexadecimal state and nonce, and a proof key for code exchange (PKCE) with `code_challenge_method=S256`.
  - `finish` sends the `code_verifier` with the code.
- `OpenIdClient`, the checks on the ID token, in order (`OpenIdClient::check`):
  - The token is at most `MAX_TOKEN_BYTES` = 16 KiB and has three parts.
  - The algorithm is accepted by `SignatureAlgorithm::from_name`.
  - Exactly one published key fits the key id and the algorithm.
  - The signature verifies over the first two parts as they arrived. No claim is read before it does.
  - `iss` equals the configured issuer.
  - `aud` contains the client id. When there are several audiences, `azp` is required, and when present it must equal the client id.
  - `exp` and `iat` are required, and `exp`, `iat` and `nbf` are checked with `CLOCK_SKEW_SECONDS` = 60.
  - `nonce` is non-empty and equals the stored one.
  - `sub` passes `Subject::parse`.
  - `email_verified` counts only when it is the JSON value `true`.
- `GitHubClient`:
  - The subject is GitHub's numeric user `id`, never the login (`finish`).
  - The email is the first address that is both primary and verified. If there is none, the email is `None`.
  - `email_verified` is `email.is_some()`.
  - The interface is `https://api.github.com` for an issuer equal to `https://github.com`. For any other issuer it is `{issuer}/api/v3` (`interface_of`).
  - The access token is used once and never stored.
- `SamlClient::finish`:
  - It reads the certificate again; if it can no longer be used, the reason is `certificate_unusable`.
  - It calls `hodor_saml::check_response`, with the stored nonce as the request id.
  - The email and name come from the configured attributes. `email_verified` is always `false`.

### Errors

- Provider failures map to `Unavailable` `federation.provider_unavailable`. Answers that fail a check map to `Unauthenticated` `federation.identity_not_verified` (`openid.rs` and `github.rs`: `unavailable`, `not_verified`).

## Side Effects

- Network: `OpenIdClient` and `GitHubClient` send HTTP requests only through the `hodor_kernel::HttpClient` port. `DirectoryClient::verify` reaches LDAP through its adapter. `SamlClient` makes no network calls.
- Storage: writes go through `ProviderStore`, `LinkStore` and `PendingAuthorizationStore`, inside `hodor_kernel::UnitOfWork`s begun from `UnitOfWorkFactory`. The new user created on first sign-in is written through `hodor_identity::api::IdentityService::create_in`, in the same unit of work as the link.
- Events: `FederationEvent`s are recorded on the unit of work with `record_event`. They become durable when the unit of work commits.
- Secrets: the `hodor_kernel::SecretBox` port seals and opens client secrets (purpose `federation.client_secret`) and code verifiers (purpose `federation.code_verifier`).
- In-memory cache: `OpenIdClient` keeps each issuer's description and keys in an `Arc<Mutex<HashMap<String, Kept>>>`. Each server instance has its own cache.
- Clock, randomness and hashing go through the `Clock`, `RandomSource` and `Digest` ports.
- Lockout: directory attempts are counted through `hodor_authentication::api::AttemptGuard` (`admit`, `succeeded`), using the rules from `LockoutPolicy`.

## Verification

- Run: `cargo test -p hodor-federation`
