# crates

## Overview

The library crates of the Hodor Cargo workspace (`members = ["crates/*", "apps/*", "tests/*"]` in the root `Cargo.toml`). They are arranged in layers that `tests/architecture/src/lib.rs` (`RULES`) enforces:

- Layer 0, the shared kernel: `hodor-kernel`.
- Layer 1, the base bounded contexts: `hodor-tenant`, `hodor-identity`, `hodor-credential`, `hodor-session`, `hodor-keys`, `hodor-audit`, `hodor-notification`, `hodor-authorization`. Each may depend only on `hodor-kernel`.
- Layer 2, the orchestrating contexts: `hodor-authentication` (depends on kernel, identity, credential, session, tenant and notification), `hodor-oauth` (allowed kernel, identity, session, keys and tenant; today it depends on the kernel, keys and session) and `hodor-saml` (kernel only in the rules; its `Cargo.toml` lists no workspace crate).
- Layer 3, the context extensions: `hodor-federation` (kernel, authentication, identity, saml) and `hodor-authorization-opa` (kernel, authorization).
- Layer 4, the adapters: `hodor-adapters-postgres`, `hodor-adapters-crypto`, `hodor-adapters-http`, `hodor-adapters-ldap`, `hodor-adapters-smtp`, `hodor-observability` and `hodor-protocol-http`.

Each bounded context crate keeps `application` and `domain` private and exposes one `api` module. Its storage and outside-world needs are port traits in `src/application/ports.rs`, which adapters implement. Every bounded context crate also has a `testing` module behind `cfg(any(test, feature = "testing"))`, with in-memory port implementations and port contract suites. The binaries in `apps/` wire the crates together.

## Subdirectories & Boundaries

Shared foundation:

- kernel: [./kernel/EGM.md](./kernel/EGM.md) - Typed identifiers (UUID version 7), `TenantContext`, `DomainError` and `ErrorKind`, events (`EventEnvelope`, `EventHandler`, `DomainEvent`), paging, `Secret` and `SealedSecret`, and the port traits `Clock`, `RandomSource`, `Digest`, `SecretBox`, `SignatureVerifier`, `HttpClient`, `UnitOfWork` and `UnitOfWorkFactory`. Depends on no other Hodor crate.
- observability: [./observability/EGM.md](./observability/EGM.md) - `Telemetry::init`, `flush` and `shutdown`: installs the global tracing subscriber that writes structured logs to standard output, and optional OpenTelemetry trace and metric exporters over HTTP.

Bounded contexts:

- tenant: [./tenant/EGM.md](./tenant/EGM.md) - `TenantService`, the tenant lifecycle (`Provisioning`, `Active`, `Suspended`, `PendingDeletion`, `Deleted`), slug rules and `TenantSettings`. Ports `TenantRepository` (bound to a tenant) and `TenantDirectory` (installation-wide lookup by slug).
- identity: [./identity/EGM.md](./identity/EGM.md) - `IdentityService` and the `User` aggregate with its status lifecycle and normalized login identifiers (username, email). Port `UserRepository`.
- credential: [./credential/EGM.md](./credential/EGM.md) - `CredentialService` (passwords with rules and history), `AccessTokenService` (`hodor_at_` tokens for the administration interface), `TotpService` (authenticator applications: time-based one-time passwords) and `WebAuthnService` (security keys and platform authenticators). Ports `PasswordHasher`, `PasswordStore`, `AccessTokenStore`, `TotpStore`, `WebAuthnStore`, `HmacSha1`.
- session: [./session/EGM.md](./session/EGM.md) - `SessionService`: starts, finds by token, lists, revokes and re-tokens browser sessions. Only the SHA-256 hash of a session token is stored. Port `SessionStore`.
- keys: [./keys/EGM.md](./keys/EGM.md) - `KeyService`: key sets per tenant and use (`sig`, `enc`, `data`), key versions with states `pending`, `active`, `retiring`, `retired` and `revoked`, one active version per algorithm, signing with it, the rotation policy and the plan of one step of rotation, and the published signing keys. `TenantSecretBox`: the kernel's `SecretBox` over the tenant's data key, which every context that keeps secrets gets. Ports `KeyStore`, `KeyProvider`, `SealingStateStore` and `FirstFormatSecrets`; the key material is never read by the context.
- authorization: [./authorization/EGM.md](./authorization/EGM.md) - `AuthorizationService`: fixed roles (`TenantAdministrator`, `TenantAuditor`), fixed permissions, deny by default. Port `RoleAssignmentStore`.
- audit: [./audit/EGM.md](./audit/EGM.md) - `AuditService` and `AuditHandler`: one hash-chained audit record per event, per tenant, and chain verification. Port `AuditLog`.
- notification: [./notification/EGM.md](./notification/EGM.md) - `Notifier` queues a message in the caller's unit of work; `DeliveryService` delivers due messages with retries (at most 8 attempts). Ports `MessageQueue`, `PendingMessages`, `EmailSender`.
- authentication: [./authentication/EGM.md](./authentication/EGM.md) - `AuthenticationService` runs a sign-in through `FlowEngine` up to the start of a session; `AttemptGuard` counts attempts and locks out; `AccountService` handles registration and password recovery by email link. Ports `AttemptStore`, `TransactionStore`, `VerificationTokenStore`.
- saml: [./saml/EGM.md](./saml/EGM.md) - Pure computation for Hodor as a SAML service provider: `check_response`, `AuthenticationRequest`, `metadata`, `IdentityProviderKey`. The only crate allowed an XML library (`xml-sec`).
- oauth: [./oauth/EGM.md](./oauth/EGM.md) - `ApplicationService`: applications, clients (types, exact redirect addresses, grants, authentication methods, secrets kept as SHA-256 hashes with rotation, public keys for `private_key_jwt`, token policy) and resource servers with their scopes. Ports `ApplicationStore`, `ClientStore`, `ResourceServerStore`. `AuthorizationCodeService`: the authorization endpoint's checks, pending requests bound to a browser, grants and single-use authorization codes kept as hashes. Ports `AuthorizationRequestStore`, `GrantStore`, `AuthorizationCodeStore`. `TokenService`: the token endpoint's client authentication (secrets, `private_key_jwt` assertions used once, public clients) and JWT access tokens signed through `KeyService`. Port `ClientAssertionStore`.
- authorization-opa: [./authorization-opa/EGM.md](./authorization-opa/EGM.md) - `OpenPolicyAgentEngine`, the engine `open_policy_agent`: asks an operator-configured Open Policy Agent instance through its Data API on a path built from the tenant and the binding, with a time budget, one retry on a failed connection and a circuit breaker per instance; every failure is indeterminate with its own reason.
- federation: [./federation/EGM.md](./federation/EGM.md) - `FederationService` (identity providers and external identity links) and `ExternalSignIn` (sign-in through OpenID Connect, GitHub, SAML and LDAP directories). Plugs into authentication as the `external` step. Ports `ProviderStore`, `LinkStore`, `PendingAuthorizationStore`, `DirectoryClient`, `LockoutPolicy`.

Adapters:

- adapters-postgres: [./adapters-postgres/EGM.md](./adapters-postgres/EGM.md) - PostgreSQL implementations of every bounded context's storage ports, `PgUnitOfWork` (tenant-bound transaction that writes recorded events to `platform.outbox`), `OutboxDispatcher`, and `migrate`, which embeds `migrations/`.
- adapters-crypto: [./adapters-crypto/EGM.md](./adapters-crypto/EGM.md) - `Sha256Digest`, `OsRandom`, `SecretKeys` (the root keys of `HODOR_SECRET_KEYS`: they wrap key versions and open secrets of the first format), `LocalKeyProvider` (implements the keys `KeyProvider`), `AwsLcVerifier`, `AwsLcHmacSha1` (implements the credential `HmacSha1`), and `Argon2idHasher` (implements the credential `PasswordHasher`).
- adapters-http: [./adapters-http/EGM.md](./adapters-http/EGM.md) - The kernel `HttpClient`, twice. `GuardedHttpClient`: public addresses only, HTTPS except listed development hosts. `ServiceHttpClient`: only the origins the operator configured, such as Open Policy Agent. Both: no redirects, size and time limits, a time limit per request.
- adapters-ldap: [./adapters-ldap/EGM.md](./adapters-ldap/EGM.md) - `LdapDirectoryClient`, the federation `DirectoryClient`, limited to allowed hosts.
- adapters-smtp: [./adapters-smtp/EGM.md](./adapters-smtp/EGM.md) - `SmtpSender`, the notification `EmailSender`.
- protocol-http: [./protocol-http/EGM.md](./protocol-http/EGM.md) - The axum HTTP layer: `public_router` (tenant from the `/t/{tenant}` path prefix), the interaction routes, the administration and console routes, `Problem` error documents, health routes (`/livez`, `/readyz`, `/startupz`) and the hosted pages. Depends on domain crates and the kernel, never on an adapter.

## Invariants

- The dependency rules in `tests/architecture/src/lib.rs` (`RULES`, `violations`) hold for normal and build dependencies; dev-dependencies are exempt. A workspace crate without an entry in `RULES` fails the check.
- Domain and application crates (layers 0 to 3) must not depend on `axum`, `hyper`, `redis`, `reqwest`, `sqlx`, `tokio` or `tower` (`INFRASTRUCTURE`).
- An adapter never depends on another adapter (`RULES` comment on layer 4; test `an_adapter_cannot_depend_on_another_adapter`).
- Only `hodor-saml` may depend on an XML library (`XML`, `XML_CRATE`; test `only_the_saml_crate_reads_xml`).
- No bounded context depends on `hodor-audit` (test `no_context_depends_on_audit`); audit records are made from outbox events by `AuditHandler`, which `apps/hodor-worker` runs.
- `RULES` also lists crates that do not exist yet (for example `hodor-adapters-redis`); they are not part of this directory today.

## Verification

- Run: `cargo test --workspace --locked` (what `.github/workflows/ci.yml` job `test` runs), or `cargo test -p <crate package name>` for one crate.
- Run: `cargo test -p hodor-architecture-tests` for the dependency rules.
- Some integration tests start containers through testcontainers and need Docker: those of `hodor-adapters-postgres` (`TestDatabase`), `hodor-adapters-ldap` (`TestDirectory`), `hodor-adapters-smtp`, `hodor-observability`, and the directory tests of `hodor-protocol-http` (`tests/federated_sign_in.rs`). The binaries in `apps/` have such tests too.
