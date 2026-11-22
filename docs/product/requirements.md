# Requirements

Priority: **Blocker** blocks the phase, **Expected** is expected in the phase, **Optional** may slip. The *Phase* column points to the [roadmap](roadmap.md).

## Functional requirements

### Tenancy (`tenant`)

| Identifier | Requirement | Phase | Prio |
|---|---|---|---|
| Requirement-Tenancy-01 | Create, suspend, reactivate and delete tenants; deletion is asynchronous and verifiable | 1 | Blocker |
| Requirement-Tenancy-02 | Each tenant has its own `issuer` (`https://{host}/t/{slug}` or a verified custom domain) | 2 | Blocker |
| Requirement-Tenancy-03 | Domains verified by DNS TXT, used for the issuer and for identity provider routing | 3 | Expected |
| Requirement-Tenancy-04 | Per-tenant policies: password, session, multi-factor authentication, lockout, open or closed registration | 1 | Blocker |
| Requirement-Tenancy-05 | Per-tenant branding (logo, colors, copy, default locale) | 4 | Expected |
| Requirement-Tenancy-06 | Per-tenant quotas (users, clients, requests per minute, policies) | 7 | Optional |
| Requirement-Tenancy-07 | A `system` tenant for platform administrators, with no implicit privilege over other tenants' data | 1 | Blocker |
| Requirement-Tenancy-08 | Cross-tenant access only through explicit federation (tenant A trusts tenant B as an identity provider) | 6 | Optional |

### Identity (`identity`)

| Identifier | Requirement | Phase | Prio |
|---|---|---|---|
| Requirement-Identity-01 | A user has an immutable `UserId` (UUIDv7), independent of username, email or external identity | 1 | Blocker |
| Requirement-Identity-02 | Login identifiers (username, email, phone) are separate entities, unique per tenant, with a verification state | 1 | Blocker |
| Requirement-Identity-03 | Lifecycle `pending → active → suspended → deactivated → deleted`, with reason and actor | 1 | Blocker |
| Requirement-Identity-04 | Profile with standard OpenID Connect claims and custom attributes validated by a tenant schema | 1 | Expected |
| Requirement-Identity-05 | Groups with bounded nesting (configurable depth, no cycles) | 1 | Expected |
| Requirement-Identity-06 | Organizations inside a tenant, with hierarchical units, memberships and invitations | 1 | Expected |
| Requirement-Identity-07 | Linked external identities (`provider_id`, `external_subject`), several per user | 3 | Blocker |
| Requirement-Identity-08 | User merge with proof of control of both accounts and an audit trail | 3 | Optional |
| Requirement-Identity-09 | Bulk import and export (NDJSON), including password hashes in known formats | 6 | Optional |
| Requirement-Identity-10 | Personal data export and deletion on the data subject's request | 4 | Expected |

### Credentials (`credential`)

| Identifier | Requirement | Phase | Prio |
|---|---|---|---|
| Requirement-Credential-01 | Passwords in Argon2id with versioned parameters and transparent rehash on login | 1 | Blocker |
| Requirement-Credential-02 | Password policy: length, breached-password list (k-anonymity), history | 1 | Expected |
| Requirement-Credential-03 | TOTP (RFC 6238) and HOTP (RFC 4226), secret encrypted at rest | 4 | Blocker |
| Requirement-Credential-04 | WebAuthn level 2/3: discoverable passkeys and second factor, with counter verification | 4 | Blocker |
| Requirement-Credential-05 | Single-use recovery codes, stored hashed | 4 | Blocker |
| Requirement-Credential-06 | API keys with an identifiable prefix, stored hashed, with scope and expiry | 5 | Expected |
| Requirement-Credential-07 | X.509 certificates bound to a user or service account | 6 | Optional |
| Requirement-Credential-08 | Revocation and rotation of any credential, with an audit event | 1 | Blocker |

### Authentication (`authentication`)

| Identifier | Requirement | Phase | Prio |
|---|---|---|---|
| Requirement-Authentication-01 | Login with identifier + password | 1 | Blocker |
| Requirement-Authentication-02 | Brute-force protection: limits per account, per IP and per pair; progressive lockout | 1 | Blocker |
| Requirement-Authentication-03 | Indistinguishable responses and timing for unknown account and wrong password | 1 | Blocker |
| Requirement-Authentication-04 | Registration, email verification, password recovery | 1 | Blocker |
| Requirement-Authentication-05 | Passwordless: magic link, email one-time password and SMS one-time password | 4 | Expected |
| Requirement-Authentication-06 | Declarative flow engine: required, alternative, conditional and optional steps | 4 | Blocker |
| Requirement-Authentication-07 | Step-up: an application can require a higher `acr` and the flow completes only what is missing | 4 | Blocker |
| Requirement-Authentication-08 | Risk signals (new IP, new device, impossible travel) feed flow conditions | 4 | Expected |
| Requirement-Authentication-09 | Trusted devices with a bound cookie and expiry | 4 | Expected |
| Requirement-Authentication-10 | Assurance levels mapped to `acr`, methods recorded in `amr` (RFC 8176) | 2 | Blocker |
| Requirement-Authentication-11 | Flow versioning, validation and simulation | 4 | Expected |
| Requirement-Authentication-12 | Client certificate (mTLS) authentication | 6 | Optional |

### Sessions (`session`)

| Identifier | Requirement | Phase | Prio |
|---|---|---|---|
| Requirement-Session-01 | Server-side single sign-on session referenced by an opaque `__Host-` cookie | 1 | Blocker |
| Requirement-Session-02 | Idle and absolute timeouts configurable per tenant | 1 | Blocker |
| Requirement-Session-03 | Application sessions (one per client inside the single sign-on session) | 2 | Blocker |
| Requirement-Session-04 | Revocation per session, per device and global; revokes dependent refresh tokens | 2 | Blocker |
| Requirement-Session-05 | Concurrent session limit with a policy (deny new or end the oldest) | 4 | Expected |
| Requirement-Session-06 | Device metadata and activity visible to the user | 4 | Expected |

### OAuth 2.x and OpenID Connect (`oauth`)

| Identifier | Requirement | Standard | Phase | Prio |
|---|---|---|---|---|
| Requirement-OAuth-01 | Authorization Code with PKCE S256, mandatory for public clients and default for all | RFC 6749, 7636, 9700 | 2 | Blocker |
| Requirement-OAuth-02 | Client Credentials | RFC 6749 | 2 | Blocker |
| Requirement-OAuth-03 | Refresh token with rotation and reuse detection (revokes the family) | RFC 9700 | 2 | Blocker |
| Requirement-OAuth-04 | Revocation and introspection | RFC 7009, 7662 | 2 | Blocker |
| Requirement-OAuth-05 | Authorization server metadata and OpenID Connect Discovery | RFC 8414, OpenID Connect Discovery | 2 | Blocker |
| Requirement-OAuth-06 | JWT access tokens | RFC 9068 | 2 | Blocker |
| Requirement-OAuth-07 | Client authentication: `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none` | RFC 7523 | 2 | Blocker |
| Requirement-OAuth-08 | ID Token, UserInfo, standard claims, `nonce`, `prompt`, `max_age`, `login_hint`, `ui_locales`, `acr_values` | OpenID Connect Core | 2 | Blocker |
| Requirement-OAuth-09 | Per-scope consent with history, expiry and revocation | — | 2 | Blocker |
| Requirement-OAuth-10 | Public and pairwise (per sector) subject identifiers | OpenID Connect Core §8 | 2 | Expected |
| Requirement-OAuth-11 | Logout initiated by the relying party, and Back-Channel Logout | OpenID Connect | 2 | Expected |
| Requirement-OAuth-12 | Pushed authorization requests | RFC 9126 | 4 | Expected |
| Requirement-OAuth-13 | DPoP | RFC 9449 | 4 | Expected |
| Requirement-OAuth-14 | mTLS client authentication and certificate-bound tokens | RFC 8705 | 6 | Optional |
| Requirement-OAuth-15 | Device Authorization Grant | RFC 8628 | 4 | Expected |
| Requirement-OAuth-16 | Token Exchange and JWT Bearer | RFC 8693, 7523 | 5 | Expected |
| Requirement-OAuth-17 | Resource Indicators and audience restriction | RFC 8707 | 2 | Expected |
| Requirement-OAuth-18 | Rich Authorization Requests | RFC 9396 | 5 | Optional |
| Requirement-OAuth-19 | Dynamic Client Registration, protected by an initial access token | RFC 7591, 7592 | 4 | Optional |
| Requirement-OAuth-20 | Front-Channel Logout and Session Management (iframe) | OpenID Connect | 6 | Optional |
| Requirement-OAuth-21 | Claims mappers configurable per client | — | 2 | Expected |
| Requirement-OAuth-22 | Application and client management: types, exact redirect URIs, origins, grants, secrets with rotation | — | 2 | Blocker |

### Federation (`federation`)

| Identifier | Requirement | Phase | Prio |
|---|---|---|---|
| Requirement-Federation-01 | Hodor as a generic OpenID Connect relying party, with Discovery, PKCE, `state` and `nonce` | 3 | Blocker |
| Requirement-Federation-02 | Generic OAuth 2.0 connector with UserInfo mapping | 3 | Blocker |
| Requirement-Federation-03 | Connectors: Google, Microsoft, GitHub, Apple (Blocker); Facebook, GitLab, LinkedIn (Optional) | 3 | Blocker/Optional |
| Requirement-Federation-04 | Declarative mapping of external claims to profile, groups and attributes | 3 | Blocker |
| Requirement-Federation-05 | Just-in-time provisioning with a per-provider policy | 3 | Blocker |
| Requirement-Federation-06 | Account linking only with proof of control; automatic linking by email requires an explicit policy and an email verified by a provider trusted for that domain | 3 | Blocker |
| Requirement-Federation-07 | Domain routing (Home Realm Discovery), configurable per tenant, application and policy | 3 | Blocker |
| Requirement-Federation-08 | Provider secrets encrypted; rotation without downtime | 3 | Blocker |
| Requirement-Federation-09 | Provider deactivation with a policy for already linked identities | 3 | Expected |
| Requirement-Federation-10 | Profile synchronization on each login, with configurable precedence | 3 | Expected |
| Requirement-Federation-11 | Failover between equivalent providers | 6 | Optional |

### Authorization (`authorization`)

| Identifier | Requirement | Phase | Prio |
|---|---|---|---|
| Requirement-Authorization-01 | `evaluate`, `batch` and `simulate` over the `AuthorizationEngine` contract | 5 | Blocker |
| Requirement-Authorization-02 | Decision `ALLOW`/`DENY`/`INDETERMINATE` with identifier, timestamp, engine, policy version and reason | 5 | Blocker |
| Requirement-Authorization-03 | Native role-based access control: roles, hierarchy, composite roles, scoped to tenant, organization and application | 5 | Blocker |
| Requirement-Authorization-04 | Per-resource access control list | 5 | Expected |
| Requirement-Authorization-05 | Native attribute-based access control with conditions over subject, resource and environment | 5 | Expected |
| Requirement-Authorization-06 | Native relationship-based access control: relation tuples and bounded-depth checks | 5 | Optional |
| Requirement-Authorization-07 | Open Policy Agent adapter: evaluation, bundles, decision logs, status | 5 | Blocker |
| Requirement-Authorization-08 | Policy lifecycle: draft, validation, test, simulation, publication, rollback | 5 | Blocker |
| Requirement-Authorization-09 | An engine failure never yields `ALLOW`; fail-open only per operation and explicitly configured | 5 | Blocker |
| Requirement-Authorization-10 | Explanation filtered by the caller's privilege | 5 | Expected |
| Requirement-Authorization-11 | Hodor's own administrative role-based access control, always on the native engine | 1 | Blocker |

### Audit and notifications

| Identifier | Requirement | Phase | Prio |
|---|---|---|---|
| Requirement-Audit-01 | Every relevant domain event produces an audit record in the same transaction (outbox) | 1 | Blocker |
| Requirement-Audit-02 | Append-only records, hash-chained per tenant | 1 | Expected |
| Requirement-Audit-03 | Search, filtering, retention and export | 2 | Expected |
| Requirement-Audit-04 | Delivery to security event management system and signed webhooks, with retry and dead-letter | 5 | Expected |
| Requirement-Audit-05 | Tokens, passwords and secrets never appear in logs or audit records (`Secret<T>` type) | 1 | Blocker |
| Requirement-Notification-01 | Email over SMTP with templates per tenant and locale | 1 | Blocker |
| Requirement-Notification-02 | SMS through a pluggable provider | 4 | Expected |

### Admin console (`admin-console`)

The reasoning behind these requirements, and how the console shows them, is in [the control plane](../design/control-plane.md#5-how-the-console-protects-itself).

| Identifier | Requirement | Phase | Prio |
|---|---|---|---|
| Requirement-Console-01 | Administrator sessions have their own idle and absolute timeouts (defaults 15 minutes and 12 hours, aligned with Authenticator Assurance Level 3 of NIST SP 800-63B), independent of the tenant's end-user session settings | 2 | Blocker |
| Requirement-Console-02 | Every console state change goes through the public Admin API and is audited with actor, client, IP address and request identifier | 2 | Blocker |
| Requirement-Console-03 | Sensitive administrative actions require recent authentication (`step_up_required` with `max_age` of 5 minutes); the console completes the step-up inline | 2 | Blocker |
| Requirement-Console-04 | Every console action has a level on the dangerous action ladder, defined once in the design system's action catalog | 2 | Blocker |
| Requirement-Console-05 | Administrators are reported on the security posture until they enroll phishing-resistant multi-factor authentication; from Phase 4 a tenant can enforce it | 2 | Expected |
| Requirement-Console-06 | Break-glass administrator accounts are marked as such; any use raises a high-severity finding and an alert | 2 | Expected |
| Requirement-Console-07 | A security posture resource: server-computed checks, findings with severity and affected objects, risk acceptance with reason and expiry, and a score | 2 | Expected |
| Requirement-Console-08 | Platform administrators reach tenant data only through time-boxed, reasoned support grants, visible to the tenant and audited | 2 | Blocker |
| Requirement-Console-09 | Concurrent edits are detected with `ETag` and `If-Match`; the console shows the conflict instead of overwriting | 2 | Blocker |
| Requirement-Console-10 | The tenant is part of every console URL; a tab never changes tenant implicitly | 2 | Blocker |
| Requirement-Console-11 | Alerts on administrative activity: administrator role grants, key revocations, policy publications, posture regressions | 5 | Expected |
| Requirement-Console-12 | Changes marked for a second approver take effect only after approval by a different administrator | 7 | Expected |

### Enterprise, keys, plugins, workloads

| Identifier | Requirement | Phase | Prio |
|---|---|---|---|
| Requirement-Key-01 | Per-tenant signing keys with scheduled rotation and an overlap period in the JWKS | 2 | Blocker |
| Requirement-Key-02 | `KeyProvider` with a local implementation (envelope encryption) | 2 | Blocker |
| Requirement-Key-03 | Amazon Web Services key management service, Google Cloud key management service, Azure Key Vault, HashiCorp Vault | 9 | Expected |
| Requirement-SAML-01 | SAML 2.0 identity provider and service provider: metadata, single sign-on, single logout, signing, encryption | 6 | Blocker |
| Requirement-LDAP-01 | LDAP and Active Directory federation: authentication and user/group synchronization over LDAPS | 6 | Blocker |
| Requirement-SCIM-01 | SCIM 2.0 server: Users, Groups, PATCH, filtering, pagination, bulk, schemas | 6 | Blocker |
| Requirement-Plugin-01 | Extension points as stable traits; WebAssembly plugins with manifest and capabilities | 8 | Expected |
| Requirement-Workload-01 | Service accounts and agent identities with their own credentials | 5 | Expected |
| Requirement-Workload-02 | Delegation through Token Exchange with an auditable actor chain (`act`) | 5 | Expected |
| Requirement-Workload-03 | Per-tool authorization for Model Context Protocol servers (scope + `authorization_details`) | 8 | Optional |

## Non-functional requirements

### Security

| Identifier | Requirement |
|---|---|
| Requirement-Security-01 | Conformance with RFC 9700; deviations require a decision record |
| Requirement-Security-02 | OWASP Application Security Verification Standard level 2 for the core; level 3 for authentication, session and cryptography |
| Requirement-Security-03 | Recoverable secrets encrypted with authenticated encryption (per-tenant data key wrapped by the `KeyProvider`); non-recoverable ones stored hashed |
| Requirement-Security-04 | Constant-time secret comparison |
| Requirement-Security-05 | TLS 1.2+ on every external connection; cookies `Secure`, `HttpOnly`, `SameSite` |
| Requirement-Security-06 | Every configured URL (JWKS, webhooks, identity provider) goes through the SSRF-protected HTTP client |
| Requirement-Security-07 | `cargo audit` and `cargo deny` in continuous integration; CycloneDX software bill of materials per release; signed artifacts |
| Requirement-Security-08 | `#![forbid(unsafe_code)]` in all domain and application crates |
| Requirement-Security-09 | Rate limiting per tenant, client, IP and account on every unauthenticated endpoint |

### Performance and scale

| Identifier | Requirement | Target |
|---|---|---|
| Requirement-Performance-01 | `/token` (`client_credentials`) | p99 ≤ 50 ms, 2,000 req/s per 2-vCPU node |
| Requirement-Performance-02 | Password login (includes Argon2id) | p95 ≤ 400 ms |
| Requirement-Performance-03 | Introspection and UserInfo | p99 ≤ 20 ms |
| Requirement-Performance-04 | Native role-based access control authorization | p99 ≤ 5 ms |
| Requirement-Performance-05 | Authorization through an Open Policy Agent sidecar | p99 ≤ 15 ms |
| Requirement-Performance-06 | Argon2id on a blocking pool behind a semaphore; a full queue returns 503 instead of starving the runtime | — |
| Requirement-Performance-07 | No mandatory node-local state; horizontal scaling without session affinity | — |
| Requirement-Performance-08 | 10,000 tenants and 10 million users in one cluster without an architecture change | — |

### Availability and operations

| Identifier | Requirement |
|---|---|
| Requirement-Operations-01 | 99.95% availability target with 3 nodes and high availability Postgres |
| Requirement-Operations-02 | Recovery point objective ≤ 5 min, recovery time objective ≤ 30 min, with rehearsed restore |
| Requirement-Operations-03 | Migrations compatible with the previous version (expand/contract), allowing rolling upgrades |
| Requirement-Operations-04 | Graceful shutdown: drains connections, stops workers, honors `terminationGracePeriod` |
| Requirement-Operations-05 | Separate health checks: `livez`, `readyz`, `startupz` |
| Requirement-Operations-06 | Works with PostgreSQL alone; a missing Redis degrades performance, not functionality |
| Requirement-Operations-07 | Configuration by file and environment variables, validated at startup |

### Observability

| Identifier | Requirement |
|---|---|
| Requirement-Observability-01 | Traces, metrics and logs through OpenTelemetry (OTLP), with `tenant_id` and `request_id` on every span |
| Requirement-Observability-02 | The metrics in section 20 of the specification exposed with bounded cardinality (no `user_id` labels) |
| Requirement-Observability-03 | Structured JSON logs; sensitive fields redacted by type |

### Maintainability and portability

| Identifier | Requirement |
|---|---|
| Requirement-Maintainability-01 | Crate dependency rules checked in continuous integration ([crates.md](../architecture/crates.md)) |
| Requirement-Maintainability-02 | Domain free of Axum, SQLx, Redis and Tokio |
| Requirement-Maintainability-03 | Business-rule test coverage ≥ 85% in domain crates |
| Requirement-Maintainability-04 | Rust stable, minimum supported Rust version pinned in `rust-toolchain.toml` |
| Requirement-Maintainability-05 | `linux/amd64` and `linux/arm64` distroless images running as non-root |

### Privacy and usability

| Identifier | Requirement |
|---|---|
| Requirement-Privacy-01 | Data minimization in tokens; claims only for consented scopes |
| Requirement-Privacy-02 | Per-tenant retention for audit, sessions and decision logs |
| Requirement-Usability-01 | User interfaces conform to Web Content Accessibility Guidelines 2.2, level AA |
| Requirement-Usability-02 | Localization: en and pt-BR at launch; all copy externalized |
