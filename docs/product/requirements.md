# Requirements

Priority: **P0** blocks the phase, **P1** is expected in the phase, **P2** may slip. The *Phase* column points to the [roadmap](roadmap.md).

## Functional requirements

### Tenancy (`tenant`)

| ID | Requirement | Phase | Prio |
|---|---|---|---|
| FR-TEN-01 | Create, suspend, reactivate and delete tenants; deletion is asynchronous and verifiable | 1 | P0 |
| FR-TEN-02 | Each tenant has its own `issuer` (`https://{host}/t/{slug}` or a verified custom domain) | 2 | P0 |
| FR-TEN-03 | Domains verified by DNS TXT, used for the issuer and for IdP routing | 3 | P1 |
| FR-TEN-04 | Per-tenant policies: password, session, MFA, lockout, open or closed registration | 1 | P0 |
| FR-TEN-05 | Per-tenant branding (logo, colors, copy, default locale) | 4 | P1 |
| FR-TEN-06 | Per-tenant quotas (users, clients, requests per minute, policies) | 7 | P2 |
| FR-TEN-07 | A `system` tenant for platform administrators, with no implicit privilege over other tenants' data | 1 | P0 |
| FR-TEN-08 | Cross-tenant access only through explicit federation (tenant A trusts tenant B as an IdP) | 6 | P2 |

### Identity (`identity`)

| ID | Requirement | Phase | Prio |
|---|---|---|---|
| FR-IDN-01 | A user has an immutable `UserId` (UUIDv7), independent of username, email or external identity | 1 | P0 |
| FR-IDN-02 | Login identifiers (username, email, phone) are separate entities, unique per tenant, with a verification state | 1 | P0 |
| FR-IDN-03 | Lifecycle `pending → active → suspended → deactivated → deleted`, with reason and actor | 1 | P0 |
| FR-IDN-04 | Profile with standard OIDC claims and custom attributes validated by a tenant schema | 1 | P1 |
| FR-IDN-05 | Groups with bounded nesting (configurable depth, no cycles) | 1 | P1 |
| FR-IDN-06 | Organizations inside a tenant, with hierarchical units, memberships and invitations | 1 | P1 |
| FR-IDN-07 | Linked external identities (`provider_id`, `external_subject`), several per user | 3 | P0 |
| FR-IDN-08 | User merge with proof of control of both accounts and an audit trail | 3 | P2 |
| FR-IDN-09 | Bulk import and export (NDJSON), including password hashes in known formats | 6 | P2 |
| FR-IDN-10 | Personal data export and deletion on the data subject's request | 4 | P1 |

### Credentials (`credential`)

| ID | Requirement | Phase | Prio |
|---|---|---|---|
| FR-CRD-01 | Passwords in Argon2id with versioned parameters and transparent rehash on login | 1 | P0 |
| FR-CRD-02 | Password policy: length, breached-password list (k-anonymity), history | 1 | P1 |
| FR-CRD-03 | TOTP (RFC 6238) and HOTP (RFC 4226), secret encrypted at rest | 4 | P0 |
| FR-CRD-04 | WebAuthn level 2/3: discoverable passkeys and second factor, with counter verification | 4 | P0 |
| FR-CRD-05 | Single-use recovery codes, stored hashed | 4 | P0 |
| FR-CRD-06 | API keys with an identifiable prefix, stored hashed, with scope and expiry | 5 | P1 |
| FR-CRD-07 | X.509 certificates bound to a user or service account | 6 | P2 |
| FR-CRD-08 | Revocation and rotation of any credential, with an audit event | 1 | P0 |

### Authentication (`authentication`)

| ID | Requirement | Phase | Prio |
|---|---|---|---|
| FR-AUT-01 | Login with identifier + password | 1 | P0 |
| FR-AUT-02 | Brute-force protection: limits per account, per IP and per pair; progressive lockout | 1 | P0 |
| FR-AUT-03 | Indistinguishable responses and timing for unknown account and wrong password | 1 | P0 |
| FR-AUT-04 | Registration, email verification, password recovery | 1 | P0 |
| FR-AUT-05 | Passwordless: magic link, email OTP and SMS OTP | 4 | P1 |
| FR-AUT-06 | Declarative flow engine: required, alternative, conditional and optional steps | 4 | P0 |
| FR-AUT-07 | Step-up: an application can require a higher `acr` and the flow completes only what is missing | 4 | P0 |
| FR-AUT-08 | Risk signals (new IP, new device, impossible travel) feed flow conditions | 4 | P1 |
| FR-AUT-09 | Trusted devices with a bound cookie and expiry | 4 | P1 |
| FR-AUT-10 | Assurance levels mapped to `acr`, methods recorded in `amr` (RFC 8176) | 2 | P0 |
| FR-AUT-11 | Flow versioning, validation and simulation | 4 | P1 |
| FR-AUT-12 | Client certificate (mTLS) authentication | 6 | P2 |

### Sessions (`session`)

| ID | Requirement | Phase | Prio |
|---|---|---|---|
| FR-SES-01 | Server-side SSO session referenced by an opaque `__Host-` cookie | 1 | P0 |
| FR-SES-02 | Idle and absolute timeouts configurable per tenant | 1 | P0 |
| FR-SES-03 | Application sessions (one per client inside the SSO session) | 2 | P0 |
| FR-SES-04 | Revocation per session, per device and global; revokes dependent refresh tokens | 2 | P0 |
| FR-SES-05 | Concurrent session limit with a policy (deny new or end the oldest) | 4 | P1 |
| FR-SES-06 | Device metadata and activity visible to the user | 4 | P1 |

### OAuth 2.x and OIDC (`oauth`)

| ID | Requirement | Standard | Phase | Prio |
|---|---|---|---|---|
| FR-OAU-01 | Authorization Code with PKCE S256, mandatory for public clients and default for all | RFC 6749, 7636, 9700 | 2 | P0 |
| FR-OAU-02 | Client Credentials | RFC 6749 | 2 | P0 |
| FR-OAU-03 | Refresh token with rotation and reuse detection (revokes the family) | RFC 9700 | 2 | P0 |
| FR-OAU-04 | Revocation and introspection | RFC 7009, 7662 | 2 | P0 |
| FR-OAU-05 | AS metadata and OIDC Discovery | RFC 8414, OIDC Discovery | 2 | P0 |
| FR-OAU-06 | JWT access tokens | RFC 9068 | 2 | P0 |
| FR-OAU-07 | Client authentication: `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none` | RFC 7523 | 2 | P0 |
| FR-OAU-08 | ID Token, UserInfo, standard claims, `nonce`, `prompt`, `max_age`, `login_hint`, `ui_locales`, `acr_values` | OIDC Core | 2 | P0 |
| FR-OAU-09 | Per-scope consent with history, expiry and revocation | — | 2 | P0 |
| FR-OAU-10 | Public and pairwise (per sector) subject identifiers | OIDC Core §8 | 2 | P1 |
| FR-OAU-11 | RP-Initiated and Back-Channel Logout | OIDC | 2 | P1 |
| FR-OAU-12 | PAR | RFC 9126 | 4 | P1 |
| FR-OAU-13 | DPoP | RFC 9449 | 4 | P1 |
| FR-OAU-14 | mTLS client authentication and certificate-bound tokens | RFC 8705 | 6 | P2 |
| FR-OAU-15 | Device Authorization Grant | RFC 8628 | 4 | P1 |
| FR-OAU-16 | Token Exchange and JWT Bearer | RFC 8693, 7523 | 5 | P1 |
| FR-OAU-17 | Resource Indicators and audience restriction | RFC 8707 | 2 | P1 |
| FR-OAU-18 | Rich Authorization Requests | RFC 9396 | 5 | P2 |
| FR-OAU-19 | Dynamic Client Registration, protected by an initial access token | RFC 7591, 7592 | 4 | P2 |
| FR-OAU-20 | Front-Channel Logout and Session Management (iframe) | OIDC | 6 | P2 |
| FR-OAU-21 | Claims mappers configurable per client | — | 2 | P1 |
| FR-OAU-22 | Application and client management: types, exact redirect URIs, origins, grants, secrets with rotation | — | 2 | P0 |

### Federation (`federation`)

| ID | Requirement | Phase | Prio |
|---|---|---|---|
| FR-FED-01 | Hodor as a generic OIDC RP, with Discovery, PKCE, `state` and `nonce` | 3 | P0 |
| FR-FED-02 | Generic OAuth 2.0 connector with UserInfo mapping | 3 | P0 |
| FR-FED-03 | Connectors: Google, Microsoft, GitHub, Apple (P0); Facebook, GitLab, LinkedIn (P2) | 3 | P0/P2 |
| FR-FED-04 | Declarative mapping of external claims to profile, groups and attributes | 3 | P0 |
| FR-FED-05 | JIT provisioning with a per-provider policy | 3 | P0 |
| FR-FED-06 | Account linking only with proof of control; automatic linking by email requires an explicit policy and an email verified by a provider trusted for that domain | 3 | P0 |
| FR-FED-07 | Domain routing (Home Realm Discovery), configurable per tenant, application and policy | 3 | P0 |
| FR-FED-08 | Provider secrets encrypted; rotation without downtime | 3 | P0 |
| FR-FED-09 | Provider deactivation with a policy for already linked identities | 3 | P1 |
| FR-FED-10 | Profile synchronization on each login, with configurable precedence | 3 | P1 |
| FR-FED-11 | Failover between equivalent providers | 6 | P2 |

### Authorization (`authorization`)

| ID | Requirement | Phase | Prio |
|---|---|---|---|
| FR-AUZ-01 | `evaluate`, `batch` and `simulate` over the `AuthorizationEngine` contract | 5 | P0 |
| FR-AUZ-02 | Decision `ALLOW`/`DENY`/`INDETERMINATE` with ID, timestamp, engine, policy version and reason | 5 | P0 |
| FR-AUZ-03 | Native RBAC: roles, hierarchy, composite roles, scoped to tenant, organization and application | 5 | P0 |
| FR-AUZ-04 | Per-resource ACL | 5 | P1 |
| FR-AUZ-05 | Native ABAC with conditions over subject, resource and environment | 5 | P1 |
| FR-AUZ-06 | Native ReBAC: relation tuples and bounded-depth checks | 5 | P2 |
| FR-AUZ-07 | OPA adapter: evaluation, bundles, decision logs, status | 5 | P0 |
| FR-AUZ-08 | Policy lifecycle: draft, validation, test, simulation, publication, rollback | 5 | P0 |
| FR-AUZ-09 | An engine failure never yields `ALLOW`; fail-open only per operation and explicitly configured | 5 | P0 |
| FR-AUZ-10 | Explanation filtered by the caller's privilege | 5 | P1 |
| FR-AUZ-11 | Hodor's own administrative RBAC, always on the native engine | 1 | P0 |

### Audit and notifications

| ID | Requirement | Phase | Prio |
|---|---|---|---|
| FR-AUD-01 | Every relevant domain event produces an audit record in the same transaction (outbox) | 1 | P0 |
| FR-AUD-02 | Append-only records, hash-chained per tenant | 1 | P1 |
| FR-AUD-03 | Search, filtering, retention and export | 2 | P1 |
| FR-AUD-04 | Delivery to SIEM and signed webhooks, with retry and dead-letter | 5 | P1 |
| FR-AUD-05 | Tokens, passwords and secrets never appear in logs or audit records (`Secret<T>` type) | 1 | P0 |
| FR-NOT-01 | Email over SMTP with templates per tenant and locale | 1 | P0 |
| FR-NOT-02 | SMS through a pluggable provider | 4 | P1 |

### Enterprise, keys, plugins, workloads

| ID | Requirement | Phase | Prio |
|---|---|---|---|
| FR-KEY-01 | Per-tenant signing keys with scheduled rotation and an overlap period in the JWKS | 2 | P0 |
| FR-KEY-02 | `KeyProvider` with a local implementation (envelope encryption) | 2 | P0 |
| FR-KEY-03 | AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault | 9 | P1 |
| FR-SAM-01 | SAML 2.0 IdP and SP: metadata, SSO, SLO, signing, encryption | 6 | P0 |
| FR-LDP-01 | LDAP/AD federation: authentication and user/group synchronization over LDAPS | 6 | P0 |
| FR-SCM-01 | SCIM 2.0 server: Users, Groups, PATCH, filtering, pagination, bulk, schemas | 6 | P0 |
| FR-PLG-01 | Extension points as stable traits; WASM plugins with manifest and capabilities | 8 | P1 |
| FR-WKL-01 | Service accounts and agent identities with their own credentials | 5 | P1 |
| FR-WKL-02 | Delegation through Token Exchange with an auditable actor chain (`act`) | 5 | P1 |
| FR-WKL-03 | Per-tool authorization for MCP servers (scope + `authorization_details`) | 8 | P2 |

## Non-functional requirements

### Security

| ID | Requirement |
|---|---|
| NFR-SEC-01 | Conformance with RFC 9700; deviations require an ADR |
| NFR-SEC-02 | OWASP ASVS level 2 for the core; level 3 for authentication, session and cryptography |
| NFR-SEC-03 | Recoverable secrets encrypted with AEAD (per-tenant data key wrapped by the `KeyProvider`); non-recoverable ones stored hashed |
| NFR-SEC-04 | Constant-time secret comparison |
| NFR-SEC-05 | TLS 1.2+ on every external connection; cookies `Secure`, `HttpOnly`, `SameSite` |
| NFR-SEC-06 | Every configured URL (JWKS, webhooks, IdP) goes through the SSRF-protected HTTP client |
| NFR-SEC-07 | `cargo audit` and `cargo deny` in CI; CycloneDX SBOM per release; signed artifacts |
| NFR-SEC-08 | `#![forbid(unsafe_code)]` in all domain and application crates |
| NFR-SEC-09 | Rate limiting per tenant, client, IP and account on every unauthenticated endpoint |

### Performance and scale

| ID | Requirement | Target |
|---|---|---|
| NFR-PRF-01 | `/token` (`client_credentials`) | p99 ≤ 50 ms, 2,000 req/s per 2-vCPU node |
| NFR-PRF-02 | Password login (includes Argon2id) | p95 ≤ 400 ms |
| NFR-PRF-03 | Introspection and UserInfo | p99 ≤ 20 ms |
| NFR-PRF-04 | Native RBAC authorization | p99 ≤ 5 ms |
| NFR-PRF-05 | Authorization through an OPA sidecar | p99 ≤ 15 ms |
| NFR-PRF-06 | Argon2id on a blocking pool behind a semaphore; a full queue returns 503 instead of starving the runtime | — |
| NFR-PRF-07 | No mandatory node-local state; horizontal scaling without session affinity | — |
| NFR-PRF-08 | 10,000 tenants and 10 million users in one cluster without an architecture change | — |

### Availability and operations

| ID | Requirement |
|---|---|
| NFR-OPS-01 | 99.95% availability target with 3 nodes and HA Postgres |
| NFR-OPS-02 | RPO ≤ 5 min, RTO ≤ 30 min, with rehearsed restore |
| NFR-OPS-03 | Migrations compatible with the previous version (expand/contract), allowing rolling upgrades |
| NFR-OPS-04 | Graceful shutdown: drains connections, stops workers, honors `terminationGracePeriod` |
| NFR-OPS-05 | Separate health checks: `livez`, `readyz`, `startupz` |
| NFR-OPS-06 | Works with PostgreSQL alone; a missing Redis degrades performance, not functionality |
| NFR-OPS-07 | Configuration by file and environment variables, validated at startup |

### Observability

| ID | Requirement |
|---|---|
| NFR-OBS-01 | Traces, metrics and logs through OpenTelemetry (OTLP), with `tenant_id` and `request_id` on every span |
| NFR-OBS-02 | The metrics in section 20 of the specification exposed with bounded cardinality (no `user_id` labels) |
| NFR-OBS-03 | Structured JSON logs; sensitive fields redacted by type |

### Maintainability and portability

| ID | Requirement |
|---|---|
| NFR-MNT-01 | Crate dependency rules checked in CI ([crates.md](../architecture/crates.md)) |
| NFR-MNT-02 | Domain free of Axum, SQLx, Redis and Tokio |
| NFR-MNT-03 | Business-rule test coverage ≥ 85% in domain crates |
| NFR-MNT-04 | Rust stable, MSRV pinned in `rust-toolchain.toml` |
| NFR-MNT-05 | `linux/amd64` and `linux/arm64` distroless images running as non-root |

### Privacy and usability

| ID | Requirement |
|---|---|
| NFR-PRV-01 | Data minimization in tokens; claims only for consented scopes |
| NFR-PRV-02 | Per-tenant retention for audit, sessions and decision logs |
| NFR-USA-01 | UIs conform to WCAG 2.2 AA |
| NFR-USA-02 | Localization: en and pt-BR at launch; all copy externalized |
