# Threat model

Method: STRIDE per trust boundary, with one focused model for each area the specification names. Each threat has an ID, the control that addresses it, and the test that proves the control. This document is the baseline; each phase revisits its area before implementation and adds what the design at that point reveals.

## Assets

| Asset | Why it matters |
|---|---|
| Signing keys | Whoever holds them mints tokens for the tenant |
| Credentials (password hashes, TOTP secrets, passkey public keys, client and IdP secrets) | Account and integration takeover |
| Sessions, authorization codes, refresh tokens | Impersonation |
| Identity data (PII) | Privacy, regulatory exposure |
| Policies and role assignments | Privilege escalation |
| Audit trail | Detection and non-repudiation |
| Tenant boundary | A breach here multiplies every other one |

## Trust boundaries

```mermaid
flowchart LR
    subgraph internet["Untrusted"]
        ua["Browsers"]
        clients["OAuth clients"]
        idps["External IdPs"]
        scim["SCIM clients"]
    end
    subgraph edge["Edge"]
        lb["Load balancer / TLS"]
    end
    subgraph app["Hodor trust zone"]
        server["hodor-server"]
        worker["hodor-worker"]
        wasm["WASM plugins<br/>sandboxed, untrusted code"]
    end
    subgraph data["Data zone"]
        pg[("PostgreSQL")]
        redis[("Redis")]
    end
    subgraph semi["Semi-trusted services"]
        opa["OPA"]
        kms["KMS"]
        smtp["SMTP / SMS"]
    end
    ua --> lb
    clients --> lb
    scim --> lb
    lb --> server
    server <--> idps
    server --> pg & redis
    worker --> pg & redis
    server <--> opa
    server --> kms
    worker --> smtp
    server --- wasm
```

Boundaries: internet → edge; edge → application; application → data; application → external IdPs (their responses are untrusted input); application → OPA (policy content may be tenant-authored); host → WASM guest; tenant ↔ tenant (logical, crossing every zone); administrator → platform.

## General STRIDE

| ID | Category | Threat | Control |
|---|---|---|---|
| G-01 | Spoofing | Credential stuffing and brute force | Per-account, per-IP and per-pair limits; progressive lockout; breached-password check; MFA |
| G-02 | Spoofing | User enumeration through login, registration or recovery | Uniform responses and timing; dummy hash verification; recovery always answers "if the account exists" |
| G-03 | Tampering | SQL injection | SQLx bound parameters only; no string-built SQL; lint in CI |
| G-04 | Tampering | Audit record modification | Append-only table, no `UPDATE`/`DELETE` grant, per-tenant hash chain, periodic anchor exported |
| G-05 | Repudiation | Administrator denies an action | Every admin API call audited with actor, client, IP and request ID |
| G-06 | Information disclosure | Secrets in logs, traces or error messages | `Secret<T>` without `Debug`/`Serialize`; request and response bodies never logged; log scanning test with canary values |
| G-07 | Information disclosure | Database dump exposes secrets | Passwords Argon2id; tokens stored as hashes; recoverable secrets AEAD-encrypted under per-tenant keys wrapped by the KMS |
| G-08 | Denial of service | Argon2 exhaustion through login floods | Bounded blocking pool + semaphore; rate limit before hashing; 503 with `Retry-After` |
| G-09 | Denial of service | Oversized bodies, slow requests, deep JSON | Body size and depth limits, header and read timeouts, concurrency limits per route |
| G-10 | Elevation of privilege | CSRF on cookie-authenticated endpoints | `SameSite=Lax` + per-session CSRF token on every state-changing interaction and BFF route; `Origin` check |
| G-11 | Elevation of privilege | XSS in hosted UI | React escaping, no `dangerouslySetInnerHTML`, strict CSP without inline script, no tenant-supplied HTML, Trusted Types |
| G-12 | Elevation of privilege | Clickjacking on login and consent | `frame-ancestors 'none'` |
| G-13 | Tampering | SSRF through configured URLs (JWKS, discovery, webhooks, `request_uri`, logout URIs) | One outbound client: HTTPS only, DNS resolution pinned and checked against private, loopback, link-local and metadata ranges, no redirects by default, size and time limits |
| G-14 | Spoofing | Session fixation and hijacking | Session ID rotated at login and step-up; cookie flags; server-side revocation; device binding signal |
| G-15 | Tampering | Dependency compromise | `cargo deny`, `cargo audit`, lockfile, vendored sources policy, pinned CI actions, signed releases, SBOM |
| G-16 | Elevation of privilege | Open redirect | Redirect targets are registered values or server-stored references, never request input |

## OAuth 2.x

Baseline: RFC 9700 and RFC 6819.

| ID | Threat | Control | Test |
|---|---|---|---|
| O-01 | Authorization code interception | PKCE S256 mandatory for public clients, default for all; code bound to client, redirect URI and challenge; 60 s lifetime | Token request without or with wrong verifier fails |
| O-02 | Authorization code replay | Single use; second redemption revokes the grant and its tokens | Replay test asserts revocation |
| O-03 | Redirect URI manipulation | Exact string match; no wildcards; loopback port exception only for native clients (RFC 8252) | Table-driven near-miss URIs |
| O-04 | Mix-up attack | `iss` in authorization responses (RFC 9207); per-tenant issuer | Response contains `iss` |
| O-05 | CSRF on the client's redirect URI | PKCE; `state` passed through unchanged; `nonce` for OIDC | — |
| O-06 | Refresh token theft | Rotation, reuse detection revokes the family; sender constraint via DPoP or mTLS; idle and absolute lifetimes | Reuse test |
| O-07 | Access token replay at another resource server | Audience restriction (RFC 8707); short lifetime; DPoP | Token with wrong `aud` rejected by introspection policy |
| O-08 | Client impersonation | `private_key_jwt` or mTLS preferred; secrets hashed, rotated, compared in constant time; `jti` replay cache for assertions | Assertion replay rejected |
| O-09 | Token leakage through the front channel | No implicit grant, no token in a URL, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on token responses | Metadata lists only `code` |
| O-10 | PKCE downgrade | A code issued with a challenge cannot be redeemed without a verifier; `plain` rejected | — |
| O-11 | Scope escalation on refresh or exchange | Refreshed scope ⊆ granted scope; token exchange policy per client pair | Property test |
| O-12 | Malicious dynamic client registration | Disabled by default; initial access token; software statements; registered URIs validated and SSRF-checked | — |
| O-13 | Device flow phishing | User code entropy and rate limit; verification page shows client and scopes; short lifetime | — |
| O-14 | JWT algorithm confusion, `none`, key injection through `jku`/`jwk` headers | Algorithm allow-list per key; key selected by `kid` from the server's own store only; header-supplied keys ignored | Fuzzed header corpus |
| O-15 | DPoP proof replay | `jti` cache for the proof lifetime; server-provided nonce | — |
| O-16 | Consent bypass or forged consent | Consent bound to the interaction and session; first-party skip only for clients flagged by an administrator | — |

## OpenID Connect

| ID | Threat | Control |
|---|---|---|
| I-01 | ID Token replay or injection into another session | `nonce` bound to the request; `aud`, `azp`, `at_hash` |
| I-02 | Correlation of users across clients | Pairwise subject identifiers with a per-tenant salt and `sector_identifier_uri` validation |
| I-03 | Stale authentication accepted | `max_age` and `auth_time` enforced server-side; `prompt=login` forces re-authentication |
| I-04 | Logout CSRF and post-logout open redirect | `id_token_hint` required for redirect; registered `post_logout_redirect_uri`; confirmation page otherwise |
| I-05 | Forged back-channel logout | Signed logout token with `events` claim, `jti` replay cache at the RP; Hodor signs with the tenant key |
| I-06 | UserInfo over-disclosure | Claims limited to consented scopes and the `claims` request |
| I-07 | Malicious `request` object or `request_uri` | Request objects must be signed by a registered client key; `request_uri` only from PAR |

## SAML

| ID | Threat | Control |
|---|---|---|
| S-01 | XML signature wrapping | Verify the signature, then read data only from the exact signed element by its resolved reference; reject documents with duplicate IDs; schema validation first |
| S-02 | XXE and entity expansion | DTDs and external entities disabled in the parser; size and depth limits |
| S-03 | Assertion replay | `InResponseTo` matched to a stored request; `NotOnOrAfter`; assertion ID cache |
| S-04 | Audience and destination confusion | `AudienceRestriction`, `Destination` and `Recipient` must match this SP exactly |
| S-05 | Unsigned or partially signed responses | Require a signed assertion (or signed response containing it); no fallback to unsigned |
| S-06 | Weak algorithms | Reject SHA-1 and RSA PKCS#1 v1.5 key transport; allow-list of algorithms |
| S-07 | Comment and canonicalization tricks in NameID | Canonicalize before comparison; treat text nodes with comments as invalid |
| S-08 | RelayState open redirect | RelayState is an opaque server-side reference |
| S-09 | Unsolicited (IdP-initiated) responses | Disabled by default; when enabled, restricted to a landing page with no privileged continuation |

SAML is the highest-risk protocol in the plan because of XML-DSig. See the [critical review](../architecture/critical-review.md).

## Social login and federation

| ID | Threat | Control |
|---|---|---|
| F-01 | Account takeover through automatic linking on an unverified or attacker-controlled email | No linking on email alone; linking needs proof of control of both sides, or an explicit policy with a provider authoritative for the domain and `email_verified` |
| F-02 | Pre-hijacking: attacker registers locally with the victim's email before the victim's first social login | Unverified local identifiers never match; on first federated login to a pre-existing unverified account, the old credentials and sessions are invalidated |
| F-03 | Login CSRF and callback forgery | `state` bound to the browser and the `AuthTransaction`, single use; PKCE toward the IdP |
| F-04 | IdP mix-up | One callback URL per provider; issuer checked against the provider's configuration |
| F-05 | Token substitution from another client of the same IdP | `aud` and `azp` validation; `nonce` |
| F-06 | Multi-tenant IdP confusion (for example, any Entra tenant accepted) | Issuer template pinned to allowed tenant IDs; domain claims not trusted from multi-tenant issuers without verification |
| F-07 | Malicious claim values escalate privilege (groups, roles) | Mappings are explicit allow-lists; mapped roles limited to a configured set per provider |
| F-08 | SSRF through discovery or JWKS URLs | G-13 |
| F-09 | Provider secret disclosure | Encrypted at rest, write-only in the API, never returned |
| F-10 | A deactivated provider keeps granting access | Deactivation blocks new logins and, by policy, revokes sessions established through it |
| F-11 | Identifier recycling at the IdP (email reassigned) | Link on the immutable `sub`, never on email |

## OPA

| ID | Threat | Control |
|---|---|---|
| P-01 | Tenant A's Rego reads tenant B's data in a shared OPA | Tenant-authored Rego only in a dedicated OPA; shared OPA runs platform-authored policy only |
| P-02 | SSRF or exfiltration through `http.send` and similar built-ins | Capabilities file removes them; checked at validation and enforced at run time |
| P-03 | Policy injection through the decision path | The path is derived from tenant and binding, never from request input |
| P-04 | Bundle tampering or rollback | Signed bundles; monotonic revision; OPA verifies the signature; per-instance bundle credentials |
| P-05 | OPA unavailable → access granted | Fail-closed default; `fail_open` only explicit, per action, audited |
| P-06 | Stale policy keeps answering after a publish | Revision tracking from status reports; lagging instances yield `Indeterminate` |
| P-07 | Sensitive attributes leak into decision logs | Mask rules by path; log sampling and retention per tenant |
| P-08 | Expensive policy as denial of service | Decision timeout; bundle size and rule-count quotas; evaluation metrics per tenant |
| P-09 | Unauthenticated OPA API | Token or mTLS; network policy restricts access to Hodor |
| P-10 | Decision cache returns a stale allow | Cache off by default; keyed by revision; short TTL; flushed on publish |

## Multi-tenancy

| ID | Threat | Control |
|---|---|---|
| T-01 | A query without a tenant filter returns another tenant's rows | Forced RLS + mandatory `TenantContext` in ports + composite foreign keys |
| T-02 | Tenant taken from request input | Resolved from host or path only; credentials validated within that tenant |
| T-03 | Token or session from tenant A accepted at tenant B | Per-tenant issuer and keys; tenant-scoped lookups |
| T-04 | Cache key collision | Single key builder requiring `TenantContext` |
| T-05 | Platform administrator abuses standing access | No standing access; audited time-boxed support grants; separate platform role |
| T-06 | Noisy neighbor | Per-tenant rate limits, quotas and worker fairness |
| T-07 | Custom domain takeover | DNS verification, periodic re-verification, domain released on failure |
| T-08 | Background job runs with the wrong tenant | Jobs carry `tenant_id`; handlers receive a rebuilt `TenantContext`; no ambient tenant |
| T-09 | Shared-origin attacks between path-based tenants | No tenant-supplied HTML or scripts; dedicated hosts recommended |
| T-10 | Data remains after tenant deletion | Purge job with verification query; crypto-shredding of the tenant key |

## Plugin system

| ID | Threat | Control |
|---|---|---|
| X-01 | Plugin escapes the sandbox | Wasmtime with no ambient authority: no filesystem, network or clock unless granted; component model with typed host functions |
| X-02 | Plugin exhausts CPU or memory | Fuel or epoch interruption, memory limit, per-call deadline |
| X-03 | Plugin reads data beyond its purpose | Capability manifest approved by an administrator; host functions check capabilities and tenant on every call |
| X-04 | Plugin exfiltrates secrets | Secrets never cross the boundary; plugins receive handles, and outbound HTTP goes through the host's SSRF-safe client with an allow-list |
| X-05 | Malicious or tampered plugin package | Signed packages, digest pinning, per-tenant installation approval |
| X-06 | Plugin failure breaks authentication | Per-extension-point failure policy; authentication actions fail closed |
| X-07 | Claims mapper injects privileged claims | Reserved claims (`iss`, `sub`, `aud`, `exp`, `acr`, `amr`, …) cannot be set by mappers |

## Authorization engine

| ID | Threat | Control |
|---|---|---|
| A-01 | PEP asserts roles or attributes it should not | Asserted attributes kept separate from resolved ones and untrusted by default |
| A-02 | Any authenticated client queries decisions about any subject | `authz:evaluate` scope per namespace; callers limited to their own resource server |
| A-03 | Explanations reveal policy internals or sensitive attributes | Stable reason codes by default; detail only with `authz:explain` |
| A-04 | Stale role cache grants revoked access | Event-driven invalidation plus a short TTL upper bound |
| A-05 | Role hierarchy cycle or explosion | Cycle check on write; bounded expansion |
| A-06 | ReBAC traversal as denial of service | Depth and fan-out limits; `Indeterminate` on limit |
| A-07 | `Indeterminate` treated as allow by a PEP | SDKs expose a boolean `allowed`; documentation and conformance tests for PEPs |
| A-08 | Self-escalation by an administrator | A principal cannot grant permissions it does not hold; segregation-of-duty rules on role assignment |
| A-09 | Simulation used to probe production data | Separate scope; simulation is audited; no real decision record |

## Residual risks

| Risk | Status |
|---|---|
| Compromise of a node's memory exposes local signing keys | Reduced by KMS-held keys (Phase 9); accepted for the local provider |
| SMS OTP interception (SIM swap) | Inherent; SMS is offered as low assurance and excluded from high `acr` |
| Phishing of passwords and TOTP | Reduced by passkeys; not eliminated while phishable factors are enabled |
| Compromised upstream IdP | Limited by claim allow-lists and per-provider MFA policy; cannot be eliminated |
