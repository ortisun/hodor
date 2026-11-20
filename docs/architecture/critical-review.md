# Critical architecture review

This review covers the original specification and the design in this directory. Each finding states what was found, what the design does about it, and what remains open. Findings marked **Needs decision** change the specification's intent and should be confirmed before implementation.

## Summary

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Scope equals several products at once | High | Mitigated by phasing; accepted risk |
| 2 | Tenant, organization and "global user" contradict each other | High | Resolved, **needs decision** |
| 3 | Tenant-authored Rego in a shared OPA is not isolated | High | Resolved by rule |
| 4 | Authorization request trusts caller-supplied tenant and roles | High | Resolved |
| 5 | "Audited RustCrypto" is not accurate as a blanket choice | High | Resolved, **needs decision** |
| 6 | SAML in Rust is a security risk | High | Deferred behind a spike |
| 7 | Circular dependencies implied by the crate list | Medium | Resolved |
| 8 | Crates with no real boundary; responsibilities with no crate | Medium | Resolved |
| 9 | Roadmap ordering puts dependencies after dependents | Medium | Resolved |
| 10 | Path-based tenants share a browser origin | Medium | Mitigated; documented |
| 11 | Native ReBAC is a product in itself | Medium | Descoped to stretch |
| 12 | Combining several authorization engines | Medium | Removed from v1 |
| 13 | Redis "optional" must be proven | Medium | Resolved |
| 14 | Visual editors and three frontends are a large hidden cost | Medium | Sequenced last |
| 15 | Plugin system specified before the core exists | Medium | Sequenced last |
| 16 | Unnecessary complexity candidates | Low | Trimmed |
| 17 | Feature gaps in the specification | Mixed | Listed |
| 18 | Weak points of this design itself | Mixed | Open |

## Findings

### 1. Scope

The specification describes the union of Keycloak, an OPA control plane, an OpenFGA-style engine, a SCIM server, a SAML stack and a WASM plugin platform. No phase plan removes that risk; it only makes it survivable. The design responds by making each phase useful alone, keeping Milestone 1 to a login, and marking three large items as separable bets: SAML (finding 6), native ReBAC (11) and the plugin runtime (15). If capacity is short, those three are the first to cut or buy.

### 2. Tenant versus organization — needs decision

The specification lists Organization under both Identity Management and Multi-tenancy, demands isolation at every layer, and asks for global users with memberships in several organizations. A user that spans isolation boundaries cannot also be isolated. [ADR-0005](../adr/0005-tenant-and-organization.md) makes the tenant the only hard boundary and puts organizations inside it; "department" becomes a kind of organization unit. The cost: one person in two unrelated tenants has two accounts. If the intent was truly global accounts across tenants, the isolation model, credential policy and deletion semantics all need rethinking, so this must be confirmed first.

### 3. OPA multi-tenancy

"Tenant-specific OPA configuration" and a Rego editor for administrators, combined with a shared OPA, would let one tenant's policy read another tenant's data: Rego has no access control between packages. Built-ins such as `http.send` add SSRF and exfiltration. The design restricts a shared OPA to platform-authored policy, requires a dedicated instance for tenant-authored Rego, and removes dangerous built-ins through a capabilities file ([ADR-0010](../adr/0010-opa-integration.md)). Open: how dedicated instances are provisioned (operator-run controller or manual) is an operations design not yet written.

### 4. Authorization request trust

The example payload puts `tenant_id` and `roles` in the subject. Taken from the body, the first is a cross-tenant hole and the second lets any caller grant itself roles. The contract takes the tenant from the caller's credential and separates asserted attributes from resolved ones ([ADR-0009](../adr/0009-authorization-engine-contract.md)). The specification also does not say who may call the decision API about whom; the design adds scopes per namespace, which needs product confirmation.

### 5. Cryptography — needs decision

RustCrypto crates are individually maintained with uneven audit history. RS256 is mandatory for OIDC interoperability, and the pure-Rust RSA crate has had a timing side-channel advisory. [ADR-0008](../adr/0008-cryptography.md) keeps RustCrypto for Argon2id and uses `aws-lc-rs` for signatures, AEAD and TLS. This contradicts the letter of the stack table. The advisory status of every candidate must be re-checked at adoption, since this review cannot vouch for their current state.

### 6. SAML

XML Signature is where SAML implementations break, and Rust's options are thin and partly bound to C libraries. The design defers SAML, gates it on a spike, fixes the validation rules in advance and requires an external review ([ADR-0014](../adr/0014-saml-deferred-with-spike.md)). Phase 6 cannot be estimated reliably until the spike is done.

### 7. Circular dependencies

Three cycles are latent in the specification's crate list:

- `oauth2` ↔ `oidc`: OIDC needs OAuth's authorization flow; OAuth's token response needs OIDC's ID Token. Resolved by merging.
- `authentication` ↔ `federation` / `social-login`: an external login is an authentication step, and its callback completes authentication. Resolved by the `Authenticator` SPI.
- `oauth2` ↔ `authentication`: authorize needs login; login returns to authorize. Resolved by removing the code dependency: the session carries the authentication facts and the two meet over HTTP.

A fourth, softer one: `authorization` needs roles and groups owned by `identity`, while `identity` administration needs authorization checks. Resolved with a port on the authorization side and by enforcing admin checks in `protocol-http`.

### 8. Crate boundaries

`shared` next to `kernel`, `consent` alone, and `social-login` apart from `federation` are splits without seams. Key management and outbound HTTP had adapters but no owner for their rules. [ADR-0002](../adr/0002-crate-consolidation.md) merges four and adds two. Remaining doubt: `oauth` is large, and application/client management may deserve its own crate once SAML service providers also need an application registry in Phase 6.

### 9. Roadmap ordering

Sessions (Phase 4 in the specification) are needed by login in Phase 1 and by OAuth in Phase 2. Signing keys (Phase 9) are needed by Phase 2. The flow engine (Phase 4) would replace hard-coded login written in Phase 1. Admin RBAC appears only with the authorization engine in Phase 5, leaving the Admin API unprotected for four phases. The [roadmap](../product/roadmap.md#changes-from-the-specifications-roadmap) moves the minimal form of each earlier.

### 10. Shared origin

Tenants under `/t/{slug}` on one host share an origin, so cookie paths do not separate them in the browser. The design forbids tenant-supplied HTML and scripts and recommends dedicated hosts for production. It also means `__Host-` cookies are only usable on dedicated hosts. Worth considering: make a subdomain per tenant the default and keep path-based addressing for development only. That needs wildcard DNS and certificates, so it is an operations trade-off left open.

### 11. Native ReBAC

A relationship engine with nested and inherited relations at scale is what Zanzibar-style systems spend years on (consistency tokens, caching, reverse indexes). The design keeps tuples and bounded checks as a Phase 5 stretch and names an OpenFGA adapter as the path for serious use. If ReBAC is a headline feature, it should be planned as its own track.

### 12. Engine combination

The specification's responsibilities list (role resolution, attribute, relationship and policy evaluation) could be read as one decision drawing on all engines. Combining decisions across engines needs a combining algorithm and yields hard-to-explain results. v1 binds one engine per namespace; OPA policies that need roles receive them as data.

### 13. Redis

Marked optional in the stack, but rate limiting, replay protection and session caching usually assume it. The design requires a non-Redis implementation behind every such port and runs the contract suites against both ([ADR-0007](../adr/0007-postgres-required-redis-optional.md)). The honest limitation: per-node rate limits without Redis are weaker by a factor of the replica count.

### 14. Frontend cost

Three React applications, a visual flow designer, a Rego editor with testing and simulation, theming, localization and accessibility are easily as much work as the backend. The design builds APIs first, consoles one phase behind, form-based flow editing before the visual designer, and theming as tokens only. The admin console as specified has 21 modules; no estimate in this repository covers it properly yet.

### 15. Plugins

Ten kinds of plugin, manifests, lifecycle and WASM before any feature exists would freeze interfaces too early. The design defines internal traits now, ships webhooks in Phase 5 and WASM in Phase 8 for five extension points only, and excludes security-critical points permanently ([ADR-0012](../adr/0012-extension-strategy.md)).

### 16. Complexity trimmed or flagged

| Item | Assessment |
|---|---|
| HOTP | Rarely needed; kept P0 only because it shares code with TOTP |
| Front-channel logout, session management iframe | Unreliable under modern third-party cookie restrictions; P2, may be dropped |
| Provider failover | Vague requirement with few real uses; P2 |
| Identity merging | Dangerous and rare; P2 behind strong proof |
| Phone + password | Supported as an identifier kind, no dedicated work |
| OPA "cluster" mode | Same as remote with several instances; no separate mechanism |
| Decision cache for OPA | Off by default; easy to get wrong |
| Mapper layers | None: adapters build aggregates directly |
| Generic repository abstractions | None: each port is specific to its aggregate |

### 17. Gaps in the specification

| Gap | Handling |
|---|---|
| Issuer and URL design per tenant, custom domains | Added (FR-TEN-02, 03) |
| Registration, email verification as explicit features | Added (FR-AUT-04) |
| Notification templates and deliverability | Minimal in Phase 1; bounce handling not designed |
| Rate limiting design | Required by NFR-SEC-09; algorithm and limits not yet specified |
| Platform administrator model and support access | Sketched in multi-tenancy; needs its own design |
| Outbox and job infrastructure | Added to Phase 0 |
| Data residency, regional deployments | Not addressed; dedicated deployments are the only answer today |
| Compliance mapping (GDPR/LGPD, SOC 2) | Only export and deletion covered |
| Password migration from other systems | Import of foreign hash formats is P2; lazy migration not designed |
| Bot detection and CAPTCHA | Not designed; a risk signal extension point exists |
| Billing and plan enforcement | Quotas only |
| Break-glass and tenant recovery procedures | Not designed |
| Internationalization of emails and UI | Required by NFR-USA-02; translation workflow not defined |
| FAPI 2.0 profile | Not requested; PAR, DPoP and `private_key_jwt` put it within reach |
| Token and key behavior during tenant suspension or deletion | Defined at high level only |

### 18. Weak points of this design

These are places where this design may itself be wrong.

- **`adapters-postgres` depends on every context.** It is one crate so that transactions and migrations are uniform, but it recompiles on any port change and is a merge hot-spot. Splitting it per context is possible later since each context has its own schema.
- **Flow engine in Phase 1** adds complexity before its benefit is visible. If Milestone 1 slips, this is the likely cause; a fallback is a fixed two-step interpreter with the same data model.
- **Outbox on PostgreSQL** makes audit eventually consistent by a short lag. Audit records that must be atomic with their cause (administrative actions) should be written in the same transaction instead; the split between the two classes is not yet specified.
- **Administrative RBAC before the authorization context exists.** Milestone 1 uses a fixed role check and a stopgap admin key. A minimal `authorization` crate with `authorization-native` should land in Phase 1 right after the milestone, or the stopgap will spread.
- **CEL for ABAC** assumes a mature Rust interpreter; unverified.
- **BFF inside `holdor-server`** makes the server its own OAuth client, a bootstrap loop to handle carefully at first start.
- **RLS with connection poolers** is sound in transaction mode but must be load-tested; a mis-set pool mode would silently break the second line of defense, so the readiness check should verify it.
- **Performance targets** in the requirements are proposals, not measurements.
- **The API specification is an outline.** Request and response schemas are deferred to the generated OpenAPI document.
- **No sizing in time.** Relative effort only, because team size is unknown.

## Decisions requested before implementation

1. Confirm the tenant and organization model (finding 2).
2. Confirm the cryptography departure from "RustCrypto only" (finding 5).
3. Confirm one engine per namespace and the asserted-versus-resolved attribute rule (findings 4, 12).
4. Confirm dedicated OPA instances for tenant-authored Rego (finding 3).
5. Choose the default tenant addressing: path, subdomain or both (finding 10).
6. Confirm the roadmap moves (finding 9) and the scope of Milestone 1.
7. State whether SAML and native ReBAC are commitments or candidates to cut (findings 6, 11).
