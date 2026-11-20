# PRD — Holdor

## 1. Problem

Teams that need identity and authorization choose today between:

- **Keycloak**: complete, but heavy in memory and operations (JVM), hard to extend (Java SPIs), and limited in fine-grained authorization.
- **Casdoor / Authentik**: lighter, but with uneven protocol coverage and security guarantees.
- **Auth0 / Okta / Entra**: SaaS, per-user pricing, no control over data.
- **OPA / OpenFGA**: solve authorization but not identity; joining the two worlds is left to each team.

There is no self-hosted option that combines an identity server, a federation broker and an authorization platform (with Rego policy management) in one light binary that is secure by default and multi-tenant from the start.

## 2. Vision

Holdor is an IAM platform written in Rust that acts as Identity Provider, OAuth 2.x Authorization Server, OpenID Provider, external identity broker and authorization platform, with tenant isolation at every layer.

## 3. Personas

| Persona | Goal | What success looks like |
|---|---|---|
| **Platform operator** (SRE) | Run Holdor in HA, upgrade without downtime | One binary, one Postgres, a Helm chart; upgrades keep sessions |
| **Tenant administrator** | Configure apps, IdPs, policies, users | SSO with Entra ID configured in under 15 minutes without reading code |
| **Application developer** | Integrate login and authorization | OIDC login working with a standard SDK in under 30 minutes |
| **Security engineer** | Audit, define policy, respond to incidents | Complete audit trail; versioned policies with rollback |
| **End user** | Sign in, manage MFA, sessions and consents | Passkey sign-in in at most two interactions |
| **Workload / AI agent** | Obtain its own short-lived credentials | No shared human credential; per-tool scope |

## 4. Goals

1. **Interoperability**: pass the OpenID conformance suite (Basic OP and Config OP profiles) in Phase 2.
2. **Secure by default**: RFC 9700 applied with no off switch for new clients (PKCE, exact redirect URI matching, refresh token rotation).
3. **Isolation**: no cross-tenant access test may pass; isolation is validated in the database (RLS), cache, sessions, keys and policies.
4. **Simple operations**: PostgreSQL is the only mandatory dependency. Redis and OPA are optional.
5. **Authorization as a product**: a single decision API over native RBAC/ACL/ABAC/ReBAC and OPA, with a policy lifecycle.
6. **Extensibility**: extension points defined as stable contracts from Phase 1, even though the plugin runtime only arrives in Phase 8.

## 5. Non-goals

- Not an LDAP directory (Holdor is an LDAP *client*, not a server).
- No implicit grant and no resource owner password credentials grant.
- No database-per-tenant in v1 (see [ADR-0006](../adr/0006-tenant-isolation.md)).
- No reimplementation of a Rego engine: OPA is used as is.
- Not an API gateway: Holdor is PDP/PAP; enforcement (PEP) stays in applications.
- No microservices at the start.

## 6. Scope by capability

| Capability | Holdor's role | Phase |
|---|---|---|
| Identity (users, groups, organizations) | System of record | 1 |
| Local password authentication | IdP | 1 |
| OAuth 2.x AS + OIDC OP | AS / OP | 2 |
| Social login and OIDC/OAuth2 federation | RP / broker | 3 |
| MFA, passkeys, flow engine | IdP | 4 |
| Native authorization + OPA | PDP / PAP | 5 |
| SAML, LDAP, SCIM | IdP / SP / client / SCIM server | 6 |
| Governance (access reviews, delegation) | — | 7 |
| Plugins, SDKs, Terraform | — | 8 |
| HA, DR, external KMS, hardening | — | 9 |

## 7. Product metrics

| Metric | Target |
|---|---|
| Time to first OIDC login (clean install) | ≤ 30 min |
| `holdor-server` memory at rest | ≤ 150 MB |
| `/token` p99 (`client_credentials`) | ≤ 50 ms |
| Native authorization evaluation p99 (RBAC) | ≤ 5 ms |
| OpenID conformance (Basic OP, Config OP) | 100% of mandatory tests |
| Critical vulnerabilities open for more than 7 days | 0 |

## 8. Product risks

| Risk | Impact | Mitigation |
|---|---|---|
| Scope equal to Keycloak + OPA + OpenFGA combined | Never reaching production | Phases that deliver value alone; a tiny M1; ReBAC and SAML treated as separate bets |
| Immature Rust ecosystem for SAML and XML-DSig | Signature wrapping vulnerabilities | Dedicated spike before Phase 6; see the [critical review](../architecture/critical-review.md) |
| Tenant-authored Rego in a shared OPA | Cross-tenant leakage | Dedicated OPA per tenant for tenant-authored policy |
| Visual flow and policy consoles consuming the budget | Core slips | Consoles after APIs; declarative JSON flows before the visual editor |

## 9. Release criteria

- **Alpha (end of Phase 2)**: conformant OP, one tenant, minimal admin console, no upgrade guarantees.
- **Beta (end of Phase 5)**: federation, MFA, authorization with OPA, compatible migrations.
- **GA (end of Phase 9)**: HA, tested DR, external pentest, published protocol conformance, signed SBOM.
