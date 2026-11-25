# Product requirements — Hodor

## 1. Problem

Teams that need identity and authorization choose today between:

- **Keycloak**: complete, but heavy in memory and operations (Java virtual machine), hard to extend (Java service provider interfaces), and limited in fine-grained authorization.
- **Casdoor / Authentik**: lighter, but with uneven protocol coverage and security guarantees.
- **Auth0 / Okta / Entra**: SaaS, per-user pricing, no control over data.
- **Open Policy Agent / OpenFGA**: solve authorization but not identity; joining the two worlds is left to each team.

There is no self-hosted option that combines an identity server, a federation broker and an authorization platform (with Rego policy management) in one light binary that is secure by default and multi-tenant from the start.

## 2. Vision

Hodor is an identity and access management platform written in Rust that acts as Identity Provider, OAuth 2.x Authorization Server, OpenID Provider, external identity broker and authorization platform, with tenant isolation at every layer.

## 3. Personas

| Persona | Goal | What success looks like |
|---|---|---|
| **Platform operator** (site reliability engineer) | Run Hodor in high availability, upgrade without downtime | One binary, one Postgres, a Helm chart; upgrades keep sessions |
| **Tenant administrator** | Configure apps, identity providers, policies, users | Single sign-on with Entra ID configured in under 15 minutes without reading code |
| **Application developer** | Integrate login and authorization | OpenID Connect login working with a standard software development kit in under 30 minutes |
| **Security engineer** | Audit, define policy, respond to incidents | Complete audit trail; versioned policies with rollback |
| **End user** | Sign in, manage multi-factor authentication, sessions and consents | Passkey sign-in in at most two interactions |
| **Workload or artificial intelligence agent** | Obtain its own short-lived credentials | No shared human credential; per-tool scope |

## 4. Goals

1. **Interoperability**: pass the OpenID conformance suite (Basic OpenID Provider and Config OpenID Provider profiles) in Phase 2.
2. **Secure by default**: RFC 9700 applied with no off switch for new clients (PKCE, exact redirect URI matching, refresh token rotation).
3. **Isolation**: no cross-tenant access test may pass; isolation is validated in the database (row-level security), cache, sessions, keys and policies.
4. **Simple operations**: PostgreSQL is the only mandatory dependency. Redis and Open Policy Agent are optional.
5. **Authorization as a product**: a single decision API over native role-based, list-based, attribute-based and relationship-based access control and Open Policy Agent, with a policy lifecycle.
6. **Extensibility**: extension points defined as stable contracts from Phase 1, even though the plugin runtime only arrives in Phase 8.

## 5. Non-goals

- Not an LDAP directory (Hodor is an LDAP *client*, not a server).
- No implicit grant and no resource owner password credentials grant.
- No database-per-tenant in v1 (see [Decision 0006](../decisions/0006-tenant-isolation.md)).
- No reimplementation of a Rego engine: Open Policy Agent is used as is.
- Not an API gateway: Hodor is the policy decision and administration point; enforcement (policy enforcement point) stays in applications, or in a service mesh's proxies, which ask through `hodor-ext-authz` ([Decision 0029](../decisions/0029-hodor-in-a-service-mesh.md)).
- Not a public key infrastructure: Hodor never issues a workload's own certificate. The optional authority per tenant signs only the intermediates of the tenant's service meshes ([Decision 0030](../decisions/0030-optional-certificate-authority.md)).
- No microservices at the start.

## 6. Scope by capability

| Capability | Hodor's role | Phase |
|---|---|---|
| Identity (users, groups, organizations) | System of record | 1 |
| Local password authentication | Identity provider | 1 |
| OAuth 2.x authorization server + OpenID Connect OpenID Provider | Authorization server / OpenID Provider | 2 |
| Social login and OpenID Connect/OAuth2 federation | Relying party / broker | 3 |
| Multi-factor authentication, passkeys, flow engine | Identity provider | 4 |
| Native authorization + Open Policy Agent | Policy decision point / policy administration point | 5 |
| SAML, LDAP, SCIM | Identity provider / service provider / client / SCIM server | 6 |
| Workload certificates, service meshes, an optional certificate authority per tenant | Verifier of workload identities / policy decision point for the mesh's proxies / authority above the meshes | 6 and 8, pulled into 0.4.0 |
| Governance (access reviews, delegation) | — | 7 |
| Plugins, software development kits, Terraform | — | 8 |
| High availability, disaster recovery, external key management service, hardening | — | 9 |

## 7. Product metrics

| Metric | Target |
|---|---|
| Time to first OpenID Connect login (clean install) | ≤ 30 min |
| `hodor-server` memory at rest | ≤ 150 MB |
| `/token` p99 (`client_credentials`) | ≤ 50 ms |
| Native authorization evaluation p99 (role-based access control) | ≤ 5 ms |
| OpenID conformance (Basic OpenID Provider, Config OpenID Provider) | 100% of mandatory tests |
| Critical vulnerabilities open for more than 7 days | 0 |

## 8. Product risks

| Risk | Impact | Mitigation |
|---|---|---|
| Scope equal to Keycloak + Open Policy Agent + OpenFGA combined | Never reaching production | Phases that deliver value alone; a tiny Milestone 1; relationship-based access control and SAML treated as separate bets |
| Immature Rust ecosystem for SAML and XML Signature | Signature wrapping vulnerabilities | Dedicated spike before Phase 6; see the [critical review](../architecture/critical-review.md) |
| Tenant-authored Rego in a shared Open Policy Agent | Cross-tenant leakage | Dedicated Open Policy Agent per tenant for tenant-authored policy |
| Visual flow and policy consoles consuming the budget | Core slips | Consoles after APIs; declarative JSON flows before the visual editor |

## 9. Release criteria

- **Alpha (end of Phase 2)**: conformant OpenID Provider, one tenant, minimal admin console, no upgrade guarantees.
- **Beta (end of Phase 5)**: federation, multi-factor authentication, authorization with Open Policy Agent, compatible migrations.
- **General availability (end of Phase 9)**: High availability, tested disaster recovery, external pentest, published protocol conformance, signed software bill of materials.
