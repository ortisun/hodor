# Competitive analysis

How Hodor's planned features and its admin console compare with comparable products, as of November 2026. The [product requirements](product-requirements.md#1-problem) name the problem Hodor solves; this page checks that claim against what the market actually ships, and lists what the comparison changes in Hodor's plans.

## How this was gathered

Facts were checked against official documentation, release notes and vendor blogs in November 2026; the main sources are listed at the end. Cells marked *not verified* come from general knowledge and were not re-checked; "unknown" means no reliable source was found. Observations about consoles come mostly from documentation, not hands-on use. Vendors move fast: revisit this page before relying on a cell for a decision.

## 1. The products compared

| Product | Kind | Hosting and license |
|---|---|---|
| Keycloak | Open-source identity and access management server | Self-hosted, Apache 2.0 |
| Auth0 (Okta Customer Identity) | Customer identity platform | Software as a service, private cloud option |
| Okta Workforce Identity | Workforce identity platform | Software as a service |
| Microsoft Entra ID | Workforce identity platform | Software as a service |
| Zitadel | Open-source identity platform | Self-hosted or cloud; GNU Affero General Public License 3.0 since version 3, commercial license available |
| authentik | Open-source identity provider | Self-hosted; open core with an Enterprise edition |
| Ory (Kratos, Hydra, Keto, Polis) | Open-source identity components | Apache 2.0 plus the Ory Enterprise License, or software as a service |
| FusionAuth | Customer identity platform | Self-hosted or cloud; proprietary with a free Community edition |
| WorkOS, Clerk | Developer identity platforms | Software as a service |
| Casdoor | Open-source identity provider | Self-hosted, Apache 2.0 |
| OpenFGA / Auth0 FGA, Permit.io, Cerbos, Open Policy Agent | Authorization engines and policy platforms | Mixed; see [section 2.4](#24-authorization-engines) |

## 2. Features

Hodor's column is the plan, with the phase from the [roadmap](roadmap.md) in which each feature arrives. "Yes" for a competitor means shipped and generally available.

### 2.1 Protocols

| Feature | Hodor | Keycloak | Auth0 | Okta | Entra ID | Zitadel | authentik |
|---|---|---|---|---|---|---|---|
| OAuth 2 and OpenID Connect | Phase 2 | Yes | Yes | Yes | Yes | Yes | Yes |
| SAML | Phase 6 | Yes | Yes | Yes | Yes | Yes | Yes |
| SCIM server | Phase 6 | Supported since 26.8 | Inbound, enterprise connections (not verified) | Yes | Outbound provisioning (not verified) | Yes (not verified) | Outbound, improved in 2026.2 |
| LDAP and Active Directory | Phase 6 (client) | Federation and Kerberos | Connector | Interface (not verified) | Through Domain Services (not verified) | As identity provider (not verified) | LDAP outpost, RADIUS (not verified) |
| PKCE | Phase 2, mandatory | Yes | Yes | Yes | Yes | Yes | Yes |
| Pushed authorization requests | 0.5.0, Milestone 13 | Yes | Add-on | Yes (not verified) | Unknown | Unknown | Unknown |
| DPoP | 0.6.0, Milestone 17 | Yes (26.4) | Add-on | Yes (not verified) | Own proof-of-possession (not verified) | Unknown | Unknown |
| FAPI 2.0 | 0.6.0, Milestones 17 and 18 | Final Security Profile and Message Signing (26.4) | Certified, add-on | Unknown | No (not verified) | Unknown | Unknown |

### 2.2 Authentication and sessions

| Feature | Hodor | Keycloak | Auth0 | Okta | Entra ID | Zitadel | authentik |
|---|---|---|---|---|---|---|---|
| Passkeys | Phase 4 | Yes, off by default | Yes | Yes | Yes, default method since July 2026 | Yes | Yes |
| Adaptive, risk-based authentication | Phase 4 (risk signals in flow conditions) | Conditional flows only | Adaptive multi-factor authentication | Identity Threat Protection | ID Protection and Conditional Access | Unknown | Policies with location and reputation |
| Breached-password check | Phase 1 | No | Yes | Unknown | Yes (not verified) | Unknown | Yes (not verified) |
| Bot detection | Not planned | No | Yes | ThreatInsight | Yes | Unknown | Unknown |
| Flow editor | Declarative flows in Phase 1, editing and simulation in Phase 4, visual editor in Phase 7 | Visual tree; Workflows in YAML | Code (Actions) and visual (Forms) | No-code Workflows | Conditional Access, user flows | Actions over webhooks | Visual flows and stages |
| Report-only or dry-run for sign-in policy | Simulation (Phase 4) | No | No | No | Report-only mode and What If tool | Unknown | Unknown |
| Session revocation | Phase 2 | Yes | Yes | Yes, Universal Logout | Continuous Access Evaluation | Yes | Yes, plus an account lockdown action |

### 2.3 Administration, audit and governance

| Feature | Hodor | Keycloak | Auth0 | Okta | Entra ID | Zitadel | authentik |
|---|---|---|---|---|---|---|---|
| Multi-tenancy | Tenants with row-level security, organizations inside (Phase 1) | Realms and Organizations | Tenants and Organizations | One organization per tenant | Tenant and administrative units | Instance, organization, project | Brands |
| Audit trail | Hash-chained, append-only, in the same transaction (Phase 1) | Admin events, off by default (not verified) | Yes | System Log | Yes | Event-sourced: every change is an event | Events and notification rules |
| Streaming to a security event management system | Phase 5 | Through an extension (not verified) | Log Streams | Yes | Yes | Unknown | Webhooks |
| Delegated administration | Fixed roles in Phase 1, delegation in Phase 7 | Organization administrators (26.7) | Tenant member roles | Custom roles and resource sets | Custom roles, administrative units | Manager roles per level | Role-based |
| Just-in-time administrator elevation | Phase 7 | No | No | Okta Privileged Access | Privileged Identity Management | Unknown | Expiring, approved grants (Enterprise) |
| Second approver on configuration changes | Phase 7 | No | No | No | No (approval is for role activation only) | No | No (approval is for access grants) |
| Access reviews | Phase 7 | No | No | Okta Identity Governance | Access Reviews | Unknown | Unknown |
| Signing key rotation | Phase 2, scheduled with overlap | Key providers by priority | Rotate and revoke | Yes | Automatic | Unknown | Certificates |
| Security posture score | Phase 2 | No | Security Center (threat view, no score) | HealthInsight | Identity Secure Score | No | No |

### 2.4 Authorization engines

| Feature | Hodor | OpenFGA / Auth0 FGA | Permit.io | Cerbos | Open Policy Agent |
|---|---|---|---|---|---|
| Model | Role-based, list-based, attribute-based, relationship-based (Optional) and Open Policy Agent behind one decision API (Phase 5) | Relationships with conditions | Roles, attributes, relationships on Open Policy Agent | Roles and attributes in YAML | Rego |
| Testing and simulation | Validate, test, simulate, publish, rollback (Phase 5) | Model tests, command-line tool | Editor or Git, approval flows | Test suites, playground with traces and diffs | Unit tests, playground |
| Identity included | Yes | No | No | No | No |

Open Policy Agent itself stays under the Cloud Native Computing Foundation. In August 2025 Apple hired its core maintainers from Styra; the future of Styra's commercial control plane is unknown. There is now no first-party graphical policy console for Open Policy Agent, which leaves room for Hodor's policy screens.

### 2.5 Workloads and artificial intelligence agents

| Product | What ships |
|---|---|
| Hodor | Service accounts and agents with their own credentials, token exchange with an actor chain (Phase 5); per-tool authorization for Model Context Protocol servers (Phase 8, Optional) |
| Keycloak | Kubernetes service-account client authentication, JWT authorization grant, token exchange with `act` (preview in 26.8) |
| Auth0 | Auth0 for AI Agents, generally available November 2025 |
| Okta | Agent single sign-on and Cross App Access, generally available August 2026 |
| Entra ID | Workload ID; Agent ID generally available |
| WorkOS, Clerk | Authorization for Model Context Protocol servers, generally available 2026 |

### 2.6 Service meshes and workload certificates

Checked against Keycloak and Ory Hydra only, the two self-hosted servers closest to Hodor. The other products of this page were not checked.

| Feature | Hodor | Keycloak | Ory Hydra |
|---|---|---|---|
| Client authentication with a client certificate (RFC 8705) and tokens bound to it | Milestone 10 (0.4.0) | Yes | Not found in its documentation; a design in a discussion of its repository |
| A client certificate forwarded by a proxy that ends TLS | Milestone 10, RFC 9440 from trusted proxies only | Lookup providers for Apache, HAProxy, NGINX, Traefik and RFC 9440 | No |
| SPIFFE client authentication with a JWT-SVID | Milestone 10 | Preview, as part of federated client authentication, until the Internet-Draft is final | No |
| Kubernetes service account tokens as client authentication | Not planned | Yes (federated client authentication) | No |
| Signing a person in with a client certificate | Phase 6 | Yes, with revocation list and OCSP checks | No |
| Decisions asked by a mesh's proxy (Envoy external authorization) | Milestone 11, through `hodor-ext-authz` | No | No; Ory Oathkeeper is a separate proxy |
| Issuing certificates | Milestone 12: an optional authority per tenant that signs the intermediates of its meshes | No | No |

Keycloak's federated client authentication trusts the outside provider fully: if that provider is compromised, it can mint assertions for every client that relies on it. Hodor binds each client to one SPIFFE identifier, so a compromised trust domain reaches only the clients bound to it.

Issuing certificates is left to public key infrastructure tools in both products: HashiCorp Vault, smallstep, SPIRE, cert-manager and the clouds' own authorities. Hodor's authority is an opportunity rather than a gap: nobody in this comparison offers it.

### 2.7 OpenID certification

Read from the Foundation's lists of certified OpenID Providers in November 2026 (sources 29 to 33). A profile is named as the Foundation's tables name it; the year is that of the most recent certification found.

| Implementation | OpenID Connect | Logout | FAPI and backchannel authentication |
|---|---|---|---|
| Hodor | Basic and Config pass in continuous integration, never certified; every profile planned for 0.5.0 | Back-Channel passes in continuous integration; every profile planned for 0.5.0 | Planned for 0.6.0 |
| Keycloak | Basic, Implicit, Hybrid, Config, Dynamic, Form Post (18.0.0, 2022) | All four (18.0.0) | FAPI 1.0 Advanced, eight variants (15.0.2, 2021); FAPI-CIBA, four (2022); no FAPI 2.0 listed, though 26.4 supports it |
| Authlete | Basic, Implicit, Hybrid, Config, Dynamic, Form Post (2.2, 2020) | None | FAPI 1.0 Advanced, eight; FAPI-CIBA, four; FAPI 2.0 final, seven and client credentials (3.0, 2025 and 2026) |
| node-oidc-provider | Basic, Implicit, Hybrid, Config, Form Post, 3rd Party-Init (2020) | RP-Initiated, Back-Channel | FAPI 1.0 Advanced, eight; FAPI-CIBA, four; FAPI 2.0 final, seven (9.2.0, 2025) |
| Ory Hydra | Basic, Implicit, Hybrid, Config, Dynamic (1.0.0, 2018) | None | None |
| Zitadel | Basic (1.53.1, 2021) | None | None |
| Authelia | Basic, Implicit, Hybrid, Config, Form Post (4.39, 2025) | None | None |
| Issuerd, in Rust | Basic, Implicit, Hybrid, Config, Dynamic, Form Post, 3rd Party-Init (0.1.17, 2026) | All four (0.1.19) | None |
| Nazo Auth Server, in Rust | Basic, Config, Form Post, 3rd Party-Init (0.2.0, 2026) | All four | FAPI 2.0 Security Profile in every variant, Message Signing with signed requests and JARM; FAPI-CIBA, four |

Certification is common among Hodor's open-source peers, and two servers written in Rust already hold most profiles. Hodor's [plan](../decisions/0044-what-0.5.0-and-0.6.0-hold.md) closes the gap at 0.5.0 for OpenID Connect and at 0.6.0 for FAPI; the differentiator stays what it was, tenant isolation and authorization, not the certificates themselves.

## 3. Admin consoles

| Product | Done well | Done badly |
|---|---|---|
| Keycloak | Organization-scoped delegation; realm search by display name | Admin events off by default (not verified); deep tab nesting; plain confirmation without re-authentication; no posture view, command palette or approvals |
| Auth0 | Security Center with attack-protection status; tenants tagged Production, Staging or Development | Environments are separate tenants with no diff or promotion; dry-run lives outside the console |
| Okta | HealthInsight ranks tasks by impact; protected actions force re-authentication for super-administrator changes; the console has its own sign-in policy | Protected actions rely on pop-ups and break for federated administrators; delegation is complex |
| Entra ID | Identity Secure Score with recommendations; protected actions bound to an authentication context; time-bound role activation; report-only policies | Very wide navigation; approval covers role activation, not individual changes |
| Zitadel | Clear context switcher between organizations | No visible posture or risk view found |
| authentik | Flow diagrams; events map without external requests | Breadth overwhelms new users |
| Ory | Workspaces with production, staging and development; command-line and Terraform parity | Many features only in the paid editions |
| Cerbos, Permit.io | Playground with diffs and execution traces; approval flows | Authorization only |

Patterns across the market:

- **Posture scores exist only in software-as-a-service products.** No self-hosted product ships one.
- **Re-authentication before sensitive console actions** exists only in Okta and Entra ID.
- **Nobody requires a second approver for configuration changes.** Approvals exist only for role activation (Entra ID) and access grants (authentik).
- **Dry-run and simulation** exist for Entra ID Conditional Access and in the policy engines, not for authentication flows or client settings elsewhere.
- **Environments are separate tenants or projects** with no diff or promotion between them.
- Command palettes and dark themes are rarely documented.

## 4. What security practitioners ask of a privileged console

| Source | What it asks |
|---|---|
| NIST SP 800-63B-4 (final, August 2025) | Authenticator Assurance Level 3, which fits administrators: phishing-resistant authentication required; reauthentication at least every 12 hours; inactivity timeout of 15 minutes or less |
| OWASP Application Security Verification Standard 5.0 | Inactivity and absolute session timeouts (7.3.1, 7.3.2); administrators can end sessions for one user or all (7.4.5); full re-authentication before changing sensitive attributes (7.5.1); an extra factor for highly sensitive operations at level 3 (7.5.3) |
| United States Cybersecurity and Infrastructure Security Agency, Secure by Design | Multi-factor authentication on by default for administrators, phishing-resistant for privileged users; secure configuration out of the box; audit logs and single sign-on at no extra cost; logs detailed enough to detect bypassed controls |
| Center for Internet Security Controls 8.1 (not verified) | Dedicated administrator accounts; multi-factor authentication for administrative access; centralized, retained audit logs |
| Microsoft emergency access guidance | At least two emergency ("break-glass") accounts with phishing-resistant authenticators different from normal administrators'; alert on every use; test them regularly |
| Zero Trust, NIST SP 800-207 (not verified) | Evaluate every request; least privilege; continuous session evaluation; just-in-time elevation instead of standing privilege |

## 5. What this changes for Hodor

### Confirmed differentiators

These are rare or absent elsewhere and are now specified in the [design system](../design/design-system.md) and the [control plane](../design/control-plane.md):

1. **A security posture page in a self-hosted product**, computed by the server (Requirement-Console-07).
2. **The dangerous action ladder**, with recent authentication for sensitive actions (Requirement-Console-03, Requirement-Console-04) and a second approver for configuration changes, not only for role activation (Requirement-Console-12).
3. **Change preview with diff, blast radius and simulation** for flows and policies, not only for one kind of policy.
4. **One product for identity and authorization**, with the policy console that Open Policy Agent no longer has.
5. **Audit on by default, hash-chained and free**, as Secure by Design asks.
6. **Administrator sessions at Authenticator Assurance Level 3** and first-class break-glass accounts (Requirement-Console-01, Requirement-Console-06).

### Gaps to decide on

These are features that competitors ship and Hodor's roadmap does not cover. None is added by this page; each needs a decision before it enters the requirements.

| Gap | Who ships it | Suggestion |
|---|---|---|
| FAPI 2.0 security profile | Keycloak, Auth0 | Decided: a certification target of 0.6.0, with FAPI 1.0 Advanced and FAPI-CIBA ([Decision 0044](../decisions/0044-what-0.5.0-and-0.6.0-hold.md)) |
| Bot detection on sign-up and sign-in | Auth0, Okta, Entra ID, Clerk | Add a risk signal source behind the existing extension points in Phase 4, without third-party scripts in the hosted login |
| Report-only mode for authentication policy conditions | Entra ID | Extend flow simulation (Requirement-Authentication-11) with a report-only mode that records what a draft would have decided on live traffic |
| Continuous session evaluation across applications | Entra ID, Okta | Consider the OpenID Shared Signals Framework for session revocation events, after back-channel logout in Phase 2 |
| Self-service setup portal for a customer's own administrators | WorkOS | Consider for Phase 7 with delegated administration per organization |
| Promotion of configuration between tenants (staging to production) with a diff | Nobody | An opportunity rather than a gap: export, diff and promote tenant configuration, building on the Terraform provider in Phase 8 |
| Workload and agent identity timing | Auth0, Okta, Entra ID, Keycloak (preview) shipped in 2025–2026 | Phase 5 and Phase 8 may be late for this market; consider moving the Model Context Protocol authorization profile earlier |

## Sources

1. Keycloak 26.8.0 release: https://www.keycloak.org/2026/10/keycloak-2680-released
2. Keycloak 26.4.0 release: https://www.keycloak.org/2025/09/keycloak-2640-released
3. Keycloak 26.7.0 release: https://www.keycloak.org/2026/07/keycloak-2670-released
4. authentik 2026.8: https://goauthentik.io/blog/2026-09-01-authentik-version-2026-8/
5. Auth0 Highly Regulated Identity: https://auth0.com/docs/secure/highly-regulated-identity
6. Auth0 Security Center: https://auth0.com/docs/secure/security-center
7. Auth0 for AI Agents: https://auth0.com/blog/auth0-for-ai-agents-generally-available/
8. Entra ID passkeys by default: https://microsoft.com/en-us/security/blog/2026/07/13/microsoft-entra-id-security-updates-passkeys-are-the-default-authentication-method-in-entra-id/
9. Entra ID protected actions: https://learn.microsoft.com/azure/active-directory/roles/protected-actions-overview
10. Entra ID recommendations and Secure Score: https://learn.microsoft.com/entra/identity/monitoring-health/overview-recommendations
11. Microsoft emergency access accounts: https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access
12. Okta HealthInsight: https://help.okta.com/en-us/content/topics/security/healthinsight/healthinsight-security-task-recomendations.htm
13. Okta protected actions: https://help.okta.com/en-us/content/topics/security/admin-console-protected-actions.htm
14. Okta Agent single sign-on: https://okta.com/newsroom/press-releases/okta-brings-first-class-identity-to-ai-agents-with-agent-sso/
15. Zitadel license change: https://zitadel.com/blog/apache-to-agpl
16. Ory workspaces: https://www.ory.com/docs/guides/workspaces
17. OpenFGA incubation: https://openfga.dev/blog/incubation-announcement
18. Open Policy Agent maintainers' note: https://openpolicyagent.org/blog/note-from-teemu-tim-and-torin-to-the-open-policy-agent-community-2dbbfe494371
19. Cerbos Hub playground: https://www.cerbos.dev/blog/cerbos-hub-playground-recent-updates
20. NIST SP 800-63B-4, authenticator assurance levels: https://pages.nist.gov/800-63-4/sp800-63b/aal
21. OWASP Application Security Verification Standard 5.0, session management: https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x16-V7-Session-Management.md
22. Secure by Design pledge: https://www.cisa.gov/securebydesign/pledge
23. Keycloak, federated client authentication: https://www.keycloak.org/2026/01/federated-client-authentication
24. Keycloak, the SPIFFE package of 26.8.1: https://www.keycloak.org/docs-api/26.8.1/javadocs/org/keycloak/broker/spiffe/package-summary.html
25. Red Hat build of Keycloak, client certificate lookup behind a proxy: https://docs.redhat.com/ja/documentation/red_hat_build_of_keycloak/26.0/html/server_configuration_guide/reverseproxy-enabling-client-certificate-lookup
26. Keycloak, the RFC 9440 client certificate lookup: https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/services/x509/Rfc9440ClientCertificateLookup.html
27. Ory Hydra, mutual TLS client authentication proposal: https://github.com/ory/hydra/discussions/2273
28. OAuth SPIFFE client authentication, Internet-Draft 03: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-spiffe-client-auth-03
29. OpenID Foundation, certified OpenID Providers: https://openid.net/certification/certified-openid-providers-profiles/
30. OpenID Foundation, certified OpenID Providers for logout profiles: https://openid.net/certification/certified-openid-providers-for-logout-profiles/
31. OpenID Foundation, certified FAPI 1.0 Advanced OpenID Providers: https://openid.net/certification/certified-fapi1-adv-openid-providers-profiles/
32. OpenID Foundation, certified FAPI 2.0 OpenID Providers: https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/
33. OpenID Foundation, certified FAPI-CIBA OpenID Providers: https://openid.net/certification/certified-fapi-ciba-openid-providers-profiles/
