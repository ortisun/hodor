# Product roadmap

The phases follow section 26 of the specification. Four items move earlier because later phases cannot be built safely without them; the moves are listed at the end.

```mermaid
flowchart LR
    phase0["0 Foundation"] --> phase1["1 Identity core"]
    phase1 --> phase2["2 OAuth2 and OpenID Connect"]
    phase2 --> phase3["3 Federation"]
    phase2 --> phase4["4 Advanced authentication"]
    phase2 --> phase5["5 Authorization engine"]
    phase3 --> phase6["6 Enterprise federation"]
    phase4 --> phase6
    phase5 --> phase7["7 Governance"]
    phase5 --> phase8["8 Ecosystem"]
    phase6 --> phase9["9 Production readiness"]
    phase7 --> phase9
    phase8 --> phase9
```

Phases 3, 4 and 5 depend only on Phase 2 and can run in parallel once there are people for it.

## Phases

| Phase | Outcome | Main deliverables | Exit criteria |
|---|---|---|---|
| **0 Foundation** | A workspace where a feature can be built, tested and shipped | Workspace and lints, architecture test, `kernel`, PostgreSQL adapter with row-level security harness, outbox, continuous integration, observability bootstrap, container image, docs skeleton | Continuous integration green; an empty server deploys with health checks and traces; architecture and tenant-isolation harness tests run |
| **1 Identity core** | A user can register and sign in to a tenant | Tenants, users, identifiers, groups, organizations, password credential, built-in login flow, single sign-on session, admin role-based access control (native, fixed roles), audit, email, minimal `auth-ui` | [Milestone 1](epics.md#milestone-1-walking-skeleton) accepted; cross-tenant suite passes |
| **2 OAuth2 and OpenID Connect** | Third-party apps can log users in | Applications and clients, Authorization Code + PKCE, Client Credentials, refresh rotation, revocation, introspection, JWKS and key rotation (local provider), Discovery, UserInfo, ID Token, consent, logout initiated by the relying party and back-channel logout, minimal admin console | OpenID conformance Basic OpenID Provider and Config OpenID Provider pass; **Alpha** |
| **3 Social login and federation** | Users sign in with external identities | Outbound HTTP client, generic OpenID Connect relying party, generic OAuth2, Google, Microsoft, GitHub, Apple, claim mapping, just-in-time, linking, routing rules | Interop suite against real and mock providers; linking threat tests pass |
| **4 Advanced authentication** | Strong and adaptive authentication | TOTP, WebAuthn and passkeys, recovery codes, one-time password and magic link, flow editing API with validation and simulation, step-up, risk signals, trusted devices, session limits, pushed authorization requests, DPoP, device grant, account console | Passkey-only login works; step-up by `acr_values` works |
| **5 Authorization engine** | Applications delegate decisions to Hodor | Authorization API, native role-based access control, access control list, attribute-based access control, Open Policy Agent adapter, bundle service, policy lifecycle, decision logs, simulation, token exchange, service accounts and agents, webhooks; native relationship-based access control as stretch | Latency targets met; Open Policy Agent failure tests pass; **Beta** |
| **6 Enterprise federation** | Enterprises connect their directories | SAML spike and implementation (identity provider and service provider), LDAP and Active Directory federation, SCIM server, mTLS client authentication, tenant-to-tenant federation | SAML attack corpus and interop pass; external review of SAML |
| **7 Governance** | Access is reviewable and delegable | Fine-grained and delegated administration, access reviews and certification, approval workflows, quotas, security monitoring and alerts | Segregation-of-duty rules enforced and audited |
| **8 Ecosystem** | Others can build on Hodor | WebAssembly plugin runtime, software development kits, developer portal, Terraform provider, command-line tool completeness, Model Context Protocol authorization profile | A third-party plugin runs under limits; Terraform manages a full tenant |
| **9 Production readiness** | Safe to run as critical infrastructure | Cloud key management service and Vault providers, high availability and disaster recovery drills, hardening, load and chaos campaigns, full conformance, Helm chart general availability, external pentest | non-functional requirement targets met and published; **General availability** |

## Console delivery

The consoles trail their APIs by one phase so that the API is settled first.

| Phase | Admin console | Account console | Hosted auth user interface |
|---|---|---|---|
| 1 | — | — | Login, registration, recovery |
| 2 | Users, applications, clients, keys, audit | — | Consent |
| 3 | Identity providers, routing | — | Provider selection, linking |
| 4 | Authentication policies, flows (form-based) | Profile, password, multi-factor authentication, passkeys, sessions, devices, linked accounts, consents | Multi-factor authentication, passkeys, branding, localization |
| 5 | Roles, policies, Rego editor, simulation, decision logs | — | — |
| 7 | Visual flow editor, access reviews | Data export, account deletion | Custom themes |

## Changes from the specification's roadmap

| Item | Specification | Here | Reason |
|---|---|---|---|
| Session management | Phase 4 | Core in Phase 1, advanced features in Phase 4 | Login without a session is not verifiable, and OAuth in Phase 2 depends on it |
| Authentication flow engine | Phase 4 | Interpreter in Phase 1 with one built-in flow; editing in Phase 4 | Avoids rewriting the login path ([Decision 0013](../decisions/0013-auth-flow-as-data.md)) |
| Key management | Phase 9 (key management service integrations) | Key domain and local provider in Phase 2; external key management service in Phase 9 | Token signing and rotation cannot wait |
| Administrative role-based access control | Phase 5 / 7 | Fixed built-in admin roles in Phase 1 | The Admin API must be protected from its first endpoint |
| Webhooks | Phase 8 | Phase 5 | First extension mechanism, and needed for security event management system delivery |
| Native relationship-based access control | Phase 5 | Phase 5 stretch (Optional) | Large and separable; OpenFGA adapter is the alternative |

## Sizing

No dates are given: team size is not known. As relative effort, with Phase 1 as the unit: Phase 0 ≈ 0.5, Phase 2 ≈ 1.5, Phase 3 ≈ 1, Phase 4 ≈ 1.5, Phase 5 ≈ 2, Phase 6 ≈ 2 (uncertain until the SAML spike), Phase 7 ≈ 1, Phase 8 ≈ 1.5, Phase 9 ≈ 1.
