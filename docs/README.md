# Hodor — Architecture and Product Documentation

This directory holds the *First Assignment* (section 28 of the specification): the complete design of Hodor before any implementation.

Start with the [critical review](architecture/critical-review.md): it lists where this design departs from the original specification and why.

## Deliverable map

| # | Deliverable | Document |
|---|---|---|
| 1 | Product requirements | [product/product-requirements.md](product/product-requirements.md) |
| 2 | Functional Requirements | [product/requirements.md](product/requirements.md#functional-requirements) |
| 3 | Non-functional Requirements | [product/requirements.md](product/requirements.md#non-functional-requirements) |
| 4 | Domain Model | [architecture/domain-model.md](architecture/domain-model.md) |
| — | Context specifications, one page per bounded context, written before the context is built | [tenant](architecture/contexts/tenant.md), [identity](architecture/contexts/identity.md), [credential](architecture/contexts/credential.md), [session](architecture/contexts/session.md), [authentication](architecture/contexts/authentication.md), [notification](architecture/contexts/notification.md), [audit](architecture/contexts/audit.md), [authorization](architecture/contexts/authorization.md), [federation](architecture/contexts/federation.md) |
| 5 | Bounded Context Map | [architecture/domain-model.md](architecture/domain-model.md#bounded-context-map) |
| 6 | C4 Context Diagram | [architecture/overview.md](architecture/overview.md#c4-level-1-context) |
| 7 | C4 Container Diagram | [architecture/overview.md](architecture/overview.md#c4-level-2-containers) |
| 8 | Component Diagrams | [architecture/overview.md](architecture/overview.md#c4-level-3-components) |
| 9 | Crate Dependency Graph | [architecture/crates.md](architecture/crates.md) |
| 10 | Authentication Sequence Diagrams | [protocols/sequences.md](protocols/sequences.md#1-local-authentication-with-conditional-multi-factor-authentication) |
| 11 | OAuth2 + PKCE Sequence | [protocols/sequences.md](protocols/sequences.md#2-oauth-20-authorization-code-with-pkce) |
| 12 | OpenID Connect Provider Sequence | [protocols/sequences.md](protocols/sequences.md#3-openid-provider) |
| 13 | OpenID Connect Social Login Sequence | [protocols/sequences.md](protocols/sequences.md#4-social-login-over-openid-connect) |
| 14 | Identity Linking Sequence | [protocols/sequences.md](protocols/sequences.md#5-identity-linking) |
| 15 | Token Lifecycle | [protocols/sequences.md](protocols/sequences.md#6-token-lifecycle) |
| 16 | Session Lifecycle | [protocols/sequences.md](protocols/sequences.md#7-session-lifecycle) |
| 17 | Authorization Evaluation Sequence | [architecture/authorization.md](architecture/authorization.md#evaluation-sequence) |
| 18 | Open Policy Agent Integration Architecture | [architecture/authorization.md](architecture/authorization.md#open-policy-agent-integration) |
| 19 | Rego Policy Lifecycle | [architecture/authorization.md](architecture/authorization.md#rego-policy-lifecycle) |
| 20 | Multi-tenant Isolation Strategy | [architecture/multi-tenancy.md](architecture/multi-tenancy.md) |
| 21 | Threat Model | [security/threat-model.md](security/threat-model.md) |
| — | Outbound HTTP: the one guarded way out to addresses other people chose | [security/outbound-http.md](security/outbound-http.md) |
| — | Secrets at rest: how the secrets Hodor must read back are kept encrypted, and how keys are changed | [security/secrets-at-rest.md](security/secrets-at-rest.md) |
| 22 | Database Model | [architecture/database.md](architecture/database.md) |
| 23 | API Specifications | [api/api-spec.md](api/api-spec.md) |
| — | The interaction interface: how a browser signs in | [api/interaction-api.md](api/interaction-api.md) |
| — | The administration interface: users, sessions and the audit log for the people who run a tenant | [api/admin-api.md](api/admin-api.md) |
| — | The hosted pages: what a person sees when they register, sign in or recover a password, and how the pages are served and tested | [architecture/hosted-pages.md](architecture/hosted-pages.md) |
| 24 | Plugin Architecture | [architecture/plugins.md](architecture/plugins.md) |
| 25 | Testing Strategy | [architecture/testing.md](architecture/testing.md) |
| 26 | Deployment Architecture | [operations/deployment.md](operations/deployment.md) |
| — | Quick-start: from a clean checkout to a tenant people sign in to, and the demonstration of Milestone 1 | [operations/quick-start.md](operations/quick-start.md) |
| 27 | Decision records | [decisions/](decisions/README.md) |
| 28 | Product Roadmap | [product/roadmap.md](product/roadmap.md) |
| 29 | Epics and Development Issues | [product/epics.md](product/epics.md) |
| — | Design system: Astryx, the Hodor theme and the security interaction patterns | [design/design-system.md](design/design-system.md) |
| — | The control plane: admin console information architecture and self-protection | [design/control-plane.md](design/control-plane.md) |
| — | The admin console: what is built of the control plane, and how | [architecture/admin-console.md](architecture/admin-console.md) |
| — | The console interface: what the admin console calls | [api/console-interface.md](api/console-interface.md) |
| — | Competitive analysis: features and consoles compared with comparable products | [product/competitive-analysis.md](product/competitive-analysis.md) |
| — | Critical architecture review | [architecture/critical-review.md](architecture/critical-review.md) |
| — | First milestone | [product/epics.md](product/epics.md#milestone-1-walking-skeleton) |

## Working on Hodor

| Page | What it answers |
|---|---|
| [development/conventions.md](development/conventions.md) | The rules: documentation first, how docs are written and organized, commits, branches, pull requests, definition of done |
| [development/local-setup.md](development/local-setup.md) | How to build, run the checks and start Hodor locally; configuration reference |
| [product/progress.md](product/progress.md) | What has been built so far, known gaps, and where the implementation departs from the design |

## Conventions

- Documentation comes first: the code follows these pages. See the [working conventions](development/conventions.md).

- Diagrams are Mermaid, versioned next to the text.
- Requirements, threats and issues have stable identifiers made of whole words (`Requirement-Tenancy-01`, `Threat-OAuth-02`, `Issue-07`), referenced by epics and tests.
- Words are written in full: no letter codes and no abbreviations. See the [working conventions](development/conventions.md#3-words-not-abbreviations).
- Every decision that constrains the design becomes a decision record in `docs/decisions/`.
