# Hodor — Architecture and Product Documentation

This directory holds the *First Assignment* (section 28 of the specification): the complete design of Hodor before any implementation.

Start with the [critical review](architecture/critical-review.md): it lists where this design departs from the original specification and why.

## Deliverable map

| # | Deliverable | Document |
|---|---|---|
| 1 | PRD | [product/prd.md](product/prd.md) |
| 2 | Functional Requirements | [product/requirements.md](product/requirements.md#functional-requirements) |
| 3 | Non-functional Requirements | [product/requirements.md](product/requirements.md#non-functional-requirements) |
| 4 | Domain Model | [architecture/domain-model.md](architecture/domain-model.md) |
| 5 | Bounded Context Map | [architecture/domain-model.md](architecture/domain-model.md#bounded-context-map) |
| 6 | C4 Context Diagram | [architecture/overview.md](architecture/overview.md#c4-level-1-context) |
| 7 | C4 Container Diagram | [architecture/overview.md](architecture/overview.md#c4-level-2-containers) |
| 8 | Component Diagrams | [architecture/overview.md](architecture/overview.md#c4-level-3-components) |
| 9 | Crate Dependency Graph | [architecture/crates.md](architecture/crates.md) |
| 10 | Authentication Sequence Diagrams | [protocols/sequences.md](protocols/sequences.md#1-local-authentication-with-conditional-mfa) |
| 11 | OAuth2 + PKCE Sequence | [protocols/sequences.md](protocols/sequences.md#2-oauth-20-authorization-code-with-pkce) |
| 12 | OIDC Provider Sequence | [protocols/sequences.md](protocols/sequences.md#3-openid-provider) |
| 13 | OIDC Social Login Sequence | [protocols/sequences.md](protocols/sequences.md#4-social-login-over-oidc) |
| 14 | Identity Linking Sequence | [protocols/sequences.md](protocols/sequences.md#5-identity-linking) |
| 15 | Token Lifecycle | [protocols/sequences.md](protocols/sequences.md#6-token-lifecycle) |
| 16 | Session Lifecycle | [protocols/sequences.md](protocols/sequences.md#7-session-lifecycle) |
| 17 | Authorization Evaluation Sequence | [architecture/authorization.md](architecture/authorization.md#evaluation-sequence) |
| 18 | OPA Integration Architecture | [architecture/authorization.md](architecture/authorization.md#opa-integration) |
| 19 | Rego Policy Lifecycle | [architecture/authorization.md](architecture/authorization.md#rego-policy-lifecycle) |
| 20 | Multi-tenant Isolation Strategy | [architecture/multi-tenancy.md](architecture/multi-tenancy.md) |
| 21 | Threat Model | [security/threat-model.md](security/threat-model.md) |
| 22 | Database Model | [architecture/database.md](architecture/database.md) |
| 23 | API Specifications | [api/api-spec.md](api/api-spec.md) |
| 24 | Plugin Architecture | [architecture/plugins.md](architecture/plugins.md) |
| 25 | Testing Strategy | [architecture/testing.md](architecture/testing.md) |
| 26 | Deployment Architecture | [operations/deployment.md](operations/deployment.md) |
| 27 | ADRs | [adr/](adr/README.md) |
| 28 | Product Roadmap | [product/roadmap.md](product/roadmap.md) |
| 29 | Epics and Development Issues | [product/epics.md](product/epics.md) |
| — | Critical architecture review | [architecture/critical-review.md](architecture/critical-review.md) |
| — | First milestone | [product/epics.md](product/epics.md#milestone-1-walking-skeleton) |

## Conventions

- Diagrams are Mermaid, versioned next to the text.
- Requirements have stable IDs (`FR-<context>-NN`, `NFR-<area>-NN`) referenced by epics and tests.
- Every decision that constrains the design becomes an ADR in `docs/adr/`.
