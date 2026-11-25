# Architecture Decision Records

Format: context, decision, consequences, alternatives considered. A decision record is immutable once accepted; a change of mind is a new decision record that supersedes the old one.

All records below are **Proposed** unless marked otherwise: they become Accepted when the design review signs them off.

| # | Decision |
|---|---|
| [0001](0001-modular-monolith-clean-architecture.md) | Modular monolith with clean architecture per bounded context |
| [0002](0002-crate-consolidation.md) | Consolidate the proposed workspace from 26 to 24 crates |
| [0003](0003-context-communication.md) | Contexts talk through facades, service provider interfaces and outbox events |
| [0004](0004-token-formats.md) | JWT access tokens, opaque hashed refresh tokens and codes |
| [0005](0005-tenant-and-organization.md) | Tenant is the isolation boundary; organizations live inside it |
| [0006](0006-tenant-isolation.md) | Shared schema with `tenant_id` and forced row-level security |
| [0007](0007-postgres-required-redis-optional.md) | PostgreSQL is required; Redis is optional |
| [0008](0008-cryptography.md) | Cryptographic primitives and key handling |
| [0009](0009-authorization-engine-contract.md) | Authorization engine contract and one engine per namespace |
| [0010](0010-opa-integration.md) | Open Policy Agent through its official APIs; dedicated instances for tenant-authored Rego |
| [0011](0011-frontends-bff.md) | Hosted user interface on an interaction API; consoles behind a backend-for-frontend |
| [0012](0012-extension-strategy.md) | Traits first, webhooks second, WebAssembly plugins last |
| [0013](0013-auth-flow-as-data.md) | Authentication flows are versioned data interpreted by one engine |
| [0014](0014-saml-deferred-with-spike.md) | SAML is deferred to Phase 6 and gated by a security spike |
| [0015](0015-observability-stack.md) | OpenTelemetry for instrumentation, VictoriaMetrics for metrics (Accepted) |
| [0016](0016-design-system.md) | One token-based design system for the three frontends, with security patterns built in (how it is built is changed by 0018) |
| [0017](0017-external-identities-before-oauth.md) | Signing in with external identities comes before OAuth (Accepted) |
| [0018](0018-astryx-component-foundation.md) | Astryx is the foundation of the design system (Accepted) |
| [0019](0019-saml-signature-verification.md) | SAML signatures are verified with `xml-sec` behind a narrow profile (Accepted) |
| [0020](0020-console-on-the-hodor-session.md) | Until Hodor issues tokens, the admin console rides the administrator's Hodor session (Accepted) |
| [0021](0021-documentation-site.md) | The documentation site is built from `docs/` with MkDocs and Material, and published on GitHub Pages from `develop` |
| [0022](0022-installation-packages.md) | Hodor is installed from two packages kept apart from the development stack, and neither holds a secret |
| [0023](0023-what-0.2.0-holds.md) | 0.2.0 holds the OAuth server, strong authentication and the authorization engine, each cut to what makes it whole (Accepted) |
| [0024](0024-webauthn-checks.md) | WebAuthn is checked by Hodor's own code, over the cryptography it already has (Accepted) |
| [0025](0025-condition-language.md) | Conditions are Common Expression Language, interpreted by the `cel` crate in a crate of their own (Accepted) |
| [0026](0026-policy-checks-in-a-sandbox.md) | Policies are checked by the `opa` binary, run by the worker as a child process with nothing of its own (Accepted) |
| [0027](0027-what-0.3.0-holds.md) | 0.3.0 holds operations, groups and organizations with SCIM, workloads with webhooks, and what 0.2.0 left out (Accepted) |
| [0031](0031-workloads-are-users.md) | Service accounts and agents are users of the identity context, and a client of the client credentials grant acts as one (Accepted) |
| [0032](0032-webhooks.md) | Webhooks are a context of their own, signed as Standard Webhooks say, and sent on leases outside any transaction (Accepted) |
| [0033](0033-api-keys.md) | API keys are credentials of workloads, recognized by their prefix, and never do more than their holder (Accepted) |
| [0034](0034-token-exchange.md) | An agent acts for a person through token exchange, with a bounded `act` chain, a policy of audiences per client and scopes that only narrow (Accepted) |
| [0035](0035-access-control-lists.md) | Access control lists are entries that only allow, read at every decision beside the roles (Accepted) |
| [0036](0036-codes-and-links-by-email.md) | A code or a link by email is an alternative of the flow, kept apart from the sign-in that asked for it, and counted as the first factor (Accepted) |
| [0037](0037-back-channel-logout.md) | Back-channel logout is made by the OAuth context from the end of a session, and sent by the worker on leases as webhooks are (Accepted) |
| [0039](0039-enrolling-during-a-sign-in.md) | A second factor is enrolled during a sign-in at the last step of the flow, only by a person the policy holds back, and counts as that sign-in's second factor (Accepted) |
