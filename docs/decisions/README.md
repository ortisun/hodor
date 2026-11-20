# Architecture Decision Records

Format: context, decision, consequences, alternatives considered. A decision record is immutable once accepted; a change of mind is a new decision record that supersedes the old one.

All records below are **Proposed**: they become Accepted when the design review signs them off.

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
