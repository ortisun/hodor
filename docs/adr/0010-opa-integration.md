# ADR-0010: OPA through its official APIs; dedicated instances for tenant-authored Rego

Status: Proposed

## Context

OPA must be a first-class engine without entering the domain. Holdor also manages the Rego lifecycle and is multi-tenant, while a Rego policy can read any document loaded into the OPA instance it runs in.

## Decision

- `authorization-opa` contains `OpaAuthorizationAdapter` and nothing in `authorization` knows OPA exists.
- Decisions use OPA's Data API. Policies and data reach OPA as signed bundles that OPA pulls from Holdor's bundle endpoint. OPA pushes decision logs and status to Holdor. Holdor never pushes policies through OPA's Policy API in production.
- The decision path is derived from the tenant and the binding, never from request input.
- OPA instances start with a capabilities file that removes network and runtime-introspection built-ins; the same file is used when validating policies.
- **Isolation rule**: a shared OPA runs only platform-authored policy, parameterized by per-tenant data. Rego written by a tenant runs only in an OPA instance dedicated to that tenant, with its own bundle credential.
- Validation and tests run with the `opa` binary in a sandboxed worker job (final mechanism confirmed by a spike in Phase 5).
- Failure handling follows [authorization.md](../architecture/authorization.md#failure-handling): bounded timeout and retry, circuit breaker, revision tracking, cache off by default, fail-closed by default, fail-open only per action and audited.

## Consequences

- OPA stays stock and upgradable; Holdor depends only on documented interfaces.
- Tenant-authored policy costs one OPA instance per tenant, which is priced into the feature (a plan-level capability, provisioned by the operator or an operator-side controller).
- Publishing is eventually consistent: a new revision is active when instances report it. The lifecycle models that state explicitly.
- Two decision-log sources (native and OPA) are normalized into one table.

## Alternatives considered

- **Embedding a Rego interpreter in-process (for example a Rust implementation)**: lowest latency and no extra process, but not the reference implementation, with possible semantic gaps; worth revisiting as an additional adapter, not as the OPA integration.
- **Shared OPA for tenant-authored Rego with package namespacing or static checks**: namespacing is not a security boundary in Rego, and static rejection of cross-root references is fragile.
- **Pushing policies via the Policy API**: no versioned artifact, no signature, no revision tracking.
