# Decision 0010: Open Policy Agent through its official APIs; dedicated instances for tenant-authored Rego

Status: Proposed

## Context

Open Policy Agent must be a first-class engine without entering the domain. Hodor also manages the Rego lifecycle and is multi-tenant, while a Rego policy can read any document loaded into the Open Policy Agent instance it runs in.

## Decision

- `authorization-opa` contains `OpaAuthorizationAdapter` and nothing in `authorization` knows Open Policy Agent exists.
- Decisions use Open Policy Agent's Data API. Policies and data reach Open Policy Agent as signed bundles that Open Policy Agent pulls from Hodor's bundle endpoint. Open Policy Agent pushes decision logs and status to Hodor. Hodor never pushes policies through Open Policy Agent's Policy API in production.
- The decision path is derived from the tenant and the binding, never from request input.
- Open Policy Agent instances start with a capabilities file that removes network and runtime-introspection built-ins; the same file is used when validating policies.
- **Isolation rule**: a shared Open Policy Agent runs only platform-authored policy, parameterized by per-tenant data. Rego written by a tenant runs only in an Open Policy Agent instance dedicated to that tenant, with its own bundle credential.
- Validation and tests run with the `opa` binary in a sandboxed worker job (final mechanism confirmed by a spike in Phase 5).
- Failure handling follows [authorization.md](../architecture/authorization.md#failure-handling): bounded timeout and retry, circuit breaker, revision tracking, cache off by default, fail-closed by default, fail-open only per action and audited.

## Consequences

- Open Policy Agent stays stock and upgradable; Hodor depends only on documented interfaces.
- Tenant-authored policy costs one Open Policy Agent instance per tenant, which is priced into the feature (a plan-level capability, provisioned by the operator or an operator-side controller).
- Publishing is eventually consistent: a new revision is active when instances report it. The lifecycle models that state explicitly.
- Two decision-log sources (native and Open Policy Agent) are normalized into one table.

## Alternatives considered

- **Embedding a Rego interpreter in-process (for example a Rust implementation)**: lowest latency and no extra process, but not the reference implementation, with possible semantic gaps; worth revisiting as an additional adapter, not as the Open Policy Agent integration.
- **Shared Open Policy Agent for tenant-authored Rego with package namespacing or static checks**: namespacing is not a security boundary in Rego, and static rejection of cross-root references is fragile.
- **Pushing policies via the Policy API**: no versioned artifact, no signature, no revision tracking.
