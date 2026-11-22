# Decision 0009: Authorization engine contract and one engine per namespace

Status: Proposed

## Context

The specification gives a conceptual `AuthorizationEngine` trait and asks that types, lifetimes and execution strategy be evaluated before it is fixed. Its example request carries `tenant_id` and `roles` inside the subject, both supplied by the caller.

## Decision

- `evaluate` and `evaluate_batch` take a `&TenantContext` derived from the caller's credential and borrow the request. No tenant identifier is read from the request body.
- The request separates `subject` (an identifier Hodor resolves through a `SubjectAttributeSource`) from `asserted` (roles and attributes claimed by the caller, untrusted unless a policy opts in).
- `evaluate_batch` returns one `Result` per request.
- Simulation and explanation live in a separate `PolicySimulator` trait; engines advertise support through `capabilities()`.
- Engines are held as `Arc<dyn AuthorizationEngine>` and use `async_trait`, since selection happens at run time per tenant and namespace.
- A decision has three effects. `Indeterminate` covers engine failure, timeouts and missing policy; enforcement points must treat it as deny.
- An `EngineBinding` assigns exactly one engine to a namespace (resource server) in a tenant, with timeout, cache and failure policy. Decisions are not combined across engines.
- Hodor's own administration namespace is always bound to the native engine.

## Consequences

- A caller cannot evaluate against another tenant or self-assert privileges by default.
- Adding an engine is a new adapter crate plus registration.
- Tenants wanting "role-based access control from native plus rules from Open Policy Agent" feed role data to Open Policy Agent through the bundle's data documents rather than chaining engines.
- Boxed futures cost one allocation per call, negligible next to evaluation.

## Alternatives considered

- **Engine chain with combining algorithms (deny-overrides, first-applicable)**: more expressive, but a known source of subtle bypasses and hard-to-explain decisions; can be added later as an engine that composes others.
- **Generic static dispatch**: no allocation, but engine choice is per tenant at run time.
- **Trusting caller-supplied roles**: simplest for stateless resource servers; kept available only as an explicit policy choice.
