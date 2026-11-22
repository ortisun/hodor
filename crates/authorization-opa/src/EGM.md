# hodor-authorization-opa source

## Overview

The engine `open_policy_agent`. The modules `answer`, `breaker`, `engine`, `instances` and `path` are private; `lib.rs` re-exports through `api`.

## Interface

- `api::OpenPolicyAgentEngine` (`engine.rs`) implements `hodor_authorization::api::AuthorizationEngine`.
  - Its constructor is `new(http: Arc<dyn HttpClient>, digest: Arc<dyn Digest>, clock: Arc<dyn Clock>, instances: Instances)`.
  - `with_token(Secret<String>)` sets the bearer token sent to every instance; `with_breaker(BreakerSettings)` replaces the circuit rules.
  - `id()` is `open_policy_agent` (`api::ENGINE`); `capabilities()` is neither simulation nor explanation; `evaluate` always returns `Ok`, with an indeterminate answer for every failure, except when the input cannot be written (`authorization.open_policy_agent_input`).
- `api::Instances` (`instances.rs`): `parse(shared: Option<&str>, dedicated: &str)` reads the shared origin and `tenant-identifier=origin` pairs. A bad pair, a non-tenant identifier or a tenant named twice is `authorization.open_policy_agent_instances_invalid`. `for_tenant` answers the tenant's own instance, else the shared one; `addresses` lists every origin once.
- `api::decision_path(tenant, namespace, digest)` (`path.rs`) is `/v1/data/hodor/tenants/t<32 hexadecimal digits of the tenant>/resource_servers/r<first 32 hexadecimal digits of the SHA-256 of the namespace>/decision`.
- `api::BreakerSettings` (`breaker.rs`): 5 failures in a row, a 10-second window with at least 10 requests of which half failed, 5 seconds open.

## Invariants

- `evaluate` (`engine.rs`):
  - no instance for the tenant is `policy_engine_not_configured`, without a request;
  - an open circuit is `policy_engine_unavailable`, without a request;
  - each attempt is a `POST` with `accept: application/json`, the bearer token if set, and `within(the time left of the binding's limit)`;
  - status 200 is read by `answer::read`; any other status is `policy_engine_error`;
  - `http.timed_out`, or no time left, is `policy_engine_timed_out`;
  - `http.unreachable` on the first attempt is tried once more at once; any other error, or a second failure, is `policy_engine_unreachable`.
- The circuit of each origin records a failure for `policy_engine_error`, `policy_engine_timed_out` and `policy_engine_unreachable`, and a success for any 200 answer, even undefined or malformed (`engine.rs`). While open it admits nothing; once `open_for` has passed it admits one probe, which closes it on success and opens it again on failure (`breaker.rs`).
- `answer::read` (`answer.rs`):
  - no `result` is `policy_undefined`;
  - a `result` that is not an object with a boolean `allow`, or a `reason` that is not a reason code, or `policies` that are not at most 64 references, or a body that is not a JSON object, is `policy_answer_malformed`;
  - otherwise `allow` or `deny` with the given reason, else `policy_allowed` or `policy_denied`, and the policies as matched policies.
- The input document holds the namespace, the subject (kind, identifier, resolved attributes), the asserted attributes as given, the resource, the action and the context's attributes (`engine.rs:input_document`).

## Side Effects

- Outbound requests through the `HttpClient` it was given; nothing else. The circuits are kept in memory, per engine.
