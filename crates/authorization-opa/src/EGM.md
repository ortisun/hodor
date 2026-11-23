# hodor-authorization-opa source

## Overview

The engine `open_policy_agent` and the bundles. The modules `answer`, `archive`, `breaker`, `bundle`, `canonical`, `engine`, `instance`, `instances`, `path`, `ports`, `reports` and `service` are private; `lib.rs` re-exports through `api`. `testing` is public behind the `testing` feature.

## Interface

- `api::OpenPolicyAgentEngine` (`engine.rs`) implements `hodor_authorization::api::AuthorizationEngine`.
  - Its constructor is `new(http: Arc<dyn HttpClient>, digest: Arc<dyn Digest>, clock: Arc<dyn Clock>, instances: Instances)`.
  - `with_token(Secret<String>)` sets the bearer token sent to every instance; `with_breaker(BreakerSettings)` replaces the circuit rules.
  - `id()` is `open_policy_agent` (`api::ENGINE`); `capabilities()` is neither simulation nor explanation; `evaluate` always returns `Ok`, with an indeterminate answer for every failure, except when the input cannot be written (`authorization.open_policy_agent_input`).
- `api::Instances` (`instances.rs`): `parse(shared: Option<&str>, dedicated: &str)` reads the shared origin and `tenant-identifier=origin` pairs. A bad pair, a non-tenant identifier or a tenant named twice is `authorization.open_policy_agent_instances_invalid`. `for_tenant` answers the tenant's own instance, else the shared one; `addresses` lists every origin once.
- `api::decision_path(tenant, namespace, digest)` (`path.rs`) is `/v1/data/hodor/tenants/t<32 hexadecimal digits of the tenant>/resource_servers/r<first 32 hexadecimal digits of the SHA-256 of the namespace>/decision`.
- `api::BreakerSettings` (`breaker.rs`): 5 failures in a row, a 10-second window with at least 10 requests of which half failed, 5 seconds open.
- `api::BundleService` (`service.rs`), over `InstanceStore`, `BundleStore`, `InstanceStatusStore`, `UploadedDecisionStore` (`ports.rs`), a `UnitOfWorkFactory`, `Digest`, `RandomSource` and `Clock`:
  - `register(name, tenant)` returns the `Instance` and its credential, shown once; `disable(name)`; `instances()`.
  - `publish(tenant, author, files, signer, caller)` builds and signs the next revision (latest plus one, from 1), stores it and records `authorization.policy_bundle_published` (`BundleEvent::Published`: revision, `written_by`, the hexadecimal SHA-256 of the archive).
  - `authenticate(credential)` is `authorization.policy_agent_unauthenticated` (`ErrorKind::Unauthenticated`) for a missing, malformed, unknown or disabled credential.
  - `pull(instance, name, if_none_match)` is `Pull::NotFound`, `Pull::NotModified { entity_tag }` or `Pull::Bundle { entity_tag, archive }`; the entity tag is the quoted hexadecimal SHA-256 of the archive, and `W/` before a held tag is ignored.
  - `report_status(instance, body, compressed)` and `upload_decisions(instance, body, compressed)` keep what concerns the tenants the instance serves; a compressed body expands to at most `MAX_EXPANDED_UPLOAD_BYTES` (8 mebibytes).
  - `statuses(tenant)` and `uploaded_decisions(tenant, limit)` read them back.
- `api::Author` (`Operator`, `Tenant`), `api::BundleFile { path, contents }`, `api::PublishedBundle { revision, author, archive, digest, published_at }` and its `entity_tag()`, `api::BundleSigner { key_id, sign }` (`bundle.rs`).
- `api::bundle_name(tenant)` is `t` and 32 hexadecimal digits; `api::tenant_of(name)` reads it back; `api::tenant_root(tenant)` is `hodor/tenants/<bundle name>`.
- `api::Instance`, `api::InstanceId`, `api::InstanceName` (1 to 63 of `a-z`, `0-9`, `-`, not starting with `-`), `api::CREDENTIAL_PREFIX` (`instance.rs`).
- `api::gzip` and `api::to_canonical`: the archive's compression and the canonical JSON, for tests and tools.

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
- Every request asks with `?provenance=true`; `answer::revision` reads `provenance.bundles.<bundle name>.revision` into the answer's `policy_version` (`engine.rs`, `answer.rs`).
- `bundle::build`: 1 to 1000 files and at most 8 mebibytes; each path relative, of `A-Z a-z 0-9 _ - .` segments with no `.` or `..`, at most 200 characters; a `.rego` file's first statement is `package` inside the tenant's package; a `data.json` is a JSON object, rewritten canonically; nothing else. The archive holds `.signatures.json`, `.manifest` and the files sorted by path, under the tenant root, with times of zero, so the same files give the same archive. The signature is a JSON Web Signature with `alg` `ES256`, the signer's `kid` and `typ` `JWT`, over `{"files": [{"name", "hash", "algorithm": "SHA-256"}…]}` for every file but `.signatures.json`.
- `reports::read_status` takes only bundles named after a tenant, at most 10,000; `reports::read_decisions` takes at most 10,000 decisions and only those with an identifier and a path in a tenant's tree, keeping the identifier, the path, the tenant bundle's revision, whether `result.allow` was true and the time — never the input.
- The input document holds the namespace, the subject (kind, identifier, resolved attributes), the asserted attributes as given, the resource, the action and the context's attributes (`engine.rs:input_document`).

## Side Effects

- Outbound requests through the `HttpClient` it was given; nothing else. The circuits are kept in memory, per engine.
- `BundleService` writes through its stores, one unit of work per tenant touched, and records one event per publication.
