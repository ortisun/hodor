# hodor-authorization-opa source

## Overview

The engine `open_policy_agent` and the bundles. The modules `answer`, `archive`, `breaker`, `bundle`, `canonical`, `engine`, `instance`, `instances`, `lifecycle`, `path`, `policy`, `ports`, `reports`, `revisions` and `service` are private; `lib.rs` re-exports through `api`. `testing` is public behind the `testing` feature.

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
- `api::PolicyService` (`lifecycle.rs`), over `PolicyVersionStore`, `PublicationStore`, `SimulationStore` (`ports.rs`), a `BundleService`, a `UnitOfWorkFactory`, `Digest` and `Clock`:
  - `draft(tenant, author, files, caller)` checks the files with `api::normalize` (the rules of `bundle::build`) and stores the next version (latest plus one, from 1) in `draft`, recording `authorization.policy_version_drafted` (`LifecycleEvent::Drafted`: version, `written_by`, digest);
  - `validate(tenant, number)` moves `draft` to `validating`, `test(tenant, number)` moves `validated` to `testing`; any other state is `authorization.policy_version_state` (`ErrorKind::Conflict`), an unknown number `authorization.policy_version_not_found`;
  - `simulate(tenant, number, namespace, inputs)` checks the inputs (`api::check_inputs`: 1 to 100 objects, 1 mebibyte) and stores a waiting `Simulation` of a validated, testing or tested version; `simulation(tenant, id)` reads it, `authorization.policy_simulation_not_found` if it is not the tenant's;
  - `run_waiting(tenant, checker)` takes up to 10 waiting versions and 10 waiting simulations: `checker.check` for `validating`, `checker.test` for `testing`, then `validated` or `tested` if `Report::passed`, else `rejected`, with the report and `authorization.policy_version_checked` (`LifecycleEvent::Checked`); a simulation evaluates the version's published files and those of the version of the latest revision with `checker.evaluate` on `decision_package(tenant, namespace)`, compares them (`api::compare`) and ends `done`, or `failed` with the report, its inputs erased. A checker error stops the pass and leaves the work waiting;
  - `publish(tenant, number, signer, caller)` takes a `tested` version, publishes its files without tests through `BundleService` in the same unit of work as the publication record and `authorization.policy_version_published` (`LifecycleEvent::Published`: version, revision, rollback); `roll_back(tenant, revision, signer, caller)` publishes the version that revision came from, or is `authorization.policy_revision_without_version`;
  - `status(tenant)` is `PolicyStatus`: the latest revision with its author, time and version, the last 20 publications, the `Activation` of each instance that should run it (`BundleService::expected_instances`) and `pending_activation`.
- `api::PolicyVersion`, `api::VersionState`, `api::Report` (`diagnostics`, `tests`, `passed`, `bounded`), `api::Diagnostic`, `api::TestResult`, `api::Simulation`, `api::SimulationId`, `api::SimulationState`, `api::SimulatedAnswer`, `api::version_digest` and `api::files_document` (the SHA-256 of `{"files":[{"path","sha256"}…]}`, by path), `api::hexadecimal`, `api::is_test` (`policy.rs`, `bundle.rs`).
- `api::PolicyChecker` (`ports.rs`): `check`, `test` and `evaluate` answer what the policy did in a `Report`; `Err` only when a run could not start.
- `api::decision_package(tenant, namespace, digest)` (`path.rs`): the decision path as a Rego package.
- `api::PublishedRevisions` and `api::StoredRevisions` (`revisions.rs`): the latest revision of a tenant from `BundleStore::latest_revision`, kept 10 seconds, at most 10,000 tenants. `OpenPolicyAgentEngine::with_revisions(revisions, lag)` applies the lag rule; `api::DEFAULT_REVISION_LAG` is 5 minutes.
- `BundleService::latest(tenant)` and `BundleService::expected_instances(tenant, author)`: the enabled instances that may pull the bundle, a shared one only once it has reported the tenant.

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
- `PolicyService` writes through its stores and records the lifecycle's events; the checker it is given runs `opa`. `StoredRevisions` reads the bundles' store and keeps what it read in memory.
