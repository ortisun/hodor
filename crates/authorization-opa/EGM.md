# hodor-authorization-opa

## Overview

The `hodor-authorization-opa` crate (`Cargo.toml` description: "Open Policy Agent as an engine of the authorization context, over its Data API."). It provides two things the authorization context knows nothing of (Decision 0010):

- `OpenPolicyAgentEngine`, an `AuthorizationEngine` of [the authorization context](../authorization/EGM.md) named `open_policy_agent`. It asks an Open Policy Agent instance named by the operator, on a path built from the tenant and the binding alone, turns every failure into an indeterminate answer with its own reason, and reads the revision of the tenant's bundle from the answer's provenance.
- `BundleService`: registering instances and their credentials, checking, building and signing a tenant's bundles, and what instances pull and report (status, decisions). Its storage is behind the ports in `ports.rs`; the signature behind `BundleSigner`.
- `PolicyService`: the policy lifecycle. Versions are drafted, validated and tested by the worker through the `PolicyChecker` port, simulated against given inputs, and published only once tested; a rollback publishes an earlier version as a new revision. The engine refuses decisions made with a revision older than the tenant's latest beyond the allowed lag, through `PublishedRevisions`.

Specified in `docs/architecture/contexts/authorization.md`, "Open Policy Agent as an engine", "Bundles" and "The policy lifecycle".

## Interface

- Source and public surface: [src](./src/EGM.md).
- Workspace dependencies: `hodor-kernel` and `hodor-authorization`, as the architecture test allows for this crate (`tests/architecture/src/lib.rs`, layer 3), plus `async-trait`, `base64`, `miniz_oxide` (deflate for the gzip archives and reports), `serde`, `serde_json` and `time`. No HTTP library: requests go through the kernel's `HttpClient` port. No tar or gzip library: `archive.rs` writes both by hand.
- Feature `testing`: the module `testing` with in-memory stores, the contracts `run_bundle_contract` and `run_lifecycle_contract`, `FakeSigner`, `FakeChecker` (stands in for `opa`), `pack` and `unpack`.
- Used by `apps/hodor-server` (the engine with a `ServiceHttpClient`, and `BundleService` behind `policy_agent_routes`), `apps/hodor-cli` (`policy-agent` and `policy` commands), `apps/hodor-worker` (`PolicyService` in the policy check job), `hodor-adapters-policy-check` (`OpaProcessChecker` implements `PolicyChecker`), `hodor-adapters-postgres` (the stores), `hodor-adapters-crypto` (`BundleSigningKey` implements `BundleSigner`) and `hodor-protocol-http` (the routes).
- Dev dependencies: `hodor-adapters-crypto` (`Sha256Digest`), `hodor-adapters-http` (`ServiceHttpClient`), `hodor-authorization`, `hodor-kernel` and this crate with `testing`, `serde_json`, `testcontainers`, `time`, `tokio`.

## Invariants

- Only the `api` module is public; see [src](./src/EGM.md).
- The address comes from `Instances`, the operator's configuration; the path from `decision_path`, the tenant and the namespace. Nothing in a request reaches either.
- Only a `result` object with a boolean `allow` decides; every other answer and every failure is `indeterminate`.
- A shared instance is never served a bundle written by a tenant; an instance of a tenant's own is served that tenant's bundle only (`Instance::may_pull`). A pull it may not make is `Pull::NotFound`, like no bundle at all.
- A bundle's modules declare packages inside `hodor.tenants.t<tenant>`, its data documents sit under `hodor/tenants/t<tenant>/`, and its manifest has that one root (`bundle.rs`). Its JSON files are written in the canonical form Open Policy Agent hashes (`canonical.rs`).
- Only the SHA-256 of a credential (`hodor_pa_` and 43 base64url characters) is stored.
- A bundle is published by `PolicyService` only from a version in `tested`, without its `_test.rego` files, and each publication records the version it came from in the same unit of work (`lifecycle.rs`). A version's files never change; its state moves only along `draft → validating → validated → testing → tested`, or to `rejected` from a waiting state (`PolicyVersionStore::transition` is conditional on the state it leaves).
- With `with_revisions`, a decision made with a revision older than the tenant's latest, or with none, once the latest was published longer ago than the lag, is `policy_revision_stale`; a latest revision that cannot be read is `policy_revision_unknown` (`engine.rs`).

## Verification

- Run: `cargo test -p hodor-authorization-opa`. `tests/open_policy_agent.rs` and `tests/capabilities.rs` start `openpolicyagent/opa:1.10.1` containers and need Docker; `tests/engine.rs`, `tests/bundles.rs`, `tests/lifecycle.rs`, `tests/lag.rs` and the unit tests do not.
- Each test of `tests/open_policy_agent.rs` starts its own instance, waits until the instance answers a request with its token (Open Policy Agent writes "Initializing server" before it listens), and reaches it through a relay of its own on the machine running the tests. A test takes an instance away by closing the relay, which then closes every connection at once; it never stops the container for that, because for a while after `docker stop` returns Docker Desktop may still accept connections on the container's port and leave them unanswered, which the engine reads as `policy_engine_timed_out` rather than `policy_engine_unreachable`.
- The bundles against a real instance pulling from Hodor: `cargo test -p hodor-protocol-http --test policy_agent` (Docker). The PostgreSQL stores: `cargo test -p hodor-adapters-postgres --test policy_bundles --test policy_lifecycle`. The checker against the real binary: `cargo test -p hodor-adapters-policy-check`.
