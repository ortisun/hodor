# Testing strategy

## Layers

| Layer | Scope | Tools | Runs |
|---|---|---|---|
| Unit | Domain rules and use cases with in-memory fakes of ports | `cargo test`, `rstest` | Every commit |
| Property-based | Invariants over generated inputs | `proptest` | Every commit |
| Architecture | Crate dependency rules, schema rules | Custom tests over `cargo metadata` and the Postgres catalog | Every commit |
| Contract | Each adapter against its port's shared test suite | Generic test functions in the context crate, instantiated per adapter | Every commit |
| Integration | Use cases against real PostgreSQL, Redis, Open Policy Agent and OpenBao | `testcontainers` | Every pull request |
| API / end-to-end | HTTP flows against a running server | `reqwest` harness; Playwright for the user interfaces | Every pull request |
| Protocol conformance | Standards suites | OpenID Conformance Suite, SAML test peers | Nightly and before release |
| Interoperability | Third-party software development kits and identity providers | Containers of real clients and identity providers | Nightly |
| Security | Abuse cases from the threat model | Dedicated suite in `tests/security`, OWASP ZAP baseline | Every pull request (suite), nightly (ZAP) |
| Fuzz | Parsers and decoders | `cargo fuzz` | Continuous, time-boxed in continuous integration |
| Concurrency | Races on single-use artifacts | Parallel integration tests; `loom` for in-process primitives | Every pull request |
| Load | Latency and throughput targets | `k6` | Weekly and before release |
| Chaos | Dependency failure | Toxiproxy, pod kills in a test cluster | Before release |

Fakes are preferred to mocks: each port has one in-memory implementation behind a `testing` feature of its crate, and the contract suite proves the fake and the real adapter behave the same.

## Containers in tests

Every test that starts a container starts it through `hodor-test-containers` (`tests/containers`): PostgreSQL, through `TestDatabase` of `hodor-adapters-postgres`; the OpenLDAP directory, through `TestDirectory` of `hodor-adapters-ldap`; the mail server, OpenBao, VictoriaMetrics and Open Policy Agent.

| Rule | Why |
|---|---|
| Each port a test asks for is published on `127.0.0.1` alone, on a port Docker chooses, and the test reaches the container at `127.0.0.1` | Docker chooses the host port without knowing what the machine's own processes listen on. Published on every address, which is Docker's default, Docker Desktop on macOS listens on that port beside a process of the machine that already listens on `127.0.0.1` at the same port, such as a server another test started, and a connection to `127.0.0.1` reaches that process, not the container: a PostgreSQL client then reads an answer that is not PostgreSQL's, `unexpected response from SSLRequest`. Published on `127.0.0.1` alone, the port cannot be shared: the start fails, and another container is started |
| The ports are read again until Docker gives every one, for up to thirty seconds | Docker gives no port for a container that is not running, which `testcontainers` reports as `PortNotExposed` when the port is read once, right after the start |
| A container that stops before its ports are given is reported with its exit code and the last lines it wrote | The failure says why the container stopped, instead of naming a port |
| A container that fails to start, stops before its ports are given, or fails the test's first check, such as the first connection to PostgreSQL, is removed and another one is started, three at most | One bad start while the machine is busy does not fail the suite |
| Being ready is checked by the test itself: a line the image writes when it listens, where it writes one, then a request the program answers: a connection to PostgreSQL, a bind to the directory, a request to the mail server's interface, to Open Policy Agent with its token, or to VictoriaMetrics' health | Docker accepts connections on a published port before anything in the container listens |

## Contract tests for ports

Every context ships, behind its `testing` feature, an in-memory implementation of its ports and a contract suite: a set of plain async functions that take the ports as trait objects (`hodor_tenant::testing::run_contract`). The in-memory fake and the PostgreSQL adapter both run it. The first one built is the tenant context's. The suite always includes the tenant isolation cases: data written under tenant A is invisible and immutable under tenant B.

## Property-based tests

| Area | Property |
|---|---|
| Refresh tokens | For any interleaving of refreshes, at most one chain stays valid; reuse of a consumed token (outside the retry window) revokes the family |
| Scopes | Scopes of a refreshed or exchanged token are a subset of the grant's |
| Redirect URIs | Only byte-identical registered URIs are accepted |
| Role hierarchy | Expansion terminates; no cycle can be written; revoking an assignment removes exactly the permissions derived from it |
| Identifier normalization | Normalization is idempotent; two values that normalize equal cannot both be registered |
| Flow engine | Any valid flow definition terminates; a transaction cannot complete without satisfying every required step |
| Key rotation | At every instant exactly one active signing key per algorithm; every unexpired token verifies against the published JWKS |
| Session timeouts | No sequence of touches extends a session past its absolute expiry |
| Attribute-based access control conditions | Evaluation is deterministic and bounded for any well-typed input |
| SCIM filters | For any text, the parser answers a tree or a refusal without failing, refuses what passes a bound, and reads back the filter it wrote out |

## Fuzz targets

JWT and JWS parsing, JWK parsing, authorization request parsing, redirect URI comparison, SCIM filter parser (until the repository has fuzz targets, it is covered by property tests over any text), SAML XML parsing and signature reference resolution, claim-mapping expressions, Common Expression Language conditions, WebAuthn attestation and assertion decoding, flow definition validation, DPoP proofs.

## Scenarios the specification calls out

| Scenario | Test |
|---|---|
| Authorization Code + PKCE | Happy path; missing, wrong and `plain` verifier; code replay revokes the grant; redirect URI near-misses; `iss` present in the response |
| OpenID Connect Discovery | Metadata matches behavior (every advertised endpoint, algorithm and grant works; nothing unadvertised does); conformance suite Config OpenID Provider profile |
| JWT validation | `none`, algorithm confusion, wrong `kid`, header-injected keys, expired, future `nbf`, wrong `iss` and `aud` |
| Token rotation | Sequential rotation; concurrent refresh with the same token; retry-window behavior |
| Refresh token reuse | Reuse revokes the family and emits `RefreshTokenReuseDetected` |
| Social login | Against a mock OpenID Connect provider and a mock OAuth2 provider: happy path, bad `state`, bad `nonce`, wrong `aud`, expired ID token, rotated JWKS |
| Account linking | Collision does not auto-link; link needs both proofs; linked-elsewhere is rejected; the pre-hijacking case from the threat model |
| OpenID Connect provider integration | Nightly against real client libraries in several languages and, as relying party, against Keycloak and Dex containers |
| SAML interoperability | Against reference identity provider and service provider implementations; signature wrapping corpus; XXE corpus |
| Open Policy Agent decision evaluation | Real Open Policy Agent container: allow, deny, undefined result, timeout, Open Policy Agent down, stale revision; each failure policy |
| Rego policy versioning | Publish, activation confirmed by status, rollback, bundle signature failure |
| Authorization bypass | Every Admin API route called with no token, wrong scope, wrong role and another tenant's token; cases generated from the OpenAPI document so new routes are covered automatically |
| Cross-tenant access | Generic repository test, row-level security test, schema lint, request replay across tenants, token cross-use ([multi-tenancy.md](multi-tenancy.md#validation)) |
| Key rotation | Tokens signed before rotation verify during overlap and fail after retirement; a revoked key leaves the JWKS at once |

## Security tests

Each threat in the [threat model](../security/threat-model.md) with a control in code has a test named after the threat identifier (`threat_oauth_02_code_replay_revokes_grant`). A continuous integration check lists threat identifiers that have no test.

Additional checks: a log-scan test runs the main flows with canary secrets and fails if a canary appears in logs, traces or audit records; timing tests compare the unknown-user and wrong-password paths statistically; security headers are asserted on every HTML route.

## Concurrency tests

Single-use artifacts are redeemed from many tasks at once and exactly one must win: authorization codes, refresh tokens, pushed authorization requests request URIs, verification tokens, recovery codes, invitations, federation state. Also covered: key rotation attempted by two workers, outbox dispatch by several workers, and optimistic-lock conflicts on aggregates.

## Load and chaos

| Load scenario | Target |
|---|---|
| `client_credentials` | Requirement-Performance-01 |
| Password login mix (80% success) | Requirement-Performance-02 without runtime starvation |
| Authorization code flow end to end | p99 under 150 ms excluding login |
| Authorization evaluation, native and Open Policy Agent | Requirement-Performance-04, Requirement-Performance-05 |
| 10,000 tenants, skewed traffic | One tenant at its limit does not move another tenant's latency |

| Chaos experiment | Expected behavior |
|---|---|
| PostgreSQL failover | Errors during failover, automatic recovery, no lost committed writes |
| Redis down | Service continues with in-memory and Postgres fallbacks |
| Open Policy Agent down or slow | Breaker opens; fail-closed bindings return `Indeterminate`; admin API unaffected |
| External identity provider down | Local login unaffected; clear error for that provider |
| Node killed mid-flow | The user retries the step on another node; no stuck state |
| Worker killed mid-job | Job runs again; handlers are idempotent |

## Continuous integration pipeline

| Stage | Contents |
|---|---|
| Lint | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo deny`, `cargo machete`, frontend lint and type check |
| Build | Workspace build with the SQLx offline cache; frontend builds |
| Test | Unit, property, architecture, contract |
| Integration | Testcontainers suites; API and security suites; Playwright |
| Artifacts | Container images, software bill of materials, signatures (on main and tags) |
| Nightly | Conformance, interoperability, ZAP, extended fuzzing |
| Pre-release | Load, chaos, and an upgrade test from the previous release with old and new binaries running together |

Coverage is measured with `cargo llvm-cov` and gated at 85% for domain modules only. Adapters are judged by their contract and integration suites, not by a percentage.
