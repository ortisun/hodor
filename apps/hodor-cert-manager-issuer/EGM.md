# hodor-cert-manager-issuer

## Overview

The package `hodor-cert-manager-issuer` (`Cargo.toml`, description
"cert-manager's outside issuer, signing intermediates through a tenant's
certificate authority in Hodor.") builds the `hodor-cert-manager-issuer`
binary and a library its tests and the server's drive. It watches every
cert-manager `CertificateRequest` of the cluster and sends to Hodor's
signing operation only those addressed to its kinds `HodorIssuer` and
`HodorClusterIssuer` (group `hodor.ortisun.github.io`, version `v1alpha1`)
that are approved, not denied, of an issuer that exists and for an
authority, with an access token of its own client for the audience
`urn:hodor:certificate-authority`. It holds no decision of its own.
Specified in `docs/operations/hodor-cert-manager-issuer.md` and
`docs/decisions/0074-hodor-cert-manager-issuer.md`.

## Interface

| File | What it holds |
| --- | --- |
| `src/config.rs` | `Settings::from_json`: the configuration file (`hodor.url`, `hodor.tenant`, `hodor.issuer`, `hodor.timeout_milliseconds`, `client.client_id`, `client.authentication` with `method` `forwarded` or `private_key_jwt` and its `key_file` and `key_id`), checked; `token_endpoint`, `signing_endpoint`; `ConfigError` says what is wrong |
| `src/assertion.rs` | `ClientKey::from_pem`: an ECDSA P-256 key in PEM, PKCS#8 or SEC 1, read with `aws-lc-rs`; `jwk`, its public part as Hodor keeps it; `assertion`, an ES256 JSON Web Token with `iss` and `sub` the client, `aud` the tenant's issuer, one minute of life and a `jti` of 16 random bytes |
| `src/hodor.rs` | `Signer`, the port to Hodor (`sign`, `check_access`); `Hodor`, its implementation: one access token by `client_credentials` with `resource=urn:hodor:certificate-authority` and `scope=certificate-authority:sign`, with an assertion for `private_key_jwt`, kept until 30 seconds before it expires and replaced once on a `401`; `Signed`; `Failure::Refused` (a `4xx` but `401`, `403`, `408` and `429`, with Hodor's `code` and `detail`) or `Failure::Unavailable` (everything else) |
| `src/request.rs` | cert-manager's `CertificateRequest` as JSON of its own types (`CertificateRequestSpec`, `IssuerReference`, `CertificateRequestStatus`, `Condition`); `step`, what is done before the issuer is read (`NotOurs`, `Finished`, `Deny`, `AwaitApproval`, `Approved`); `prepare` (`NotAnAuthority`, `Unreadable`, `Send` with the lifetime from `spec.duration` in whole days, at least one); `Outcome` and its `status_patch`, which keeps the other conditions and writes `Ready`, `certificate` and `ca` (the chain's last certificate apart), or `failureTime` |
| `src/reconcile.rs` | `Cluster`, the port to the cluster (`issuer_exists`, `write_status`); `Reconciler::reconcile`, the order of "What it signs" and the answers of "What it writes back"; a pending request waits 10 seconds, doubling to 5 minutes, per request, and the same pending reason is not written twice; the metric `hodor.cert_manager_issuer.requests` by `outcome` |
| `src/kubernetes.rs` | `Kubernetes`, the `Cluster` over `kube` with `ApiResource`s for `certificaterequests`, `hodorissuers` and `hodorclusterissuers`; a status written as a merge patch naming the version read; `run`, the controller over every `CertificateRequest`; `keep_issuers_ready`, the `Ready` condition of every issuer of both kinds every minute from `check_access` |
| `src/lib.rs` | the modules; `operations`, the router of `/startupz`, `/readyz` and `/livez` |
| `src/main.rs` | the binary: `HODOR_CERT_MANAGER_ISSUER_CONFIG`, `HODOR_OPS_ADDR` (`0.0.0.0:9090`), `HODOR_LOG_FORMAT`, `HODOR_LOG_FILTER`, `HODOR_OTLP_TRACES_ENDPOINT`, `HODOR_OTLP_METRICS_ENDPOINT`; reads the file and the key before it starts; the cluster from the pod's service account or `KUBECONFIG`; stops on SIGTERM or Ctrl-C. `jwk --key <file> [--key-id <kid>]` prints a key's public part |

## Dependencies

From `Cargo.toml`: `async-trait`, `aws-lc-rs`, `axum`, `base64`, `clap`,
`form_urlencoded`, `futures`, `k8s-openapi` and `kube` with its runtime
(the Kubernetes client for Rust, under the Apache License 2.0),
`opentelemetry`, `reqwest` with `rustls`, `serde`, `serde_json`, `time`,
`tokio`, `tracing`, and the workspace crate `hodor-observability` alone: the
architecture test allows it no other (`tests/architecture`).

## Verification

- Run: `cargo test -p hodor-cert-manager-issuer` for the configuration, the
  key and its assertions, the answers of Hodor, the reading of requests, and
  the reconciliation with the cluster and Hodor in memory
  (`tests/reconcile.rs`).
- Against the real server: `cargo test -p hodor-server --test cert_manager_issuer`.
- Against a real Kubernetes interface with cert-manager, its controller
  feature gate `UseCertificateRequestBasicConstraints` on, and the chart's
  two kinds defined, with the real server:
  `HODOR_ISSUER_TEST_KUBECONFIG=<file> cargo test -p hodor-server --test cert_manager_issuer on_kubernetes -- --ignored`.
