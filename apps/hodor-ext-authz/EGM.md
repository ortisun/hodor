# hodor-ext-authz

## Overview

The package `hodor-ext-authz` (`Cargo.toml`, description "Envoy's external
authorization over gRPC, answered by Hodor's Authorization API.") builds the
`hodor-ext-authz` binary and a library the server's tests drive. It serves
`envoy.service.auth.v3.Authorization` and turns each check into one call of
the Authorization API's `evaluate`, asked as the client of the destination's
application, with an access token it gets by its mesh identity alone. It
holds no decision and keeps none; every failure is a denial. Specified in
`docs/operations/hodor-ext-authz.md`,
`docs/decisions/0058-hodor-ext-authz.md`,
`docs/decisions/0077-ext-authz-checks-the-audience.md` and
`docs/decisions/0082-ext-authz-checks-the-signature.md`.

## Interface

| File | What it holds |
| --- | --- |
| `src/config.rs` | `Settings::from_json`: the configuration file (`hodor.url`, `hodor.tenant`, `hodor.issuer`, `hodor.timeout_milliseconds`, `token` as `bearer`, or `metadata` or `header` as written before, `applications` with `destination`, `client_id`, `audience`, required, and `routes`), checked; `ConfigError` says what is wrong |
| `src/pattern.rs` | `PathPattern`: literals, `{id}`, `*` and a final `**`; `segments` refuses paths with dot segments or encoded separators |
| `src/check.rs` | `bearer`: the bearer token to check, if the configuration reads tokens, with the rules of the `header` and `metadata` forms; `question`: the application by `destination.principal`, the resource and action by the first matching rule or by `context_extensions` (`hodor_resource_type`, `hodor_action`, `hodor_resource_id`), the subject by the verified token's claims (`iss` the tenant's issuer, `aud` holding the application's `audience`, `exp` not past, `sub`, `client` when it equals `client_id`) or by `source.principal` as `workload_identity`; or a `Denial` |
| `src/key_set.rs` | `KeySet`: the tenant's published key set, fetched at `hodor.url` + `/t/<slug>/oauth2/jwks`, kept five minutes, fetched again for an unknown `kid` at most once every ten seconds, within the timeout, 64 kibibytes and 32 keys; `verify` checks a token's header (`ES256`, `RS256`, `PS256` or `EdDSA`, a `kid`, no `crit`) and signature with `aws-lc-rs`, and answers its claims or a `Denial` |
| `src/hodor.rs` | `Hodor`: one access token per application's client by `client_credentials` with `client_id`, `resource=urn:hodor:authorization` and `scope=authz:evaluate`, kept until 30 seconds before it expires and replaced once on a `401`; `evaluate`; every other answer a `Failure` |
| `src/service.rs` | `ExtAuthz`: the `Authorization` service; `OK`, or `PERMISSION_DENIED` with an HTTP 403, never a gRPC error; the metrics `hodor.ext_authz.checks` (by `outcome`) and `hodor.ext_authz.check.duration` |
| `src/lib.rs` | `serve` on a listener until a future resolves; `operations`, the router of `/startupz`, `/readyz` and `/livez` |
| `src/main.rs` | the binary: `HODOR_EXT_AUTHZ_CONFIG`, `HODOR_EXT_AUTHZ_LISTEN_ADDR` (`0.0.0.0:9191`), `HODOR_OPS_ADDR` (`0.0.0.0:9090`), `HODOR_LOG_FORMAT`, `HODOR_LOG_FILTER`, `HODOR_OTLP_TRACES_ENDPOINT`, `HODOR_OTLP_METRICS_ENDPOINT`; reads the file before it listens; stops on SIGTERM or Ctrl-C |

## Dependencies

From `Cargo.toml`: `aws-lc-rs` (the signatures), `axum`, `base64`, `clap`, `envoy-types` (Envoy's types,
shipped compiled, so no build needs `protoc`), `form_urlencoded`,
`opentelemetry`, `reqwest` with `rustls`, `serde`, `serde_json`, `tokio`,
`tonic`, `tracing`, and the workspace crate `hodor-observability` alone: the
architecture test allows it no other (`tests/architecture`).

## Verification

- Run: `cargo test -p hodor-ext-authz` for the configuration, the patterns,
  the reading of checks, the key set and the signatures, and the answers to
  the proxy.
- Against the real server: `cargo test -p hodor-server --test ext_authz`,
  with tokens signed by the tenant's own keys; a forged token is denied and
  Hodor records no decision.
- Latency: `cargo test --release -p hodor-server --test ext_authz -- --ignored --nocapture latency`.
