# hodor-observability

## Overview

The telemetry bootstrap crate (package `hodor-observability`). Its manifest describes it as "structured logs, and traces and metrics exported over OTLP" (`Cargo.toml` `description`). It implements no kernel port and depends on no other Hodor crate.

## Subdirectories & Boundaries

- `src`: [./src/EGM.md](./src/EGM.md) - `Config`, `LogFormat`, `Telemetry` (`init`, `flush`, `shutdown`) and `TelemetryError`. It installs the process-wide `tracing` subscriber and the OpenTelemetry providers, and exports over HTTP.
- `tests`: integration tests (not documented here).

## Workspace Dependencies

From `Cargo.toml`, every dependency comes from the workspace:

- Runtime: `opentelemetry`, `opentelemetry-otlp`, `opentelemetry_sdk`, `thiserror`, `tracing`, `tracing-opentelemetry`, `tracing-subscriber`.
- Development only: `hodor-test-containers` (starts VictoriaMetrics), `opentelemetry`, `reqwest` (features `json`, `query`), `serde_json`, `testcontainers`, `tokio`.

## Verification

- Run: `cargo test -p hodor-observability`
