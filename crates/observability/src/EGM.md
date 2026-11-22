# hodor-observability source

## Overview

Telemetry bootstrap for the Hodor binaries. Logs go to standard output, as JSON in production. Traces and metrics are exported over the OpenTelemetry Protocol (OTLP) on HTTP. The reference metrics backend is VictoriaMetrics (`lib.rs` crate documentation, which points to `docs/decisions/0015-observability-stack.md`). The single source file is `lib.rs`.

## Interface

- `LogFormat`: `Json` (the default), one JSON object per line, or `Pretty`, readable text for local development (`lib.rs:LogFormat`).
- `Config`, with all fields public: `service_name`, `service_version`, `log_format`, `log_filter` (in `tracing` filter syntax), `traces_endpoint: Option<String>`, `metrics_endpoint: Option<String>` and `metrics_interval: Duration` (`lib.rs:Config`).
- `Config::new(service_name, service_version)` (`#[must_use]`): JSON logs, the `info` filter, no trace or metric export, and a metric interval of 15 seconds (`lib.rs:Config::new`).
- `TelemetryError` has three variants (`lib.rs:TelemetryError`):
  - `InvalidLogFilter { filter, reason }`: the log filter is not valid syntax.
  - `Exporter { signal, reason }`: an exporter could not be built; `signal` is `traces` or `metrics`.
  - `AlreadyInitialized`: telemetry is already set up in this process.
- `Telemetry` (private fields: an optional tracer provider and an optional meter provider) has three methods (`lib.rs:Telemetry`):
  - `Telemetry::init(&Config) -> Result<Telemetry, TelemetryError>` installs the global logger, tracer and meter.
  - `flush(&self)` sends buffered traces and metrics right away.
  - `shutdown(self)` flushes and stops the exporters.

## Invariants

- Endpoints are full URLs that include the path. Setting an endpoint to `None` turns off that signal: no provider is built for it, and no OpenTelemetry tracing layer is added (`lib.rs:Config`, `lib.rs:Telemetry::init`).
- The log filter comes from `Config.log_filter` through `EnvFilter::try_new`, not from an environment variable. Invalid syntax returns `InvalidLogFilter` before anything is installed (`lib.rs:Telemetry::init`).
- `init` works once per process. If a global subscriber already exists, `try_init` fails and `init` returns `TelemetryError::AlreadyInitialized`. The global tracer and meter providers are set only after the subscriber installs (`lib.rs:Telemetry::init`).
- The documentation of `init` says an unreachable backend is not an error, because export failures are logged and the process keeps running (`lib.rs:Telemetry::init`).
- The resource carries `service.name` and `service.version` from the configuration. Spans are bridged through a tracer named `hodor` (`lib.rs:Telemetry::init`).
- The `Telemetry` value must stay alive for the whole process, and `shutdown` must be called once, during graceful shutdown. `Telemetry` has no `Drop` implementation, so dropping it does not flush (`lib.rs:Telemetry`, `lib.rs:Telemetry::shutdown`).
- `flush` and `shutdown` never return errors. Failures are reported through `tracing::warn!` (`lib.rs:Telemetry::flush`, `lib.rs:Telemetry::shutdown`).

## Side Effects

- Installs a global `tracing` subscriber (`try_init`) that writes logs to standard output (`lib.rs:Telemetry::init`).
- Sets the global OpenTelemetry tracer provider and meter provider (`opentelemetry::global::set_tracer_provider`, `set_meter_provider`) when the matching endpoint is set (`lib.rs:Telemetry::init`).
- Exports spans over HTTP through a batch exporter (`with_http`, `with_batch_exporter`) to `traces_endpoint` (`lib.rs:tracer_provider`).
- Pushes metrics over HTTP through a `PeriodicReader` every `metrics_interval` to `metrics_endpoint` (`lib.rs:meter_provider`).
- `flush` and `shutdown` send buffered data over the network (`lib.rs:Telemetry`).
- Reads no environment variables.

## Verification

- Run: `cargo test -p hodor-observability`
