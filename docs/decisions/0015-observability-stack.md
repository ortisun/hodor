# Decision 0015: OpenTelemetry for instrumentation, VictoriaMetrics for metrics

Status: Accepted (requested by the project owner)

## Context

The specification requires OpenTelemetry. It does not name a backend. The project owner chose VictoriaMetrics for metrics.

## Decision

- Code is instrumented only through `tracing` and the OpenTelemetry API. No backend-specific client is used anywhere.
- Traces and metrics leave the process over OTLP/HTTP (protobuf). Endpoints are configured as full URLs, because backends accept OTLP on different paths.
- **Metrics** are pushed to VictoriaMetrics, which ingests OTLP natively at `/opentelemetry/v1/metrics` and is queried with PromQL/MetricsQL. Dashboards and alert rules shipped with the Helm chart target it.
- **Traces** go to any OTLP-compatible backend. VictoriaTraces is the natural companion: it ingests OTLP at `/insert/opentelemetry/v1/traces` and answers queries in the Jaeger format. It is part of the development Compose file, and [the demonstration](../operations/quick-start.md#the-demonstration), which runs in continuous integration, finds the trace of a sign-in in it.
- **Logs** are JSON on standard output, collected by the platform. VictoriaLogs is the suggested store.
- Metrics are pushed, not scraped: the binaries expose no Prometheus endpoint in v1. This removes a listener and a second metrics format.
- Telemetry is initialized from `main` before the async runtime starts, because the exporters use a blocking HTTP client on their own threads.
- An unreachable backend never stops the process; export failures are logged.

## Consequences

- Changing backend is a configuration change as long as it speaks OTLP.
- Pushed metrics need the backend reachable from every pod; short outages lose the samples of that interval.
- Metric names and labels reach VictoriaMetrics as OpenTelemetry emits them; resource attributes such as `service.name` become labels.
- Label cardinality remains our responsibility: no user or session identifiers in metric attributes (Requirement-Observability-02).

## Alternatives considered

- **Prometheus scrape endpoint**: familiar, but adds a listener and a pull topology, and VictoriaMetrics does not need it.
- **OpenTelemetry Collector in front of every backend**: flexible routing; operators can still add one, since the binaries only speak OTLP.
- **Backend-specific software development kits**: ties the code to a vendor.
