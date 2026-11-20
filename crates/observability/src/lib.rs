//! Telemetry bootstrap for the Holdor binaries.
//!
//! * **Logs** are written to standard output, as JSON in production.
//! * **Traces** are exported over OTLP/HTTP to any compatible backend.
//! * **Metrics** are exported over OTLP/HTTP; the reference backend is
//!   VictoriaMetrics, which ingests OTLP natively.
//!
//! Endpoints are full URLs including the path, because backends differ in
//! where they accept OTLP. For VictoriaMetrics the metrics endpoint is
//! `http://<host>:8428/opentelemetry/v1/metrics`.
//!
//! See `docs/adr/0015-observability-stack.md`.

use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::time::Duration;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _};

/// How log lines are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// One JSON object per line, for log collectors.
    #[default]
    Json,
    /// Human-readable, for local development.
    Pretty,
}

/// Telemetry settings of one process.
#[derive(Debug, Clone)]
pub struct Config {
    /// Name reported as `service.name`, such as `holdor-server`.
    pub service_name: String,
    /// Version reported as `service.version`.
    pub service_version: String,
    /// Log rendering.
    pub log_format: LogFormat,
    /// Log filter in `tracing` syntax, such as `info` or
    /// `info,holdor_oauth=debug`.
    pub log_filter: String,
    /// Full URL of the OTLP/HTTP traces endpoint. `None` disables export.
    pub traces_endpoint: Option<String>,
    /// Full URL of the OTLP/HTTP metrics endpoint. `None` disables export.
    pub metrics_endpoint: Option<String>,
    /// How often metrics are pushed.
    pub metrics_interval: Duration,
}

impl Config {
    /// Settings with logging only: JSON at `info`, no export.
    #[must_use]
    pub fn new(service_name: impl Into<String>, service_version: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            service_version: service_version.into(),
            log_format: LogFormat::default(),
            log_filter: "info".to_owned(),
            traces_endpoint: None,
            metrics_endpoint: None,
            metrics_interval: Duration::from_secs(15),
        }
    }
}

/// Why telemetry could not be started.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// The log filter is not valid `tracing` filter syntax.
    #[error("invalid log filter `{filter}`: {reason}")]
    InvalidLogFilter {
        /// The rejected filter.
        filter: String,
        /// What is wrong with it.
        reason: String,
    },
    /// An OTLP exporter could not be built, usually a malformed endpoint.
    #[error("cannot build the OTLP {signal} exporter: {reason}")]
    Exporter {
        /// `traces` or `metrics`.
        signal: &'static str,
        /// The underlying error.
        reason: String,
    },
    /// Telemetry was already initialized in this process.
    #[error("telemetry is already initialized")]
    AlreadyInitialized,
}

/// Running telemetry. Keep it alive for the life of the process and call
/// [`Telemetry::shutdown`] before exiting so that buffered data is sent.
#[derive(Debug)]
pub struct Telemetry {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

impl Telemetry {
    /// Installs the global logger, tracer and meter.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or telemetry was
    /// already initialized. An unreachable backend is not an error: export
    /// failures are logged and the process keeps running.
    pub fn init(config: &Config) -> Result<Self, TelemetryError> {
        let filter = EnvFilter::try_new(&config.log_filter).map_err(|error| {
            TelemetryError::InvalidLogFilter {
                filter: config.log_filter.clone(),
                reason: error.to_string(),
            }
        })?;
        let resource = Resource::builder()
            .with_service_name(config.service_name.clone())
            .with_attribute(KeyValue::new(
                "service.version",
                config.service_version.clone(),
            ))
            .build();

        let tracer_provider = config
            .traces_endpoint
            .as_deref()
            .map(|endpoint| tracer_provider(endpoint, resource.clone()))
            .transpose()?;
        let meter_provider = config
            .metrics_endpoint
            .as_deref()
            .map(|endpoint| meter_provider(endpoint, config.metrics_interval, resource))
            .transpose()?;

        let logs = match config.log_format {
            LogFormat::Json => tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .with_span_list(false)
                .boxed(),
            LogFormat::Pretty => tracing_subscriber::fmt::layer().boxed(),
        };
        let traces = tracer_provider
            .as_ref()
            .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer("holdor")));

        tracing_subscriber::registry()
            .with(filter)
            .with(logs)
            .with(traces)
            .try_init()
            .map_err(|_| TelemetryError::AlreadyInitialized)?;

        if let Some(provider) = &tracer_provider {
            opentelemetry::global::set_tracer_provider(provider.clone());
        }
        if let Some(provider) = &meter_provider {
            opentelemetry::global::set_meter_provider(provider.clone());
        }

        Ok(Self {
            tracer_provider,
            meter_provider,
        })
    }

    /// Sends buffered traces and metrics now. Failures are logged.
    pub fn flush(&self) {
        if let Some(provider) = &self.tracer_provider
            && let Err(error) = provider.force_flush()
        {
            tracing::warn!(%error, "flushing traces failed");
        }
        if let Some(provider) = &self.meter_provider
            && let Err(error) = provider.force_flush()
        {
            tracing::warn!(%error, "flushing metrics failed");
        }
    }

    /// Flushes and stops the exporters. Call once, during graceful shutdown.
    pub fn shutdown(self) {
        if let Some(provider) = &self.tracer_provider
            && let Err(error) = provider.shutdown()
        {
            tracing::warn!(%error, "shutting down traces failed");
        }
        if let Some(provider) = &self.meter_provider
            && let Err(error) = provider.shutdown()
        {
            tracing::warn!(%error, "shutting down metrics failed");
        }
    }
}

fn tracer_provider(
    endpoint: &str,
    resource: Resource,
) -> Result<SdkTracerProvider, TelemetryError> {
    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .build()
        .map_err(|error| TelemetryError::Exporter {
            signal: "traces",
            reason: error.to_string(),
        })?;
    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build())
}

fn meter_provider(
    endpoint: &str,
    interval: Duration,
    resource: Resource,
) -> Result<SdkMeterProvider, TelemetryError> {
    let exporter = MetricExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .build()
        .map_err(|error| TelemetryError::Exporter {
            signal: "metrics",
            reason: error.to_string(),
        })?;
    let reader = PeriodicReader::builder(exporter)
        .with_interval(interval)
        .build();
    Ok(SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build())
}
