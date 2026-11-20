//! Background jobs composition root.
//!
//! Today the worker has one job: delivering outbox events to their
//! handlers. See `docs/operations/deployment.md`, "The worker".

use clap::{Parser, ValueEnum};
use hodor_adapters_postgres::{Database, OutboxDispatcher, PgPool, connect_pool, ping_pool};
use hodor_kernel::Secret;
use hodor_observability::{LogFormat, Telemetry};
use hodor_protocol_http::{Health, ReadinessCheck, ops_router, serve};
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// Shortest pause after a failed pass, so a broken database is not hammered.
const MIN_ERROR_PAUSE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, ValueEnum)]
enum LogFormatArg {
    Json,
    Pretty,
}

/// Hodor background worker.
#[derive(Parser)]
#[command(name = "hodor-worker", version, about)]
struct Config {
    /// Database URL of a login role that is a member of `hodor_app`. Used
    /// to handle each piece of work inside its tenant.
    #[arg(long, env = "HODOR_DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Database URL of a login role that is a member of `hodor_platform`.
    /// Used only to find pending work across tenants.
    #[arg(long, env = "HODOR_PLATFORM_DATABASE_URL", hide_env_values = true)]
    platform_database_url: String,

    /// Size of each of the two connection pools.
    #[arg(long, env = "HODOR_DATABASE_MAX_CONNECTIONS", default_value_t = 5)]
    database_max_connections: u32,

    /// Address of the operations listener (health endpoints).
    #[arg(long, env = "HODOR_OPS_ADDR", default_value = "127.0.0.1:9091")]
    ops_addr: SocketAddr,

    /// Most outbox events handled per pass.
    #[arg(long, env = "HODOR_OUTBOX_BATCH_SIZE", default_value_t = 100)]
    outbox_batch_size: u32,

    /// Pause between passes when there is nothing to deliver.
    #[arg(long, env = "HODOR_OUTBOX_POLL_INTERVAL_MS", default_value_t = 500)]
    outbox_poll_interval_ms: u64,

    /// Log rendering.
    #[arg(long, env = "HODOR_LOG_FORMAT", value_enum, default_value = "json")]
    log_format: LogFormatArg,

    /// Log filter, such as `info` or `info,hodor_adapters_postgres=debug`.
    #[arg(long, env = "HODOR_LOG_FILTER", default_value = "info")]
    log_filter: String,

    /// Full URL of the OTLP/HTTP traces endpoint. Unset disables export.
    #[arg(long, env = "HODOR_OTLP_TRACES_ENDPOINT")]
    otlp_traces_endpoint: Option<String>,

    /// Full URL of the OTLP/HTTP metrics endpoint. Unset disables export.
    #[arg(long, env = "HODOR_OTLP_METRICS_ENDPOINT")]
    otlp_metrics_endpoint: Option<String>,
}

struct PoolCheck {
    name: &'static str,
    pool: PgPool,
}

#[async_trait::async_trait]
impl ReadinessCheck for PoolCheck {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn check(&self) -> Result<(), String> {
        ping_pool(&self.pool)
            .await
            .map_err(|error| error.to_string())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse();

    // Telemetry starts before the async runtime: its exporters use a
    // blocking HTTP client on their own threads.
    let mut telemetry_config =
        hodor_observability::Config::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    telemetry_config.log_format = match config.log_format {
        LogFormatArg::Json => LogFormat::Json,
        LogFormatArg::Pretty => LogFormat::Pretty,
    };
    telemetry_config.log_filter.clone_from(&config.log_filter);
    telemetry_config
        .traces_endpoint
        .clone_from(&config.otlp_traces_endpoint);
    telemetry_config
        .metrics_endpoint
        .clone_from(&config.otlp_metrics_endpoint);
    let telemetry = Telemetry::init(&telemetry_config)?;

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(config));

    if let Err(error) = &result {
        tracing::error!(%error, "worker stopped with an error");
    }
    telemetry.shutdown();
    result
}

async fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let database = Database::connect(
        &Secret::from(config.database_url),
        config.database_max_connections,
    )
    .await?;
    let platform = connect_pool(
        &Secret::from(config.platform_database_url),
        config.database_max_connections,
    )
    .await?;

    let health = Health::new(vec![
        Arc::new(PoolCheck {
            name: "database",
            pool: database.pool().clone(),
        }),
        Arc::new(PoolCheck {
            name: "platform_database",
            pool: platform.clone(),
        }),
    ]);

    // No handlers are registered yet; audit and notification add theirs.
    let dispatcher = OutboxDispatcher::new(platform, database, Vec::new());

    let ops_listener = TcpListener::bind(config.ops_addr).await?;
    tracing::info!(ops = %ops_listener.local_addr()?, "hodor-worker started");

    let (stop, stopped) = watch::channel(false);
    let draining = health.clone();
    tokio::spawn(async move {
        stop_signal().await;
        tracing::info!("stop signal received, finishing the current batch");
        draining.begin_draining();
        let _ = stop.send(true);
    });

    let ops_server = tokio::spawn(serve(
        ops_listener,
        ops_router(health),
        wait_for(stopped.clone()),
    ));

    dispatch_loop(
        &dispatcher,
        config.outbox_batch_size,
        Duration::from_millis(config.outbox_poll_interval_ms),
        stopped,
    )
    .await;

    ops_server.await??;
    tracing::info!("hodor-worker stopped");
    Ok(())
}

/// Delivers outbox events until asked to stop.
///
/// A pass that did work is followed by another at once; an empty pass by a
/// pause. A database error is logged and followed by a pause, never by an
/// exit: the worker waits for the database to come back.
async fn dispatch_loop(
    dispatcher: &OutboxDispatcher,
    batch_size: u32,
    poll_interval: Duration,
    mut stopped: watch::Receiver<bool>,
) {
    let meter = opentelemetry::global::meter("hodor.worker");
    let events: Counter<u64> = meter
        .u64_counter("hodor.outbox.events")
        .with_description("Outbox events handled, by outcome")
        .build();
    let passes: Counter<u64> = meter
        .u64_counter("hodor.outbox.passes")
        .with_description("Outbox dispatch passes, by outcome")
        .build();

    while !*stopped.borrow() {
        let pause = match dispatcher.dispatch_batch(batch_size).await {
            Ok(report) => {
                passes.add(1, &[KeyValue::new("outcome", "ok")]);
                events.add(
                    report.delivered as u64,
                    &[KeyValue::new("outcome", "delivered")],
                );
                events.add(report.failed as u64, &[KeyValue::new("outcome", "failed")]);
                if report.failed > 0 {
                    tracing::warn!(
                        failed = report.failed,
                        "outbox deliveries failed, will retry"
                    );
                }
                (report.delivered + report.failed == 0).then_some(poll_interval)
            }
            Err(error) => {
                passes.add(1, &[KeyValue::new("outcome", "error")]);
                tracing::warn!(%error, "outbox pass failed");
                Some(poll_interval.max(MIN_ERROR_PAUSE))
            }
        };
        if let Some(pause) = pause {
            tokio::select! {
                () = tokio::time::sleep(pause) => {}
                _ = stopped.changed() => {}
            }
        }
    }
}

async fn wait_for(mut stopped: watch::Receiver<bool>) {
    // An error means the sender is gone, which also means: stop.
    let _ = stopped.wait_for(|stop| *stop).await;
}

/// Resolves on SIGTERM (orchestrators) or Ctrl-C (terminals).
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = terminate.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(error) => {
                tracing::warn!(%error, "cannot listen for SIGTERM, only Ctrl-C will stop the worker");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
