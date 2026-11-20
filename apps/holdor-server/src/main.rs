//! HTTP composition root: protocols, APIs and the console BFF.
//!
//! This is the only place that knows concrete adapter types. It reads the
//! configuration, builds the adapters, hands them to the HTTP layer as
//! trait objects and runs the listeners until asked to stop.

use clap::{Parser, ValueEnum};
use holdor_adapters_postgres::Database;
use holdor_kernel::{DomainError, Secret};
use holdor_observability::{LogFormat, Telemetry};
use holdor_protocol_http::{
    Health, Limits, ReadinessCheck, ResolvedTenant, TenantResolver, ops_router, public_router,
    serve,
};
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;

#[derive(Clone, Copy, ValueEnum)]
enum LogFormatArg {
    Json,
    Pretty,
}

/// Holdor identity server.
#[derive(Parser)]
#[command(name = "holdor-server", version, about)]
struct Config {
    /// Address of the public listener.
    #[arg(long, env = "HOLDOR_LISTEN_ADDR", default_value = "0.0.0.0:8080")]
    listen_addr: SocketAddr,

    /// Address of the operations listener (health endpoints). Keep it off
    /// the internet.
    #[arg(long, env = "HOLDOR_OPS_ADDR", default_value = "127.0.0.1:9090")]
    ops_addr: SocketAddr,

    /// Database URL of the application role (a member of `holdor_app`).
    #[arg(long, env = "HOLDOR_DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Size of the database connection pool.
    #[arg(long, env = "HOLDOR_DATABASE_MAX_CONNECTIONS", default_value_t = 10)]
    database_max_connections: u32,

    /// Log rendering.
    #[arg(long, env = "HOLDOR_LOG_FORMAT", value_enum, default_value = "json")]
    log_format: LogFormatArg,

    /// Log filter, such as `info` or `info,holdor_oauth=debug`.
    #[arg(long, env = "HOLDOR_LOG_FILTER", default_value = "info")]
    log_filter: String,

    /// Full URL of the OTLP/HTTP traces endpoint. Unset disables export.
    #[arg(long, env = "HOLDOR_OTLP_TRACES_ENDPOINT")]
    otlp_traces_endpoint: Option<String>,

    /// Full URL of the OTLP/HTTP metrics endpoint. For VictoriaMetrics:
    /// `http://<host>:8428/opentelemetry/v1/metrics`. Unset disables export.
    #[arg(long, env = "HOLDOR_OTLP_METRICS_ENDPOINT")]
    otlp_metrics_endpoint: Option<String>,

    /// Seconds to keep serving after a stop signal while readiness fails,
    /// so the load balancer can take the instance out of rotation.
    #[arg(long, env = "HOLDOR_SHUTDOWN_DRAIN_SECONDS", default_value_t = 5)]
    shutdown_drain_seconds: u64,
}

/// Until the tenant context exists (M1-11 to M1-13) there are no tenants to
/// resolve, so every tenant path answers "not found".
struct NoTenants;

#[async_trait::async_trait]
impl TenantResolver for NoTenants {
    async fn resolve(&self, _slug: &str) -> Result<Option<ResolvedTenant>, DomainError> {
        Ok(None)
    }
}

struct DatabaseCheck(Database);

#[async_trait::async_trait]
impl ReadinessCheck for DatabaseCheck {
    fn name(&self) -> &'static str {
        "database"
    }

    async fn check(&self) -> Result<(), String> {
        self.0.ping().await.map_err(|error| error.to_string())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse();

    // Telemetry starts before the async runtime: its exporters use a
    // blocking HTTP client on their own threads.
    let mut telemetry_config =
        holdor_observability::Config::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
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
        tracing::error!(%error, "server stopped with an error");
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
    let health = Health::new(vec![Arc::new(DatabaseCheck(database))]);

    let public = public_router(Arc::new(NoTenants), axum::Router::new(), Limits::default());
    let ops = ops_router(health.clone());

    let public_listener = TcpListener::bind(config.listen_addr).await?;
    let ops_listener = TcpListener::bind(config.ops_addr).await?;
    tracing::info!(
        listen = %public_listener.local_addr()?,
        ops = %ops_listener.local_addr()?,
        "holdor-server started"
    );

    // One signal stops both listeners, after the drain delay.
    let (stop, stopped) = watch::channel(false);
    let drain = Duration::from_secs(config.shutdown_drain_seconds);
    tokio::spawn(async move {
        stop_signal().await;
        tracing::info!(
            drain_seconds = drain.as_secs(),
            "stop signal received, draining"
        );
        health.begin_draining();
        tokio::time::sleep(drain).await;
        let _ = stop.send(true);
    });

    let public_server = serve(public_listener, public, wait_for(stopped.clone()));
    let ops_server = serve(ops_listener, ops, wait_for(stopped));
    let (public_result, ops_result) = tokio::join!(public_server, ops_server);
    public_result?;
    ops_result?;
    tracing::info!("holdor-server stopped");
    Ok(())
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
                tracing::warn!(%error, "cannot listen for SIGTERM, only Ctrl-C will stop the server");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
