//! `hodor-ext-authz`: reads its configuration, then serves Envoy's external
//! authorization and the operations port until it is told to stop. See
//! `docs/operations/hodor-ext-authz.md`.

use clap::{Parser, ValueEnum};
use hodor_ext_authz::{ExtAuthz, Settings, operations, serve};
use hodor_observability::{LogFormat, Telemetry};
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::net::TcpListener;
use tokio::sync::watch;

#[derive(Clone, Copy, ValueEnum)]
enum LogFormatArg {
    Json,
    Pretty,
}

/// Envoy's external authorization, answered by Hodor.
#[derive(Parser)]
#[command(name = "hodor-ext-authz", version, about)]
struct Arguments {
    /// The configuration file, JSON.
    #[arg(long, env = "HODOR_EXT_AUTHZ_CONFIG")]
    config: PathBuf,

    /// Where the gRPC service listens.
    #[arg(
        long,
        env = "HODOR_EXT_AUTHZ_LISTEN_ADDR",
        default_value = "0.0.0.0:9191"
    )]
    listen_addr: SocketAddr,

    /// Where the operations port listens: `/startupz`, `/readyz`, `/livez`.
    #[arg(long, env = "HODOR_OPS_ADDR", default_value = "0.0.0.0:9090")]
    ops_addr: SocketAddr,

    /// Log rendering.
    #[arg(long, env = "HODOR_LOG_FORMAT", value_enum, default_value = "json")]
    log_format: LogFormatArg,

    /// Log filter, such as `info` or `info,hodor_ext_authz=debug`.
    #[arg(long, env = "HODOR_LOG_FILTER", default_value = "info")]
    log_filter: String,

    /// Full URL of the OTLP/HTTP traces endpoint. Unset disables export.
    #[arg(long, env = "HODOR_OTLP_TRACES_ENDPOINT")]
    otlp_traces_endpoint: Option<String>,

    /// Full URL of the OTLP/HTTP metrics endpoint. Unset disables export.
    #[arg(long, env = "HODOR_OTLP_METRICS_ENDPOINT")]
    otlp_metrics_endpoint: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = Arguments::parse();
    // Read before anything starts: a file that does not read stops the
    // process before it listens.
    let text = std::fs::read_to_string(&arguments.config).map_err(|error| {
        format!(
            "the configuration file {} cannot be read: {error}",
            arguments.config.display()
        )
    })?;
    let settings = Settings::from_json(&text)?;

    // Telemetry starts before the async runtime: its exporters use a
    // blocking HTTP client on their own threads.
    let mut telemetry_config =
        hodor_observability::Config::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    telemetry_config.log_format = match arguments.log_format {
        LogFormatArg::Json => LogFormat::Json,
        LogFormatArg::Pretty => LogFormat::Pretty,
    };
    telemetry_config
        .log_filter
        .clone_from(&arguments.log_filter);
    telemetry_config
        .traces_endpoint
        .clone_from(&arguments.otlp_traces_endpoint);
    telemetry_config
        .metrics_endpoint
        .clone_from(&arguments.otlp_metrics_endpoint);
    let telemetry = Telemetry::init(&telemetry_config)?;

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(&arguments, settings));
    if let Err(error) = &result {
        tracing::error!(%error, "hodor-ext-authz stopped on an error");
    }
    telemetry.shutdown();
    result
}

async fn run(arguments: &Arguments, settings: Settings) -> Result<(), Box<dyn Error>> {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    tracing::info!(
        tenant = %settings.tenant,
        hodor = %settings.hodor_url,
        applications = settings.applications.len(),
        "configuration read"
    );
    let adapter = ExtAuthz::new(settings, http);
    let listener = TcpListener::bind(arguments.listen_addr).await?;
    let ops_listener = TcpListener::bind(arguments.ops_addr).await?;
    tracing::info!(
        listen = %arguments.listen_addr,
        operations = %arguments.ops_addr,
        "serving Envoy's external authorization"
    );

    let (stop, stopped) = watch::channel(false);
    let waiter = |mut stopped: watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };
    let ops = tokio::spawn(
        axum::serve(ops_listener, operations())
            .with_graceful_shutdown(waiter(stopped.clone()))
            .into_future(),
    );
    let grpc = tokio::spawn(serve(listener, adapter, waiter(stopped)));
    stop_signal().await;
    tracing::info!("stopping");
    let _ = stop.send(true);
    grpc.await??;
    ops.await??;
    Ok(())
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
                tracing::warn!(%error, "cannot listen for SIGTERM, only Ctrl-C will stop it");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
