//! `hodor-cert-manager-issuer`: reads its configuration, then signs the
//! requests addressed to it and serves the operations port until it is
//! told to stop; or prints the public part of a key. See
//! `docs/operations/hodor-cert-manager-issuer.md`.

use clap::{Parser, Subcommand, ValueEnum};
use hodor_cert_manager_issuer::kubernetes::{
    ISSUER_CHECK_INTERVAL, Kubernetes, keep_issuers_ready, run as watch_requests,
};
use hodor_cert_manager_issuer::{
    Authentication, ClientKey, Hodor, Reconciler, Settings, Signer, operations,
};
use hodor_observability::{LogFormat, Telemetry};
use std::error::Error;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;

#[derive(Clone, Copy, ValueEnum)]
enum LogFormatArg {
    Json,
    Pretty,
}

/// cert-manager's outside issuer, signing through Hodor.
#[derive(Parser)]
#[command(name = "hodor-cert-manager-issuer", version, about)]
struct Arguments {
    #[command(subcommand)]
    command: Option<Command>,

    /// The configuration file, JSON.
    #[arg(long, env = "HODOR_CERT_MANAGER_ISSUER_CONFIG")]
    config: Option<PathBuf>,

    /// Where the operations port listens: `/startupz`, `/readyz`, `/livez`.
    #[arg(long, env = "HODOR_OPS_ADDR", default_value = "0.0.0.0:9090")]
    ops_addr: SocketAddr,

    /// Log rendering.
    #[arg(long, env = "HODOR_LOG_FORMAT", value_enum, default_value = "json")]
    log_format: LogFormatArg,

    /// Log filter, such as `info` or `info,hodor_cert_manager_issuer=debug`.
    #[arg(long, env = "HODOR_LOG_FILTER", default_value = "info")]
    log_filter: String,

    /// Full URL of the OTLP/HTTP traces endpoint. Unset disables export.
    #[arg(long, env = "HODOR_OTLP_TRACES_ENDPOINT")]
    otlp_traces_endpoint: Option<String>,

    /// Full URL of the OTLP/HTTP metrics endpoint. Unset disables export.
    #[arg(long, env = "HODOR_OTLP_METRICS_ENDPOINT")]
    otlp_metrics_endpoint: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Prints the public part of a key, as the JSON Web Key Hodor keeps
    /// for the client.
    Jwk {
        /// The key, in PEM.
        #[arg(long)]
        key: PathBuf,
        /// Its `kid` among the client's keys.
        #[arg(long)]
        key_id: Option<String>,
    },
}

fn read_key(path: &Path, key_id: Option<String>) -> Result<ClientKey, Box<dyn Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("the key file {} cannot be read: {error}", path.display()))?;
    Ok(ClientKey::from_pem(&text, key_id)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = Arguments::parse();
    if let Some(Command::Jwk { key, key_id }) = &arguments.command {
        let jwk = read_key(key, key_id.clone())?.jwk();
        writeln!(std::io::stdout(), "{jwk}")?;
        return Ok(());
    }
    // Read before anything starts: a file or a key that does not read
    // stops the process at once.
    let path = arguments
        .config
        .clone()
        .ok_or("HODOR_CERT_MANAGER_ISSUER_CONFIG names no configuration file")?;
    let text = std::fs::read_to_string(&path).map_err(|error| {
        format!(
            "the configuration file {} cannot be read: {error}",
            path.display()
        )
    })?;
    let settings = Settings::from_json(&text)?;
    let key = match &settings.authentication {
        Authentication::Forwarded => None,
        Authentication::PrivateKeyJwt { key_file, key_id } => {
            Some(read_key(key_file, key_id.clone())?)
        }
    };

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
        .block_on(run(&arguments, settings, key));
    if let Err(error) = &result {
        tracing::error!(%error, "hodor-cert-manager-issuer stopped on an error");
    }
    telemetry.shutdown();
    result
}

async fn run(
    arguments: &Arguments,
    settings: Settings,
    key: Option<ClientKey>,
) -> Result<(), Box<dyn Error>> {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    tracing::info!(
        tenant = %settings.tenant,
        hodor = %settings.hodor_url,
        authentication = match settings.authentication {
            Authentication::Forwarded => "forwarded",
            Authentication::PrivateKeyJwt { .. } => "private_key_jwt",
        },
        "configuration read"
    );
    let signer: Arc<dyn Signer> = Arc::new(Hodor::new(&settings, key, http));
    // In a pod, its service account; elsewhere, KUBECONFIG.
    let client = kube::Client::try_default().await?;
    let reconciler = Arc::new(Reconciler::new(
        Arc::new(Kubernetes::new(client.clone())),
        signer.clone(),
    ));
    let ops_listener = TcpListener::bind(arguments.ops_addr).await?;
    tracing::info!(operations = %arguments.ops_addr, "signing the certificate requests addressed to Hodor's issuers");

    let (stop, stopped) = watch::channel(false);
    let mut waiting = stopped.clone();
    let ops = tokio::spawn(
        axum::serve(ops_listener, operations())
            .with_graceful_shutdown(async move {
                let _ = waiting.wait_for(|stop| *stop).await;
            })
            .into_future(),
    );
    let readiness = tokio::spawn(keep_issuers_ready(
        client.clone(),
        signer,
        ISSUER_CHECK_INTERVAL,
    ));
    let mut controller_stopped = stopped;
    tokio::select! {
        () = watch_requests(client, reconciler, async move {
            let _ = controller_stopped.wait_for(|stop| *stop).await;
        }) => {}
        () = stop_signal() => {
            tracing::info!("stopping");
        }
    }
    let _ = stop.send(true);
    readiness.abort();
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
