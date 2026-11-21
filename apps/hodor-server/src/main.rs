//! HTTP composition root: protocols, APIs and the console BFF.
//!
//! This is the only place that knows concrete adapter types. It reads the
//! configuration, builds the adapters, hands them to the HTTP layer as
//! trait objects and runs the listeners until asked to stop.

use clap::{Parser, ValueEnum};
use hodor_adapters_crypto::{
    Argon2Parameters, Argon2idHasher, HashingLimits, OsRandom, Sha256Digest,
};
use hodor_adapters_postgres::{
    Database, PgAttemptStore, PgMessageQueue, PgPasswordStore, PgSessionStore, PgTenantDirectory,
    PgTenantRepository, PgTransactionStore, PgUserRepository, PgVerificationTokenStore,
};
use hodor_authentication::api::{
    AccountService, AttemptGuard, AuthFlow, AuthenticationService, FlowEngine,
    IdentifierAuthenticator, PasswordAuthenticator,
};
use hodor_credential::api::CredentialService;
use hodor_identity::api::IdentityService;
use hodor_kernel::{DomainError, Secret, SystemClock, TenantContext};
use hodor_notification::api::Notifier;
use hodor_observability::{LogFormat, Telemetry};
use hodor_protocol_http::{
    Health, InteractionState, Limits, ReadinessCheck, ResolvedTenant, TenantResolver,
    TenantStatus as HttpTenantStatus, interaction_routes, ops_router, public_router, serve,
};
use hodor_session::api::SessionService;
use hodor_tenant::api::{TenantDirectory as _, TenantService, TenantStatus};
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

/// Hodor identity server.
#[derive(Parser)]
#[command(name = "hodor-server", version, about)]
struct Config {
    /// Address of the public listener.
    #[arg(long, env = "HODOR_LISTEN_ADDR", default_value = "0.0.0.0:8080")]
    listen_addr: SocketAddr,

    /// Address of the operations listener (health endpoints). Keep it off
    /// the internet.
    #[arg(long, env = "HODOR_OPS_ADDR", default_value = "127.0.0.1:9090")]
    ops_addr: SocketAddr,

    /// Database URL of the application role (a member of `hodor_app`).
    #[arg(long, env = "HODOR_DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Size of the database connection pool.
    #[arg(long, env = "HODOR_DATABASE_MAX_CONNECTIONS", default_value_t = 10)]
    database_max_connections: u32,

    /// Log rendering.
    #[arg(long, env = "HODOR_LOG_FORMAT", value_enum, default_value = "json")]
    log_format: LogFormatArg,

    /// Log filter, such as `info` or `info,hodor_oauth=debug`.
    #[arg(long, env = "HODOR_LOG_FILTER", default_value = "info")]
    log_filter: String,

    /// Full URL of the OTLP/HTTP traces endpoint. Unset disables export.
    #[arg(long, env = "HODOR_OTLP_TRACES_ENDPOINT")]
    otlp_traces_endpoint: Option<String>,

    /// Full URL of the OTLP/HTTP metrics endpoint. For VictoriaMetrics:
    /// `http://<host>:8428/opentelemetry/v1/metrics`. Unset disables export.
    #[arg(long, env = "HODOR_OTLP_METRICS_ENDPOINT")]
    otlp_metrics_endpoint: Option<String>,

    /// Seconds to keep serving after a stop signal while readiness fails,
    /// so the load balancer can take the instance out of rotation.
    #[arg(long, env = "HODOR_SHUTDOWN_DRAIN_SECONDS", default_value_t = 5)]
    shutdown_drain_seconds: u64,

    /// The address people reach this installation at, without a path.
    /// Links in messages start with it.
    #[arg(
        long,
        env = "HODOR_PUBLIC_URL",
        default_value = "http://localhost:8080"
    )]
    public_url: String,

    /// Memory one password hash uses, in kibibytes.
    #[arg(long, env = "HODOR_PASSWORD_HASH_MEMORY_KIBIBYTES", default_value_t = 19 * 1024)]
    password_hash_memory_kibibytes: u32,

    /// Passes over that memory.
    #[arg(long, env = "HODOR_PASSWORD_HASH_PASSES", default_value_t = 2)]
    password_hash_passes: u32,

    /// Lanes computed in parallel within one hash.
    #[arg(long, env = "HODOR_PASSWORD_HASH_LANES", default_value_t = 1)]
    password_hash_lanes: u32,

    /// Password hashes computed at the same time. Defaults to one per
    /// processor core.
    #[arg(long, env = "HODOR_PASSWORD_HASH_CONCURRENCY")]
    password_hash_concurrency: Option<usize>,

    /// Requests allowed to wait for a hash. Defaults to four times the
    /// concurrency.
    #[arg(long, env = "HODOR_PASSWORD_HASH_QUEUE")]
    password_hash_queue: Option<usize>,
}

/// Resolves tenants through the directory, answering by status as
/// specified in `docs/architecture/contexts/tenant.md`, "Lifecycle".
struct DirectoryResolver(PgTenantDirectory);

#[async_trait::async_trait]
impl TenantResolver for DirectoryResolver {
    async fn resolve(&self, slug: &str) -> Result<Option<ResolvedTenant>, DomainError> {
        let Some(entry) = self.0.find_by_slug(slug).await? else {
            return Ok(None);
        };
        let status = match entry.status {
            TenantStatus::Active => HttpTenantStatus::Active,
            TenantStatus::Suspended | TenantStatus::PendingDeletion => HttpTenantStatus::Suspended,
            // Not there yet, or not there any more: indistinguishable from
            // a tenant that never existed.
            TenantStatus::Provisioning | TenantStatus::Deleted => return Ok(None),
        };
        Ok(Some(ResolvedTenant {
            // The request path named this tenant and the directory
            // confirmed it: this is where its context is established.
            context: TenantContext::assume(entry.tenant_id),
            status,
        }))
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
        tracing::error!(%error, "server stopped with an error");
    }
    telemetry.shutdown();
    result
}

async fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let database = Database::connect(
        &Secret::from(config.database_url.clone()),
        config.database_max_connections,
    )
    .await?;
    let health = Health::new(vec![Arc::new(DatabaseCheck(database.clone()))]);

    let public = public_router(
        Arc::new(DirectoryResolver(PgTenantDirectory::new(database.clone()))),
        axum::Router::new().nest(
            "/interaction",
            interaction_routes(interaction(&config, &database)?),
        ),
        Limits::default(),
    );
    let ops = ops_router(health.clone());

    let public_listener = TcpListener::bind(config.listen_addr).await?;
    let ops_listener = TcpListener::bind(config.ops_addr).await?;
    tracing::info!(
        listen = %public_listener.local_addr()?,
        ops = %ops_listener.local_addr()?,
        "hodor-server started"
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
    tracing::info!("hodor-server stopped");
    Ok(())
}

/// Builds everything the interaction interface needs. This is the composition root: the
/// one place that knows which adapter stands behind each port.
fn interaction(config: &Config, database: &Database) -> Result<InteractionState, DomainError> {
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let digest = Arc::new(Sha256Digest);
    let random = Arc::new(OsRandom);

    let defaults = HashingLimits::for_this_machine();
    let concurrent = config
        .password_hash_concurrency
        .unwrap_or(defaults.concurrent);
    let hasher = Arc::new(Argon2idHasher::new(
        Argon2Parameters {
            memory_kibibytes: config.password_hash_memory_kibibytes,
            passes: config.password_hash_passes,
            lanes: config.password_hash_lanes,
        },
        HashingLimits {
            concurrent,
            queued: config.password_hash_queue.unwrap_or(concurrent * 4),
        },
        random.clone(),
    )?);

    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        clock.clone(),
    );
    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone());
    let credentials =
        CredentialService::new(units(), Arc::new(PgPasswordStore), hasher, clock.clone());
    let sessions = SessionService::new(
        units(),
        Arc::new(PgSessionStore),
        digest.clone(),
        random.clone(),
        clock.clone(),
    );
    let guard = AttemptGuard::new(
        units(),
        Arc::new(PgAttemptStore),
        digest.clone(),
        clock.clone(),
    );
    let engine = FlowEngine::new()
        .with(Arc::new(IdentifierAuthenticator::new(
            identity.clone(),
            digest.clone(),
        )))
        .with(Arc::new(PasswordAuthenticator::new(
            credentials.clone(),
            identity.clone(),
            tenants.clone(),
            guard.clone(),
        )));
    // The server only queues messages; the worker delivers them.
    let accounts = AccountService::new(
        units(),
        Arc::new(PgVerificationTokenStore),
        identity.clone(),
        credentials,
        sessions.clone(),
        tenants.clone(),
        Notifier::new(Arc::new(PgMessageQueue), clock.clone()),
        guard,
        digest.clone(),
        random.clone(),
        clock.clone(),
        &config.public_url,
    );
    let authentication = AuthenticationService::new(
        units(),
        Arc::new(PgTransactionStore),
        engine,
        AuthFlow::built_in(),
        identity,
        sessions.clone(),
        tenants,
        digest.clone(),
        random,
        clock.clone(),
    )?;
    Ok(InteractionState {
        authentication,
        accounts,
        sessions,
        digest,
        clock,
    })
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
