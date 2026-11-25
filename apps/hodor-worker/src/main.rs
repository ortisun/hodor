//! Background jobs composition root.
//!
//! The worker delivers outbox events to their handlers, the audit log, the
//! fan-out of webhooks and the fan-out of back-channel logout, delivers
//! queued messages to the mail server, sends webhooks and logout tokens,
//! runs the cleanup jobs, rotates the tenants' signing keys, and checks,
//! tests and simulates policy versions with the `opa` binary. See
//! `docs/operations/deployment.md`, "The worker".

use clap::{Parser, ValueEnum};
use hodor_adapters_crypto::{
    AwsLcHmacSha256, LocalKeyProvider, OsRandom, SecretKeys, Sha256Digest,
};
use hodor_adapters_http::{GuardedHttpClient, OutboundPolicy};
use hodor_adapters_policy_check::{OpaProcessChecker, RunLimits};
use hodor_adapters_postgres::{
    AccessTokenCleanup, CleanupReport, Database, DecisionLogMaintenance, ExpiredKind,
    ExpiredRowCleanup, KeyRotationJob, OutboxDispatcher, PendingAuthorizationCleanup, PgAuditLog,
    PgBundleStore, PgDeliveryStore, PgDueDeliveries, PgEndpointStore, PgInstanceStatusStore,
    PgInstanceStore, PgKeyStore, PgMessageQueue, PgPendingMessages, PgPolicyVersionStore, PgPool,
    PgPublicationStore, PgSealingStateStore, PgSimulationStore, PgUploadedDecisionStore,
    PolicyCheckJob, connect_pool, ping_pool,
};
use hodor_adapters_postgres::{
    PgApplicationStore, PgClientStore, PgDueLogoutDeliveries, PgLogoutDeliveryStore,
    PgPairwiseSecretStore, PgSessionClients, PgTenantDirectory, PgTenantRepository,
};
use hodor_adapters_smtp::SmtpSender;
use hodor_audit::api::{AuditHandler, AuditService};
use hodor_authorization_opa::api::{BundleService, PolicyService};
use hodor_kernel::{Clock as _, DomainError, Secret, SystemClock, TenantContext, Timestamp};
use hodor_keys::api::{KeyService, RotationPolicy, TenantSecretBox};
use hodor_notification::api::DeliveryService;
use hodor_oauth::api::{
    BackChannelLogoutFanOut, BackChannelLogoutSender, LogoutDeliverySettings, LogoutRetryPolicy,
    LogoutSenderPorts, PairwisePorts, PairwiseSubjects, TenantIssuer,
};
use hodor_observability::{LogFormat, Telemetry};
use hodor_protocol_http::{Health, ReadinessCheck, ops_router, serve};
use hodor_tenant::api::TenantService;
use hodor_webhooks::api::{
    DeliverySettings, RetryPolicy, SenderPorts, WebhookFanOut, WebhookSender,
};
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

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

    /// Where to send mail, such as `smtps://user:password@host:465`.
    /// Unset: no mail is delivered and messages wait.
    #[arg(long, env = "HODOR_SMTP_URL", hide_env_values = true)]
    smtp_url: Option<String>,

    /// The address messages are sent from, such as
    /// `Hodor <no-reply@example.com>`. Required with the mail server.
    #[arg(long, env = "HODOR_MAIL_FROM", requires = "smtp_url")]
    mail_from: Option<String>,

    /// Most messages handled per pass.
    #[arg(long, env = "HODOR_MAIL_BATCH_SIZE", default_value_t = 50)]
    mail_batch_size: u32,

    /// Pause between passes when there is no message to deliver.
    #[arg(long, env = "HODOR_MAIL_POLL_INTERVAL_MS", default_value_t = 1000)]
    mail_poll_interval_ms: u64,

    /// Pause between passes of the cleanup jobs.
    #[arg(long, env = "HODOR_CLEANUP_INTERVAL_MS", default_value_t = 60_000)]
    cleanup_interval_ms: u64,

    /// Most rows a cleanup job removes in one tenant per pass.
    #[arg(long, env = "HODOR_CLEANUP_BATCH_SIZE", default_value_t = 500)]
    cleanup_batch_size: u32,

    /// Retentions that differ from the defaults, as `kind=days` pairs
    /// separated by commas, such as `sessions=30,messages=90`.
    #[arg(long, env = "HODOR_CLEANUP_RETENTION_DAYS", default_value = "")]
    cleanup_retention_days: String,

    /// The keys that wrap the tenants' signing keys: the same as the
    /// server's. Unset: keys do not rotate, and no tenant gets one.
    #[arg(long, env = "HODOR_SECRET_KEYS", hide_env_values = true)]
    secret_keys: Option<String>,

    /// How long a signing key signs before it is replaced, in days.
    #[arg(long, env = "HODOR_KEY_ROTATION_DAYS", default_value_t = 90)]
    key_rotation_days: i64,

    /// How long a new signing key is published before it signs, in hours.
    #[arg(long, env = "HODOR_KEY_PUBLICATION_HOURS", default_value_t = 24)]
    key_publication_hours: i64,

    /// How long a replaced signing key stays published, in hours.
    #[arg(long, env = "HODOR_KEY_OVERLAP_HOURS", default_value_t = 24)]
    key_overlap_hours: i64,

    /// Pause between passes of the rotation job.
    #[arg(
        long,
        env = "HODOR_KEY_ROTATION_INTERVAL_MS",
        default_value_t = 600_000
    )]
    key_rotation_interval_ms: u64,

    /// The `opa` binary that checks, tests and simulates policy versions.
    /// Unset, no version is checked, and so none can be published.
    #[arg(long, env = "HODOR_OPEN_POLICY_AGENT_BINARY")]
    open_policy_agent_binary: Option<std::path::PathBuf>,

    /// The SHA-256 the binary must have, as 64 hexadecimal digits. Unset,
    /// only its version is checked.
    #[arg(long, env = "HODOR_OPEN_POLICY_AGENT_BINARY_SHA256")]
    open_policy_agent_binary_sha256: Option<String>,

    /// The longest one run of the binary may take, in seconds.
    #[arg(
        long,
        env = "HODOR_POLICY_CHECK_TIME_LIMIT_SECONDS",
        default_value_t = 30
    )]
    policy_check_time_limit_seconds: u64,

    /// What `GOMEMLIMIT` asks a run to stay under, in mebibytes.
    #[arg(
        long,
        env = "HODOR_POLICY_CHECK_MEMORY_MEBIBYTES",
        default_value_t = 256
    )]
    policy_check_memory_mebibytes: u32,

    /// Pause between passes of the policy check job.
    #[arg(long, env = "HODOR_POLICY_CHECK_INTERVAL_MS", default_value_t = 2000)]
    policy_check_interval_ms: u64,

    /// Attempts before a webhook delivery is set aside, 1 to 20.
    #[arg(long, env = "HODOR_WEBHOOK_MAX_ATTEMPTS", default_value_t = 8)]
    webhook_max_attempts: u32,

    /// The wait after a delivery's first failed attempt; each next wait is
    /// twice as long, up to an hour.
    #[arg(long, env = "HODOR_WEBHOOK_FIRST_RETRY_MS", default_value_t = 30_000)]
    webhook_first_retry_ms: u64,

    /// The longest one attempt may take, 1 to 30 seconds.
    #[arg(long, env = "HODOR_WEBHOOK_TIME_LIMIT_SECONDS", default_value_t = 10)]
    webhook_time_limit_seconds: u64,

    /// Deliveries leased at once to one endpoint, across every worker, 1 to
    /// 32.
    #[arg(
        long,
        env = "HODOR_WEBHOOK_IN_FLIGHT_PER_ENDPOINT",
        default_value_t = 4
    )]
    webhook_in_flight_per_endpoint: u32,

    /// Deliveries this worker sends at once, 1 to 256.
    #[arg(long, env = "HODOR_WEBHOOK_CONCURRENCY", default_value_t = 32)]
    webhook_concurrency: u32,

    /// Pause between passes when no delivery is due.
    #[arg(long, env = "HODOR_WEBHOOK_POLL_INTERVAL_MS", default_value_t = 1000)]
    webhook_poll_interval_ms: u64,

    /// The address people reach this installation at, without a path, as
    /// the server has it: the issuer of a logout token starts with it.
    /// Unset: no logout token is sent, and logout deliveries wait.
    #[arg(long, env = "HODOR_PUBLIC_URL")]
    public_url: Option<String>,

    /// Attempts before a logout delivery is set aside, 1 to 20.
    #[arg(
        long,
        env = "HODOR_BACKCHANNEL_LOGOUT_MAX_ATTEMPTS",
        default_value_t = 8
    )]
    backchannel_logout_max_attempts: u32,

    /// The wait after a logout delivery's first failed attempt; each next
    /// wait is twice as long, up to an hour.
    #[arg(
        long,
        env = "HODOR_BACKCHANNEL_LOGOUT_FIRST_RETRY_MS",
        default_value_t = 30_000
    )]
    backchannel_logout_first_retry_ms: u64,

    /// The longest one attempt to send a logout token may take, 1 to 30
    /// seconds.
    #[arg(
        long,
        env = "HODOR_BACKCHANNEL_LOGOUT_TIME_LIMIT_SECONDS",
        default_value_t = 10
    )]
    backchannel_logout_time_limit_seconds: u64,

    /// Pause between passes when no logout delivery is due.
    #[arg(
        long,
        env = "HODOR_BACKCHANNEL_LOGOUT_POLL_INTERVAL_MS",
        default_value_t = 1000
    )]
    backchannel_logout_poll_interval_ms: u64,

    /// Hosts with their ports that webhooks and logout tokens may reach
    /// without the address check and over plain HTTP, separated by commas.
    /// For a development stack on one machine; never set it anywhere real.
    #[arg(long, env = "HODOR_OUTBOUND_DEVELOPMENT_HOSTS", value_delimiter = ',')]
    outbound_development_hosts: Vec<String>,

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
    // Checked before anything is connected, so that a mistake in the mail
    // or rotation settings is reported at once.
    let delivery_settings = webhook_settings(&config)?;
    let logout_settings = backchannel_logout_settings(&config)?;
    let development_hosts: Vec<String> = config
        .outbound_development_hosts
        .iter()
        .map(|host| host.trim().to_owned())
        .filter(|host| !host.is_empty())
        .collect();
    let mail_sender = mail_sender(config.smtp_url, config.mail_from.as_deref())?;
    let rotation_policy = RotationPolicy::new(
        time::Duration::days(config.key_rotation_days),
        time::Duration::hours(config.key_publication_hours),
        time::Duration::hours(config.key_overlap_hours),
    )?;
    let retentions = cleanup_retentions(&config.cleanup_retention_days)?;
    let root_keys = config
        .secret_keys
        .clone()
        .map(|setting| SecretKeys::parse(&Secret::from(setting)))
        .transpose()?
        .map(Arc::new);

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

    let delivery = mail_sender.map(|sender| {
        DeliveryService::new(
            Arc::new(database.clone()),
            Arc::new(PgMessageQueue),
            Arc::new(PgPendingMessages::new(platform.clone())),
            Arc::new(sender),
            Arc::new(SystemClock),
        )
    });
    if delivery.is_none() {
        tracing::warn!("HODOR_SMTP_URL is not set: no mail is delivered and messages wait");
    }

    // Every event becomes an audit record, in the transaction that marks
    // the event delivered.
    let audit = AuditService::new(
        Arc::new(database.clone()),
        Arc::new(PgAuditLog),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
    );
    let pending_cleanup = CleanupJob::PendingAuthorizations(PendingAuthorizationCleanup::new(
        platform.clone(),
        database.clone(),
    ));
    let access_token_cleanup =
        CleanupJob::AccessTokens(AccessTokenCleanup::new(platform.clone(), database.clone()));
    let expired_rows: Vec<CleanupJob> = ExpiredKind::ALL
        .into_iter()
        .map(|kind| {
            CleanupJob::Expired(ExpiredRowCleanup::new(
                kind,
                retentions
                    .get(&kind)
                    .copied()
                    .unwrap_or(kind.default_retention_days()),
                platform.clone(),
                database.clone(),
            ))
        })
        .collect();
    let decision_log_maintenance = CleanupJob::DecisionLog(DecisionLogMaintenance::new(
        platform.clone(),
        database.clone(),
    ));
    let webhook_sender = match &root_keys {
        Some(root) => Some(Arc::new(webhook_sender(
            development_hosts.clone(),
            &database,
            &platform,
            root,
            delivery_settings,
        )?)),
        None => None,
    };
    // Logout tokens are signed with the tenant's key and name its issuer.
    let logout_sender = match (&root_keys, &config.public_url) {
        (Some(root), Some(public_url)) => Some(Arc::new(logout_sender(
            development_hosts,
            &database,
            &platform,
            root,
            public_url,
            logout_settings,
        )?)),
        _ => {
            tracing::warn!(
                "HODOR_SECRET_KEYS or HODOR_PUBLIC_URL is not set: no logout token is sent, and logout deliveries wait"
            );
            None
        }
    };
    let rotation = root_keys.map(|root| {
        let keys = KeyService::new(
            Arc::new(database.clone()),
            Arc::new(PgKeyStore),
            Arc::new(LocalKeyProvider::new(root)),
            Arc::new(SystemClock),
        );
        KeyRotationJob::new(platform.clone(), keys, rotation_policy)
    });
    if rotation.is_none() {
        tracing::warn!(
            "HODOR_SECRET_KEYS is not set: keys do not rotate, no tenant gets one, and no webhook is sent"
        );
    }
    let policy_checks = match &config.open_policy_agent_binary {
        Some(binary) => {
            let checker = OpaProcessChecker::verified(
                binary.clone(),
                config.open_policy_agent_binary_sha256.as_deref(),
                &Sha256Digest,
                RunLimits {
                    time: Duration::from_secs(config.policy_check_time_limit_seconds.max(1)),
                    memory_mebibytes: config.policy_check_memory_mebibytes,
                    ..RunLimits::default()
                },
                None,
            )
            .await?;
            Some(PolicyCheckJob::new(
                platform.clone(),
                policy_service(&database),
                Arc::new(checker),
            ))
        }
        None => {
            tracing::warn!(
                "HODOR_OPEN_POLICY_AGENT_BINARY is not set: no policy version is checked, so none can be published"
            );
            None
        }
    };
    // The fan-out of webhooks needs no key: deliveries are made whether or
    // not this worker can send them.
    let fan_out = WebhookFanOut::new(
        Arc::new(PgEndpointStore),
        Arc::new(PgDeliveryStore),
        Arc::new(SystemClock),
    );
    // Nor does the fan-out of back-channel logout.
    let logout_fan_out = BackChannelLogoutFanOut::new(
        Arc::new(PgSessionClients),
        Arc::new(PgClientStore),
        Arc::new(PgApplicationStore),
        Arc::new(PgLogoutDeliveryStore),
        Arc::new(SystemClock),
    );
    let dispatcher = OutboxDispatcher::new(
        platform,
        database,
        vec![
            Arc::new(AuditHandler::new(audit)),
            Arc::new(fan_out),
            Arc::new(logout_fan_out),
        ],
    );

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

    tokio::join!(
        dispatch_loop(
            &dispatcher,
            config.outbox_batch_size,
            Duration::from_millis(config.outbox_poll_interval_ms),
            stopped.clone(),
        ),
        delivery_loop(
            delivery.as_ref(),
            config.mail_batch_size,
            Duration::from_millis(config.mail_poll_interval_ms),
            stopped.clone(),
        ),
        sending_loop(
            webhook_sender,
            &WEBHOOKS,
            config.webhook_concurrency as usize,
            Duration::from_millis(config.webhook_poll_interval_ms),
            stopped.clone(),
        ),
        sending_loop(
            logout_sender,
            &LOGOUT_TOKENS,
            LogoutDeliverySettings::CONCURRENCY as usize,
            Duration::from_millis(config.backchannel_logout_poll_interval_ms),
            stopped.clone(),
        ),
        cleanup_loop(
            std::slice::from_ref(&pending_cleanup),
            config.cleanup_batch_size,
            Duration::from_millis(config.cleanup_interval_ms),
            stopped.clone(),
        ),
        cleanup_loop(
            std::slice::from_ref(&access_token_cleanup),
            config.cleanup_batch_size,
            Duration::from_millis(config.cleanup_interval_ms),
            stopped.clone(),
        ),
        cleanup_loop(
            std::slice::from_ref(&decision_log_maintenance),
            config.cleanup_batch_size,
            Duration::from_millis(config.cleanup_interval_ms),
            stopped.clone(),
        ),
        cleanup_loop(
            &expired_rows,
            config.cleanup_batch_size,
            Duration::from_millis(config.cleanup_interval_ms),
            stopped.clone(),
        ),
        rotation_loop(
            rotation.as_ref(),
            Duration::from_millis(config.key_rotation_interval_ms),
            stopped.clone(),
        ),
        policy_check_loop(
            policy_checks.as_ref(),
            Duration::from_millis(config.policy_check_interval_ms),
            stopped,
        ),
    );

    ops_server.await??;
    tracing::info!("hodor-worker stopped");
    Ok(())
}

/// A cleanup job: what it removes, and how.
enum CleanupJob {
    /// Pending authorizations that expired.
    PendingAuthorizations(PendingAuthorizationCleanup),
    /// Records of access tokens that expired.
    AccessTokens(AccessTokenCleanup),
    /// The partitions of the record of decisions, and each tenant's records
    /// past its retention.
    DecisionLog(DecisionLogMaintenance),
    /// Rows of one kind that stopped being useful, past their retention.
    Expired(ExpiredRowCleanup),
}

impl CleanupJob {
    /// The job's name, in metrics and logs.
    const fn name(&self) -> &'static str {
        match self {
            Self::PendingAuthorizations(_) => "pending_authorizations",
            Self::AccessTokens(_) => "access_tokens",
            Self::DecisionLog(_) => "decision_log",
            Self::Expired(job) => job.kind().name(),
        }
    }

    async fn run(&self, now: Timestamp, batch: u32) -> Result<CleanupReport, DomainError> {
        match self {
            Self::PendingAuthorizations(job) => job.run(now, batch).await,
            Self::AccessTokens(job) => job.run(now, batch).await,
            Self::Expired(job) => job.run(now, batch).await,
            Self::DecisionLog(job) => {
                let report = job.run(now, batch).await?;
                if report.created > 0 || report.dropped > 0 {
                    tracing::info!(
                        created = report.created,
                        dropped = report.dropped,
                        "partitions of the record of decisions prepared"
                    );
                }
                Ok(CleanupReport {
                    tenants: report.tenants,
                    removed: report.removed,
                })
            }
        }
    }
}

/// Runs cleanup jobs until asked to stop: a pass of each now, then after
/// every pause. When a pass of any of them removed a full batch somewhere,
/// the next pass follows at once, since more may be waiting.
async fn cleanup_loop(
    jobs: &[CleanupJob],
    batch_size: u32,
    interval: Duration,
    mut stopped: watch::Receiver<bool>,
) {
    let meter = opentelemetry::global::meter("hodor.worker");
    let removed: Counter<u64> = meter
        .u64_counter("hodor.cleanup.removed")
        .with_description("Rows removed by the cleanup jobs, by job")
        .build();
    let passes: Counter<u64> = meter
        .u64_counter("hodor.cleanup.passes")
        .with_description("Passes of the cleanup jobs, by job and outcome")
        .build();

    while !*stopped.borrow() {
        let mut full = false;
        let mut failed = false;
        for cleanup in jobs {
            if *stopped.borrow() {
                return;
            }
            let job = KeyValue::new("job", cleanup.name());
            let now = SystemClock.now();
            match cleanup.run(now, batch_size).await {
                Ok(report) => {
                    passes.add(1, &[job.clone(), KeyValue::new("outcome", "ok")]);
                    removed.add(report.removed, std::slice::from_ref(&job));
                    if report.removed > 0 {
                        tracing::info!(
                            job = cleanup.name(),
                            tenants = report.tenants,
                            removed = report.removed,
                            "expired rows removed"
                        );
                    }
                    // A full batch in every tenant looked at: there may be more.
                    full |= report.tenants > 0
                        && report.removed >= report.tenants * u64::from(batch_size);
                }
                Err(error) => {
                    passes.add(1, &[job.clone(), KeyValue::new("outcome", "error")]);
                    tracing::warn!(
                        job = cleanup.name(),
                        code = error.code(),
                        detail = ?error.detail(),
                        "cleanup pass failed"
                    );
                    failed = true;
                }
            }
        }
        let pause = if failed {
            Some(interval.max(MIN_ERROR_PAUSE))
        } else {
            (!full).then_some(interval)
        };
        if let Some(pause) = pause {
            tokio::select! {
                () = tokio::time::sleep(pause) => {}
                _ = stopped.changed() => {}
            }
        }
    }
}

/// Rotates the tenants' signing keys until asked to stop: now, then after
/// every pause. A pass that looked at as many tenants as it may is
/// followed by another at once, unless a step failed in one of them.
/// Without root keys there is nothing to do.
/// Reads `HODOR_CLEANUP_RETENTION_DAYS`: `kind=days` pairs separated by
/// commas. A kind that is not known, a kind given twice, or a number of
/// days that is not a whole number stops the worker from starting.
fn cleanup_retentions(setting: &str) -> Result<HashMap<ExpiredKind, u32>, String> {
    let mut retentions = HashMap::new();
    for pair in setting
        .split(',')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
    {
        let (kind, days) = pair.split_once('=').ok_or_else(|| {
            format!("HODOR_CLEANUP_RETENTION_DAYS: `{pair}` is not written as kind=days")
        })?;
        let kind = kind.trim();
        if matches!(kind, "pending_authorizations" | "access_tokens") {
            return Err(format!(
                "HODOR_CLEANUP_RETENTION_DAYS: the retention of `{kind}` is fixed at 0"
            ));
        }
        let kind: ExpiredKind = kind
            .parse()
            .map_err(|error| format!("HODOR_CLEANUP_RETENTION_DAYS: {error}"))?;
        let days = days.trim();
        let days: u32 = days
            .parse()
            .ok()
            .filter(|_| days.bytes().all(|byte| byte.is_ascii_digit()))
            .filter(|days| *days <= 3650)
            .ok_or_else(|| {
                format!(
                    "HODOR_CLEANUP_RETENTION_DAYS: `{days}` is not a whole number of days from 0 to 3650"
                )
            })?;
        if retentions.insert(kind, days).is_some() {
            return Err(format!(
                "HODOR_CLEANUP_RETENTION_DAYS: `{kind}` is given more than once"
            ));
        }
    }
    Ok(retentions)
}

/// The policy lifecycle over the application role's database.
fn policy_service(database: &Database) -> PolicyService {
    let bundles = BundleService::new(
        Arc::new(PgInstanceStore::new(database.clone())),
        Arc::new(PgBundleStore),
        Arc::new(PgInstanceStatusStore),
        Arc::new(PgUploadedDecisionStore),
        Arc::new(database.clone()),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    );
    PolicyService::new(
        Arc::new(PgPolicyVersionStore),
        Arc::new(PgPublicationStore),
        Arc::new(PgSimulationStore),
        bundles,
        Arc::new(database.clone()),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
    )
}

/// Runs the policy check job until asked to stop: now, then after every
/// pause; at once again after a pass that may have left work waiting.
async fn policy_check_loop(
    job: Option<&PolicyCheckJob>,
    interval: Duration,
    mut stopped: watch::Receiver<bool>,
) {
    let Some(job) = job else {
        return;
    };
    let meter = opentelemetry::global::meter("hodor.worker");
    let passes: Counter<u64> = meter
        .u64_counter("hodor.policy.check.passes")
        .with_description("Passes of the policy check job, by outcome")
        .build();
    let done: Counter<u64> = meter
        .u64_counter("hodor.policy.check.done")
        .with_description("Policy versions checked or tested, and simulations run")
        .build();

    while !*stopped.borrow() {
        let pause = match job.run().await {
            Ok(pass) if pass.skipped => {
                passes.add(1, &[KeyValue::new("outcome", "skipped")]);
                Some(interval)
            }
            Ok(pass) => {
                passes.add(1, &[KeyValue::new("outcome", "ok")]);
                done.add(pass.versions, &[KeyValue::new("kind", "version")]);
                done.add(pass.simulations, &[KeyValue::new("kind", "simulation")]);
                if pass.versions + pass.simulations > 0 {
                    tracing::info!(
                        tenants = pass.tenants,
                        versions = pass.versions,
                        simulations = pass.simulations,
                        "policy versions checked"
                    );
                }
                for (tenant, error) in &pass.failures {
                    tracing::warn!(
                        %tenant,
                        code = error.code(),
                        detail = ?error.detail(),
                        "a policy check could not run in a tenant"
                    );
                }
                (!pass.full || !pass.failures.is_empty()).then_some(interval)
            }
            Err(error) => {
                passes.add(1, &[KeyValue::new("outcome", "error")]);
                tracing::warn!(code = error.code(), detail = ?error.detail(), "policy check pass failed");
                Some(interval.max(MIN_ERROR_PAUSE))
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

async fn rotation_loop(
    rotation: Option<&KeyRotationJob>,
    interval: Duration,
    mut stopped: watch::Receiver<bool>,
) {
    let Some(rotation) = rotation else {
        return;
    };
    let meter = opentelemetry::global::meter("hodor.worker");
    let passes: Counter<u64> = meter
        .u64_counter("hodor.keys.rotation.passes")
        .with_description("Passes of the key rotation job, by outcome")
        .build();
    let changes: Counter<u64> = meter
        .u64_counter("hodor.keys.rotation.changes")
        .with_description("Key versions made, activated and retired by rotation")
        .build();

    while !*stopped.borrow() {
        let pause = match rotation.run(SystemClock.now()).await {
            Ok(pass) if pass.skipped => {
                passes.add(1, &[KeyValue::new("outcome", "skipped")]);
                Some(interval)
            }
            Ok(pass) => {
                passes.add(1, &[KeyValue::new("outcome", "ok")]);
                for (change, count) in [
                    ("created", pass.changes.created),
                    ("activated", pass.changes.activated),
                    ("retired", pass.changes.retired),
                ] {
                    changes.add(count, &[KeyValue::new("change", change)]);
                }
                if pass.changes.changed() {
                    tracing::info!(
                        tenants = pass.tenants,
                        created = pass.changes.created,
                        activated = pass.changes.activated,
                        retired = pass.changes.retired,
                        "signing keys rotated"
                    );
                }
                for (tenant, error) in &pass.failures {
                    tracing::warn!(
                        %tenant,
                        code = error.code(),
                        detail = ?error.detail(),
                        "key rotation failed in a tenant"
                    );
                }
                (!pass.was_full() || !pass.failures.is_empty()).then_some(interval)
            }
            Err(error) => {
                passes.add(1, &[KeyValue::new("outcome", "error")]);
                tracing::warn!(code = error.code(), detail = ?error.detail(), "key rotation pass failed");
                Some(interval.max(MIN_ERROR_PAUSE))
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

/// Reads the settings of webhook delivery. A value out of its bounds stops
/// the worker from starting.
fn webhook_settings(config: &Config) -> Result<DeliverySettings, Box<dyn Error>> {
    let first_wait = i64::try_from(config.webhook_first_retry_ms)
        .map(time::Duration::milliseconds)
        .map_err(|_| "HODOR_WEBHOOK_FIRST_RETRY_MS is too large")?;
    let retry = RetryPolicy::new(config.webhook_max_attempts, first_wait).map_err(|_| {
        "HODOR_WEBHOOK_MAX_ATTEMPTS is 1 to 20, and HODOR_WEBHOOK_FIRST_RETRY_MS more than 0 and at most an hour"
    })?;
    if !(1..=30).contains(&config.webhook_time_limit_seconds) {
        return Err("HODOR_WEBHOOK_TIME_LIMIT_SECONDS is 1 to 30".into());
    }
    if !(1..=32).contains(&config.webhook_in_flight_per_endpoint) {
        return Err("HODOR_WEBHOOK_IN_FLIGHT_PER_ENDPOINT is 1 to 32".into());
    }
    if !(1..=256).contains(&config.webhook_concurrency) {
        return Err("HODOR_WEBHOOK_CONCURRENCY is 1 to 256".into());
    }
    Ok(DeliverySettings {
        retry,
        time_limit: Duration::from_secs(config.webhook_time_limit_seconds),
        in_flight_per_endpoint: config.webhook_in_flight_per_endpoint,
    })
}

/// What sends webhooks: the guarded outbound client with the time limit of
/// an attempt and a small limit on answers, and the secret box that opens
/// the endpoints' secrets with the same root keys as the server.
fn webhook_sender(
    development_hosts: Vec<String>,
    database: &Database,
    platform: &PgPool,
    root: &Arc<SecretKeys>,
    settings: DeliverySettings,
) -> Result<WebhookSender, Box<dyn Error>> {
    let http = GuardedHttpClient::new(OutboundPolicy {
        timeout: settings.time_limit,
        connect_timeout: settings.time_limit.min(Duration::from_secs(5)),
        max_response_bytes: 64 * 1024,
        development_hosts,
    })?;
    let secrets = TenantSecretBox::new(
        Arc::new(database.clone()),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root.clone())),
        Arc::new(PgSealingStateStore),
        Some(root.clone()),
        Arc::new(SystemClock),
    );
    Ok(WebhookSender::new(
        SenderPorts {
            units_of_work: Arc::new(database.clone()),
            endpoints: Arc::new(PgEndpointStore),
            deliveries: Arc::new(PgDeliveryStore),
            due: Arc::new(PgDueDeliveries::new(platform.clone())),
            secrets: Arc::new(secrets),
            http: Arc::new(http),
            hmac: Arc::new(AwsLcHmacSha256),
            clock: Arc::new(SystemClock),
        },
        settings,
    ))
}

/// What sends deliveries leased from the database: webhooks and logout
/// tokens, each by its own context's use case.
#[async_trait::async_trait]
trait LeasedSends: Send + Sync + 'static {
    /// A delivery leased to this worker.
    type Lease: Send + 'static;

    /// Leases up to `limit` deliveries that are due.
    async fn lease_due(&self, limit: u32) -> Result<Vec<Self::Lease>, DomainError>;

    /// Sends one and records it; answers the outcome's name.
    async fn send_one(&self, lease: Self::Lease) -> Result<&'static str, DomainError>;
}

#[async_trait::async_trait]
impl LeasedSends for WebhookSender {
    type Lease = hodor_webhooks::api::Lease;

    async fn lease_due(&self, limit: u32) -> Result<Vec<Self::Lease>, DomainError> {
        Self::lease_due(self, limit).await
    }

    async fn send_one(&self, lease: Self::Lease) -> Result<&'static str, DomainError> {
        self.send(lease).await.map(|outcome| outcome.as_str())
    }
}

#[async_trait::async_trait]
impl LeasedSends for BackChannelLogoutSender {
    type Lease = hodor_oauth::api::LogoutLease;

    async fn lease_due(&self, limit: u32) -> Result<Vec<Self::Lease>, DomainError> {
        Self::lease_due(self, limit).await
    }

    async fn send_one(&self, lease: Self::Lease) -> Result<&'static str, DomainError> {
        self.send(lease).await.map(|outcome| outcome.as_str())
    }
}

/// The names a sending loop reports under.
struct LoopNames {
    /// The counter of attempts, by outcome.
    attempts: &'static str,
    /// The counter of passes, by outcome.
    passes: &'static str,
    /// What is sent, in logs.
    what: &'static str,
}

const WEBHOOKS: LoopNames = LoopNames {
    attempts: "hodor.webhooks.attempts",
    passes: "hodor.webhooks.passes",
    what: "webhook",
};

const LOGOUT_TOKENS: LoopNames = LoopNames {
    attempts: "hodor.backchannel_logout.attempts",
    passes: "hodor.backchannel_logout.passes",
    what: "logout token",
};

/// Counts what one send did, and says what went wrong.
fn finished(
    done: Result<Result<&'static str, DomainError>, tokio::task::JoinError>,
    names: &LoopNames,
    attempts: &Counter<u64>,
    passes: &Counter<u64>,
) {
    match done {
        Ok(Ok(outcome)) => {
            attempts.add(1, &[KeyValue::new("outcome", outcome)]);
            if outcome == "set_aside" {
                tracing::warn!(
                    what = names.what,
                    "a delivery failed for the last time and was set aside"
                );
            } else if outcome == "skipped" {
                // The request was made, but the delivery had changed since
                // it was leased, so what the endpoint answered is not kept.
                tracing::warn!(
                    what = names.what,
                    "an attempt was made but not recorded: the delivery was no longer as it was leased"
                );
            }
        }
        Ok(Err(error)) => {
            passes.add(1, &[KeyValue::new("outcome", "error")]);
            tracing::warn!(what = names.what, code = error.code(), detail = ?error.detail(), "an attempt could not be recorded");
        }
        Err(error) => {
            passes.add(1, &[KeyValue::new("outcome", "error")]);
            tracing::warn!(what = names.what, %error, "an attempt stopped");
        }
    }
}

/// Sends deliveries until asked to stop, many at once and each on its own:
/// while there is room, it leases what is due and starts sending it; when
/// nothing is due or there is no room, it waits for a send to finish, the
/// poll interval, or the stop. A send that takes long holds only its own
/// place. On stop, the sends under way finish, each within its time limit.
/// Without a sender there is nothing to do.
async fn sending_loop<S: LeasedSends>(
    sender: Option<Arc<S>>,
    names: &LoopNames,
    concurrency: usize,
    poll_interval: Duration,
    mut stopped: watch::Receiver<bool>,
) {
    let Some(sender) = sender else {
        return;
    };
    let meter = opentelemetry::global::meter("hodor.worker");
    let attempts: Counter<u64> = meter
        .u64_counter(names.attempts)
        .with_description("Delivery attempts, by outcome")
        .build();
    let passes: Counter<u64> = meter
        .u64_counter(names.passes)
        .with_description("Passes of the delivery loop, by outcome")
        .build();

    let mut running = JoinSet::new();
    while !*stopped.borrow() {
        while let Some(done) = running.try_join_next() {
            finished(done, names, &attempts, &passes);
        }
        let room = concurrency.saturating_sub(running.len());
        let mut leased = 0;
        let mut failed = false;
        if room > 0 {
            match sender
                .lease_due(u32::try_from(room).unwrap_or(u32::MAX))
                .await
            {
                Ok(leases) => {
                    passes.add(1, &[KeyValue::new("outcome", "ok")]);
                    leased = leases.len();
                    for lease in leases {
                        let sender = sender.clone();
                        running.spawn(async move { sender.send_one(lease).await });
                    }
                }
                Err(error) => {
                    passes.add(1, &[KeyValue::new("outcome", "error")]);
                    tracing::warn!(what = names.what, code = error.code(), detail = ?error.detail(), "delivery pass failed");
                    failed = true;
                }
            }
        }
        if leased == 0 || running.len() >= concurrency {
            let pause = if failed {
                poll_interval.max(MIN_ERROR_PAUSE)
            } else {
                poll_interval
            };
            tokio::select! {
                Some(done) = running.join_next(), if !running.is_empty() && !failed => {
                    finished(done, names, &attempts, &passes);
                }
                () = tokio::time::sleep(pause) => {}
                _ = stopped.changed() => {}
            }
        }
    }
    while let Some(done) = running.join_next().await {
        finished(done, names, &attempts, &passes);
    }
}

/// Reads the settings of back-channel logout. A value out of its bounds
/// stops the worker from starting.
fn backchannel_logout_settings(config: &Config) -> Result<LogoutDeliverySettings, Box<dyn Error>> {
    let first_wait = i64::try_from(config.backchannel_logout_first_retry_ms)
        .map(time::Duration::milliseconds)
        .map_err(|_| "HODOR_BACKCHANNEL_LOGOUT_FIRST_RETRY_MS is too large")?;
    let retry = LogoutRetryPolicy::new(config.backchannel_logout_max_attempts, first_wait)
        .map_err(|_| {
            "HODOR_BACKCHANNEL_LOGOUT_MAX_ATTEMPTS is 1 to 20, and HODOR_BACKCHANNEL_LOGOUT_FIRST_RETRY_MS more than 0 and at most an hour"
        })?;
    if !(1..=30).contains(&config.backchannel_logout_time_limit_seconds) {
        return Err("HODOR_BACKCHANNEL_LOGOUT_TIME_LIMIT_SECONDS is 1 to 30".into());
    }
    Ok(LogoutDeliverySettings {
        retry,
        time_limit: Duration::from_secs(config.backchannel_logout_time_limit_seconds),
        ..LogoutDeliverySettings::default()
    })
}

/// The issuer of a tenant, as the server names it: the public address and
/// the tenant's slug, read through the tenant context.
struct TenantIssuers {
    tenants: TenantService,
    public_url: String,
}

#[async_trait::async_trait]
impl TenantIssuer for TenantIssuers {
    async fn issuer(&self, tenant: &TenantContext) -> Result<String, DomainError> {
        let found = self.tenants.get(tenant).await?;
        Ok(format!(
            "{}/t/{}",
            self.public_url.trim_end_matches('/'),
            found.snapshot().slug.as_str()
        ))
    }
}

/// What sends logout tokens: the guarded outbound client with the time
/// limit of an attempt and a small limit on answers, and the tenants' keys
/// opened with the same root keys as the server.
fn logout_sender(
    development_hosts: Vec<String>,
    database: &Database,
    platform: &PgPool,
    root: &Arc<SecretKeys>,
    public_url: &str,
    settings: LogoutDeliverySettings,
) -> Result<BackChannelLogoutSender, Box<dyn Error>> {
    let http = GuardedHttpClient::new(OutboundPolicy {
        timeout: settings.time_limit,
        connect_timeout: settings.time_limit.min(Duration::from_secs(5)),
        max_response_bytes: 64 * 1024,
        development_hosts,
    })?;
    let keys = KeyService::new(
        Arc::new(database.clone()),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root.clone())),
        Arc::new(SystemClock),
    );
    let tenants = TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    );
    Ok(BackChannelLogoutSender::new(
        LogoutSenderPorts {
            units_of_work: Arc::new(database.clone()),
            clients: Arc::new(PgClientStore),
            deliveries: Arc::new(PgLogoutDeliveryStore),
            due: Arc::new(PgDueLogoutDeliveries::new(platform.clone())),
            issuers: Arc::new(TenantIssuers {
                tenants,
                public_url: public_url.to_owned(),
            }),
            keys,
            http: Arc::new(http),
            random: Arc::new(OsRandom),
            clock: Arc::new(SystemClock),
        },
        settings,
    )
    // A pairwise client is told of the person and the session as it knows
    // them, with the tenant's pairwise secret, opened with the same root
    // keys as the server's.
    .with_pairwise_subjects(PairwiseSubjects::new(PairwisePorts {
        units_of_work: Arc::new(database.clone()),
        secrets: Arc::new(PgPairwiseSecretStore),
        secret_box: Arc::new(TenantSecretBox::new(
            Arc::new(database.clone()),
            Arc::new(PgKeyStore),
            Arc::new(LocalKeyProvider::new(root.clone())),
            Arc::new(PgSealingStateStore),
            Some(root.clone()),
            Arc::new(SystemClock),
        )),
        mac: Arc::new(AwsLcHmacSha256),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    })))
}

/// Sets up the mail server, if one is configured.
fn mail_sender(
    smtp_url: Option<String>,
    mail_from: Option<&str>,
) -> Result<Option<SmtpSender>, Box<dyn Error>> {
    let Some(url) = smtp_url else {
        return Ok(None);
    };
    let from = mail_from.ok_or("HODOR_MAIL_FROM is required when HODOR_SMTP_URL is set")?;
    Ok(Some(SmtpSender::new(&Secret::from(url), from)?))
}

/// Delivers queued messages until asked to stop. Without a mail server
/// there is nothing to do.
///
/// Paced like [`dispatch_loop`]: a pass that did work is followed by
/// another at once, unless every message in it is now waiting to be tried
/// again; an empty pass and a storage error are followed by a pause.
async fn delivery_loop(
    delivery: Option<&DeliveryService>,
    batch_size: u32,
    poll_interval: Duration,
    mut stopped: watch::Receiver<bool>,
) {
    let Some(delivery) = delivery else {
        return;
    };
    let meter = opentelemetry::global::meter("hodor.worker");
    let messages: Counter<u64> = meter
        .u64_counter("hodor.notification.messages")
        .with_description("Messages handled, by outcome")
        .build();
    let passes: Counter<u64> = meter
        .u64_counter("hodor.notification.passes")
        .with_description("Message delivery passes, by outcome")
        .build();

    while !*stopped.borrow() {
        let pause = match delivery.deliver_pending(batch_size).await {
            Ok(report) => {
                passes.add(1, &[KeyValue::new("outcome", "ok")]);
                for (outcome, count) in [
                    ("sent", report.sent),
                    ("retrying", report.retrying),
                    ("failed", report.failed),
                    ("expired", report.expired),
                ] {
                    messages.add(count as u64, &[KeyValue::new("outcome", outcome)]);
                }
                if report.retrying + report.failed > 0 {
                    tracing::warn!(
                        retrying = report.retrying,
                        failed = report.failed,
                        "message deliveries failed"
                    );
                }
                // Messages waiting for their next try are not due, so a
                // pass that only failed would otherwise spin.
                (report.sent + report.expired == 0).then_some(poll_interval)
            }
            Err(error) => {
                passes.add(1, &[KeyValue::new("outcome", "error")]);
                tracing::warn!(code = error.code(), detail = ?error.detail(), "message delivery pass failed");
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

#[cfg(test)]
mod cleanup_retention_tests {
    use super::*;

    #[test]
    fn retentions_are_read_as_kind_and_days() {
        let retentions = cleanup_retentions(" sessions=30, messages = 90 ,").expect("read");
        assert_eq!(retentions.get(&ExpiredKind::Sessions), Some(&30));
        assert_eq!(retentions.get(&ExpiredKind::Messages), Some(&90));
        assert_eq!(retentions.len(), 2);
        assert!(cleanup_retentions("").expect("nothing").is_empty());
    }

    #[test]
    fn a_retention_that_cannot_be_used_stops_the_worker() {
        for setting in [
            "sessions",
            "sessions=",
            "sessions=-1",
            "sessions=+1",
            "sessions=1.5",
            "sessions=3651",
            "audit=1",
            "sessions=1,sessions=2",
            "pending_authorizations=1",
            "access_tokens=0",
        ] {
            assert!(
                cleanup_retentions(setting).is_err(),
                "{setting} was accepted"
            );
        }
    }
}
