//! Background jobs composition root.
//!
//! The worker delivers outbox events to their handlers, of which the audit
//! log is the first, delivers queued messages to the mail server, runs the
//! cleanup jobs and rotates the tenants' signing keys. See
//! `docs/operations/deployment.md`, "The worker".

use clap::{Parser, ValueEnum};
use hodor_adapters_crypto::{LocalKeyProvider, SecretKeys, Sha256Digest};
use hodor_adapters_postgres::{
    AccessTokenCleanup, CleanupReport, Database, KeyRotationJob, OutboxDispatcher,
    PendingAuthorizationCleanup, PgAuditLog, PgKeyStore, PgMessageQueue, PgPendingMessages, PgPool,
    connect_pool, ping_pool,
};
use hodor_adapters_smtp::SmtpSender;
use hodor_audit::api::{AuditHandler, AuditService};
use hodor_kernel::{Clock as _, DomainError, Secret, SystemClock, Timestamp};
use hodor_keys::api::{KeyService, RotationPolicy};
use hodor_notification::api::DeliveryService;
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
    let mail_sender = mail_sender(config.smtp_url, config.mail_from.as_deref())?;
    let rotation_policy = RotationPolicy::new(
        time::Duration::days(config.key_rotation_days),
        time::Duration::hours(config.key_publication_hours),
        time::Duration::hours(config.key_overlap_hours),
    )?;
    let root_keys = config
        .secret_keys
        .map(|setting| SecretKeys::parse(&Secret::from(setting)))
        .transpose()?;

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
    let rotation = root_keys.map(|root| {
        let keys = KeyService::new(
            Arc::new(database.clone()),
            Arc::new(PgKeyStore),
            Arc::new(LocalKeyProvider::new(Arc::new(root))),
            Arc::new(SystemClock),
        );
        KeyRotationJob::new(platform.clone(), keys, rotation_policy)
    });
    if rotation.is_none() {
        tracing::warn!("HODOR_SECRET_KEYS is not set: keys do not rotate and no tenant gets one");
    }
    let dispatcher =
        OutboxDispatcher::new(platform, database, vec![Arc::new(AuditHandler::new(audit))]);

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
        cleanup_loop(
            &pending_cleanup,
            config.cleanup_batch_size,
            Duration::from_millis(config.cleanup_interval_ms),
            stopped.clone(),
        ),
        cleanup_loop(
            &access_token_cleanup,
            config.cleanup_batch_size,
            Duration::from_millis(config.cleanup_interval_ms),
            stopped.clone(),
        ),
        rotation_loop(
            rotation.as_ref(),
            Duration::from_millis(config.key_rotation_interval_ms),
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
}

impl CleanupJob {
    /// The job's name, in metrics and logs.
    const fn name(&self) -> &'static str {
        match self {
            Self::PendingAuthorizations(_) => "pending_authorizations",
            Self::AccessTokens(_) => "access_tokens",
        }
    }

    async fn run(&self, now: Timestamp, batch: u32) -> Result<CleanupReport, DomainError> {
        match self {
            Self::PendingAuthorizations(job) => job.run(now, batch).await,
            Self::AccessTokens(job) => job.run(now, batch).await,
        }
    }
}

/// Runs a cleanup job until asked to stop: now, then after every pause. A
/// pass that removed a full batch somewhere is followed by another at once,
/// since more may be waiting.
async fn cleanup_loop(
    cleanup: &CleanupJob,
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
    let job = KeyValue::new("job", cleanup.name());

    while !*stopped.borrow() {
        let now = SystemClock.now();
        let pause = match cleanup.run(now, batch_size).await {
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
                let full =
                    report.tenants > 0 && report.removed >= report.tenants * u64::from(batch_size);
                (!full).then_some(interval)
            }
            Err(error) => {
                passes.add(1, &[job.clone(), KeyValue::new("outcome", "error")]);
                tracing::warn!(
                    job = cleanup.name(),
                    code = error.code(),
                    detail = ?error.detail(),
                    "cleanup pass failed"
                );
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

/// Rotates the tenants' signing keys until asked to stop: now, then after
/// every pause. A pass that looked at as many tenants as it may is
/// followed by another at once, unless a step failed in one of them.
/// Without root keys there is nothing to do.
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
