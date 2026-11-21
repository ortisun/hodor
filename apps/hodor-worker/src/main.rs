//! Background jobs composition root.
//!
//! The worker has two jobs: delivering outbox events to their handlers,
//! of which the audit log is the first, and delivering queued messages to
//! the mail server. See
//! `docs/operations/deployment.md`, "The worker".

use clap::{Parser, ValueEnum};
use hodor_adapters_crypto::Sha256Digest;
use hodor_adapters_postgres::{
    Database, OutboxDispatcher, PgAuditLog, PgMessageQueue, PgPendingMessages, PgPool,
    connect_pool, ping_pool,
};
use hodor_adapters_smtp::SmtpSender;
use hodor_audit::api::{AuditHandler, AuditService};
use hodor_kernel::{Secret, SystemClock};
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
    // settings is reported at once.
    let mail_sender = mail_sender(config.smtp_url, config.mail_from.as_deref())?;

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
            stopped,
        ),
    );

    ops_server.await??;
    tracing::info!("hodor-worker stopped");
    Ok(())
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
