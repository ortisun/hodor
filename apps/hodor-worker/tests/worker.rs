//! The worker binary, run as a real process against a real database.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{
    Actor, CorrelationId, DomainEvent, EventEnvelope, EventMetadata, TenantContext, TenantId,
    Timestamp, UnitOfWorkFactory,
};
use serde::Serialize;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

#[derive(Serialize)]
struct SomethingHappened;

impl DomainEvent for SomethingHappened {
    fn event_type(&self) -> &'static str {
        "test.something_happened"
    }
}

async fn record_events(database: &TestDatabase, tenant: &TenantContext, count: usize) {
    let clock = FixedClock::at(Timestamp::UNIX_EPOCH);
    let mut uow = UnitOfWorkFactory::begin(database.app(), tenant)
        .await
        .expect("begin");
    for _ in 0..count {
        let metadata = EventMetadata::new(
            tenant.tenant_id(),
            Actor::System,
            CorrelationId::generate(),
            &clock,
        );
        uow.record_event(EventEnvelope::new(metadata, &SomethingHappened).expect("event"));
    }
    uow.commit().await.expect("commit");
}

async fn pending(database: &TestDatabase) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM platform.outbox WHERE dispatched_at IS NULL")
        .fetch_one(database.owner())
        .await
        .expect("count")
}

fn start_worker(database: &TestDatabase) -> Child {
    worker_command(database)
        .spawn()
        .expect("worker should start")
}

fn worker_command(database: &TestDatabase) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hodor-worker"));
    command
        .env_remove("HODOR_SMTP_URL")
        .env_remove("HODOR_MAIL_FROM")
        .env("HODOR_DATABASE_URL", database.app_url())
        .env("HODOR_PLATFORM_DATABASE_URL", database.platform_url())
        .env("HODOR_OPS_ADDR", "127.0.0.1:0")
        .env("HODOR_OUTBOX_POLL_INTERVAL_MS", "50")
        .env("HODOR_LOG_FORMAT", "pretty")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn terminate(worker: &Child) {
    let status = Command::new("kill")
        .args(["-TERM", &worker.id().to_string()])
        .status()
        .expect("kill should run");
    assert!(status.success(), "sending SIGTERM failed");
}

#[tokio::test]
async fn a_running_worker_delivers_events_and_stops_cleanly() {
    let database = TestDatabase::start().await;
    let a = TenantContext::assume(TenantId::generate());
    let b = TenantContext::assume(TenantId::generate());
    record_events(&database, &a, 3).await;

    let mut worker = start_worker(&database);

    // Events that were waiting, and events that arrive while it runs, are
    // delivered, across tenants.
    record_events(&database, &b, 2).await;
    let mut remaining = pending(&database).await;
    for _ in 0..100 {
        if remaining == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        remaining = pending(&database).await;
    }
    assert_eq!(remaining, 0, "the worker should deliver every event");

    // Each event became one audit record, in its own tenant's chain.
    let chains: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT count(*), max(sequence) FROM audit.record GROUP BY tenant_id ORDER BY 1",
    )
    .fetch_all(database.owner())
    .await
    .expect("read");
    assert_eq!(chains, [(2, 2), (3, 3)]);

    terminate(&worker);
    let status = tokio::task::spawn_blocking(move || worker.wait())
        .await
        .expect("wait task")
        .expect("worker exit status");
    assert!(
        status.success(),
        "the worker should exit with code 0: {status}"
    );
}

async fn stop(mut worker: Child) {
    terminate(&worker);
    let status = tokio::task::spawn_blocking(move || worker.wait())
        .await
        .expect("wait task")
        .expect("worker exit status");
    assert!(
        status.success(),
        "the worker should exit with code 0: {status}"
    );
}

/// What the development mail server has received, read through its own
/// interface.
async fn received(api: &str) -> Option<Vec<serde_json::Value>> {
    let response = reqwest::get(format!("{api}/messages")).await.ok()?;
    let text = response.error_for_status().ok()?.text().await.ok()?;
    let list: serde_json::Value = serde_json::from_str(&text).ok()?;
    list["messages"].as_array().cloned()
}

#[tokio::test]
async fn a_running_worker_delivers_queued_messages_to_the_mail_server() {
    use hodor_adapters_postgres::PgMessageQueue;
    use hodor_notification::api::MessageQueue;
    use hodor_notification::testing::verification_message;
    use testcontainers::core::IntoContainerPort as _;
    use testcontainers::runners::AsyncRunner as _;

    let mail = testcontainers::GenericImage::new("axllent/mailpit", "v1.27")
        .with_exposed_port(1025.tcp())
        .with_exposed_port(8025.tcp())
        .start()
        .await
        .expect("start the mail server");
    let smtp_port = mail.get_host_port_ipv4(1025).await.expect("port");
    let api = format!(
        "http://127.0.0.1:{}/api/v1",
        mail.get_host_port_ipv4(8025).await.expect("port")
    );
    for _ in 0..100 {
        if received(&api).await.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let database = TestDatabase::start().await;
    // A real moment: the worker uses the real clock, and the message must
    // not have expired.
    let now = Timestamp::now_utc().replace_nanosecond(0).expect("valid");
    let mut queued = Vec::new();
    for recipient in ["first@example.com", "second@example.com"] {
        let tenant = TenantContext::assume(TenantId::generate());
        let message = verification_message(recipient, now);
        let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
            .await
            .expect("begin");
        PgMessageQueue
            .insert(uow.as_mut(), &message)
            .await
            .expect("insert");
        uow.commit().await.expect("commit");
        queued.push(message.id().as_uuid());
    }

    let worker = worker_command(&database)
        .env("HODOR_SMTP_URL", format!("smtp://127.0.0.1:{smtp_port}"))
        .env("HODOR_MAIL_FROM", "Hodor <no-reply@example.com>")
        .env("HODOR_MAIL_POLL_INTERVAL_MS", "50")
        .spawn()
        .expect("worker should start");

    let mut arrived = Vec::new();
    for _ in 0..100 {
        arrived = received(&api).await.unwrap_or_default();
        if arrived.len() >= queued.len() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut recipients: Vec<&str> = arrived
        .iter()
        .filter_map(|message| message["To"][0]["Address"].as_str())
        .collect();
    recipients.sort_unstable();
    assert_eq!(recipients, ["first@example.com", "second@example.com"]);
    assert_eq!(arrived[0]["From"]["Address"], "no-reply@example.com");

    // Each message is recorded as sent, with its contents erased.
    let mut stored: Vec<(String, String)> = Vec::new();
    for _ in 0..50 {
        stored = sqlx::query_as("SELECT status, variables::text FROM notification.message")
            .fetch_all(database.owner())
            .await
            .expect("read");
        if stored.iter().all(|(status, _)| status == "sent") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        stored,
        vec![("sent".to_owned(), "{}".to_owned()); queued.len()]
    );

    stop(worker).await;
}

#[tokio::test]
async fn without_a_mail_server_messages_wait_and_the_worker_still_runs() {
    use hodor_adapters_postgres::PgMessageQueue;
    use hodor_notification::api::MessageQueue;
    use hodor_notification::testing::verification_message;

    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let now = Timestamp::now_utc().replace_nanosecond(0).expect("valid");
    let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    PgMessageQueue
        .insert(
            uow.as_mut(),
            &verification_message("person@example.com", now),
        )
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
    record_events(&database, &tenant, 1).await;

    let worker = start_worker(&database);

    // The outbox is still served.
    let mut remaining = pending(&database).await;
    for _ in 0..100 {
        if remaining == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        remaining = pending(&database).await;
    }
    assert_eq!(remaining, 0);
    let status: String = sqlx::query_scalar("SELECT status FROM notification.message")
        .fetch_one(database.owner())
        .await
        .expect("read");
    assert_eq!(status, "pending");

    stop(worker).await;
}

#[test]
fn a_mail_server_without_a_sender_address_is_refused_at_start() {
    let output = Command::new(env!("CARGO_BIN_EXE_hodor-worker"))
        .env_remove("HODOR_MAIL_FROM")
        .env("HODOR_DATABASE_URL", "postgres://unused@127.0.0.1:1/unused")
        .env(
            "HODOR_PLATFORM_DATABASE_URL",
            "postgres://unused@127.0.0.1:1/unused",
        )
        .env("HODOR_SMTP_URL", "smtp://user:hunter2@127.0.0.1:1")
        .output()
        .expect("worker should run");
    assert!(!output.status.success());
    let shown = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(shown.contains("HODOR_MAIL_FROM"), "{shown}");
    assert!(!shown.contains("hunter2"), "{shown}");
}
