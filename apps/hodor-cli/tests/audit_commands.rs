//! The audit command, run as the real binary against a real database.

use hodor_adapters_crypto::Sha256Digest;
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{OutboxDispatcher, PgAuditLog};
use hodor_audit::api::{AuditHandler, AuditService};
use hodor_kernel::SystemClock;
use std::process::{Command, Output};
use std::sync::Arc;

fn cli(database: &TestDatabase, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(arguments)
        .env("HODOR_DATABASE_URL", database.app_url())
        .output()
        .expect("the command-line tool should run")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

/// Does the worker's part: turns every waiting event into an audit record.
async fn record_events(database: &TestDatabase) {
    let audit = AuditService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgAuditLog),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
    );
    let dispatcher = OutboxDispatcher::new(
        database.platform().clone(),
        database.app().clone(),
        vec![Arc::new(AuditHandler::new(audit))],
    );
    while dispatcher
        .dispatch_batch(100)
        .await
        .expect("dispatch")
        .delivered
        > 0
    {}
}

#[tokio::test]
async fn an_intact_chain_is_reported_and_a_changed_record_is_found() {
    let database = TestDatabase::start().await;
    let commands: [&[&str]; 3] = [
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
        &["tenant", "suspend", "--slug", "acme", "--reason", "unpaid"],
        &["tenant", "reactivate", "--slug", "acme"],
    ];
    for arguments in commands {
        let output = cli(&database, arguments);
        assert!(output.status.success(), "{}", text(&output.stderr));
    }
    record_events(&database).await;
    let records: i64 = sqlx::query_scalar("SELECT count(*) FROM audit.record")
        .fetch_one(database.owner())
        .await
        .expect("count");
    assert!(records >= 3, "{records} records");

    let intact = cli(&database, &["audit", "verify", "--tenant", "acme"]);
    assert!(intact.status.success(), "{}", text(&intact.stderr));
    assert_eq!(text(&intact.stdout), format!("intact: {records} records"));

    // Someone who owns the table switches its protection off and rewrites
    // why the tenant was suspended.
    for statement in [
        "ALTER TABLE audit.record DISABLE TRIGGER record_is_append_only",
        "UPDATE audit.record SET details = jsonb_set(details, '{reason}', '\"nothing\"')
         WHERE action = 'tenant.suspended'",
        "ALTER TABLE audit.record ENABLE TRIGGER record_is_append_only",
    ] {
        sqlx::query(statement)
            .execute(database.owner())
            .await
            .expect("forced change");
    }
    let changed: i64 =
        sqlx::query_scalar("SELECT sequence FROM audit.record WHERE action = 'tenant.suspended'")
            .fetch_one(database.owner())
            .await
            .expect("sequence");

    let broken = cli(&database, &["audit", "verify", "--tenant", "acme"]);
    assert!(!broken.status.success());
    let message = text(&broken.stderr);
    assert!(
        message.contains(&format!("broken at record {changed}")),
        "{message}"
    );
    assert!(message.contains("it was changed"), "{message}");
}

#[tokio::test]
async fn a_tenant_with_no_records_is_intact_and_an_unknown_tenant_is_an_error() {
    let database = TestDatabase::start().await;
    cli(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    );

    // Nothing has been recorded yet: the worker has not run.
    let empty = cli(&database, &["audit", "verify", "--tenant", "acme"]);
    assert!(empty.status.success(), "{}", text(&empty.stderr));
    assert_eq!(text(&empty.stdout), "intact: 0 records");

    let unknown = cli(&database, &["audit", "verify", "--tenant", "nobody"]);
    assert!(!unknown.status.success());
    assert!(text(&unknown.stderr).contains("tenant.not_found"));
}
