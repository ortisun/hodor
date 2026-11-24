//! The commands for service accounts and agents, run as the real binary
//! against a real database.

use hodor_adapters_postgres::testing::TestDatabase;
use std::process::{Command, Output};

fn run(database: &TestDatabase, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(arguments)
        .env("HODOR_DATABASE_URL", database.app_url())
        .output()
        .expect("the command-line tool should run")
}

fn said(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn refused(output: &Output, code: &str) {
    assert!(!output.status.success(), "refused");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(code), "{error}");
}

/// The word of a line at `position`.
fn word(output: &Output, position: usize) -> String {
    said(output)
        .split_whitespace()
        .nth(position)
        .expect("a word")
        .to_owned()
}

#[tokio::test]
async fn service_accounts_and_agents_are_managed_from_the_command_line() {
    let database = TestDatabase::start().await;
    said(&run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    ));
    said(&run(
        &database,
        &[
            "admin",
            "bootstrap",
            "--tenant",
            "acme",
            "--email",
            "ana@example.com",
        ],
    ));
    let (ana,): (sqlx::types::Uuid,) = sqlx::query_as(
        "SELECT user_id FROM identity.user_identifier WHERE value_normalized = 'ana@example.com'",
    )
    .fetch_one(database.owner())
    .await
    .expect("the person");
    let ana = ana.to_string();

    let export = word(
        &run(
            &database,
            &[
                "service-account",
                "create",
                "--tenant",
                "acme",
                "--name",
                "Nightly export",
                "--owner",
                &ana,
            ],
        ),
        1,
    );
    let listed = said(&run(
        &database,
        &["service-account", "list", "--tenant", "acme"],
    ));
    assert_eq!(listed, format!("{export} active Nightly export"));
    let agents = said(&run(&database, &["agent", "list", "--tenant", "acme"]));
    assert!(agents.is_empty(), "{agents}");
    refused(
        &run(
            &database,
            &["agent", "disable", "--tenant", "acme", "--id", &export],
        ),
        "identity.workload_not_found",
    );
    refused(
        &run(
            &database,
            &[
                "agent", "create", "--tenant", "acme", "--name", "Helper", "--owner", &export,
            ],
        ),
        "identity.workload_owner_invalid",
    );

    // A client is bound to it; a person is refused as a principal.
    let application = word(
        &run(
            &database,
            &[
                "application",
                "add",
                "--tenant",
                "acme",
                "--name",
                "Billing",
                "--first-party",
            ],
        ),
        1,
    );
    let client = run(
        &database,
        &[
            "client",
            "add",
            "--tenant",
            "acme",
            "--application",
            &application,
            "--name",
            "Export",
            "--type",
            "confidential",
            "--grant",
            "client_credentials",
            "--principal",
            &export,
        ],
    );
    said(&client);
    let (principal,): (Option<sqlx::types::Uuid>,) =
        sqlx::query_as("SELECT principal_id FROM oauth.client")
            .fetch_one(database.owner())
            .await
            .expect("the client");
    assert_eq!(principal.map(|id| id.to_string()), Some(export.clone()));
    refused(
        &run(
            &database,
            &[
                "client",
                "add",
                "--tenant",
                "acme",
                "--application",
                &application,
                "--name",
                "Person",
                "--type",
                "confidential",
                "--grant",
                "client_credentials",
                "--principal",
                &ana,
            ],
        ),
        "oauth.client_principal_invalid",
    );

    assert_eq!(
        said(&run(
            &database,
            &[
                "service-account",
                "disable",
                "--tenant",
                "acme",
                "--id",
                &export
            ],
        )),
        format!("disabled {export}")
    );
    assert_eq!(
        said(&run(
            &database,
            &[
                "service-account",
                "enable",
                "--tenant",
                "acme",
                "--id",
                &export
            ],
        )),
        format!("active {export}")
    );
    said(&run(
        &database,
        &[
            "service-account",
            "delete",
            "--tenant",
            "acme",
            "--id",
            &export,
        ],
    ));
    let listed = said(&run(
        &database,
        &["service-account", "list", "--tenant", "acme"],
    ));
    assert!(listed.is_empty(), "a deleted one is not listed: {listed}");
    // What the commands did is waiting to be audited, with Hodor itself as
    // the actor.
    let events: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM platform.outbox
         WHERE event_type LIKE 'identity.%' ORDER BY created_at",
    )
    .fetch_all(database.owner())
    .await
    .expect("the outbox");
    for expected in [
        "identity.workload_owner_added",
        "identity.user_deactivated",
        "identity.user_restored",
        "identity.user_deleted",
    ] {
        assert!(events.iter().any(|event| event == expected), "{events:?}");
    }
}
