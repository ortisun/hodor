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

#[tokio::test]
async fn a_workloads_api_keys_and_roles_are_managed_from_the_command_line() {
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
    let agent = word(
        &run(
            &database,
            &[
                "agent", "create", "--tenant", "acme", "--name", "Helper", "--owner", &ana,
            ],
        ),
        1,
    );

    let made = said(&run(
        &database,
        &[
            "agent",
            "key",
            "create",
            "--tenant",
            "acme",
            "--id",
            &agent,
            "--name",
            "Reports",
            "--scope",
            "users:read",
        ],
    ));
    let lines: Vec<&str> = made.lines().collect();
    let key_id = lines[0].strip_prefix("key ").expect("the key's identifier");
    let key = lines[1].strip_prefix("api-key ").expect("the key, once");
    assert!(key.starts_with("hodor_ak_") && key.len() == 73, "{made}");
    assert!(lines[2].starts_with("expires "));
    let listed = said(&run(
        &database,
        &["agent", "key", "list", "--tenant", "acme", "--id", &agent],
    ));
    assert_eq!(
        listed,
        format!("{key_id} active {} Reports", &key[key.len() - 4..])
    );
    assert!(!listed.contains(&key[9..]), "never shown again");
    refused(
        &run(
            &database,
            &[
                "agent",
                "key",
                "create",
                "--tenant",
                "acme",
                "--id",
                &agent,
                "--name",
                "x",
                "--scope",
                "users:delete",
            ],
        ),
        "authorization.scope_unknown",
    );

    let rotated = said(&run(
        &database,
        &[
            "agent",
            "key",
            "rotate",
            "--tenant",
            "acme",
            "--id",
            &agent,
            "--key",
            key_id,
            "--keep-previous-days",
            "0",
        ],
    ));
    assert!(rotated.contains("api-key hodor_ak_"), "{rotated}");
    let new_id = rotated
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("key "))
        .expect("the new key")
        .to_owned();
    assert_eq!(
        said(&run(
            &database,
            &[
                "agent", "key", "revoke", "--tenant", "acme", "--id", &agent, "--key", &new_id,
            ],
        )),
        format!("revoked {new_id}")
    );

    // A built-in role is given to the agent, and taken away.
    assert_eq!(
        said(&run(
            &database,
            &[
                "admin",
                "grant",
                "--tenant",
                "acme",
                "--user",
                &agent,
                "--role",
                "tenant_auditor",
            ],
        )),
        format!("granted tenant_auditor {agent}")
    );
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM \"authorization\".role_assignment WHERE principal_id = $1",
    )
    .bind(&agent)
    .fetch_one(database.owner())
    .await
    .expect("assignments");
    assert_eq!(count, 1);
    said(&run(
        &database,
        &[
            "admin",
            "revoke",
            "--tenant",
            "acme",
            "--user",
            &agent,
            "--role",
            "tenant_auditor",
        ],
    ));
    refused(
        &run(
            &database,
            &[
                "admin", "grant", "--tenant", "acme", "--user", &agent, "--role", "owner",
            ],
        ),
        "authorization.unknown_role",
    );
}
