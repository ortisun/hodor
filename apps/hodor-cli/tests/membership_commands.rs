//! The commands for groups and organizations, run as the real binary
//! against a real database.

use hodor_adapters_postgres::testing::TestDatabase;
use std::process::{Command, Output};

fn run(database: &TestDatabase, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(arguments)
        .env("HODOR_DATABASE_URL", database.app_url())
        .env("HODOR_PUBLIC_URL", "https://login.example.com")
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

/// The identifier a `created <id> <name>` line names.
fn created(output: &Output) -> String {
    said(output)
        .split_whitespace()
        .nth(1)
        .expect("an identifier")
        .to_owned()
}

async fn user_of(database: &TestDatabase, email: &str) -> String {
    let (id,): (sqlx::types::Uuid,) =
        sqlx::query_as("SELECT user_id FROM identity.user_identifier WHERE value_normalized = $1")
            .bind(email)
            .fetch_one(database.owner())
            .await
            .expect("the user");
    id.to_string()
}

#[tokio::test]
async fn groups_and_organizations_are_managed_from_the_command_line() {
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
    let ana = user_of(&database, "ana@example.com").await;

    let finance = created(&run(
        &database,
        &["group", "create", "--tenant", "acme", "--name", "finance"],
    ));
    let payables = created(&run(
        &database,
        &["group", "create", "--tenant", "acme", "--name", "payables"],
    ));
    said(&run(
        &database,
        &[
            "group",
            "add",
            "--tenant",
            "acme",
            "--group",
            &finance,
            "--member-group",
            &payables,
        ],
    ));
    said(&run(
        &database,
        &[
            "group", "add", "--tenant", "acme", "--group", &payables, "--user", &ana,
        ],
    ));
    let cycle = run(
        &database,
        &[
            "group",
            "add",
            "--tenant",
            "acme",
            "--group",
            &payables,
            "--member-group",
            &finance,
        ],
    );
    assert!(!cycle.status.success(), "a cycle is refused");
    assert!(String::from_utf8_lossy(&cycle.stderr).contains("identity.group_cycle"));
    let listed = said(&run(&database, &["group", "list", "--tenant", "acme"]));
    assert_eq!(listed.lines().count(), 2, "{listed}");
    said(&run(
        &database,
        &[
            "group", "remove", "--tenant", "acme", "--group", &payables, "--user", &ana,
        ],
    ));
    said(&run(
        &database,
        &["group", "delete", "--tenant", "acme", "--group", &finance],
    ));

    let acme = created(&run(
        &database,
        &[
            "organization",
            "create",
            "--tenant",
            "acme",
            "--name",
            "Acme Rockets",
        ],
    ));
    let engineering = created(&run(
        &database,
        &[
            "organization",
            "unit",
            "--tenant",
            "acme",
            "--organization",
            &acme,
            "--name",
            "Engineering",
        ],
    ));
    let platform = created(&run(
        &database,
        &[
            "organization",
            "unit",
            "--tenant",
            "acme",
            "--organization",
            &acme,
            "--name",
            "Platform",
            "--kind",
            "department",
            "--parent",
            &engineering,
        ],
    ));
    let joined = said(&run(
        &database,
        &[
            "organization",
            "member",
            "--tenant",
            "acme",
            "--organization",
            &acme,
            "--user",
            &ana,
            "--unit",
            &platform,
        ],
    ));
    assert!(joined.ends_with("in 1 units"), "{joined}");
    let moved = said(&run(
        &database,
        &[
            "organization",
            "member",
            "--tenant",
            "acme",
            "--organization",
            &acme,
            "--user",
            &ana,
            "--unit",
            &platform,
            "--unit",
            &engineering,
        ],
    ));
    assert!(moved.ends_with("in 2 units"), "{moved}");
    said(&run(
        &database,
        &[
            "organization",
            "invite",
            "--tenant",
            "acme",
            "--organization",
            &acme,
            "--email",
            "bruno@example.com",
            "--locale",
            "pt-BR",
        ],
    ));

    // The invitation's message waits for a worker, with its link.
    let (link,): (String,) = sqlx::query_as(
        "SELECT variables ->> 'link' FROM notification.message WHERE template = 'organization_invitation'",
    )
    .fetch_one(database.owner())
    .await
    .expect("the message");
    assert!(
        link.starts_with("https://login.example.com/t/acme/account/accept-invitation#token="),
        "{link}"
    );
    let listed = said(&run(
        &database,
        &["organization", "list", "--tenant", "acme"],
    ));
    assert!(listed.ends_with("Acme Rockets"), "{listed}");
}
