//! The commands for applications, clients and resource servers, run as
//! the real binary against a real database.

use hodor_adapters_postgres::testing::TestDatabase;
use std::process::{Command, Output};

fn run(database: &TestDatabase, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(arguments)
        .env("HODOR_DATABASE_URL", database.app_url())
        .output()
        .expect("the command-line tool should run")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

/// What a command printed after `prefix ` on its first line that has it.
fn value(output: &Output, prefix: &str) -> String {
    text(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{prefix} ")))
        .unwrap_or_else(|| panic!("no `{prefix}` in {output:?}"))
        .split(' ')
        .next()
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn an_operator_registers_an_application_with_a_client_and_a_resource_server() {
    let database = TestDatabase::start().await;
    let created = run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    );
    assert!(created.status.success(), "{created:?}");

    let added = run(
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
    );
    assert!(added.status.success(), "{added:?}");
    let application = value(&added, "application");
    let listed = run(&database, &["application", "list", "--tenant", "acme"]);
    assert_eq!(
        text(&listed.stdout),
        format!("{application} enabled first-party Billing")
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
            "Billing web site",
            "--type",
            "confidential",
            "--grant",
            "authorization_code",
            "--grant",
            "refresh_token",
            "--redirect-uri",
            "https://billing.example.com/callback",
            "--scope",
            "openid",
        ],
    );
    assert!(client.status.success(), "{client:?}");
    let client_id = value(&client, "client");
    let first = value(&client, "secret");
    assert!(first.starts_with("hodor_cs_"), "{client:?}");
    assert!(text(&client.stdout).contains("\nexpires "));

    let clients = run(
        &database,
        &[
            "client",
            "list",
            "--tenant",
            "acme",
            "--application",
            &application,
        ],
    );
    assert_eq!(
        text(&clients.stdout),
        format!("{client_id} enabled confidential client_secret_basic Billing web site")
    );
    // The list never shows a secret.
    assert!(!text(&clients.stdout).contains(&first));

    let rotated = run(
        &database,
        &[
            "client",
            "rotate-secret",
            "--tenant",
            "acme",
            "--id",
            &client_id,
            "--keep-previous-days",
            "0",
        ],
    );
    assert!(rotated.status.success(), "{rotated:?}");
    let second = value(&rotated, "secret");
    assert!(second.starts_with("hodor_cs_"));
    assert_ne!(first, second);

    let disabled = run(
        &database,
        &["client", "disable", "--tenant", "acme", "--id", &client_id],
    );
    assert_eq!(
        text(&disabled.stdout),
        format!("client {client_id} disabled")
    );

    let server = run(
        &database,
        &[
            "resource-server",
            "add",
            "--tenant",
            "acme",
            "--application",
            &application,
            "--audience",
            "https://api.billing.example.com",
            "--name",
            "Billing interface",
            "--scope",
            "invoices:read=Read your invoices",
            "--scope",
            "invoices:write",
        ],
    );
    assert!(server.status.success(), "{server:?}");
    let servers = run(&database, &["resource-server", "list", "--tenant", "acme"]);
    assert!(
        text(&servers.stdout).ends_with(
            "https://api.billing.example.com Billing interface [invoices:read invoices:write]"
        ),
        "{servers:?}"
    );

    let disabled = run(
        &database,
        &[
            "application",
            "disable",
            "--tenant",
            "acme",
            "--id",
            &application,
        ],
    );
    assert_eq!(
        text(&disabled.stdout),
        format!("application {application} disabled")
    );
}

#[tokio::test]
async fn what_the_oauth_context_refuses_the_tool_refuses_with_the_same_code() {
    let database = TestDatabase::start().await;
    let created = run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    );
    assert!(created.status.success(), "{created:?}");
    let added = run(
        &database,
        &[
            "application",
            "add",
            "--tenant",
            "acme",
            "--name",
            "Billing",
        ],
    );
    let application = value(&added, "application");
    // Third party unless said.
    let listed = run(&database, &["application", "list", "--tenant", "acme"]);
    assert!(text(&listed.stdout).contains(" third-party "));

    let public_with_a_secret = run(
        &database,
        &[
            "client",
            "add",
            "--tenant",
            "acme",
            "--application",
            &application,
            "--name",
            "Mobile",
            "--type",
            "public",
            "--grant",
            "authorization_code",
            "--redirect-uri",
            "com.example.billing:/callback",
            "--method",
            "client_secret_post",
        ],
    );
    assert!(!public_with_a_secret.status.success());
    assert!(
        text(&public_with_a_secret.stderr).contains("oauth.client_authentication_method_invalid"),
        "{public_with_a_secret:?}"
    );

    let unknown_tenant = run(&database, &["application", "list", "--tenant", "nowhere"]);
    assert!(!unknown_tenant.status.success());
    assert!(text(&unknown_tenant.stderr).contains("tenant.not_found"));

    let unknown_client = run(
        &database,
        &[
            "client",
            "enable",
            "--tenant",
            "acme",
            "--id",
            "not-a-client",
        ],
    );
    assert!(!unknown_client.status.success());
    assert!(text(&unknown_client.stderr).contains("oauth.client_not_found"));
}
