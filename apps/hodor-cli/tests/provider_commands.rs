//! The provider commands, run as the real binary against a real database.

use hodor_adapters_crypto::{OsRandom, SecretKeys};
use hodor_adapters_postgres::testing::TestDatabase;
use std::process::{Command, Output};

const CLIENT_SECRET: &str = "the-client-secret-of-the-provider";

struct Tool<'a> {
    database: &'a TestDatabase,
    keys: String,
}

impl Tool<'_> {
    fn run(&self, arguments: &[&str], client_secret: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hodor-cli"));
        command
            .args(arguments)
            .env("HODOR_DATABASE_URL", self.database.app_url())
            .env("HODOR_SECRET_KEYS", &self.keys)
            .env("HODOR_PUBLIC_URL", "https://auth.example")
            .env_remove("HODOR_PROVIDER_CLIENT_SECRET");
        if let Some(secret) = client_secret {
            command.env("HODOR_PROVIDER_CLIENT_SECRET", secret);
        }
        command.output().expect("the command-line tool should run")
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

const ADD: [&str; 12] = [
    "provider",
    "add",
    "--tenant",
    "acme",
    "--alias",
    "example",
    "--name",
    "Example",
    "--issuer",
    "https://accounts.example.com",
    "--client-id",
    "hodor",
];

#[tokio::test]
async fn an_operator_adds_lists_disables_and_enables_a_provider() {
    let database = TestDatabase::start().await;
    let tool = Tool {
        database: &database,
        keys: format!("test:{}", SecretKeys::generate(&OsRandom).expose()),
    };
    let created = tool.run(
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
        None,
    );
    assert!(created.status.success(), "{created:?}");

    let added = tool.run(&ADD, Some(CLIENT_SECRET));
    assert!(added.status.success(), "{added:?}");
    let said = text(&added.stdout);
    assert!(
        said.starts_with("created example enabled https://accounts.example.com "),
        "{said}"
    );
    assert!(
        said.contains("register this address at the provider: https://auth.example/t/acme/account/providers/example/callback"),
        "{said}"
    );
    // The secret is said nowhere, and stored nowhere in the clear.
    assert!(!said.contains(CLIENT_SECRET));
    let stored: String = sqlx::query_scalar(
        "SELECT string_agg(to_jsonb(t)::text || encode(t.client_secret, 'escape'), '')
         FROM federation.identity_provider t",
    )
    .fetch_one(database.owner())
    .await
    .expect("dump");
    assert!(stored.contains("accounts.example.com"));
    assert!(!stored.contains(CLIENT_SECRET));

    let listed = tool.run(&["provider", "list", "--tenant", "acme"], None);
    assert_eq!(
        text(&listed.stdout),
        "example enabled https://accounts.example.com https://auth.example/t/acme/account/providers/example/callback"
    );

    let disabled = tool.run(
        &[
            "provider", "disable", "--tenant", "acme", "--alias", "example",
        ],
        None,
    );
    assert!(
        text(&disabled.stdout).starts_with("example disabled "),
        "{disabled:?}"
    );
    let enabled = tool.run(
        &[
            "provider", "enable", "--tenant", "acme", "--alias", "example",
        ],
        None,
    );
    assert!(
        text(&enabled.stdout).starts_with("example enabled "),
        "{enabled:?}"
    );
}

#[tokio::test]
async fn what_cannot_be_done_is_refused_with_its_reason() {
    let database = TestDatabase::start().await;
    let tool = Tool {
        database: &database,
        keys: format!("test:{}", SecretKeys::generate(&OsRandom).expose()),
    };
    tool.run(
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
        None,
    );

    // No secret in the environment.
    let refused = tool.run(&ADD, None);
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("HODOR_PROVIDER_CLIENT_SECRET"),
        "{refused:?}"
    );

    // A tenant that does not exist, an alias nobody has, a taken alias.
    let mut elsewhere = ADD;
    elsewhere[3] = "nobody";
    let refused = tool.run(&elsewhere, Some(CLIENT_SECRET));
    assert!(!refused.status.success());
    let refused = tool.run(
        &[
            "provider", "disable", "--tenant", "acme", "--alias", "missing",
        ],
        None,
    );
    assert!(
        text(&refused.stderr).contains("federation.provider_not_found"),
        "{refused:?}"
    );
    assert!(tool.run(&ADD, Some(CLIENT_SECRET)).status.success());
    let again = tool.run(&ADD, Some(CLIENT_SECRET));
    assert!(
        text(&again.stderr).contains("federation.alias_taken"),
        "{again:?}"
    );

    // Without the keys nothing is added.
    let without_keys = Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(["provider", "list", "--tenant", "acme"])
        .env("HODOR_DATABASE_URL", database.app_url())
        .env_remove("HODOR_SECRET_KEYS")
        .output()
        .expect("the command-line tool should run");
    assert!(!without_keys.status.success());
    assert!(
        text(&without_keys.stderr).contains("HODOR_SECRET_KEYS"),
        "{without_keys:?}"
    );
}

#[tokio::test]
async fn an_operator_adds_a_directory_on_the_list_and_no_other() {
    let database = TestDatabase::start().await;
    let tool = Tool {
        database: &database,
        keys: format!("test:{}", SecretKeys::generate(&OsRandom).expose()),
    };
    tool.run(
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
        None,
    );
    let add = |issuer: &'static str| {
        [
            "provider",
            "add",
            "--tenant",
            "acme",
            "--alias",
            "company",
            "--kind",
            "ldap",
            "--name",
            "Company",
            "--issuer",
            issuer,
            "--client-id",
            "cn=hodor,ou=services,dc=example,dc=com",
            "--base",
            "ou=people,dc=example,dc=com",
            "--filter",
            "(uid={identifier})",
        ]
    };
    let run = |arguments: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
            .args(arguments)
            .env("HODOR_DATABASE_URL", database.app_url())
            .env("HODOR_SECRET_KEYS", &tool.keys)
            .env("HODOR_DIRECTORY_HOSTS", "ldap.example.com:636")
            .env("HODOR_PROVIDER_CLIENT_SECRET", "the bind password")
            .output()
            .expect("the command-line tool should run")
    };

    let refused = run(&add("ldaps://ldap.elsewhere.example"));
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("federation.directory_not_allowed"),
        "{refused:?}"
    );

    let added = run(&add("ldaps://ldap.example.com"));
    assert!(added.status.success(), "{added:?}");
    let said = text(&added.stdout);
    // Nobody leaves for a directory: there is no address to register.
    assert_eq!(said, "created company enabled ldaps://ldap.example.com -");
}
