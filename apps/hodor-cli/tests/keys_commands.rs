//! The keys commands, run as the real binary against a real database.

use hodor_adapters_crypto::{OsRandom, SecretKeys};
use hodor_adapters_postgres::testing::TestDatabase;
use std::process::{Command, Output};

struct Tool<'a> {
    database: &'a TestDatabase,
    keys: Option<String>,
}

impl Tool<'_> {
    fn run(&self, arguments: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hodor-cli"));
        command
            .args(arguments)
            .env("HODOR_DATABASE_URL", self.database.app_url())
            .env_remove("HODOR_KEY_OVERLAP_HOURS");
        match &self.keys {
            Some(keys) => command.env("HODOR_SECRET_KEYS", keys),
            None => command.env_remove("HODOR_SECRET_KEYS"),
        };
        command.output().expect("the command-line tool should run")
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

/// The identifier and the state of each line of `keys list`.
fn listed(output: &Output) -> Vec<(String, String)> {
    text(&output.stdout)
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            (fields[0].to_owned(), fields[2].to_owned())
        })
        .collect()
}

#[tokio::test]
async fn an_operator_rotates_lists_and_revokes_a_tenants_signing_keys() {
    let database = TestDatabase::start().await;
    let tool = Tool {
        database: &database,
        keys: Some(format!("test:{}", SecretKeys::generate(&OsRandom).expose())),
    };
    let created = tool.run(&["tenant", "create", "--slug", "acme", "--name", "Acme"]);
    assert!(created.status.success(), "{created:?}");

    let empty = tool.run(&["keys", "list", "--tenant", "acme"]);
    assert!(empty.status.success(), "{empty:?}");
    assert_eq!(text(&empty.stdout), "");

    let first = tool.run(&["keys", "rotate", "--tenant", "acme"]);
    assert!(first.status.success(), "{first:?}");
    let said = text(&first.stdout);
    assert!(said.contains(" ES256 active created "), "{said}");
    let first_id = said.split(' ').next().expect("identifier").to_owned();

    let second = tool.run(&["keys", "rotate", "--tenant", "acme", "--algorithm", "es256"]);
    assert!(second.status.success(), "{second:?}");
    let second_id = text(&second.stdout)
        .split(' ')
        .next()
        .expect("identifier")
        .to_owned();

    let both = tool.run(&["keys", "list", "--tenant", "acme"]);
    assert_eq!(
        listed(&both),
        vec![
            (second_id.clone(), "active".to_owned()),
            (first_id.clone(), "retiring".to_owned()),
        ]
    );
    assert!(text(&both.stdout).contains(" retire-after "));

    let revoked = tool.run(&[
        "keys",
        "revoke",
        "--tenant",
        "acme",
        "--version",
        &first_id,
        "--reason",
        "the laptop was stolen",
    ]);
    assert!(revoked.status.success(), "{revoked:?}");
    assert!(text(&revoked.stdout).ends_with(" the laptop was stolen"));
    assert_eq!(
        listed(&tool.run(&["keys", "list", "--tenant", "acme"])),
        vec![
            (second_id, "active".to_owned()),
            (first_id, "revoked".to_owned()),
        ]
    );

    // Nothing of a key is written in the clear: what is stored opens only
    // with the root key.
    let material: Vec<Vec<u8>> = sqlx::query_scalar("SELECT key_material FROM keys.key_version")
        .fetch_all(database.owner())
        .await
        .expect("read");
    for bytes in material {
        assert!(!bytes.windows(4).any(|window| window == b"\x30\x81\x87\x02"));
    }
}

#[tokio::test]
async fn what_the_keys_commands_refuse_is_said_with_its_code() {
    let database = TestDatabase::start().await;
    let with = Tool {
        database: &database,
        keys: Some(format!("test:{}", SecretKeys::generate(&OsRandom).expose())),
    };
    let created = with.run(&["tenant", "create", "--slug", "acme", "--name", "Acme"]);
    assert!(created.status.success(), "{created:?}");

    let cases: [(&Tool<'_>, Vec<&str>, &str); 4] = [
        (
            &Tool {
                database: &database,
                keys: None,
            },
            vec!["keys", "list", "--tenant", "acme"],
            "secret.keys_missing",
        ),
        (
            &with,
            vec!["keys", "list", "--tenant", "globex"],
            "tenant.not_found",
        ),
        (
            &with,
            vec![
                "keys",
                "revoke",
                "--tenant",
                "acme",
                "--version",
                "0193f1c2-0000-7000-8000-000000000000",
                "--reason",
                "unknown",
            ],
            "keys.version_not_found",
        ),
        (
            &with,
            vec![
                "keys",
                "rotate",
                "--tenant",
                "acme",
                "--key-overlap-hours",
                "0",
            ],
            "keys.rotation_policy_invalid",
        ),
    ];
    for (tool, arguments, code) in cases {
        let output = tool.run(&arguments);
        assert!(!output.status.success(), "{arguments:?}");
        let shown = text(&output.stderr);
        assert!(shown.contains(code), "{arguments:?}: {shown}");
    }
}
