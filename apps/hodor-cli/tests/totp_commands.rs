//! The commands about authenticator applications and the second factor
//! policy, run as the real binary against a real database.

use hodor_adapters_crypto::{AwsLcHmacSha1, OsRandom, SecretKeys};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_credential::api::totp_code_at;
use hodor_credential::testing::base32_secret;
use hodor_kernel::Timestamp;
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
            .env("HODOR_DATABASE_URL", self.database.app_url());
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

const LOGIN: &str = "ana@example.com";

#[tokio::test]
async fn an_operator_enrolls_confirms_and_removes_an_authenticator_application() {
    let database = TestDatabase::start().await;
    let tool = Tool {
        database: &database,
        keys: Some(format!("test:{}", SecretKeys::generate(&OsRandom).expose())),
    };
    assert!(
        tool.run(&["tenant", "create", "--slug", "acme", "--name", "Acme Inc"])
            .status
            .success()
    );
    // The first administrator is a person of the tenant to enroll.
    let made = tool.run(&["admin", "bootstrap", "--tenant", "acme", "--email", LOGIN]);
    assert!(made.status.success(), "{made:?}");

    let enrolled = tool.run(&["totp", "enroll", "--tenant", "acme", "--login", LOGIN]);
    assert!(enrolled.status.success(), "{enrolled:?}");
    let said = text(&enrolled.stdout);
    let mut lines = said.lines();
    let secret = lines
        .next()
        .and_then(|line| line.strip_prefix("secret "))
        .expect("the secret")
        .to_owned();
    let address = lines
        .next()
        .and_then(|line| line.strip_prefix("address "))
        .expect("the address");
    assert!(
        address.starts_with("otpauth://totp/Acme%20Inc:ana%40example.com?secret="),
        "{address}"
    );
    let secret = base32_secret(&secret);

    // Only the sealed secret is stored.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT sealed_secret FROM credential.totp")
        .fetch_one(database.owner())
        .await
        .expect("stored");
    assert!(
        !stored
            .windows(secret.len())
            .any(|window| window == secret.as_slice())
    );

    let wrong = tool.run(&[
        "totp", "confirm", "--tenant", "acme", "--login", LOGIN, "--code", "abcdef",
    ]);
    assert!(!wrong.status.success());
    assert!(
        text(&wrong.stderr).contains("credential.totp_code_wrong"),
        "{wrong:?}"
    );

    let code = totp_code_at(&AwsLcHmacSha1, &secret, Timestamp::now_utc());
    let confirmed = tool.run(&[
        "totp", "confirm", "--tenant", "acme", "--login", LOGIN, "--code", &code,
    ]);
    assert!(confirmed.status.success(), "{confirmed:?}");
    let said = text(&confirmed.stdout);
    let mut lines = said.lines();
    assert_eq!(lines.next(), Some("confirmed"));
    assert_eq!(
        lines.next(),
        Some("recovery codes, shown once: 10"),
        "a first second factor comes with recovery codes"
    );
    assert_eq!(lines.count(), 10);
    let again = tool.run(&[
        "totp", "confirm", "--tenant", "acme", "--login", LOGIN, "--code", &code,
    ]);
    assert!(
        text(&again.stderr).contains("credential.totp_enrollment_not_found"),
        "{again:?}"
    );

    let removed = tool.run(&["totp", "remove", "--tenant", "acme", "--login", LOGIN]);
    assert_eq!(text(&removed.stdout), "removed");
    let removed = tool.run(&["totp", "remove", "--tenant", "acme", "--login", LOGIN]);
    assert_eq!(text(&removed.stdout), "nothing to remove");

    let events: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM platform.outbox WHERE event_type LIKE 'credential.totp%'
         ORDER BY occurred_at, event_type",
    )
    .fetch_all(database.owner())
    .await
    .expect("events");
    assert_eq!(
        events,
        ["credential.totp_enrolled", "credential.totp_removed"]
    );
}

#[tokio::test]
async fn the_commands_need_the_keys_a_known_tenant_and_a_known_person() {
    let database = TestDatabase::start().await;
    let without_keys = Tool {
        database: &database,
        keys: None,
    };
    let refused = without_keys.run(&["totp", "enroll", "--tenant", "acme", "--login", LOGIN]);
    assert!(
        text(&refused.stderr).contains("secret.keys_missing"),
        "{refused:?}"
    );

    let tool = Tool {
        database: &database,
        keys: Some(format!("test:{}", SecretKeys::generate(&OsRandom).expose())),
    };
    let refused = tool.run(&["totp", "enroll", "--tenant", "nowhere", "--login", LOGIN]);
    assert!(
        text(&refused.stderr).contains("tenant.not_found"),
        "{refused:?}"
    );
    assert!(
        tool.run(&["tenant", "create", "--slug", "acme", "--name", "Acme"])
            .status
            .success()
    );
    let refused = tool.run(&["totp", "enroll", "--tenant", "acme", "--login", LOGIN]);
    assert!(
        text(&refused.stderr).contains("identity.user_not_found"),
        "{refused:?}"
    );
}

#[tokio::test]
async fn an_operator_turns_the_second_factor_policy_on_and_off() {
    let database = TestDatabase::start().await;
    let tool = Tool {
        database: &database,
        keys: None,
    };
    assert!(
        tool.run(&["tenant", "create", "--slug", "acme", "--name", "Acme"])
            .status
            .success()
    );
    let policy = async || -> String {
        sqlx::query_scalar(
            "SELECT settings #>> '{authentication,second_factor}' FROM tenant.tenant",
        )
        .fetch_one(database.owner())
        .await
        .expect("settings")
    };

    let on = tool.run(&[
        "tenant",
        "second-factor",
        "--slug",
        "acme",
        "--policy",
        "required",
    ]);
    assert_eq!(text(&on.stdout), "acme second-factor required", "{on:?}");
    assert_eq!(policy().await, "required");
    let off = tool.run(&[
        "tenant",
        "second-factor",
        "--slug",
        "acme",
        "--policy",
        "not-required",
    ]);
    assert_eq!(
        text(&off.stdout),
        "acme second-factor not-required",
        "{off:?}"
    );
    assert_eq!(policy().await, "not_required");
}
