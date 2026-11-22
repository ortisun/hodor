//! The commands about recovery codes, run as the real binary against a
//! real database.

use hodor_adapters_crypto::{AwsLcHmacSha1, OsRandom, SecretKeys, Sha256Digest};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_credential::api::totp_code_at;
use hodor_credential::testing::base32_secret;
use hodor_kernel::{Digest as _, Timestamp};
use std::process::{Command, Output};

fn run(database: &TestDatabase, keys: &str, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(arguments)
        .env("HODOR_DATABASE_URL", database.app_url())
        .env("HODOR_SECRET_KEYS", keys)
        .output()
        .expect("the command-line tool should run")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

/// The codes a command printed after its line saying what they are.
fn codes_in(said: &str) -> Vec<String> {
    said.lines()
        .skip_while(|line| !line.starts_with("recovery codes, shown once"))
        .skip(1)
        .map(str::to_owned)
        .collect()
}

const LOGIN: &str = "ana@example.com";
const PERSON: [&str; 4] = ["--tenant", "acme", "--login", LOGIN];

async fn hashes(database: &TestDatabase) -> Vec<Vec<u8>> {
    sqlx::query_scalar("SELECT code_hash FROM credential.recovery_code ORDER BY code_hash")
        .fetch_all(database.owner())
        .await
        .expect("hashes")
}

#[tokio::test]
async fn an_operator_generates_counts_and_removes_recovery_codes() {
    let database = TestDatabase::start().await;
    let keys = format!("test:{}", SecretKeys::generate(&OsRandom).expose());
    let tool = |arguments: &[&str]| run(&database, &keys, arguments);
    assert!(
        tool(&["tenant", "create", "--slug", "acme", "--name", "Acme"])
            .status
            .success()
    );
    let made = tool(&["admin", "bootstrap", "--tenant", "acme", "--email", LOGIN]);
    assert!(made.status.success(), "{made:?}");

    // Confirming a first authenticator application prints a set.
    let enrolled = tool(&[&["totp", "enroll"][..], &PERSON].concat());
    let secret = text(&enrolled.stdout)
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("secret "))
        .map(base32_secret)
        .expect("the secret");
    let code = totp_code_at(&AwsLcHmacSha1, &secret, Timestamp::now_utc());
    let confirmed = tool(&[&["totp", "confirm"][..], &PERSON, &["--code", &code]].concat());
    assert!(confirmed.status.success(), "{confirmed:?}");
    let first = codes_in(&text(&confirmed.stdout));
    assert_eq!(first.len(), 10);
    assert!(
        first
            .iter()
            .all(|code| { code.len() == 19 && code.split('-').all(|group| group.len() == 4) }),
        "{first:?}"
    );

    // Only the hash of each code is stored.
    let stored = hashes(&database).await;
    let mut expected: Vec<Vec<u8>> = first
        .iter()
        .map(|code| {
            Sha256Digest
                .sha256(code.replace('-', "").as_bytes())
                .to_vec()
        })
        .collect();
    expected.sort();
    assert_eq!(stored, expected);

    let count = tool(&[&["recovery-codes", "count"][..], &PERSON].concat());
    assert_eq!(text(&count.stdout), "unused 10", "{count:?}");

    // Generating again replaces the set.
    let generated = tool(&[&["recovery-codes", "generate"][..], &PERSON].concat());
    assert!(generated.status.success(), "{generated:?}");
    let second = codes_in(&text(&generated.stdout));
    assert_eq!(second.len(), 10);
    assert!(second.iter().all(|code| !first.contains(code)));
    assert_eq!(hashes(&database).await.len(), 10, "the earlier set is gone");

    // A person who still has unused codes keeps them when an application
    // is enrolled again.
    tool(&[&["totp", "remove"][..], &PERSON].concat());
    let enrolled = tool(&[&["totp", "enroll"][..], &PERSON].concat());
    let secret = text(&enrolled.stdout)
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("secret "))
        .map(base32_secret)
        .expect("the secret");
    let code = totp_code_at(&AwsLcHmacSha1, &secret, Timestamp::now_utc());
    let confirmed = tool(&[&["totp", "confirm"][..], &PERSON, &["--code", &code]].concat());
    assert_eq!(text(&confirmed.stdout), "confirmed", "{confirmed:?}");

    let removed = tool(&[&["recovery-codes", "remove"][..], &PERSON].concat());
    assert_eq!(text(&removed.stdout), "removed");
    let removed = tool(&[&["recovery-codes", "remove"][..], &PERSON].concat());
    assert_eq!(text(&removed.stdout), "nothing to remove");
    let count = tool(&[&["recovery-codes", "count"][..], &PERSON].concat());
    assert_eq!(text(&count.stdout), "unused 0");

    let events: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM platform.outbox WHERE event_type LIKE 'credential.recovery%'
         ORDER BY occurred_at, event_type",
    )
    .fetch_all(database.owner())
    .await
    .expect("events");
    assert_eq!(
        events,
        [
            "credential.recovery_codes_generated",
            "credential.recovery_codes_generated",
            "credential.recovery_codes_removed"
        ]
    );
}

#[tokio::test]
async fn the_commands_need_a_known_tenant_and_a_known_person() {
    let database = TestDatabase::start().await;
    let keys = format!("test:{}", SecretKeys::generate(&OsRandom).expose());
    let refused = run(
        &database,
        &keys,
        &[
            "recovery-codes",
            "count",
            "--tenant",
            "nowhere",
            "--login",
            LOGIN,
        ],
    );
    assert!(
        text(&refused.stderr).contains("tenant.not_found"),
        "{refused:?}"
    );
    assert!(
        run(
            &database,
            &keys,
            &["tenant", "create", "--slug", "acme", "--name", "Acme"]
        )
        .status
        .success()
    );
    let refused = run(
        &database,
        &keys,
        &[&["recovery-codes", "generate"][..], &PERSON].concat(),
    );
    assert!(
        text(&refused.stderr).contains("identity.user_not_found"),
        "{refused:?}"
    );
}
