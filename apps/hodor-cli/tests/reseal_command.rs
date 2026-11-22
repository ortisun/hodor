//! `hodor-cli secrets reseal`, run as the real binary against a real
//! database: a secret left by 0.1.0 is sealed again under the tenant's
//! data key, and the tenant then refuses the first format.

use hodor_adapters_crypto::{OsRandom, SecretKeys};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_federation::api::CLIENT_SECRET_PURPOSE;
use hodor_kernel::{Secret, TenantContext, TenantId};
use hodor_keys::api::SEALED_FORMAT;
use std::process::{Command, Output};

fn run(database: &TestDatabase, keys: &str, arguments: &[&str], secret: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hodor-cli"));
    command
        .args(arguments)
        .env("HODOR_DATABASE_URL", database.app_url())
        .env("HODOR_SECRET_KEYS", keys)
        .env("HODOR_PUBLIC_URL", "https://auth.example")
        .env_remove("HODOR_PROVIDER_CLIENT_SECRET");
    if let Some(secret) = secret {
        command.env("HODOR_PROVIDER_CLIENT_SECRET", secret);
    }
    command.output().expect("the command-line tool should run")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

#[tokio::test]
async fn a_secret_of_0_1_0_is_sealed_again_and_the_tenant_then_refuses_the_first_format() {
    let database = TestDatabase::start().await;
    let key = SecretKeys::generate(&OsRandom);
    let setting = format!("test:{}", key.expose());
    let root = SecretKeys::parse(&Secret::new(setting.clone())).expect("root keys");

    let created = run(
        &database,
        &setting,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
        None,
    );
    assert!(created.status.success(), "{created:?}");
    let added = run(
        &database,
        &setting,
        &[
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
        ],
        Some("the-client-secret"),
    );
    assert!(added.status.success(), "{added:?}");

    // Put back the secret as 0.1.0 stored it: sealed directly with the
    // root key.
    let tenant_id: sqlx::types::Uuid =
        sqlx::query_scalar("SELECT id FROM tenant.tenant WHERE slug = 'acme'")
            .fetch_one(database.owner())
            .await
            .expect("tenant");
    let tenant = TenantContext::assume(TenantId::from_uuid(tenant_id));
    let old = root
        .seal(
            &tenant,
            CLIENT_SECRET_PURPOSE,
            &Secret::new(b"the-client-secret".to_vec()),
        )
        .expect("seal as 0.1.0 did");
    sqlx::query("UPDATE federation.identity_provider SET client_secret = $1")
        .bind(old.as_bytes())
        .execute(database.owner())
        .await
        .expect("as 0.1.0 left it");

    let resealed = run(&database, &setting, &["secrets", "reseal"], None);
    assert!(resealed.status.success(), "{resealed:?}");
    assert_eq!(
        text(&resealed.stdout),
        "acme: 1 sealed again, 0 already current, 0 did not open; the first format is refused"
    );
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT client_secret FROM federation.identity_provider")
            .fetch_one(database.owner())
            .await
            .expect("stored");
    assert_eq!(stored[0], SEALED_FORMAT);

    let again = run(
        &database,
        &setting,
        &["secrets", "reseal", "--tenant", "acme"],
        None,
    );
    assert!(again.status.success(), "{again:?}");
    assert_eq!(
        text(&again.stdout),
        "acme: 0 sealed again, 1 already current, 0 did not open; the first format is refused"
    );

    // The provider still works with what was sealed again.
    let listed = run(
        &database,
        &setting,
        &["provider", "list", "--tenant", "acme"],
        None,
    );
    assert!(listed.status.success(), "{listed:?}");
}

#[tokio::test]
async fn a_secret_that_does_not_open_is_left_and_the_command_fails() {
    let database = TestDatabase::start().await;
    let setting = format!("test:{}", SecretKeys::generate(&OsRandom).expose());
    let other = format!("other:{}", SecretKeys::generate(&OsRandom).expose());

    let created = run(
        &database,
        &setting,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
        None,
    );
    assert!(created.status.success(), "{created:?}");
    let added = run(
        &database,
        &setting,
        &[
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
        ],
        Some("the-client-secret"),
    );
    assert!(added.status.success(), "{added:?}");

    // A secret of the first format sealed with a root key this
    // installation no longer has: it does not open, so it is left as it
    // was and the first format is not refused.
    let tenant_id: sqlx::types::Uuid =
        sqlx::query_scalar("SELECT id FROM tenant.tenant WHERE slug = 'acme'")
            .fetch_one(database.owner())
            .await
            .expect("tenant");
    let tenant = TenantContext::assume(TenantId::from_uuid(tenant_id));
    let gone = SecretKeys::parse(&Secret::new(other)).expect("another root key");
    let lost = gone
        .seal(
            &tenant,
            CLIENT_SECRET_PURPOSE,
            &Secret::new(b"the-client-secret".to_vec()),
        )
        .expect("seal");
    sqlx::query("UPDATE federation.identity_provider SET client_secret = $1")
        .bind(lost.as_bytes())
        .execute(database.owner())
        .await
        .expect("a secret that will not open");

    let resealed = run(&database, &setting, &["secrets", "reseal"], None);
    assert!(!resealed.status.success(), "{resealed:?}");
    assert_eq!(
        text(&resealed.stdout),
        "acme: 0 sealed again, 0 already current, 1 did not open; the first format is still accepted"
    );
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT client_secret FROM federation.identity_provider")
            .fetch_one(database.owner())
            .await
            .expect("stored");
    assert_eq!(stored, lost.as_bytes(), "left as it was");
    let refused: i64 = sqlx::query_scalar("SELECT count(*) FROM keys.sealing_state")
        .fetch_one(database.owner())
        .await
        .expect("state");
    assert_eq!(refused, 0);
}
