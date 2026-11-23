//! The commands about Open Policy Agent instances and their bundles, run
//! as the real binary against a real database.

use hodor_adapters_postgres::testing::TestDatabase;
use std::process::{Command, Output};

fn run(database: &TestDatabase, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(["policy-agent"])
        .args(arguments)
        .env("HODOR_DATABASE_URL", database.app_url())
        .env_remove("HODOR_OPEN_POLICY_AGENT_SIGNING_KEY_FILE")
        .env_remove("HODOR_OPEN_POLICY_AGENT_SIGNING_KEY_ID")
        .output()
        .expect("the command-line tool should run")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

#[tokio::test]
async fn an_operator_registers_an_instance_and_publishes_a_signed_bundle() {
    let database = TestDatabase::start().await;
    let made = Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(["tenant", "create", "--slug", "acme", "--name", "Acme Inc"])
        .env("HODOR_DATABASE_URL", database.app_url())
        .output()
        .expect("tenant");
    assert!(made.status.success(), "{made:?}");

    // The key: a private key in PKCS #8 and its public key, and no
    // database needed.
    let key = Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(["policy-agent", "signing-key"])
        .env_remove("HODOR_DATABASE_URL")
        .output()
        .expect("key");
    assert!(key.status.success(), "{key:?}");
    let key = text(&key.stdout);
    assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(key.contains("-----BEGIN PUBLIC KEY-----"));
    let directory = std::env::temp_dir().join(format!("hodor-bundle-{}", std::process::id()));
    let files = directory.join("files");
    std::fs::create_dir_all(&files).expect("directory");
    let key_file = directory.join("signing.pem");
    let private = &key[..key.find("-----BEGIN PUBLIC KEY-----").expect("public")];
    std::fs::write(&key_file, private).expect("key file");

    // An instance of the tenant's own, its credential shown once.
    let added = run(
        &database,
        &[
            "instance",
            "add",
            "--name",
            "acme-policy",
            "--tenant",
            "acme",
        ],
    );
    assert!(added.status.success(), "{added:?}");
    let said = text(&added.stdout);
    let credential = said.lines().nth(1).expect("credential");
    assert!(credential.starts_with("hodor_pa_"), "{said}");
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT credential_digest FROM platform.policy_agent_instance")
            .fetch_one(database.owner())
            .await
            .expect("stored");
    assert_eq!(stored.len(), 32, "only a digest is kept");
    let again = run(&database, &["instance", "add", "--name", "acme-policy"]);
    assert!(!again.status.success(), "a name is taken once");

    // The names to write a policy with.
    let name = run(&database, &["bundle-name", "--tenant", "acme"]);
    let name = text(&name.stdout);
    assert!(name.starts_with('t') && name.len() == 33, "{name}");
    let package = run(
        &database,
        &[
            "bundle-name",
            "--tenant",
            "acme",
            "--namespace",
            "https://documents.example.com",
        ],
    );
    let package = text(&package.stdout);
    assert!(
        package.starts_with(&format!("hodor.tenants.{name}.resource_servers.r")),
        "{package}"
    );

    // Publishing checks the files: a module outside the tenant is refused.
    std::fs::write(
        files.join("other.rego"),
        "package hodor.tenants.someone_else\n",
    )
    .expect("file");
    let refused = run(
        &database,
        &[
            "publish",
            "--tenant",
            "acme",
            "--directory",
            files.to_str().expect("path"),
            "--signing-key-file",
            key_file.to_str().expect("path"),
        ],
    );
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("authorization.bundle_file_invalid"),
        "{refused:?}"
    );
    std::fs::remove_file(files.join("other.rego")).expect("remove");

    let below = package.split('.').skip(3).collect::<Vec<_>>().join("/");
    std::fs::create_dir_all(files.join(&below)).expect("directory");
    std::fs::write(
        files.join(&below).join("policy.rego"),
        format!("package {package}\n\ndecision := {{\"allow\": true}}\n"),
    )
    .expect("policy");
    for expected in ["1", "2"] {
        let published = run(
            &database,
            &[
                "publish",
                "--tenant",
                "acme",
                "--directory",
                files.to_str().expect("path"),
                "--written-by",
                "operator",
                "--signing-key-file",
                key_file.to_str().expect("path"),
            ],
        );
        assert!(published.status.success(), "{published:?}");
        assert!(text(&published.stdout).starts_with(&format!("{expected}\t\"")));
    }
    let kept: Vec<(i64, String)> = sqlx::query_as(
        "SELECT revision, written_by FROM \"authorization\".policy_bundle ORDER BY revision",
    )
    .fetch_all(database.owner())
    .await
    .expect("bundles");
    assert_eq!(
        kept,
        vec![(1, "operator".to_owned()), (2, "operator".to_owned())]
    );

    // Listed, then disabled.
    let listed = text(&run(&database, &["instance", "list"]).stdout);
    assert!(
        listed.contains("acme-policy") && listed.contains("enabled"),
        "{listed}"
    );
    assert!(
        run(&database, &["instance", "disable", "--name", "acme-policy"])
            .status
            .success()
    );
    assert!(
        !run(&database, &["instance", "disable", "--name", "acme-policy"])
            .status
            .success()
    );
    let listed = text(&run(&database, &["instance", "list"]).stdout);
    assert!(listed.contains("disabled"), "{listed}");
    let status = run(&database, &["status", "--tenant", "acme"]);
    assert!(status.status.success(), "{status:?}");
    std::fs::remove_dir_all(&directory).expect("clean up");
}
