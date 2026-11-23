//! The commands about Open Policy Agent instances and their bundles, run
//! as the real binary against a real database.

use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgBundleStore, PgInstanceStatusStore, PgInstanceStore, PgPolicyVersionStore,
    PgPublicationStore, PgSimulationStore, PgUploadedDecisionStore, PolicyCheckJob,
};
use hodor_authorization_opa::api::{BundleService, PolicyService};
use hodor_authorization_opa::testing::FakeChecker;
use hodor_kernel::SystemClock;
use std::process::{Command, Output};
use std::sync::Arc;

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

fn policy(database: &TestDatabase, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(["policy"])
        .args(arguments)
        .env("HODOR_DATABASE_URL", database.app_url())
        .env_remove("HODOR_OPEN_POLICY_AGENT_SIGNING_KEY_FILE")
        .env_remove("HODOR_OPEN_POLICY_AGENT_SIGNING_KEY_ID")
        .output()
        .expect("the command-line tool should run")
}

/// The worker's policy check job, with a checker that stands in for `opa`.
fn worker(database: &TestDatabase) -> PolicyCheckJob {
    let bundles = BundleService::new(
        Arc::new(PgInstanceStore::new(database.app().clone())),
        Arc::new(PgBundleStore),
        Arc::new(PgInstanceStatusStore),
        Arc::new(PgUploadedDecisionStore),
        Arc::new(database.app().clone()),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    );
    let policies = PolicyService::new(
        Arc::new(PgPolicyVersionStore),
        Arc::new(PgPublicationStore),
        Arc::new(PgSimulationStore),
        bundles,
        Arc::new(database.app().clone()),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
    );
    PolicyCheckJob::new(
        database.platform().clone(),
        policies,
        Arc::new(FakeChecker::default()),
    )
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

#[tokio::test]
async fn an_operator_registers_an_instance_and_publishes_a_tested_policy() {
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

    // Drafting checks the files: a module outside the tenant is refused.
    std::fs::write(
        files.join("other.rego"),
        "package hodor.tenants.someone_else\n",
    )
    .expect("file");
    let refused = policy(
        &database,
        &[
            "draft",
            "--tenant",
            "acme",
            "--directory",
            files.to_str().expect("path"),
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
    let drafted = policy(
        &database,
        &[
            "draft",
            "--tenant",
            "acme",
            "--directory",
            files.to_str().expect("path"),
            "--written-by",
            "operator",
        ],
    );
    assert!(drafted.status.success(), "{drafted:?}");
    assert!(text(&drafted.stdout).starts_with("1\t"), "{drafted:?}");

    // Only a tested version is published; the worker checks and tests.
    let early = policy(
        &database,
        &[
            "publish",
            "--tenant",
            "acme",
            "--version",
            "1",
            "--signing-key-file",
            key_file.to_str().expect("path"),
        ],
    );
    assert!(!early.status.success());
    assert!(
        text(&early.stderr).contains("authorization.policy_version_state"),
        "{early:?}"
    );
    let job = worker(&database);
    for step in ["validate", "test"] {
        let asked = policy(
            &database,
            &[step, "--tenant", "acme", "--version", "1", "--wait", "0"],
        );
        assert!(asked.status.success(), "{asked:?}");
        job.run().await.expect("the worker's pass");
        let shown = policy(&database, &["show", "--tenant", "acme", "--version", "1"]);
        assert!(
            text(&shown.stdout).starts_with(&format!(
                "1\t{}",
                if step == "validate" {
                    "validated"
                } else {
                    "tested"
                }
            )),
            "{shown:?}"
        );
    }
    for expected in ["1", "2"] {
        let published = policy(
            &database,
            &[
                "publish",
                "--tenant",
                "acme",
                "--version",
                "1",
                "--signing-key-file",
                key_file.to_str().expect("path"),
            ],
        );
        assert!(published.status.success(), "{published:?}");
        assert!(
            text(&published.stdout).starts_with(&format!("{expected}\t1\t\"")),
            "{published:?}"
        );
    }
    let rolled_back = policy(
        &database,
        &[
            "rollback",
            "--tenant",
            "acme",
            "--revision",
            "1",
            "--signing-key-file",
            key_file.to_str().expect("path"),
        ],
    );
    assert!(rolled_back.status.success(), "{rolled_back:?}");
    assert!(
        text(&rolled_back.stdout).starts_with("3\t1\t"),
        "{rolled_back:?}"
    );
    let kept: Vec<(i64, String)> = sqlx::query_as(
        "SELECT revision, written_by FROM \"authorization\".policy_bundle ORDER BY revision",
    )
    .fetch_all(database.owner())
    .await
    .expect("bundles");
    assert_eq!(
        kept,
        vec![
            (1, "operator".to_owned()),
            (2, "operator".to_owned()),
            (3, "operator".to_owned())
        ]
    );
    let status = text(&policy(&database, &["status", "--tenant", "acme"]).stdout);
    assert!(status.starts_with("revision 3\toperator\t"), "{status}");
    assert!(status.contains("version 1"), "{status}");
    let versions = text(&policy(&database, &["versions", "--tenant", "acme"]).stdout);
    assert!(versions.starts_with("1\ttested\toperator\t"), "{versions}");

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
