//! The checker against the real `opa` 1.10.1 binary: what compiles, what
//! is refused and why, tests, simulations, and the limits of a run.
//!
//! The binary is `HODOR_TEST_OPA_BINARY` when set. Otherwise the release
//! for this machine is downloaded once into Cargo's temporary directory
//! for tests, and used only if its SHA-256 is the one the project
//! publishes.

use hodor_adapters_crypto::Sha256Digest;
use hodor_adapters_policy_check::{OpaProcessChecker, RunLimits};
use hodor_authorization_opa::api::{BundleFile, PolicyChecker as _, tenant_root};
use hodor_kernel::{Digest as _, TenantId};
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;

/// The release binaries of `opa` 1.10.1 and their published SHA-256.
fn release() -> (&'static str, &'static str) {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => (
            "opa_darwin_arm64_static",
            "81ca091b6f8a54f9e9e11204c060e616bf0ea0b01378621f081b3ff13be77f09",
        ),
        ("macos", "x86_64") => (
            "opa_darwin_amd64",
            "06b87b33385cbeabc913604e1d76fcfaac3d96cb1f084db1a456244989ea32b5",
        ),
        ("linux", "x86_64") => (
            "opa_linux_amd64_static",
            "43b1efa7e81425456dbb8d82c0256b6dbe69c934e5c4a1cb71dc65715ac4b35d",
        ),
        ("linux", "aarch64") => (
            "opa_linux_arm64_static",
            "3b77a28ec99dcf7d98ec014ab4773bd1f9ad0340faee7b8ae811cbb8baa9f5bf",
        ),
        other => panic!("no opa release is pinned for {other:?}; set HODOR_TEST_OPA_BINARY"),
    }
}

fn sha256(path: &PathBuf) -> String {
    let bytes = std::fs::read(path).expect("binary");
    hodor_authorization_opa::api::hexadecimal(&Sha256Digest.sha256(&bytes))
}

/// The binary the tests run, and its SHA-256 when it is a pinned release.
/// Found or downloaded once for all the tests of this file.
fn binary() -> (PathBuf, Option<&'static str>) {
    static FOUND: std::sync::OnceLock<(PathBuf, Option<&'static str>)> = std::sync::OnceLock::new();
    FOUND.get_or_init(find).clone()
}

fn find() -> (PathBuf, Option<&'static str>) {
    if let Ok(path) = std::env::var("HODOR_TEST_OPA_BINARY") {
        return (PathBuf::from(path), None);
    }
    let (name, digest) = release();
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("opa-1.10.1-{name}"));
    if !path.exists() || sha256(&path) != digest {
        let partial = path.with_extension(format!("part-{}", std::process::id()));
        let downloaded = std::process::Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--output",
            ])
            .arg(&partial)
            .arg(format!(
                "https://github.com/open-policy-agent/opa/releases/download/v1.10.1/{name}"
            ))
            .status()
            .expect("curl runs");
        assert!(
            downloaded.success(),
            "the opa release could not be downloaded"
        );
        assert_eq!(
            sha256(&partial),
            digest,
            "the download is not the published binary"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o755))
                .expect("executable");
        }
        std::fs::rename(&partial, &path).expect("in place");
    }
    (path, Some(digest))
}

async fn checker(limits: RunLimits) -> OpaProcessChecker {
    let (path, digest) = binary();
    OpaProcessChecker::verified(path, digest, &Sha256Digest, limits, None)
        .await
        .expect("the pinned binary is accepted")
}

fn package(tenant: TenantId) -> String {
    format!("{}.documents", tenant_root(tenant).replace('/', "."))
}

fn file(path: &str, contents: &str) -> BundleFile {
    BundleFile {
        path: path.to_owned(),
        contents: contents.as_bytes().to_vec(),
    }
}

fn policy(tenant: TenantId, body: &str) -> BundleFile {
    file(
        "documents/policy.rego",
        &format!("package {}\n\n{body}\n", package(tenant)),
    )
}

const READS: &str = "default decision := {\"allow\": false}\n\ndecision := {\"allow\": true} if input.action == \"read\"";

#[tokio::test]
async fn a_policy_that_compiles_passes_and_its_problems_are_named_with_their_file() {
    let checker = checker(RunLimits::default()).await;
    let tenant = TenantId::generate();
    let good = checker
        .check(tenant, &[policy(tenant, READS), file("data.json", "{}")])
        .await
        .expect("ran");
    assert!(good.passed(), "{good:?}");

    let reaching = checker
        .check(
            tenant,
            &[policy(
                tenant,
                "decision := {\"allow\": r.status_code == 200} if {\n\tr := http.send({\"method\": \"get\", \"url\": \"https://example.com\"})\n}",
            )],
        )
        .await
        .expect("ran");
    assert!(!reaching.passed());
    assert_eq!(
        reaching.diagnostics[0].file.as_deref(),
        Some("documents/policy.rego"),
        "{reaching:?}"
    );
    assert!(
        reaching.diagnostics[0].message.contains("http.send"),
        "{reaching:?}"
    );

    for refused in [
        "decision := {\"allow\": x}",                       // unsafe variable
        "decision := {\"allow\": true} if { input.a == 1",  // parse error
        "decision := {\"allow\": opa.runtime().env != {}}", // a removed built-in
        "decision := {\"allow\": count(net.lookup_ip_addr(\"example.com\")) > 0}",
    ] {
        let report = checker
            .check(tenant, &[policy(tenant, refused)])
            .await
            .expect("ran");
        assert!(!report.passed(), "{refused}");
    }

    // Strict mode: an unused local is refused.
    let strict = checker
        .check(
            tenant,
            &[policy(
                tenant,
                "decision := {\"allow\": true} if {\n\tunused := 1\n\ttrue\n}",
            )],
        )
        .await
        .expect("ran");
    assert!(!strict.passed(), "strict mode refuses an unused variable");
}

#[tokio::test]
async fn tests_are_run_and_each_reported() {
    let checker = checker(RunLimits::default()).await;
    let tenant = TenantId::generate();
    let tests = file(
        "documents/policy_test.rego",
        &format!(
            "package {}\n\ntest_reading_is_allowed if decision.allow with input as {{\"action\": \"read\"}}\n\ntest_writing_is_allowed if decision.allow with input as {{\"action\": \"write\"}}\n",
            package(tenant)
        ),
    );
    let report = checker
        .test(tenant, &[policy(tenant, READS), tests])
        .await
        .expect("ran");
    assert!(!report.passed());
    let mut outcomes: Vec<(String, bool)> = report
        .tests
        .iter()
        .map(|test| (test.name.clone(), test.passed))
        .collect();
    outcomes.sort();
    assert_eq!(
        outcomes,
        [
            ("test_reading_is_allowed".to_owned(), true),
            ("test_writing_is_allowed".to_owned(), false)
        ]
    );

    let none = checker
        .test(tenant, &[policy(tenant, READS)])
        .await
        .expect("ran");
    assert!(none.passed(), "{none:?}");
    assert!(none.tests.is_empty(), "no test file, no test");

    let broken = checker
        .test(tenant, &[policy(tenant, "decision := {\"allow\": y}")])
        .await
        .expect("ran");
    assert!(
        !broken.passed(),
        "a module that does not compile fails its tests"
    );
}

#[tokio::test]
async fn a_simulation_answers_each_input_and_says_where_the_rule_is_undefined() {
    let checker = checker(RunLimits::default()).await;
    let tenant = TenantId::generate();
    let only_reading = format!(
        "package {}\n\ndecision := {{\"allow\": true, \"reason\": \"reads\"}} if input.action == \"read\"\n",
        package(tenant)
    );
    let answers = checker
        .evaluate(
            tenant,
            &[file("documents/policy.rego", &only_reading)],
            &package(tenant),
            &[
                json!({"action": "read"}),
                json!({"action": "write"}),
                json!({}),
            ],
        )
        .await
        .expect("ran")
        .expect("compiles");
    assert_eq!(
        answers,
        [Some(json!({"allow": true, "reason": "reads"})), None, None]
    );

    let failed = checker
        .evaluate(
            tenant,
            &[policy(tenant, "decision := {\"allow\": z}")],
            &package(tenant),
            &[json!({})],
        )
        .await
        .expect("ran")
        .expect_err("does not compile");
    assert!(!failed.passed());
}

#[tokio::test]
async fn a_run_that_takes_too_long_is_stopped_and_reported() {
    let checker = checker(RunLimits {
        time: Duration::from_millis(1),
        ..RunLimits::default()
    })
    .await;
    let tenant = TenantId::generate();
    let report = checker
        .check(tenant, &[policy(tenant, READS)])
        .await
        .expect("ran");
    assert_eq!(
        report.diagnostics[0].code, "policy_check_timed_out",
        "{report:?}"
    );
}

#[tokio::test]
async fn a_binary_that_is_not_the_pinned_one_is_refused() {
    let (path, _) = binary();
    let wrong = OpaProcessChecker::verified(
        path,
        Some(&"0".repeat(64)),
        &Sha256Digest,
        RunLimits::default(),
        None,
    )
    .await
    .expect_err("another digest");
    assert_eq!(wrong.code(), "authorization.policy_checker_binary_refused");
    let missing = OpaProcessChecker::verified(
        PathBuf::from("/nonexistent/opa"),
        None,
        &Sha256Digest,
        RunLimits::default(),
        None,
    )
    .await
    .expect_err("missing");
    assert_eq!(
        missing.code(),
        "authorization.policy_checker_binary_refused"
    );
    // A program that is not opa 1.10.1.
    let other = OpaProcessChecker::verified(
        PathBuf::from("/bin/echo"),
        None,
        &Sha256Digest,
        RunLimits::default(),
        None,
    )
    .await
    .expect_err("not opa");
    assert_eq!(other.code(), "authorization.policy_checker_binary_refused");
}

#[tokio::test]
async fn a_run_leaves_nothing_behind() {
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("policy-check-scratch-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("scratch");
    let (path, digest) = binary();
    let checker = OpaProcessChecker::verified(
        path,
        digest,
        &Sha256Digest,
        RunLimits::default(),
        Some(scratch.clone()),
    )
    .await
    .expect("checker");
    let tenant = TenantId::generate();
    let report = checker
        .check(
            tenant,
            &[policy(
                tenant,
                "decision := {\"allow\": true} if input.action == \"read\"",
            )],
        )
        .await
        .expect("ran");
    assert!(report.passed());
    let left: Vec<_> = std::fs::read_dir(&scratch).expect("scratch").collect();
    assert!(left.is_empty(), "every run's directory is removed");
    std::fs::remove_dir_all(&scratch).expect("cleanup");
}
