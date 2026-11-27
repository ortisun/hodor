//! The tenant commands, run as the real binary against a real database.

use hodor_adapters_postgres::testing::TestDatabase;
use std::process::{Command, Output};

fn cli(database: &TestDatabase, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .arg("tenant")
        .args(arguments)
        .env("HODOR_DATABASE_URL", database.app_url())
        .output()
        .expect("the command-line tool should run")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_owned()
}

#[tokio::test]
async fn tenants_are_created_listed_suspended_and_reactivated() {
    let database = TestDatabase::start().await;

    let created = cli(
        &database,
        &["create", "--slug", "acme", "--name", "Acme Corporation"],
    );
    assert!(created.status.success(), "{}", stderr(&created));
    assert!(
        stdout(&created).starts_with("created acme "),
        "{}",
        stdout(&created)
    );

    cli(
        &database,
        &[
            "create",
            "--slug",
            "globex",
            "--name",
            "Globex",
            "--open-registration",
        ],
    );

    let listed = stdout(&cli(&database, &["list"]));
    let lines: Vec<&str> = listed.lines().collect();
    assert_eq!(lines.len(), 2, "{listed}");
    assert!(
        lines[0].starts_with("acme ") && lines[0].ends_with(" active"),
        "{listed}"
    );
    assert!(
        lines[1].starts_with("globex ") && lines[1].ends_with(" active"),
        "{listed}"
    );

    let suspended = cli(
        &database,
        &["suspend", "--slug", "acme", "--reason", "unpaid invoice"],
    );
    assert_eq!(stdout(&suspended), "acme suspended");
    assert!(stdout(&cli(&database, &["list"])).contains(" suspended"));

    let reactivated = cli(&database, &["reactivate", "--slug", "acme"]);
    assert_eq!(stdout(&reactivated), "acme active");
}

#[tokio::test]
async fn creating_the_system_tenant_is_safe_to_repeat() {
    let database = TestDatabase::start().await;

    let first = stdout(&cli(&database, &["create-system"]));
    let second = stdout(&cli(&database, &["create-system"]));

    assert!(first.starts_with("created system "), "{first}");
    assert_eq!(second, first.replacen("created", "exists", 1));
    assert_eq!(stdout(&cli(&database, &["list"])).lines().count(), 1);
}

#[tokio::test]
async fn failures_exit_non_zero_with_the_error_code() {
    let database = TestDatabase::start().await;
    cli(&database, &["create", "--slug", "acme", "--name", "Acme"]);

    for (arguments, code) in [
        (
            vec!["create", "--slug", "acme", "--name", "Again"],
            "tenant.slug_taken",
        ),
        (
            vec!["create", "--slug", "system", "--name", "Sneaky"],
            "tenant.slug_reserved",
        ),
        (
            vec!["create", "--slug", "Not Valid", "--name", "Bad"],
            "tenant.slug_invalid",
        ),
        (
            vec!["suspend", "--slug", "nobody", "--reason", "x"],
            "tenant.not_found",
        ),
        (
            vec!["reactivate", "--slug", "acme"],
            "tenant.invalid_transition",
        ),
    ] {
        let output = cli(&database, &arguments);
        assert!(!output.status.success(), "{arguments:?} should fail");
        assert!(
            stderr(&output).contains(code),
            "{arguments:?}: {}",
            stderr(&output)
        );
    }
    assert_eq!(stdout(&cli(&database, &["list"])).lines().count(), 1);
}

#[tokio::test]
async fn the_depth_of_groups_is_set_within_its_bounds() {
    let database = TestDatabase::start().await;
    let created = cli(&database, &["create", "--slug", "acme", "--name", "Acme"]);
    assert!(created.status.success(), "{}", stderr(&created));

    let set = cli(
        &database,
        &["group-depth", "--slug", "acme", "--depth", "3"],
    );
    assert!(set.status.success(), "{}", stderr(&set));
    assert_eq!(stdout(&set), "acme group-depth 3");
    let (depth,): (Option<i32>,) =
        sqlx::query_as("SELECT (settings -> 'groups' ->> 'max_depth')::integer FROM tenant.tenant")
            .fetch_one(database.owner())
            .await
            .expect("the setting");
    assert_eq!(depth, Some(3));

    for refused in ["0", "11"] {
        let out = cli(
            &database,
            &["group-depth", "--slug", "acme", "--depth", refused],
        );
        assert!(!out.status.success(), "{refused} was accepted");
    }
}

#[tokio::test]
async fn signing_in_by_email_is_turned_on_and_off_one_method_at_a_time() {
    let database = TestDatabase::start().await;
    let created = cli(&database, &["create", "--slug", "acme", "--name", "Acme"]);
    assert!(created.status.success(), "{}", stderr(&created));
    let read = || async {
        let (policy,): (Option<String>,) = sqlx::query_as(
            "SELECT (settings -> 'authentication' -> 'email_sign_in')::text FROM tenant.tenant",
        )
        .fetch_one(database.owner())
        .await
        .expect("the setting");
        policy
    };
    let shown = cli(&database, &["email-sign-in", "--slug", "acme"]);
    assert!(shown.status.success(), "{}", stderr(&shown));
    assert_eq!(stdout(&shown), "acme email-sign-in code off link off");

    let set = cli(
        &database,
        &["email-sign-in", "--slug", "acme", "--code", "on"],
    );
    assert!(set.status.success(), "{}", stderr(&set));
    assert_eq!(stdout(&set), "acme email-sign-in code on link off");
    let set = cli(
        &database,
        &["email-sign-in", "--slug", "acme", "--link", "on"],
    );
    assert_eq!(stdout(&set), "acme email-sign-in code on link on");
    let set = cli(
        &database,
        &[
            "email-sign-in",
            "--slug",
            "acme",
            "--code",
            "off",
            "--link",
            "on",
        ],
    );
    assert_eq!(stdout(&set), "acme email-sign-in code off link on");
    assert_eq!(
        read().await.as_deref(),
        Some(r#"{"code": false, "link": true}"#)
    );
    let refused = cli(
        &database,
        &["email-sign-in", "--slug", "acme", "--code", "yes"],
    );
    assert!(!refused.status.success(), "an unknown value was accepted");
    let unknown = cli(
        &database,
        &["email-sign-in", "--slug", "nowhere", "--code", "on"],
    );
    assert!(!unknown.status.success(), "an unknown tenant was accepted");
}

#[tokio::test]
async fn the_life_and_the_requirement_of_pushed_requests_are_set_within_their_bounds() {
    let database = TestDatabase::start().await;
    let created = cli(&database, &["create", "--slug", "acme", "--name", "Acme"]);
    assert!(created.status.success(), "{}", stderr(&created));
    let shown = cli(&database, &["pushed-requests", "--slug", "acme"]);
    assert!(shown.status.success(), "{}", stderr(&shown));
    assert_eq!(
        stdout(&shown),
        "acme pushed-requests seconds 60 required off"
    );

    let set = cli(
        &database,
        &["pushed-requests", "--slug", "acme", "--seconds", "600"],
    );
    assert!(set.status.success(), "{}", stderr(&set));
    assert_eq!(
        stdout(&set),
        "acme pushed-requests seconds 600 required off"
    );
    let set = cli(
        &database,
        &["pushed-requests", "--slug", "acme", "--required", "on"],
    );
    assert_eq!(stdout(&set), "acme pushed-requests seconds 600 required on");
    let (policy,): (Option<String>,) =
        sqlx::query_as("SELECT (settings -> 'pushed_requests')::text FROM tenant.tenant")
            .fetch_one(database.owner())
            .await
            .expect("the setting");
    assert_eq!(
        policy.as_deref(),
        Some(r#"{"required": true, "lifetime_seconds": 600}"#)
    );

    for refused in ["9", "601"] {
        let out = cli(
            &database,
            &["pushed-requests", "--slug", "acme", "--seconds", refused],
        );
        assert!(!out.status.success(), "{refused} was accepted");
        assert!(
            stderr(&out).contains("tenant.settings_invalid"),
            "{}",
            stderr(&out)
        );
    }
}

#[tokio::test]
async fn the_scim_deprovisioning_policy_is_set_by_name() {
    let database = TestDatabase::start().await;
    let created = cli(&database, &["create", "--slug", "acme", "--name", "Acme"]);
    assert!(created.status.success(), "{}", stderr(&created));
    let read = || async {
        let (policy,): (Option<String>,) = sqlx::query_as(
            "SELECT settings -> 'provisioning' ->> 'deprovisioning' FROM tenant.tenant",
        )
        .fetch_one(database.owner())
        .await
        .expect("the setting");
        policy
    };
    for (policy, stored) in [("delete", "delete"), ("deactivate", "deactivate")] {
        let set = cli(
            &database,
            &["scim-deprovisioning", "--slug", "acme", "--policy", policy],
        );
        assert!(set.status.success(), "{}", stderr(&set));
        assert_eq!(stdout(&set), format!("acme scim-deprovisioning {stored}"));
        assert_eq!(read().await.as_deref(), Some(stored));
    }
    let refused = cli(
        &database,
        &[
            "scim-deprovisioning",
            "--slug",
            "acme",
            "--policy",
            "suspend",
        ],
    );
    assert!(!refused.status.success(), "an unknown policy was accepted");
}
