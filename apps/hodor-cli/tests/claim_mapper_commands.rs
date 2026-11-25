//! The commands for the claim mappers of a client, run as the real binary
//! against a real database.

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

/// The first word after `prefix ` on the first line that has it.
fn value(output: &Output, prefix: &str) -> String {
    assert!(output.status.success(), "{output:?}");
    text(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{prefix} ")))
        .unwrap_or_else(|| panic!("no `{prefix}` in {output:?}"))
        .split(' ')
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn refused(output: &Output, code: &str) {
    assert!(!output.status.success(), "{output:?}");
    assert!(text(&output.stderr).contains(code), "{output:?}");
}

/// A tenant with a client of an application, and a group.
fn tenant_with_a_client(database: &TestDatabase, slug: &str) -> (String, String) {
    let created = run(
        database,
        &["tenant", "create", "--slug", slug, "--name", slug],
    );
    assert!(created.status.success(), "{created:?}");
    let application = value(
        &run(
            database,
            &[
                "application",
                "add",
                "--tenant",
                slug,
                "--name",
                "Billing",
                "--first-party",
            ],
        ),
        "application",
    );
    let client = value(
        &run(
            database,
            &[
                "client",
                "add",
                "--tenant",
                slug,
                "--application",
                &application,
                "--name",
                "Billing web site",
                "--type",
                "public",
                "--grant",
                "authorization_code",
                "--redirect-uri",
                "https://billing.example.com/callback",
                "--scope",
                "openid",
                "--scope",
                "profile",
            ],
        ),
        "client",
    );
    let group = value(
        &run(
            database,
            &["group", "create", "--tenant", slug, "--name", "finance"],
        ),
        "created",
    );
    (client, group)
}

#[tokio::test]
async fn an_operator_adds_lists_and_removes_the_claim_mappers_of_a_client() {
    let database = TestDatabase::start().await;
    let (client, finance) = tenant_with_a_client(&database, "acme");
    let add = |extra: &[&str]| {
        let mut arguments = vec![
            "client", "mapper", "add", "--tenant", "acme", "--client", &client,
        ];
        arguments.extend_from_slice(extra);
        run(&database, &arguments)
    };

    let member = value(
        &add(&[
            "--claim",
            "in_finance",
            "--target",
            "id_token",
            "--target",
            "access_token",
            "--source",
            "group_member",
            "--group",
            &finance,
        ]),
        "mapper",
    );
    let teams = value(
        &add(&[
            "--claim", "teams", "--target", "userinfo", "--source", "groups",
        ]),
        "mapper",
    );
    let plan = value(
        &add(&[
            "--claim",
            "plan",
            "--target",
            "access_token",
            "--source",
            "constant",
            "--value",
            r#"{"tier": "gold"}"#,
            "--scope",
            "profile",
        ]),
        "mapper",
    );
    let name = value(
        &add(&[
            "--claim",
            "full_name",
            "--target",
            "id_token",
            "--source",
            "attribute",
            "--attribute",
            "display_name",
        ]),
        "mapper",
    );

    let listed = run(
        &database,
        &[
            "client", "mapper", "list", "--tenant", "acme", "--client", &client,
        ],
    );
    assert!(listed.status.success(), "{listed:?}");
    assert_eq!(
        text(&listed.stdout),
        [
            format!("{name} full_name id_token attribute:display_name -"),
            format!("{member} in_finance id_token,access_token group_member:{finance} -"),
            format!("{plan} plan access_token constant profile"),
            format!("{teams} teams userinfo groups -"),
        ]
        .join("\n")
    );

    let removed = run(
        &database,
        &[
            "client", "mapper", "remove", "--tenant", "acme", "--client", &client, "--id", &plan,
        ],
    );
    assert!(removed.status.success(), "{removed:?}");
    assert_eq!(text(&removed.stdout), format!("removed {plan}"));
    let listed = run(
        &database,
        &[
            "client", "mapper", "list", "--tenant", "acme", "--client", &client,
        ],
    );
    assert_eq!(text(&listed.stdout).lines().count(), 3);
}

#[tokio::test]
async fn a_mapper_is_refused_with_the_code_of_the_rule_it_breaks() {
    let database = TestDatabase::start().await;
    let (client, _) = tenant_with_a_client(&database, "acme");
    let (_, globex_group) = tenant_with_a_client(&database, "globex");
    let add = |extra: &[&str]| {
        let mut arguments = vec![
            "client", "mapper", "add", "--tenant", "acme", "--client", &client,
        ];
        arguments.extend_from_slice(extra);
        run(&database, &arguments)
    };
    for name in ["sub", "iss", "acr"] {
        refused(
            &add(&[
                "--claim", name, "--target", "id_token", "--source", "groups",
            ]),
            "oauth.claim_mapper_name_reserved",
        );
    }
    value(
        &add(&[
            "--claim", "teams", "--target", "id_token", "--source", "groups",
        ]),
        "mapper",
    );
    refused(
        &add(&[
            "--claim", "squads", "--target", "id_token", "--source", "groups",
        ]),
        "oauth.claim_mapper_token_too_large",
    );
    refused(
        &add(&[
            "--claim",
            "in_finance",
            "--target",
            "id_token",
            "--source",
            "group_member",
            "--group",
            &globex_group,
        ]),
        "oauth.claim_mapper_group_unknown",
    );
    refused(
        &add(&[
            "--claim", "plan", "--target", "id_token", "--source", "constant", "--value",
            "not json",
        ]),
        "oauth.claim_mapper_source_invalid",
    );
    refused(
        &add(&[
            "--claim",
            "plan",
            "--target",
            "logout_token",
            "--source",
            "groups",
        ]),
        "oauth.claim_mapper_targets_invalid",
    );
    let listed = run(
        &database,
        &[
            "client", "mapper", "list", "--tenant", "acme", "--client", &client,
        ],
    );
    assert_eq!(
        text(&listed.stdout).lines().count(),
        1,
        "only what was accepted"
    );
}
