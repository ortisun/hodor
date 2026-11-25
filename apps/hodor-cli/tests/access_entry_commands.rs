//! The commands for entries of access control lists, run as the real
//! binary against a real database.

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

fn succeeds(database: &TestDatabase, arguments: &[&str]) -> String {
    let output = run(database, arguments);
    assert!(output.status.success(), "{arguments:?}: {output:?}");
    text(&output.stdout)
}

const API: &str = "https://api.documents.example.com";
const GROUP: &str = "0193f2a0-0000-7000-8000-000000000001";
const USER: &str = "0193f2a0-0000-7000-8000-000000000002";

fn grant<'a>(tenant: &'a str, resource: &'a str, who: [&'a str; 2]) -> Vec<&'a str> {
    vec![
        "authorization",
        "access-entry",
        "grant",
        "--tenant",
        tenant,
        "--namespace",
        API,
        "--permission",
        "document:read",
        "--resource",
        resource,
        who[0],
        who[1],
    ]
}

#[tokio::test]
async fn an_operator_grants_lists_and_removes_entries() {
    let database = TestDatabase::start().await;
    for slug in ["acme", "globex"] {
        succeeds(
            &database,
            &["tenant", "create", "--slug", slug, "--name", slug],
        );
        succeeds(
            &database,
            &[
                "authorization",
                "permission",
                "declare",
                "--tenant",
                slug,
                "--namespace",
                API,
                "--name",
                "document:read",
            ],
        );
    }

    // Granted once; the same grant again finds the same entry.
    let granted = succeeds(&database, &grant("acme", "d-42", ["--group", GROUP]));
    let entry = granted
        .strip_prefix("granted ")
        .expect("an identifier")
        .to_owned();
    assert_eq!(
        succeeds(&database, &grant("acme", "d-42", ["--group", GROUP])),
        granted
    );
    succeeds(&database, &grant("acme", "d-43", ["--user", USER]));

    // A permission the resource server does not declare is refused with
    // the code of the administration interface.
    let undeclared = run(
        &database,
        &[
            "authorization",
            "access-entry",
            "grant",
            "--tenant",
            "acme",
            "--namespace",
            API,
            "--permission",
            "document:write",
            "--resource",
            "d-42",
            "--group",
            GROUP,
        ],
    );
    assert!(!undeclared.status.success());
    assert!(
        text(&undeclared.stderr).contains("authorization.permission_not_declared"),
        "{undeclared:?}"
    );

    // Listed oldest first, and narrowed.
    let list = |extra: &[&str]| {
        let mut arguments = vec![
            "authorization",
            "access-entry",
            "list",
            "--tenant",
            "acme",
            "--namespace",
            API,
        ];
        arguments.extend_from_slice(extra);
        succeeds(&database, &arguments)
    };
    let all = list(&[]);
    let lines: Vec<&str> = all.lines().collect();
    assert_eq!(lines.len(), 2, "{all}");
    assert_eq!(
        lines[0],
        format!("{entry}\tdocument:read\td-42\tgroup:{GROUP}")
    );
    assert!(lines[1].ends_with(&format!("\td-43\tuser:{USER}")), "{all}");
    assert_eq!(list(&["--resource", "d-43"]).lines().count(), 1);
    assert_eq!(list(&["--group", GROUP]).lines().count(), 1);
    assert_eq!(list(&["--resource-kind", "folder"]), "");

    // Another tenant has none of them, and cannot remove them.
    let theirs = succeeds(
        &database,
        &[
            "authorization",
            "access-entry",
            "list",
            "--tenant",
            "globex",
            "--namespace",
            API,
        ],
    );
    assert_eq!(theirs, "");
    let remove = |tenant: &str| {
        succeeds(
            &database,
            &[
                "authorization",
                "access-entry",
                "remove",
                "--tenant",
                tenant,
                "--id",
                &entry,
            ],
        )
    };
    assert_eq!(remove("globex"), "no such entry");

    // Removed once.
    assert_eq!(remove("acme"), "removed");
    assert_eq!(remove("acme"), "no such entry");
    assert_eq!(list(&[]).lines().count(), 1);
}
