//! The commands for permissions, roles, assignments and bindings, run as
//! the real binary against a real database.

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

#[tokio::test]
async fn an_operator_defines_roles_gives_them_and_binds_a_resource_server() {
    let database = TestDatabase::start().await;
    succeeds(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    );
    for name in ["document:read", "document:write"] {
        let said = succeeds(
            &database,
            &[
                "authorization",
                "permission",
                "declare",
                "--tenant",
                "acme",
                "--namespace",
                API,
                "--name",
                name,
                "--description",
                "A document",
            ],
        );
        assert_eq!(said, format!("declared {API}#{name}"));
    }
    let listed = succeeds(
        &database,
        &[
            "authorization",
            "permission",
            "list",
            "--tenant",
            "acme",
            "--namespace",
            API,
        ],
    );
    assert_eq!(
        listed,
        "document:read\tA document\ndocument:write\tA document"
    );

    // A condition in Common Expression Language is checked when the role
    // is saved: one that does not compile is refused.
    succeeds(
        &database,
        &[
            "authorization",
            "role",
            "define",
            "--tenant",
            "acme",
            "--namespace",
            API,
            "--name",
            "reader",
            "--permission",
            "document:read",
        ],
    );
    let editor = succeeds(
        &database,
        &[
            "authorization",
            "role",
            "define",
            "--tenant",
            "acme",
            "--namespace",
            API,
            "--name",
            "editor",
            "--permission",
            "document:write",
            "--condition",
            "document:write=resource.attributes.owner == subject.id",
            "--include",
            &format!("{API}#reader"),
        ],
    );
    assert_eq!(editor, format!("defined {API}#editor"));
    let broken = run(
        &database,
        &[
            "authorization",
            "role",
            "define",
            "--tenant",
            "acme",
            "--namespace",
            API,
            "--name",
            "broken",
            "--permission",
            "document:read",
            "--condition",
            "document:read=subject.id ==",
        ],
    );
    assert!(!broken.status.success());
    assert!(
        text(&broken.stderr).contains("authorization.condition_invalid"),
        "{broken:?}"
    );
    let roles = succeeds(
        &database,
        &["authorization", "role", "list", "--tenant", "acme"],
    );
    assert!(
        roles.contains(&format!("{API}#editor\tdocument:write\tconditions=1")),
        "{roles}"
    );

    // Given to a client, taken away, and taken away again for nothing.
    let client = "0193f1c4-0000-7000-8000-000000000001";
    let assigned = succeeds(
        &database,
        &[
            "authorization",
            "assign",
            "--tenant",
            "acme",
            "--client",
            client,
            "--role",
            &format!("{API}#editor"),
        ],
    );
    assert_eq!(
        assigned,
        format!("assigned {API}#editor to client:{client}")
    );
    let revoke = [
        "authorization",
        "revoke",
        "--tenant",
        "acme",
        "--client",
        client,
        "--role",
        &format!("{API}#editor"),
    ];
    assert_eq!(succeeds(&database, &revoke), "revoked");
    assert_eq!(succeeds(&database, &revoke), "not held");

    // Bound to Open Policy Agent; Hodor's own namespace cannot be bound.
    let bound = succeeds(
        &database,
        &[
            "authorization",
            "bind",
            "--tenant",
            "acme",
            "--namespace",
            API,
            "--engine",
            "open-policy-agent",
            "--time-limit-milliseconds",
            "250",
        ],
    );
    assert_eq!(bound, format!("bound {API} to open_policy_agent"));
    let bindings = succeeds(
        &database,
        &["authorization", "bindings", "--tenant", "acme"],
    );
    assert_eq!(bindings, format!("{API}\topen_policy_agent\t250ms"));
    let reserved = run(
        &database,
        &[
            "authorization",
            "bind",
            "--tenant",
            "acme",
            "--namespace",
            "hodor:admin",
            "--engine",
            "native",
        ],
    );
    assert!(!reserved.status.success());
    assert!(
        text(&reserved.stderr).contains("authorization.namespace_reserved"),
        "{reserved:?}"
    );
    assert_eq!(
        succeeds(
            &database,
            &[
                "authorization",
                "unbind",
                "--tenant",
                "acme",
                "--namespace",
                API
            ]
        ),
        "unbound"
    );
}
