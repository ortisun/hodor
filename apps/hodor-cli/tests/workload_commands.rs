//! The commands for service accounts and agents, run as the real binary
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

fn said(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn refused(output: &Output, code: &str) {
    assert!(!output.status.success(), "refused");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(code), "{error}");
}

/// The word of a line at `position`.
fn word(output: &Output, position: usize) -> String {
    said(output)
        .split_whitespace()
        .nth(position)
        .expect("a word")
        .to_owned()
}

#[tokio::test]
async fn service_accounts_and_agents_are_managed_from_the_command_line() {
    let database = TestDatabase::start().await;
    said(&run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    ));
    said(&run(
        &database,
        &[
            "admin",
            "bootstrap",
            "--tenant",
            "acme",
            "--email",
            "ana@example.com",
        ],
    ));
    let (ana,): (sqlx::types::Uuid,) = sqlx::query_as(
        "SELECT user_id FROM identity.user_identifier WHERE value_normalized = 'ana@example.com'",
    )
    .fetch_one(database.owner())
    .await
    .expect("the person");
    let ana = ana.to_string();

    let export = word(
        &run(
            &database,
            &[
                "service-account",
                "create",
                "--tenant",
                "acme",
                "--name",
                "Nightly export",
                "--owner",
                &ana,
            ],
        ),
        1,
    );
    let listed = said(&run(
        &database,
        &["service-account", "list", "--tenant", "acme"],
    ));
    assert_eq!(listed, format!("{export} active Nightly export"));
    let agents = said(&run(&database, &["agent", "list", "--tenant", "acme"]));
    assert!(agents.is_empty(), "{agents}");
    refused(
        &run(
            &database,
            &["agent", "disable", "--tenant", "acme", "--id", &export],
        ),
        "identity.workload_not_found",
    );
    refused(
        &run(
            &database,
            &[
                "agent", "create", "--tenant", "acme", "--name", "Helper", "--owner", &export,
            ],
        ),
        "identity.workload_owner_invalid",
    );

    // A client is bound to it; a person is refused as a principal.
    let application = word(
        &run(
            &database,
            &[
                "application",
                "add",
                "--tenant",
                "acme",
                "--name",
                "Billing",
                "--first-party",
            ],
        ),
        1,
    );
    let client = run(
        &database,
        &[
            "client",
            "add",
            "--tenant",
            "acme",
            "--application",
            &application,
            "--name",
            "Export",
            "--type",
            "confidential",
            "--grant",
            "client_credentials",
            "--principal",
            &export,
        ],
    );
    said(&client);
    let (principal,): (Option<sqlx::types::Uuid>,) =
        sqlx::query_as("SELECT principal_id FROM oauth.client")
            .fetch_one(database.owner())
            .await
            .expect("the client");
    assert_eq!(principal.map(|id| id.to_string()), Some(export.clone()));
    refused(
        &run(
            &database,
            &[
                "client",
                "add",
                "--tenant",
                "acme",
                "--application",
                &application,
                "--name",
                "Person",
                "--type",
                "confidential",
                "--grant",
                "client_credentials",
                "--principal",
                &ana,
            ],
        ),
        "oauth.client_principal_invalid",
    );

    assert_eq!(
        said(&run(
            &database,
            &[
                "service-account",
                "disable",
                "--tenant",
                "acme",
                "--id",
                &export
            ],
        )),
        format!("disabled {export}")
    );
    assert_eq!(
        said(&run(
            &database,
            &[
                "service-account",
                "enable",
                "--tenant",
                "acme",
                "--id",
                &export
            ],
        )),
        format!("active {export}")
    );
    said(&run(
        &database,
        &[
            "service-account",
            "delete",
            "--tenant",
            "acme",
            "--id",
            &export,
        ],
    ));
    let listed = said(&run(
        &database,
        &["service-account", "list", "--tenant", "acme"],
    ));
    assert!(listed.is_empty(), "a deleted one is not listed: {listed}");
    // What the commands did is waiting to be audited, with Hodor itself as
    // the actor.
    let events: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM platform.outbox
         WHERE event_type LIKE 'identity.%' ORDER BY created_at",
    )
    .fetch_all(database.owner())
    .await
    .expect("the outbox");
    for expected in [
        "identity.workload_owner_added",
        "identity.user_deactivated",
        "identity.user_restored",
        "identity.user_deleted",
    ] {
        assert!(events.iter().any(|event| event == expected), "{events:?}");
    }
}

#[tokio::test]
async fn a_workloads_api_keys_and_roles_are_managed_from_the_command_line() {
    let database = TestDatabase::start().await;
    said(&run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    ));
    said(&run(
        &database,
        &[
            "admin",
            "bootstrap",
            "--tenant",
            "acme",
            "--email",
            "ana@example.com",
        ],
    ));
    let (ana,): (sqlx::types::Uuid,) = sqlx::query_as(
        "SELECT user_id FROM identity.user_identifier WHERE value_normalized = 'ana@example.com'",
    )
    .fetch_one(database.owner())
    .await
    .expect("the person");
    let ana = ana.to_string();
    let agent = word(
        &run(
            &database,
            &[
                "agent", "create", "--tenant", "acme", "--name", "Helper", "--owner", &ana,
            ],
        ),
        1,
    );

    let made = said(&run(
        &database,
        &[
            "agent",
            "key",
            "create",
            "--tenant",
            "acme",
            "--id",
            &agent,
            "--name",
            "Reports",
            "--scope",
            "users:read",
        ],
    ));
    let lines: Vec<&str> = made.lines().collect();
    let key_id = lines[0].strip_prefix("key ").expect("the key's identifier");
    let key = lines[1].strip_prefix("api-key ").expect("the key, once");
    assert!(key.starts_with("hodor_ak_") && key.len() == 73, "{made}");
    assert!(lines[2].starts_with("expires "));
    let listed = said(&run(
        &database,
        &["agent", "key", "list", "--tenant", "acme", "--id", &agent],
    ));
    assert_eq!(
        listed,
        format!("{key_id} active {} Reports", &key[key.len() - 4..])
    );
    assert!(!listed.contains(&key[9..]), "never shown again");
    refused(
        &run(
            &database,
            &[
                "agent",
                "key",
                "create",
                "--tenant",
                "acme",
                "--id",
                &agent,
                "--name",
                "x",
                "--scope",
                "users:delete",
            ],
        ),
        "authorization.scope_unknown",
    );

    let rotated = said(&run(
        &database,
        &[
            "agent",
            "key",
            "rotate",
            "--tenant",
            "acme",
            "--id",
            &agent,
            "--key",
            key_id,
            "--keep-previous-days",
            "0",
        ],
    ));
    assert!(rotated.contains("api-key hodor_ak_"), "{rotated}");
    let new_id = rotated
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("key "))
        .expect("the new key")
        .to_owned();
    assert_eq!(
        said(&run(
            &database,
            &[
                "agent", "key", "revoke", "--tenant", "acme", "--id", &agent, "--key", &new_id,
            ],
        )),
        format!("revoked {new_id}")
    );

    // A built-in role is given to the agent, and taken away.
    assert_eq!(
        said(&run(
            &database,
            &[
                "admin",
                "grant",
                "--tenant",
                "acme",
                "--user",
                &agent,
                "--role",
                "tenant_auditor",
            ],
        )),
        format!("granted tenant_auditor {agent}")
    );
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM \"authorization\".role_assignment WHERE principal_id = $1",
    )
    .bind(&agent)
    .fetch_one(database.owner())
    .await
    .expect("assignments");
    assert_eq!(count, 1);
    said(&run(
        &database,
        &[
            "admin",
            "revoke",
            "--tenant",
            "acme",
            "--user",
            &agent,
            "--role",
            "tenant_auditor",
        ],
    ));
    refused(
        &run(
            &database,
            &[
                "admin", "grant", "--tenant", "acme", "--user", &agent, "--role", "owner",
            ],
        ),
        "authorization.unknown_role",
    );
}

#[tokio::test]
async fn an_agents_client_is_given_exchange_rules_from_the_command_line() {
    let database = TestDatabase::start().await;
    said(&run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    ));
    said(&run(
        &database,
        &[
            "admin",
            "bootstrap",
            "--tenant",
            "acme",
            "--email",
            "ana@example.com",
        ],
    ));
    let (ana,): (sqlx::types::Uuid,) = sqlx::query_as(
        "SELECT user_id FROM identity.user_identifier WHERE value_normalized = 'ana@example.com'",
    )
    .fetch_one(database.owner())
    .await
    .expect("the person");
    let ana = ana.to_string();
    let agent = word(
        &run(
            &database,
            &[
                "agent",
                "create",
                "--tenant",
                "acme",
                "--name",
                "Assistant",
                "--owner",
                &ana,
            ],
        ),
        1,
    );
    let account = word(
        &run(
            &database,
            &[
                "service-account",
                "create",
                "--tenant",
                "acme",
                "--name",
                "Export",
                "--owner",
                &ana,
            ],
        ),
        1,
    );
    let application = word(
        &run(
            &database,
            &[
                "application",
                "add",
                "--tenant",
                "acme",
                "--name",
                "Assistant",
                "--first-party",
            ],
        ),
        1,
    );
    let client = |principal: &str| {
        run(
            &database,
            &[
                "client",
                "add",
                "--tenant",
                "acme",
                "--application",
                &application,
                "--name",
                "Assistant",
                "--type",
                "confidential",
                "--grant",
                "client_credentials",
                "--grant",
                "urn:ietf:params:oauth:grant-type:token-exchange",
                "--principal",
                principal,
                "--exchange-rule",
                "urn:example:assistant=>https://api.example.com",
            ],
        )
    };
    said(&client(&agent));
    let (rules,): (serde_json::Value,) = sqlx::query_as("SELECT exchange_rules FROM oauth.client")
        .fetch_one(database.owner())
        .await
        .expect("the client");
    assert_eq!(
        rules,
        serde_json::json!([
            { "subject_audience": "urn:example:assistant", "audience": "https://api.example.com" }
        ])
    );
    refused(&client(&account), "oauth.client_principal_invalid");
}

#[tokio::test]
async fn a_service_accounts_clients_are_bound_to_its_workload_identities() {
    const PAYROLL: &str = "spiffe://workloads.example.org/ns/payroll/sa/payroll";
    const MESH: &str = "spiffe://cluster.local/ns/payroll/sa/payroll";
    const LINKERD: &str = "payroll.payroll.serviceaccount.identity.linkerd.cluster.local";
    let database = TestDatabase::start().await;
    said(&run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    ));
    said(&run(
        &database,
        &[
            "admin",
            "bootstrap",
            "--tenant",
            "acme",
            "--email",
            "ana@example.com",
        ],
    ));
    let (ana,): (sqlx::types::Uuid,) = sqlx::query_as(
        "SELECT user_id FROM identity.user_identifier WHERE value_normalized = 'ana@example.com'",
    )
    .fetch_one(database.owner())
    .await
    .expect("the person");
    let ana = ana.to_string();
    let payroll = word(
        &run(
            &database,
            &[
                "service-account",
                "create",
                "--tenant",
                "acme",
                "--name",
                "Payroll",
                "--owner",
                &ana,
            ],
        ),
        1,
    );
    let assistant = word(
        &run(
            &database,
            &[
                "agent", "create", "--tenant", "acme", "--name", "Helper", "--owner", &ana,
            ],
        ),
        1,
    );
    let application = word(
        &run(
            &database,
            &[
                "application",
                "add",
                "--tenant",
                "acme",
                "--name",
                "Payroll",
                "--first-party",
            ],
        ),
        1,
    );
    let client = |method: &str, extra: &[&str], principal: &str| {
        let mut arguments = vec![
            "client",
            "add",
            "--tenant",
            "acme",
            "--application",
            &application,
            "--name",
            "Payroll",
            "--type",
            "confidential",
            "--grant",
            "client_credentials",
            "--method",
            method,
            "--principal",
            principal,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        arguments.extend(extra.iter().map(|given| (*given).to_owned()));
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        run(&database, &arguments)
    };

    // One client by its JWT-SVIDs, one by the certificate its sidecar
    // presents with bound tokens, one by its Linkerd identity: none has a
    // secret.
    let by_svid = said(&client("spiffe_jwt", &["--spiffe-id", PAYROLL], &payroll));
    let by_certificate = said(&client(
        "spiffe_x509",
        &["--spiffe-id", MESH, "--bound-tokens"],
        &payroll,
    ));
    let by_linkerd = said(&client(
        "linkerd_identity",
        &["--linkerd-identity", LINKERD],
        &payroll,
    ));
    for output in [&by_svid, &by_certificate, &by_linkerd] {
        assert!(
            output.starts_with("client ") && !output.contains("secret"),
            "{output}"
        );
    }
    let stored: Vec<(String, Option<String>, Option<String>, bool)> = sqlx::query_as(
        "SELECT authentication_method, spiffe_id, linkerd_identity,
                certificate_bound_access_tokens
         FROM oauth.client ORDER BY id",
    )
    .fetch_all(database.owner())
    .await
    .expect("the clients");
    assert_eq!(
        stored,
        [
            (
                "spiffe_jwt".to_owned(),
                Some(PAYROLL.to_owned()),
                None,
                false
            ),
            ("spiffe_x509".to_owned(), Some(MESH.to_owned()), None, true),
            (
                "linkerd_identity".to_owned(),
                None,
                Some(LINKERD.to_owned()),
                false
            ),
        ]
    );
    let listed = said(&run(
        &database,
        &[
            "client",
            "list",
            "--tenant",
            "acme",
            "--application",
            &application,
        ],
    ));
    assert!(listed.contains(" spiffe_x509 Payroll"), "{listed}");

    // Bound tokens for a client of a secret, which is printed once.
    let bound = said(&run(
        &database,
        &[
            "client",
            "add",
            "--tenant",
            "acme",
            "--application",
            &application,
            "--name",
            "Back end",
            "--type",
            "confidential",
            "--grant",
            "client_credentials",
            "--bound-tokens",
        ],
    ));
    assert!(bound.contains("\nsecret "), "{bound}");

    // The OAuth context's rules, with its codes.
    refused(
        &client("spiffe_jwt", &[], &payroll),
        "oauth.client_spiffe_id_invalid",
    );
    refused(
        &client(
            "spiffe_jwt",
            &["--spiffe-id", "spiffe://workloads.example.org/ns/*"],
            &payroll,
        ),
        "oauth.client_spiffe_id_invalid",
    );
    // An identity binds the clients of one service account (Decision
    // 0058): another client of Payroll may share it, a client of another
    // service account may not.
    let ledger = word(
        &run(
            &database,
            &[
                "service-account",
                "create",
                "--tenant",
                "acme",
                "--name",
                "Ledger",
                "--owner",
                &ana,
            ],
        ),
        1,
    );
    said(&client("spiffe_jwt", &["--spiffe-id", PAYROLL], &payroll));
    refused(
        &client("spiffe_jwt", &["--spiffe-id", PAYROLL], &ledger),
        "oauth.client_spiffe_id_taken",
    );
    refused(
        &client(
            "linkerd_identity",
            &["--linkerd-identity", LINKERD],
            &ledger,
        ),
        "oauth.client_linkerd_identity_taken",
    );
    refused(
        &client(
            "linkerd_identity",
            &["--linkerd-identity", "not an identity"],
            &payroll,
        ),
        "oauth.client_linkerd_identity_invalid",
    );
    refused(
        &client(
            "linkerd_identity",
            &[
                "--linkerd-identity",
                "web.shop.serviceaccount.identity.linkerd.cluster.local",
                "--bound-tokens",
            ],
            &payroll,
        ),
        "oauth.client_certificate_bound_access_tokens_invalid",
    );
    refused(
        &client(
            "tls_client_auth",
            &[
                "--spiffe-id",
                "spiffe://cluster.local/ns/shop/sa/web",
                "--linkerd-identity",
                "web.shop.serviceaccount.identity.linkerd.cluster.local",
            ],
            &payroll,
        ),
        "oauth.client_spiffe_id_invalid",
    );
    // Only a service account proves who it is with its identity.
    refused(
        &client(
            "spiffe_x509",
            &["--spiffe-id", "spiffe://cluster.local/ns/shop/sa/web"],
            &assistant,
        ),
        "oauth.client_principal_invalid",
    );
    refused(
        &client(
            "spiffe_x509",
            &["--spiffe-id", "spiffe://cluster.local/ns/shop/sa/web"],
            &ana,
        ),
        "oauth.client_principal_invalid",
    );
}
