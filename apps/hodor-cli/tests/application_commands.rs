//! The commands for applications, clients and resource servers, run as
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

/// What a command printed after `prefix ` on its first line that has it.
fn value(output: &Output, prefix: &str) -> String {
    text(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{prefix} ")))
        .unwrap_or_else(|| panic!("no `{prefix}` in {output:?}"))
        .split(' ')
        .next()
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn an_operator_registers_an_application_with_a_client_and_a_resource_server() {
    let database = TestDatabase::start().await;
    let created = run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    );
    assert!(created.status.success(), "{created:?}");

    let added = run(
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
    );
    assert!(added.status.success(), "{added:?}");
    let application = value(&added, "application");
    let listed = run(&database, &["application", "list", "--tenant", "acme"]);
    assert_eq!(
        text(&listed.stdout),
        format!("{application} enabled first-party Billing")
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
            "Billing web site",
            "--type",
            "confidential",
            "--grant",
            "authorization_code",
            "--grant",
            "refresh_token",
            "--redirect-uri",
            "https://billing.example.com/callback",
            "--scope",
            "openid",
        ],
    );
    assert!(client.status.success(), "{client:?}");
    let client_id = value(&client, "client");
    let first = value(&client, "secret");
    assert!(first.starts_with("hodor_cs_"), "{client:?}");
    assert!(text(&client.stdout).contains("\nexpires "));

    let clients = run(
        &database,
        &[
            "client",
            "list",
            "--tenant",
            "acme",
            "--application",
            &application,
        ],
    );
    assert_eq!(
        text(&clients.stdout),
        format!("{client_id} enabled confidential client_secret_basic Billing web site")
    );
    // The list never shows a secret.
    assert!(!text(&clients.stdout).contains(&first));

    let rotated = run(
        &database,
        &[
            "client",
            "rotate-secret",
            "--tenant",
            "acme",
            "--id",
            &client_id,
            "--keep-previous-days",
            "0",
        ],
    );
    assert!(rotated.status.success(), "{rotated:?}");
    let second = value(&rotated, "secret");
    assert!(second.starts_with("hodor_cs_"));
    assert_ne!(first, second);

    let disabled = run(
        &database,
        &["client", "disable", "--tenant", "acme", "--id", &client_id],
    );
    assert_eq!(
        text(&disabled.stdout),
        format!("client {client_id} disabled")
    );

    let server = run(
        &database,
        &[
            "resource-server",
            "add",
            "--tenant",
            "acme",
            "--application",
            &application,
            "--audience",
            "https://api.billing.example.com",
            "--name",
            "Billing interface",
            "--scope",
            "invoices:read=Read your invoices",
            "--scope",
            "invoices:write",
        ],
    );
    assert!(server.status.success(), "{server:?}");
    let servers = run(&database, &["resource-server", "list", "--tenant", "acme"]);
    assert!(
        text(&servers.stdout).ends_with(
            "https://api.billing.example.com Billing interface [invoices:read invoices:write]"
        ),
        "{servers:?}"
    );

    let disabled = run(
        &database,
        &[
            "application",
            "disable",
            "--tenant",
            "acme",
            "--id",
            &application,
        ],
    );
    assert_eq!(
        text(&disabled.stdout),
        format!("application {application} disabled")
    );
}

#[tokio::test]
async fn what_the_oauth_context_refuses_the_tool_refuses_with_the_same_code() {
    let database = TestDatabase::start().await;
    let created = run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    );
    assert!(created.status.success(), "{created:?}");
    let added = run(
        &database,
        &[
            "application",
            "add",
            "--tenant",
            "acme",
            "--name",
            "Billing",
        ],
    );
    let application = value(&added, "application");
    // Third party unless said.
    let listed = run(&database, &["application", "list", "--tenant", "acme"]);
    assert!(text(&listed.stdout).contains(" third-party "));

    let public_with_a_secret = run(
        &database,
        &[
            "client",
            "add",
            "--tenant",
            "acme",
            "--application",
            &application,
            "--name",
            "Mobile",
            "--type",
            "public",
            "--grant",
            "authorization_code",
            "--redirect-uri",
            "com.example.billing:/callback",
            "--method",
            "client_secret_post",
        ],
    );
    assert!(!public_with_a_secret.status.success());
    assert!(
        text(&public_with_a_secret.stderr).contains("oauth.client_authentication_method_invalid"),
        "{public_with_a_secret:?}"
    );

    let unknown_tenant = run(&database, &["application", "list", "--tenant", "nowhere"]);
    assert!(!unknown_tenant.status.success());
    assert!(text(&unknown_tenant.stderr).contains("tenant.not_found"));

    let unknown_client = run(
        &database,
        &[
            "client",
            "enable",
            "--tenant",
            "acme",
            "--id",
            "not-a-client",
        ],
    );
    assert!(!unknown_client.status.success());
    assert!(text(&unknown_client.stderr).contains("oauth.client_not_found"));
}

#[tokio::test]
async fn a_client_is_given_a_back_channel_logout_address_checked_as_the_server_checks_it() {
    let database = TestDatabase::start().await;
    let created = run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    );
    assert!(created.status.success(), "{created:?}");
    let added = run(
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
    );
    let application = value(&added, "application");
    let client = |address: &str, development_hosts: &str| {
        Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
            .args([
                "client",
                "add",
                "--tenant",
                "acme",
                "--application",
                &application,
                "--name",
                "Billing web site",
                "--type",
                "confidential",
                "--grant",
                "authorization_code",
                "--redirect-uri",
                "https://billing.example.com/callback",
                "--backchannel-logout-uri",
                address,
                "--backchannel-logout-session-required",
            ])
            .env("HODOR_DATABASE_URL", database.app_url())
            .env("HODOR_OUTBOUND_DEVELOPMENT_HOSTS", development_hosts)
            .output()
            .expect("the command-line tool should run")
    };

    // An address on this machine is refused, unless it is one of the
    // development exception, as the server has it.
    let refused = client("https://localhost/logout", "");
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("oauth.client_backchannel_logout_uri_forbidden"),
        "{refused:?}"
    );
    let made = client("http://relay:8080/logout", "relay:8080");
    assert!(made.status.success(), "{made:?}");
    let id = value(&made, "client");
    let stored: (Option<String>, bool) = sqlx::query_as(
        "SELECT backchannel_logout_uri, backchannel_logout_session_required
         FROM oauth.client WHERE id = $1::uuid",
    )
    .bind(&id)
    .fetch_one(database.owner())
    .await
    .expect("client");
    assert_eq!(stored, (Some("http://relay:8080/logout".to_owned()), true));
}

/// Answers every request on a port of this machine with `body` as JSON,
/// as a sector identifier address would; answers the address.
fn sector_document(body: &'static str) -> String {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let address = listener.local_addr().expect("address");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("127.0.0.1:{}", address.port())
}

#[tokio::test]
async fn a_client_is_made_pairwise_and_its_sector_identifier_address_fetched() {
    let database = TestDatabase::start().await;
    let created = run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    );
    assert!(created.status.success(), "{created:?}");
    let added = run(
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
    );
    let application = value(&added, "application");
    let host = sector_document(
        r#"["https://billing.example.com/callback", "https://billing.example.net/callback"]"#,
    );
    let client = |extra: &[&str], development_hosts: &str| {
        Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
            .args([
                "client",
                "add",
                "--tenant",
                "acme",
                "--application",
                &application,
                "--name",
                "Billing web site",
                "--type",
                "confidential",
                "--grant",
                "authorization_code",
                "--redirect-uri",
                "https://billing.example.com/callback",
                "--redirect-uri",
                "https://billing.example.net/callback",
                "--subject-type",
                "pairwise",
            ])
            .args(extra)
            .env("HODOR_DATABASE_URL", database.app_url())
            .env("HODOR_OUTBOUND_DEVELOPMENT_HOSTS", development_hosts)
            .output()
            .expect("the command-line tool should run")
    };
    // Two hosts and no address: no sector.
    let refused = client(&[], "");
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("oauth.client_sector_identifier_uri_required"),
        "{refused:?}"
    );
    // An address on this machine, outside the development exception.
    let address = format!("http://{host}/redirect_uris.json");
    let refused = client(&["--sector-identifier-uri", &address], "");
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("oauth.client_sector_identifier_uri_"),
        "{refused:?}"
    );
    // Fetched with the development exception, and listing both addresses.
    let made = client(&["--sector-identifier-uri", &address], &host);
    assert!(made.status.success(), "{made:?}");
    let id = value(&made, "client");
    let stored: (String, Option<String>) = sqlx::query_as(
        "SELECT subject_type, sector_identifier_uri FROM oauth.client WHERE id = $1::uuid",
    )
    .bind(&id)
    .fetch_one(database.owner())
    .await
    .expect("client");
    assert_eq!(stored, ("pairwise".to_owned(), Some(address)));
    // An unknown subject type is refused with the context's code.
    let unknown = Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args([
            "client",
            "add",
            "--tenant",
            "acme",
            "--application",
            &application,
            "--name",
            "Billing web site",
            "--type",
            "confidential",
            "--grant",
            "authorization_code",
            "--redirect-uri",
            "https://billing.example.com/callback",
            "--subject-type",
            "secret",
        ])
        .env("HODOR_DATABASE_URL", database.app_url())
        .output()
        .expect("the command-line tool should run");
    assert!(!unknown.status.success());
    assert!(text(&unknown.stderr).contains("oauth.client_subject_type_invalid"));
}

#[tokio::test]
async fn a_client_is_told_how_it_signs_its_request_objects() {
    let database = TestDatabase::start().await;
    let created = run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    );
    assert!(created.status.success(), "{created:?}");
    let added = run(
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
    );
    let application = value(&added, "application");
    let client = |extra: &[&str]| {
        let mut arguments = vec![
            "client",
            "add",
            "--tenant",
            "acme",
            "--application",
            &application,
            "--name",
            "Billing web site",
            "--type",
            "confidential",
            "--grant",
            "authorization_code",
            "--redirect-uri",
            "https://billing.example.com/callback",
        ];
        arguments.extend_from_slice(extra);
        run(&database, &arguments)
    };
    let stored = |id: String| {
        let database = &database;
        async move {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT request_object_signing_alg FROM oauth.client WHERE id = $1::uuid",
            )
            .bind(id)
            .fetch_one(database.owner())
            .await
            .expect("client")
        }
    };

    // None chosen unless given.
    let plain = client(&[]);
    assert!(plain.status.success(), "{plain:?}");
    assert_eq!(stored(value(&plain, "client")).await, None);

    // `none`, as the conformance suite's clients are made.
    let unsigned = client(&["--request-object-signing-alg", "none"]);
    assert!(unsigned.status.success(), "{unsigned:?}");
    assert_eq!(
        stored(value(&unsigned, "client")).await.as_deref(),
        Some("none")
    );

    // An algorithm Hodor does not check is refused with the context's code.
    let refused = client(&["--request-object-signing-alg", "HS256"]);
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("oauth.client_request_object_algorithm_invalid"),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_client_is_told_how_its_id_tokens_and_userinfo_answers_are_signed() {
    let database = TestDatabase::start().await;
    let created = run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    );
    assert!(created.status.success(), "{created:?}");
    let added = run(
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
    );
    let application = value(&added, "application");
    let client = |extra: &[&str]| {
        let mut arguments = vec![
            "client",
            "add",
            "--tenant",
            "acme",
            "--application",
            &application,
            "--name",
            "Billing web site",
            "--type",
            "confidential",
            "--grant",
            "authorization_code",
            "--redirect-uri",
            "https://billing.example.com/callback",
        ];
        arguments.extend_from_slice(extra);
        run(&database, &arguments)
    };
    let stored = |id: String| {
        let database = &database;
        async move {
            sqlx::query_as::<_, (String, Option<String>)>(
                "SELECT id_token_algorithm, userinfo_signed_response_alg
                 FROM oauth.client WHERE id = $1::uuid",
            )
            .bind(id)
            .fetch_one(database.owner())
            .await
            .expect("client")
        }
    };

    // ES256 and answers in JSON unless given.
    let plain = client(&[]);
    assert!(plain.status.success(), "{plain:?}");
    assert_eq!(
        stored(value(&plain, "client")).await,
        ("ES256".to_owned(), None)
    );

    for (id_token, userinfo) in [
        ("RS256", "PS256"),
        ("PS256", "EdDSA"),
        ("EdDSA", "ES256"),
        ("ES256", "RS256"),
    ] {
        let made = client(&[
            "--id-token-algorithm",
            id_token,
            "--userinfo-signed-response-alg",
            userinfo,
        ]);
        assert!(made.status.success(), "{made:?}");
        assert_eq!(
            stored(value(&made, "client")).await,
            (id_token.to_owned(), Some(userinfo.to_owned()))
        );
    }

    // An algorithm no tenant signs with is refused with the context's code,
    // and nothing is made.
    for (option, name, code) in [
        (
            "--id-token-algorithm",
            "HS256",
            "oauth.client_id_token_algorithm_invalid",
        ),
        (
            "--userinfo-signed-response-alg",
            "none",
            "oauth.client_userinfo_algorithm_invalid",
        ),
        (
            "--userinfo-signed-response-alg",
            "ES384",
            "oauth.client_userinfo_algorithm_invalid",
        ),
    ] {
        let refused = client(&[option, name]);
        assert!(!refused.status.success(), "{option} {name}");
        assert!(text(&refused.stderr).contains(code), "{refused:?}");
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth.client")
        .fetch_one(database.owner())
        .await
        .expect("count");
    assert_eq!(count, 5, "the refused clients were not made");
}
