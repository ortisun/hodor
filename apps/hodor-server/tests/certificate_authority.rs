//! The certificate authority of a tenant on the real server binary,
//! against a real database: nothing of it with the setting off, refused on
//! the local key provider when on, and its whole life for development.

use hodor_adapters_crypto::{OsRandom, Sha256Digest, check_path};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    OutboxDispatcher, PgAccessTokenStore, PgAuditLog, PgRoleAssignmentStore, PgTenantDirectory,
    PgTenantRepository, PgUserRepository,
};
use hodor_audit::api::{AuditHandler, AuditService};
use hodor_authorization::api::{AuthorizationService, Role};
use hodor_credential::api::AccessTokenService;
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, Clock as _, SystemClock, TenantContext};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Client, Method, StatusCode};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod support;
use support::{Server, start_server_with};

/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";

/// Creates a tenant with an administrator and an auditor, and a token for
/// each.
async fn tenant(database: &TestDatabase, slug: &str) -> (TenantContext, String, String) {
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(SystemClock);
    let tenant = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        clock.clone(),
    )
    .create(
        CreateTenant {
            slug: slug.to_owned(),
            display_name: slug.to_owned(),
            open_registration: false,
            system: false,
        },
        Caller::system(),
    )
    .await
    .expect("tenant");
    let tenant = TenantContext::assume(tenant.id());
    let mut tokens = Vec::new();
    for (name, role) in [
        ("root", Role::TenantAdministrator),
        ("auditor", Role::TenantAuditor),
    ] {
        let user = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
            .create(
                &tenant,
                CreateUser {
                    kind: UserKind::Human,
                    identifiers: vec![(IdentifierKind::Email, format!("{name}@{slug}.example"))],
                    profile: Profile::default(),
                    confirmed: true,
                },
                Caller::system(),
            )
            .await
            .expect("user")
            .id();
        AuthorizationService::new(units(), Arc::new(PgRoleAssignmentStore), clock.clone())
            .assign(&tenant, user, role, Caller::system())
            .await
            .expect("role");
        let (_, secret) = AccessTokenService::new(
            units(),
            Arc::new(PgAccessTokenStore),
            Arc::new(Sha256Digest),
            Arc::new(OsRandom),
            clock.clone(),
        )
        .issue(
            &tenant,
            user,
            "test",
            std::time::Duration::from_secs(600)
                .try_into()
                .expect("duration"),
            Caller::system(),
        )
        .await
        .expect("token");
        tokens.push(secret.expose().to_owned());
    }
    let auditor = tokens.pop().expect("auditor");
    let administrator = tokens.pop().expect("administrator");
    (tenant, administrator, auditor)
}

async fn call(
    server: &Server,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Client::new().request(method, format!("{}{path}", server.base));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.expect("response");
    let status = response.status();
    (
        status,
        response.json().await.unwrap_or(serde_json::Value::Null),
    )
}

/// Does the worker's part: turns every waiting event into an audit record.
async fn record_events(database: &TestDatabase) {
    let audit = AuditService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgAuditLog),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
    );
    let dispatcher = OutboxDispatcher::new(
        database.platform().clone(),
        database.app().clone(),
        vec![Arc::new(AuditHandler::new(audit))],
    );
    while dispatcher
        .dispatch_batch(100)
        .await
        .expect("dispatch")
        .delivered
        > 0
    {}
}

fn root_request() -> serde_json::Value {
    serde_json::json!({
        "kind": "root",
        "trust_domains": ["prod.example.com", "edge.example.com"],
        "intermediate_lifetime_days": 14
    })
}

#[tokio::test]
async fn with_the_authority_off_no_route_document_or_bundle_mentions_it() {
    let database = TestDatabase::start().await;
    let (_, administrator, _) = tenant(&database, "acme").await;
    let server = start_server_with(&database, &[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;

    for (method, path) in [
        (Method::GET, "/certificate-authority"),
        (Method::POST, "/certificate-authority"),
        (Method::POST, "/certificate-authority:install"),
        (Method::DELETE, "/certificate-authority"),
    ] {
        let (status, _) = call(
            &server,
            method.clone(),
            &format!("/t/acme/api/v1/admin{path}"),
            Some(&administrator),
            Some(root_request()),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
    }
    let (status, _) = call(
        &server,
        Method::GET,
        "/t/acme/certificate-authority/bundle",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    for document in [
        "/t/acme/api/v1/admin/openapi.json",
        "/t/acme/.well-known/openid-configuration",
        "/t/acme/.well-known/oauth-authorization-server",
    ] {
        let (status, body) = call(&server, Method::GET, document, None, None).await;
        assert_eq!(status, StatusCode::OK, "{document}");
        let written = body.to_string();
        assert!(!written.contains("certificate-authority"), "{document}");
        assert!(!written.contains("CertificateAuthority"), "{document}");
    }
}

#[tokio::test]
async fn the_server_refuses_to_start_an_authority_without_keys_or_with_a_wrong_setting() {
    let database = TestDatabase::start().await;
    for settings in [
        vec![("HODOR_CERTIFICATE_AUTHORITY", "on")],
        vec![
            ("HODOR_CERTIFICATE_AUTHORITY", "yes"),
            ("HODOR_SECRET_KEYS", ROOT_KEY),
        ],
    ] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_hodor-server"))
            .envs(settings.iter().copied())
            .env("HODOR_DATABASE_URL", database.app_url())
            .env("HODOR_LISTEN_ADDR", "127.0.0.1:0")
            .env("HODOR_OPS_ADDR", "127.0.0.1:0")
            .env("HODOR_LOG_FORMAT", "json")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the server starts");
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = process.try_wait().expect("status") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = process.kill();
                panic!("the server kept running with {settings:?}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert!(!status.success(), "{settings:?}");
        let output = process.wait_with_output().expect("output");
        let written =
            String::from_utf8_lossy(&[output.stdout, output.stderr].concat()).into_owned();
        assert!(written.contains("HODOR_CERTIFICATE_AUTHORITY"), "{written}");
    }
}

#[tokio::test]
async fn on_the_local_key_provider_an_authority_is_refused_outside_development() {
    let database = TestDatabase::start().await;
    let (_, administrator, _) = tenant(&database, "acme").await;
    let server = start_server_with(
        &database,
        &[
            ("HODOR_SECRET_KEYS", ROOT_KEY),
            ("HODOR_CERTIFICATE_AUTHORITY", "on"),
        ],
    )
    .await;
    let (status, body) = call(
        &server,
        Method::POST,
        "/t/acme/api/v1/admin/certificate-authority",
        Some(&administrator),
        Some(root_request()),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "keys.authority_provider_unsuitable");
    let (status, body) = call(
        &server,
        Method::GET,
        "/t/acme/api/v1/admin/certificate-authority",
        Some(&administrator),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "keys.authority_not_found");
}

#[tokio::test]
async fn an_authority_for_development_is_created_published_trusted_audited_and_removed() {
    let database = TestDatabase::start().await;
    let (_, administrator, auditor) = tenant(&database, "acme").await;
    let server = start_server_with(
        &database,
        &[
            ("HODOR_SECRET_KEYS", ROOT_KEY),
            ("HODOR_CERTIFICATE_AUTHORITY", "development"),
            ("HODOR_PUBLIC_URL", "https://id.example.com"),
        ],
    )
    .await;
    let admin = |path: &str| format!("/t/acme/api/v1/admin{path}");

    // The auditor reads, and may not create.
    let (status, _) = call(
        &server,
        Method::POST,
        &admin("/certificate-authority"),
        Some(&auditor),
        Some(root_request()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = call(
        &server,
        Method::POST,
        &admin("/certificate-authority"),
        Some(&administrator),
        Some(serde_json::json!({ "kind": "root", "trust_domains": ["under_score.example"] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "keys.authority_trust_domain_invalid");

    let (status, created) = call(
        &server,
        Method::POST,
        &admin("/certificate-authority"),
        Some(&administrator),
        Some(root_request()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["kind"], "root");
    assert_eq!(created["state"], "active");
    assert_eq!(created["for_development"], true);
    assert_eq!(created["key"]["provider"], "local");
    assert_eq!(created["key"]["algorithm"], "ES256");
    assert_eq!(created["intermediate_lifetime_days"], 14);
    assert_eq!(
        created["common_name"],
        "Hodor certificate authority (development)"
    );
    assert_eq!(
        created["name_constraints"],
        serde_json::json!({
            "permitted_uris": ["prod.example.com", "edge.example.com"],
            "permitted_dns_names": ["prod.example.com", "edge.example.com"],
            "excluded_ip_ranges": ["0.0.0.0/0", "::/0"],
        })
    );
    assert_eq!(
        created["bundle_endpoint"],
        "https://id.example.com/t/acme/certificate-authority/bundle"
    );
    assert!(created.get("certificate_signing_request").is_none());
    assert!(!created.to_string().contains("material"));
    let (status, read) = call(
        &server,
        Method::GET,
        &admin("/certificate-authority"),
        Some(&auditor),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read, created);
    let (status, again) = call(
        &server,
        Method::POST,
        &admin("/certificate-authority"),
        Some(&administrator),
        Some(root_request()),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(again["code"], "keys.authority_exists");

    // Its bundle is published, with the certificate the authority answers.
    let response = Client::new()
        .get(format!(
            "{}/t/acme/certificate-authority/bundle",
            server.base
        ))
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["cache-control"].to_str().ok(),
        Some("public, max-age=300")
    );
    let bundle: serde_json::Value = response.json().await.expect("JSON");
    assert_eq!(bundle["spiffe_refresh_hint"], 300);
    let element = &bundle["keys"][0];
    assert_eq!(element["use"], "x509-svid");
    let certificate_pem = created["certificate"].as_str().expect("PEM");
    let body: String = certificate_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    assert_eq!(element["x5c"][0], body.as_str());

    // Hodor's trust domains of those names hold it.
    let (_, domains) = call(
        &server,
        Method::GET,
        &admin("/trust-domains"),
        Some(&administrator),
        None,
    )
    .await;
    let items = domains["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    for domain in items {
        assert_eq!(domain["source"], "authority");
        assert_eq!(domain["bundle"], bundle);
    }
    let first = items[0]["id"].as_str().expect("id");
    let (status, refused) = call(
        &server,
        Method::PUT,
        &admin(&format!("/trust-domains/{first}")),
        Some(&administrator),
        Some(serde_json::json!({ "source": "mesh" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refused["code"], "keys.trust_domain_of_authority");

    // A workload certificate under it is checked against the bundle Hodor
    // keeps, through Hodor's own chain checking: the anchor reads, and a
    // certificate that is not under it does not chain.
    use base64::Engine as _;
    let anchor = base64::engine::general_purpose::STANDARD
        .decode(element["x5c"][0].as_str().expect("x5c"))
        .expect("base64");
    let refused = check_path(
        &anchor,
        &[],
        std::slice::from_ref(&anchor),
        SystemClock.now(),
    )
    .expect_err("an authority is not a workload");
    assert_eq!(refused.code(), "certificate.path_refused");

    // Every signature is audited.
    record_events(&database).await;
    let (_, records) = call(
        &server,
        Method::GET,
        &admin("/audit-records"),
        Some(&auditor),
        None,
    )
    .await;
    let actions: Vec<&str> = records["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|record| record["action"].as_str())
        .collect();
    for action in [
        "keys.authority_created",
        "keys.authority_signed",
        "keys.authority_activated",
        "keys.trust_domain_added",
    ] {
        assert!(actions.contains(&action), "{action} in {actions:?}");
    }
    let signed = records["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|record| record["action"] == "keys.authority_signed")
        .expect("a signature");
    assert_eq!(signed["details"]["signed"], "certificate");
    assert_eq!(signed["details"]["serial_number"], created["serial_number"]);

    // Removed, nothing of it stays.
    let (status, _) = call(
        &server,
        Method::DELETE,
        &admin("/certificate-authority"),
        Some(&administrator),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        &server,
        Method::GET,
        "/t/acme/certificate-authority/bundle",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, domains) = call(
        &server,
        Method::GET,
        &admin("/trust-domains"),
        Some(&administrator),
        None,
    )
    .await;
    assert_eq!(domains["items"], serde_json::json!([]));
}
