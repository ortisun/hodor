//! The administration interface on the real server binary, against a real
//! database: what an administrator may do, and what nobody else may.

use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    OutboxDispatcher, PgAccessTokenStore, PgAuditLog, PgRoleAssignmentStore, PgTenantDirectory,
    PgTenantRepository, PgUserRepository,
};
use hodor_audit::api::{AuditHandler, AuditService};
use hodor_authorization::api::{AuthorizationService, Role};
use hodor_credential::api::AccessTokenService;
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, SystemClock, TenantContext, UserId};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Client, Method, StatusCode};
use std::sync::Arc;

mod support;
use support::{Server, start_server};

/// Creates a tenant with one user holding the given roles, and a token for
/// that user: what the bootstrap command will do.
async fn tenant_with(
    database: &TestDatabase,
    slug: &str,
    roles: &[Role],
) -> (TenantContext, UserId, String) {
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
    let user = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
        .create(
            &tenant,
            CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, format!("root@{slug}.example"))],
                profile: Profile::default(),
                confirmed: true,
            },
            Caller::system(),
        )
        .await
        .expect("user")
        .id();
    let authorization =
        AuthorizationService::new(units(), Arc::new(PgRoleAssignmentStore), clock.clone());
    for role in roles {
        authorization
            .assign(&tenant, user, *role, Caller::system())
            .await
            .expect("role");
    }
    let (_, secret) = AccessTokenService::new(
        units(),
        Arc::new(PgAccessTokenStore),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        clock,
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
    (tenant, user, secret.expose().to_owned())
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

#[tokio::test]
async fn an_administrator_manages_users_and_reads_the_audit_log_on_the_running_server() {
    let database = TestDatabase::start().await;
    let (_, administrator, token) =
        tenant_with(&database, "acme", &[Role::TenantAdministrator]).await;
    let server = start_server(&database).await;
    let admin = "/t/acme/api/v1/admin";

    let (status, created) = call(
        &server,
        Method::POST,
        &format!("{admin}/users"),
        Some(&token),
        Some(serde_json::json!({ "email": "ana@example.com", "display_name": "Ana" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let ana = created["id"].as_str().expect("identifier").to_owned();

    let (status, listed) = call(
        &server,
        Method::GET,
        &format!("{admin}/users"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let addresses: Vec<&str> = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|user| user["identifiers"][0]["value"].as_str())
        .collect();
    assert_eq!(addresses, ["root@acme.example", "ana@example.com"]);

    let (status, suspended) = call(
        &server,
        Method::POST,
        &format!("{admin}/users/{ana}:suspend"),
        Some(&token),
        Some(serde_json::json!({ "reason": "left the company" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(suspended["status"], "suspended");

    // What was done is in the audit log, under the administrator's name,
    // and the log's chain holds together.
    record_events(&database).await;
    let (status, log) = call(
        &server,
        Method::GET,
        &format!("{admin}/audit-records?limit=200"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let records = log["items"].as_array().expect("items");
    let suspension = records
        .iter()
        .find(|record| record["action"] == "identity.user_suspended")
        .expect("the suspension is recorded");
    assert_eq!(suspension["actor"]["id"], administrator.to_string());
    assert_eq!(suspension["details"]["reason"], "left the company");
    for pair in records.windows(2) {
        assert_eq!(pair[1]["previous_hash"], pair[0]["hash"]);
    }
    assert!(!log.to_string().contains(&token));

    // The interface describes itself without a token.
    let (status, document) = call(
        &server,
        Method::GET,
        &format!("{admin}/openapi.json"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(document["openapi"], "3.1.0");
}

#[tokio::test]
async fn the_running_server_refuses_everyone_who_is_not_an_administrator_of_the_tenant() {
    let database = TestDatabase::start().await;
    let (_, _, acme_token) = tenant_with(&database, "acme", &[Role::TenantAdministrator]).await;
    let (_, _, globex_token) = tenant_with(&database, "globex", &[Role::TenantAdministrator]).await;
    let (_, _, auditor_token) = tenant_with(&database, "initech", &[Role::TenantAuditor]).await;
    let (_, _, nobody_token) = tenant_with(&database, "umbrella", &[]).await;
    let server = start_server(&database).await;
    let new_user = || Some(serde_json::json!({ "email": "ana@example.com" }));

    // No token, and a token of another tenant: not authenticated.
    for token in [None, Some(globex_token.as_str())] {
        let (status, body) = call(
            &server,
            Method::POST,
            "/t/acme/api/v1/admin/users",
            token,
            new_user(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "admin.not_authenticated");
    }
    // The same token is good in its own tenant.
    let (status, _) = call(
        &server,
        Method::GET,
        "/t/globex/api/v1/admin/users",
        Some(&globex_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // A user without a role may do nothing; an auditor may read and not
    // write.
    let (status, body) = call(
        &server,
        Method::GET,
        "/t/umbrella/api/v1/admin/users",
        Some(&nobody_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "admin.forbidden");
    let (status, _) = call(
        &server,
        Method::GET,
        "/t/initech/api/v1/admin/users",
        Some(&auditor_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &server,
        Method::POST,
        "/t/initech/api/v1/admin/users",
        Some(&auditor_token),
        new_user(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Nothing that was refused happened: Acme still has only its own
    // administrator, and no token is stored where it could be read.
    let (_, listed) = call(
        &server,
        Method::GET,
        "/t/acme/api/v1/admin/users",
        Some(&acme_token),
        None,
    )
    .await;
    assert_eq!(listed["items"].as_array().map(Vec::len), Some(1));
    let stored: String = sqlx::query_scalar(
        "SELECT string_agg(to_jsonb(t)::text, '') FROM credential.access_token t",
    )
    .fetch_one(database.owner())
    .await
    .expect("read");
    for token in [&acme_token, &globex_token, &auditor_token, &nobody_token] {
        assert!(!stored.contains(token.as_str()));
        assert!(!stored.contains(&token[9..]));
    }
}
