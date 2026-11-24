//! Service accounts and agents, against the real server binary and a real
//! database: managed through the administration interface, acting through
//! a client bound to them, holding roles in the Authorization API, never
//! signing in, and stopped at once when disabled.
//!
//! Specified in `docs/architecture/contexts/identity.md`, "Service
//! accounts and agents", and `docs/architecture/contexts/oauth.md`,
//! "Clients that act as a workload".

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgAccessTokenStore, PgRoleAssignmentStore, PgTenantDirectory, PgTenantRepository,
    PgUserRepository,
};
use hodor_authorization::api::{AuthorizationService, Role};
use hodor_credential::api::AccessTokenService;
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, SystemClock, TenantContext, UserId};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;

mod support;
use support::{Browser, Server, start_server_with};

/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";
const API: &str = "urn:hodor:authorization";
const PAYROLL: &str = "urn:example:payroll";

struct World {
    server: Server,
    /// Kept alive for as long as the server runs.
    _database: TestDatabase,
    /// The person who owns the service account.
    ana: UserId,
    /// The tenant administrator's token for the administration interface.
    administrator: String,
}

async fn world() -> World {
    let database = TestDatabase::start().await;
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
            slug: "acme".to_owned(),
            display_name: "Acme".to_owned(),
            open_registration: false,
            system: false,
        },
        Caller::system(),
    )
    .await
    .expect("tenant");
    let tenant = TenantContext::assume(tenant.id());
    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone());
    let mut people = Vec::new();
    for email in ["ana@example.com", "root@example.com"] {
        let user = identity
            .create(
                &tenant,
                CreateUser {
                    kind: UserKind::Human,
                    identifiers: vec![(IdentifierKind::Email, email.to_owned())],
                    profile: Profile::default(),
                    confirmed: true,
                },
                Caller::system(),
            )
            .await
            .expect("a person");
        people.push(user.id());
    }
    AuthorizationService::new(units(), Arc::new(PgRoleAssignmentStore), clock.clone())
        .assign(
            &tenant,
            people[1],
            Role::TenantAdministrator,
            Caller::system(),
        )
        .await
        .expect("role");
    let (_, secret) = AccessTokenService::new(
        units(),
        Arc::new(PgAccessTokenStore),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        clock,
    )
    .issue(
        &tenant,
        people[1],
        "workloads",
        time::Duration::minutes(30),
        Caller::system(),
    )
    .await
    .expect("token");
    let server = start_server_with(&database, &[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    World {
        server,
        _database: database,
        ana: people[0],
        administrator: secret.expose().to_owned(),
    }
}

impl World {
    /// A request to the administration interface with `token`.
    async fn admin_with(
        &self,
        token: &str,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let url = format!("{}/t/acme/api/v1/admin{path}", self.server.base);
        let mut request = Client::new().request(method, url).bearer_auth(token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("response");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    /// A request to the administration interface as the administrator,
    /// which must succeed.
    async fn admin(&self, method: Method, path: &str, body: Option<Value>) -> Value {
        let (status, answer) = self
            .admin_with(&self.administrator, method.clone(), path, body)
            .await;
        assert!(status.is_success(), "{method} {path}: {status} {answer}");
        answer
    }

    /// A form to an OAuth endpoint, with the client's secret.
    async fn oauth(
        &self,
        endpoint: &str,
        client: &(String, String),
        pairs: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let basic = STANDARD.encode(format!("{}:{}", client.0, client.1));
        let response = Client::new()
            .post(format!("{}/t/acme/oauth2/{endpoint}", self.server.base))
            .header("authorization", format!("Basic {basic}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(pairs)
                    .finish(),
            )
            .send()
            .await
            .expect("response");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    async fn token(&self, client: &(String, String)) -> (StatusCode, Value) {
        self.oauth(
            "token",
            client,
            &[
                ("grant_type", "client_credentials"),
                ("resource", API),
                ("scope", "authz:evaluate"),
            ],
        )
        .await
    }

    async fn active(&self, client: &(String, String), token: &str) -> Value {
        let (status, answer) = self.oauth("introspect", client, &[("token", token)]).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        answer
    }

    /// Asks the Authorization API whether `subject` may approve an invoice.
    async fn evaluate(&self, token: &str, subject: &str) -> (StatusCode, Value) {
        let response = Client::new()
            .post(format!(
                "{}/t/acme/api/v1/authorization/evaluate",
                self.server.base
            ))
            .bearer_auth(token)
            .json(&json!({
                "subject": { "type": "user", "id": subject },
                "resource": { "type": "invoice", "id": "invoice-456" },
                "action": "approve",
                "context": {}
            }))
            .send()
            .await
            .expect("response");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    async fn userinfo(&self, token: &str) -> StatusCode {
        Client::new()
            .get(format!("{}/t/acme/oauth2/userinfo", self.server.base))
            .bearer_auth(token)
            .send()
            .await
            .expect("response")
            .status()
    }
}

/// The claims of a JSON Web Token, read without checking it.
fn claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("a payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url")).expect("JSON")
}

/// Payroll asks the Authorization API about its invoices, answered by the
/// native engine from the role `approver`; the service account, its
/// client of Payroll and its role. Answers the service account and the
/// client's identifier and secret.
async fn payroll_with_a_service_account(world: &World) -> (String, (String, String)) {
    let api = world
        .admin(
            Method::POST,
            "/applications",
            Some(json!({ "name": "Authorization API", "first_party": true })),
        )
        .await;
    world
        .admin(
            Method::POST,
            "/resource-servers",
            Some(json!({
                "application_id": api["id"], "audience": API, "name": "Authorization API",
                "scopes": [{ "name": "authz:evaluate", "description": "Ask" }]
            })),
        )
        .await;
    let payroll = world
        .admin(
            Method::POST,
            "/applications",
            Some(json!({ "name": "Payroll", "first_party": true })),
        )
        .await;
    let server = world
        .admin(
            Method::POST,
            "/resource-servers",
            Some(json!({
                "application_id": payroll["id"], "audience": PAYROLL, "name": "Payroll",
                "scopes": [{ "name": "payroll:read", "description": "Read payroll" }]
            })),
        )
        .await;
    let server = server["id"].as_str().expect("id").to_owned();
    world
        .admin(
            Method::PUT,
            &format!("/resource-servers/{server}/permissions/invoice:approve"),
            Some(json!({ "description": "Approve an invoice" })),
        )
        .await;
    world
        .admin(
            Method::PUT,
            &format!("/resource-servers/{server}/roles/approver"),
            Some(json!({
                "description": "Approves invoices",
                "permissions": [{ "name": "invoice:approve" }],
                "includes": []
            })),
        )
        .await;
    world
        .admin(
            Method::PUT,
            &format!("/resource-servers/{server}/binding"),
            Some(json!({
                "engine": "native", "time_limit_milliseconds": 200, "sensitive": false,
                "fail_open_actions": [], "trust_asserted": false
            })),
        )
        .await;

    let account = world
        .admin(
            Method::POST,
            "/service-accounts",
            Some(json!({ "name": "Nightly export", "owners": [world.ana.to_string()] })),
        )
        .await;
    let account = account["id"].as_str().expect("id").to_owned();
    let client = world
        .admin(
            Method::POST,
            &format!(
                "/applications/{}/clients",
                payroll["id"].as_str().expect("id")
            ),
            Some(json!({
                "name": "Nightly export", "type": "confidential",
                "grant_types": ["client_credentials"], "allowed_scopes": ["authz:evaluate"],
                "principal": account
            })),
        )
        .await;
    world
        .admin(
            Method::POST,
            "/role-assignments",
            Some(json!({
                "principal": { "kind": "user", "id": account },
                "role": { "namespace": PAYROLL, "name": "approver" }
            })),
        )
        .await;
    (
        account,
        (
            client["id"].as_str().expect("id").to_owned(),
            client["client_secret"]
                .as_str()
                .expect("a secret")
                .to_owned(),
        ),
    )
}

#[tokio::test]
async fn a_service_account_acts_through_its_client_and_is_stopped_at_once_when_disabled() {
    let world = world().await;
    let (account, client) = payroll_with_a_service_account(&world).await;

    // Its client's token names it, and says it is a service account.
    let (status, issued) = world.token(&client).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let token = issued["access_token"].as_str().expect("a token").to_owned();
    let said = claims(&token);
    assert_eq!(said["sub"], account.as_str());
    assert_eq!(said["client_id"], client.0.as_str());
    assert_eq!(said["principal_kind"], "service_account");
    let introspected = world.active(&client, &token).await;
    assert_eq!(introspected["active"], true);
    assert_eq!(introspected["sub"], account.as_str());
    assert_eq!(introspected["principal_kind"], "service_account");

    // The role assigned to it counts in the Authorization API.
    let (status, decision) = world.evaluate(&token, &account).await;
    assert_eq!(status, StatusCode::OK, "{decision}");
    assert_eq!(decision["decision"], "ALLOW", "{decision}");
    let (_, nobody) = world.evaluate(&token, &world.ana.to_string()).await;
    assert_eq!(nobody["decision"], "DENY");

    // It is not a person: UserInfo and the administration interface refuse
    // its token.
    assert_eq!(world.userinfo(&token).await, StatusCode::UNAUTHORIZED);
    let (status, refused) = world.admin_with(&token, Method::GET, "/users", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused["code"], "admin.not_authenticated");

    // Disabled: everything it holds stops at once.
    let disabled = world
        .admin(
            Method::POST,
            &format!("/service-accounts/{account}:disable"),
            None,
        )
        .await;
    assert_eq!(disabled["status"], "disabled");
    assert_eq!(
        world.active(&client, &token).await,
        json!({ "active": false })
    );
    let (status, _) = world.evaluate(&token, &account).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(world.userinfo(&token).await, StatusCode::UNAUTHORIZED);
    let (status, refused) = world.token(&client).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{refused}");
    assert_eq!(refused["error"], "invalid_client");

    // Enabled again: a new token works, the revoked one never again.
    world
        .admin(
            Method::POST,
            &format!("/service-accounts/{account}:enable"),
            None,
        )
        .await;
    assert_eq!(
        world.active(&client, &token).await,
        json!({ "active": false })
    );
    let (status, again) = world.token(&client).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    let fresh = again["access_token"].as_str().expect("a token").to_owned();
    let (status, decision) = world.evaluate(&fresh, &account).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(decision["decision"], "ALLOW");

    // Deleted: its token stops, its client gets none, and it is gone.
    let (status, _) = world
        .admin_with(
            &world.administrator,
            Method::DELETE,
            &format!("/service-accounts/{account}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = world.evaluate(&fresh, &account).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = world.token(&client).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, gone) = world
        .admin_with(
            &world.administrator,
            Method::GET,
            &format!("/service-accounts/{account}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(gone["code"], "identity.workload_not_found");
}

#[tokio::test]
async fn a_service_account_or_an_agent_cannot_sign_in_through_the_interaction_interface() {
    let world = world().await;
    let owners = json!([world.ana.to_string()]);
    let account = world
        .admin(
            Method::POST,
            "/service-accounts",
            Some(json!({ "name": "robot", "owners": owners })),
        )
        .await;
    let agent = world
        .admin(
            Method::POST,
            "/agents",
            Some(json!({ "name": "helper", "owners": owners })),
        )
        .await;
    // Neither has a login identifier to type, so whatever is typed, its
    // identifier or its name included, finds nobody, and the sign-in
    // fails as for anyone unknown.
    for typed in [
        account["id"].as_str().expect("id"),
        "robot",
        agent["id"].as_str().expect("id"),
        "helper",
    ] {
        let mut browser = Browser::new(&world.server);
        let (_, answer) = browser.sign_in("acme", typed, "any password at all").await;
        assert_ne!(answer["status"], "completed", "{typed}: {answer}");
        assert!(
            !browser.cookies.contains_key("__Secure-hodor_session"),
            "{typed}: no session"
        );
    }
    // A client of the authorization code grant cannot be bound to one, so
    // nothing signs in a person as it either.
    let application = world
        .admin(
            Method::POST,
            "/applications",
            Some(json!({ "name": "Web", "first_party": true })),
        )
        .await;
    let (status, refused) = world
        .admin_with(
            &world.administrator,
            Method::POST,
            &format!(
                "/applications/{}/clients",
                application["id"].as_str().expect("id")
            ),
            Some(json!({
                "name": "Web", "type": "confidential",
                "grant_types": ["authorization_code"],
                "redirect_uris": ["https://web.example.com/callback"],
                "principal": account["id"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused["code"], "oauth.client_grants_invalid");
}
