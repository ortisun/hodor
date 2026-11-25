//! Access control lists, against the real server binary and a real
//! database: an administrator shares one document with a group, a service
//! account and a client through the administration interface, and an
//! application asks the Authorization API about them.
//!
//! Specified in `docs/architecture/contexts/authorization.md`, "Access
//! control lists".

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
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
use support::{Server, start_server_with};

/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";
const API: &str = "urn:hodor:authorization";
const DOCUMENTS: &str = "urn:example:documents";

struct World {
    server: Server,
    /// Kept alive for as long as the server runs.
    _database: TestDatabase,
    /// A person in the group `finance`.
    ana: UserId,
    /// A person in no group.
    bob: UserId,
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
    for email in ["ana@example.com", "bob@example.com", "root@example.com"] {
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
            people[2],
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
        people[2],
        "access lists",
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
        bob: people[1],
        administrator: secret.expose().to_owned(),
    }
}

impl World {
    /// A request to the administration interface as the administrator.
    async fn admin_with_status(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let url = format!("{}/t/acme/api/v1/admin{path}", self.server.base);
        let mut request = Client::new()
            .request(method, url)
            .bearer_auth(&self.administrator);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("response");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    /// A request to the administration interface that must succeed.
    async fn admin(&self, method: Method, path: &str, body: Option<Value>) -> Value {
        let (status, answer) = self.admin_with_status(method.clone(), path, body).await;
        assert!(status.is_success(), "{method} {path}: {status} {answer}");
        answer
    }

    /// An access token of the Documents client for the Authorization API.
    async fn token(&self, client: &(String, String)) -> String {
        let basic = STANDARD.encode(format!("{}:{}", client.0, client.1));
        let response = Client::new()
            .post(format!("{}/t/acme/oauth2/token", self.server.base))
            .header("authorization", format!("Basic {basic}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([
                        ("grant_type", "client_credentials"),
                        ("resource", API),
                        ("scope", "authz:evaluate"),
                    ])
                    .finish(),
            )
            .send()
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let issued: Value = response.json().await.expect("JSON");
        issued["access_token"].as_str().expect("a token").to_owned()
    }

    /// Asks whether `subject`, of `kind`, may read the document `document`.
    async fn reads(&self, token: &str, kind: &str, subject: &str, document: &str) -> Value {
        let response = Client::new()
            .post(format!(
                "{}/t/acme/api/v1/authorization/evaluate",
                self.server.base
            ))
            .bearer_auth(token)
            .json(&json!({
                "subject": { "type": kind, "id": subject },
                "resource": { "type": "document", "id": document },
                "action": "read",
                "context": {}
            }))
            .send()
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        response.json().await.expect("JSON")
    }
}

/// The Documents application, answered by the native engine, with the
/// permission `document:read` and a client allowed to ask the
/// Authorization API. Answers the resource server and the client's
/// identifier and secret.
async fn documents(world: &World) -> (String, (String, String)) {
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
    let application = world
        .admin(
            Method::POST,
            "/applications",
            Some(json!({ "name": "Documents", "first_party": true })),
        )
        .await;
    let server = world
        .admin(
            Method::POST,
            "/resource-servers",
            Some(json!({
                "application_id": application["id"], "audience": DOCUMENTS, "name": "Documents",
                "scopes": [{ "name": "documents:read", "description": "Read documents" }]
            })),
        )
        .await;
    let server = server["id"].as_str().expect("id").to_owned();
    world
        .admin(
            Method::PUT,
            &format!("/resource-servers/{server}/permissions/document:read"),
            Some(json!({ "description": "Read a document" })),
        )
        .await;
    world
        .admin(
            Method::PUT,
            &format!("/resource-servers/{server}/binding"),
            Some(json!({
                "engine": "native", "time_limit_milliseconds": 1000, "sensitive": false,
                "fail_open_actions": [], "trust_asserted": false
            })),
        )
        .await;
    let client = world
        .admin(
            Method::POST,
            &format!(
                "/applications/{}/clients",
                application["id"].as_str().expect("id")
            ),
            Some(json!({
                "name": "Documents back end", "type": "confidential",
                "grant_types": ["client_credentials"], "allowed_scopes": ["authz:evaluate"]
            })),
        )
        .await;
    (
        server,
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
async fn a_document_shared_with_a_group_is_read_by_its_members_until_they_leave() {
    let world = world().await;
    let (server, client) = documents(&world).await;
    let token = world.token(&client).await;
    let (ana, bob) = (world.ana.to_string(), world.bob.to_string());

    // Nothing is shared yet.
    let before = world.reads(&token, "user", &ana, "d-42").await;
    assert_eq!(before["decision"], "DENY", "{before}");

    let finance = world
        .admin(Method::POST, "/groups", Some(json!({ "name": "finance" })))
        .await;
    let finance = finance["id"].as_str().expect("id").to_owned();
    world
        .admin(
            Method::POST,
            &format!("/groups/{finance}/members"),
            Some(json!({ "kind": "user", "id": ana })),
        )
        .await;
    let entry = world
        .admin(
            Method::POST,
            &format!("/resource-servers/{server}/access-entries"),
            Some(json!({
                "permission": "document:read", "resource_id": "d-42",
                "principal": { "kind": "group", "id": finance }
            })),
        )
        .await;
    let entry = entry["id"].as_str().expect("id").to_owned();

    // A member reads it, and nothing else; someone else does not.
    let member = world.reads(&token, "user", &ana, "d-42").await;
    assert_eq!(member["decision"], "ALLOW", "{member}");
    assert_eq!(member["reason"], "matching_entry");
    let other_document = world.reads(&token, "user", &ana, "d-43").await;
    assert_eq!(other_document["decision"], "DENY");
    let someone_else = world.reads(&token, "user", &bob, "d-42").await;
    assert_eq!(someone_else["decision"], "DENY");

    // Taken out of the group: refused on the next decision.
    world
        .admin(
            Method::POST,
            &format!("/groups/{finance}/members:remove"),
            Some(json!({ "kind": "user", "id": ana })),
        )
        .await;
    let left = world.reads(&token, "user", &ana, "d-42").await;
    assert_eq!(left["decision"], "DENY", "{left}");

    // Back in, and allowed until the entry is removed.
    world
        .admin(
            Method::POST,
            &format!("/groups/{finance}/members"),
            Some(json!({ "kind": "user", "id": ana })),
        )
        .await;
    assert_eq!(
        world.reads(&token, "user", &ana, "d-42").await["decision"],
        "ALLOW"
    );
    let (status, _) = world
        .admin_with_status(Method::DELETE, &format!("/access-entries/{entry}"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        world.reads(&token, "user", &ana, "d-42").await["decision"],
        "DENY"
    );
}

#[tokio::test]
async fn a_document_is_shared_with_a_service_account_and_a_client() {
    let world = world().await;
    let (server, client) = documents(&world).await;
    let token = world.token(&client).await;
    let account = world
        .admin(
            Method::POST,
            "/service-accounts",
            Some(json!({ "name": "Indexer", "owners": [world.ana.to_string()] })),
        )
        .await;
    let account = account["id"].as_str().expect("id").to_owned();
    for (kind, id, document) in [
        ("user", account.as_str(), "d-7"),
        ("client", client.0.as_str(), "d-8"),
    ] {
        let (status, granted) = world
            .admin_with_status(
                Method::POST,
                &format!("/resource-servers/{server}/access-entries"),
                Some(json!({
                    "permission": "document:read", "resource_id": document,
                    "principal": { "kind": kind, "id": id }
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{granted}");
    }
    let by_account = world.reads(&token, "user", &account, "d-7").await;
    assert_eq!(by_account["decision"], "ALLOW", "{by_account}");
    let by_client = world.reads(&token, "client", &client.0, "d-8").await;
    assert_eq!(by_client["decision"], "ALLOW", "{by_client}");
    let crossed = world.reads(&token, "user", &account, "d-8").await;
    assert_eq!(crossed["decision"], "DENY");

    let listed = world
        .admin(
            Method::GET,
            &format!("/resource-servers/{server}/access-entries?principal_kind=user&principal_id={account}"),
            None,
        )
        .await;
    assert_eq!(listed["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["items"][0]["resource_id"], "d-7");
}
