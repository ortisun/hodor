//! A directory provisions people and groups through the SCIM server of the
//! real server binary, against a real database, with an access token it
//! got with its own credentials.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgApplicationStore, PgClientStore, PgResourceServerStore, PgTenantDirectory, PgTenantRepository,
};
use hodor_kernel::{Caller, SystemClock, TenantContext};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
    ClientSettings, ClientType, CreateClient, CreateResourceServer, GrantType,
    ResourceServerSettings, ScopeDefinition,
};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;

mod support;
use support::{Server, start_server_with};

/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";
const SCIM: &str = "urn:hodor:scim";
const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const ENTERPRISE: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

struct Credentials {
    id: String,
    secret: String,
}

struct Opened {
    /// Allowed the scope `scim`.
    directory: Credentials,
    /// Allowed only another scope of SCIM's resource server.
    auditor: Credentials,
}

fn applications(database: &TestDatabase) -> ApplicationService {
    ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(database.app().clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    })
}

async fn client(
    applications: &ApplicationService,
    tenant: &TenantContext,
    application_id: ApplicationId,
    scopes: &[&str],
) -> Credentials {
    let mut settings = ClientSettings::new(
        "Directory",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    settings.authentication_method = AuthenticationMethod::ClientSecretBasic;
    settings.allowed_scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    let (client, secret) = applications
        .create_client(
            tenant,
            CreateClient {
                application_id,
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    Credentials {
        id: client.id().to_string(),
        secret: secret.expect("a secret").expose().to_owned(),
    }
}

/// A tenant that opened SCIM: a resource server with the audience
/// `urn:hodor:scim`, and a client of the directory.
async fn open(database: &TestDatabase, slug: &str) -> Opened {
    let created = TenantService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        Arc::new(SystemClock),
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
    let context = TenantContext::assume(created.id());
    let applications = applications(database);
    let scim = applications
        .create_application(
            &context,
            ApplicationSettings {
                name: "SCIM".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application")
        .id();
    applications
        .create_resource_server(
            &context,
            CreateResourceServer {
                application_id: scim,
                audience: SCIM.to_owned(),
                settings: ResourceServerSettings {
                    name: "SCIM".to_owned(),
                    scopes: ["scim", "scim:audit"]
                        .iter()
                        .map(|scope| ScopeDefinition {
                            name: (*scope).to_owned(),
                            description: (*scope).to_owned(),
                        })
                        .collect(),
                },
            },
            Caller::system(),
        )
        .await
        .expect("resource server");
    let directory_application = applications
        .create_application(
            &context,
            ApplicationSettings {
                name: "Directory".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application")
        .id();
    Opened {
        directory: client(&applications, &context, directory_application, &["scim"]).await,
        auditor: client(
            &applications,
            &context,
            directory_application,
            &["scim:audit"],
        )
        .await,
    }
}

fn basic(client: &Credentials) -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{}", client.id, client.secret))
    )
}

async fn token(server: &Server, slug: &str, client: &Credentials, scope: &str) -> String {
    let response = reqwest::Client::new()
        .post(format!("{}/t/{slug}/oauth2/token", server.base))
        .header("authorization", basic(client))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("grant_type", "client_credentials"),
                    ("resource", SCIM),
                    ("scope", scope),
                ])
                .finish(),
        )
        .send()
        .await
        .expect("token response");
    let status = response.status();
    let body: Value = response.json().await.expect("token body");
    assert_eq!(status, StatusCode::OK, "{body}");
    body["access_token"].as_str().expect("token").to_owned()
}

struct Answer {
    status: StatusCode,
    content_type: Option<String>,
    location: Option<String>,
    challenge: Option<String>,
    body: Value,
}

async fn scim(
    server: &Server,
    slug: &str,
    token: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Answer {
    let mut request = reqwest::Client::new()
        .request(method, format!("{}/t/{slug}/scim/v2{path}", server.base))
        .bearer_auth(token);
    if let Some(body) = body {
        request = request
            .header("content-type", "application/scim+json")
            .body(body.to_string());
    }
    let response = request.send().await.expect("response");
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let (content_type, location, challenge) = (
        header("content-type"),
        header("location"),
        header("www-authenticate"),
    );
    let status = response.status();
    let body = response.json().await.unwrap_or(Value::Null);
    Answer {
        status,
        content_type,
        location,
        challenge,
        body,
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one directory's day, step by step")]
async fn a_directory_provisions_people_and_groups_and_is_recorded_as_the_actor() {
    let database = TestDatabase::start().await;
    let acme = open(&database, "acme").await;
    let server = start_server_with(&database, &[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let access = token(&server, "acme", &acme.directory, "scim").await;

    let config = scim(
        &server,
        "acme",
        &access,
        Method::GET,
        "/ServiceProviderConfig",
        None,
    )
    .await;
    assert_eq!(config.status, StatusCode::OK);
    assert_eq!(
        config.content_type.as_deref(),
        Some("application/scim+json")
    );
    assert_eq!(config.body["patch"]["supported"], false);

    // The directory creates a person, with their work address as userName.
    let created = scim(
        &server,
        "acme",
        &access,
        Method::POST,
        "/Users",
        Some(json!({
            "schemas": [USER, ENTERPRISE],
            "userName": "bjensen@example.com",
            "externalId": "701984",
            "name": { "givenName": "Barbara", "familyName": "Jensen", "formatted": "Barbara Jensen" },
            "emails": [{ "value": "babs@jensen.org" }],
            ENTERPRISE: { "department": "Tour Operations", "manager": { "value": "26118915" } },
        })),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let id = created.body["id"].as_str().expect("an id").to_owned();
    assert_eq!(
        created.location.as_deref(),
        created.body["meta"]["location"].as_str()
    );
    assert_eq!(created.body["displayName"], "Barbara Jensen");
    assert_eq!(created.body[ENTERPRISE]["department"], "Tour Operations");
    let verified: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity.user_identifier WHERE verified_at IS NOT NULL",
    )
    .fetch_one(database.owner())
    .await
    .expect("a count");
    assert_eq!(verified, 2, "addresses SCIM sets count as verified");

    // It finds them again, by its own identifier and by a part of a name.
    for filter in [
        "externalId eq \"701984\"",
        "name.familyName sw \"jen\" and emails[value ew \".org\"]",
        "userName eq \"BJENSEN@example.com\"",
    ] {
        let path = format!(
            "/Users?{}",
            form_urlencoded::Serializer::new(String::new())
                .append_pair("filter", filter)
                .finish()
        );
        let found = scim(&server, "acme", &access, Method::GET, &path, None).await;
        assert_eq!(found.status, StatusCode::OK, "{}", found.body);
        assert_eq!(found.body["totalResults"], 1, "{filter}");
        assert_eq!(found.body["Resources"][0]["id"], id.as_str());
    }

    // It suspends them, and the person cannot sign in.
    let suspended = scim(
        &server,
        "acme",
        &access,
        Method::PUT,
        &format!("/Users/{id}"),
        Some(json!({
            "schemas": [USER],
            "userName": "bjensen@example.com",
            "externalId": "701984",
            "active": false,
        })),
    )
    .await;
    assert_eq!(suspended.status, StatusCode::OK, "{}", suspended.body);
    assert_eq!(suspended.body["active"], false);
    let status: String = sqlx::query_scalar("SELECT status FROM identity.\"user\"")
        .fetch_one(database.owner())
        .await
        .expect("a status");
    assert_eq!(status, "suspended");

    // It makes a group with the person in it, and deletes it.
    let group = scim(
        &server,
        "acme",
        &access,
        Method::POST,
        "/Groups",
        Some(json!({
            "schemas": [GROUP],
            "displayName": "Tour Operations",
            "externalId": "G-7",
            "members": [{ "value": id, "type": "User" }],
        })),
    )
    .await;
    assert_eq!(group.status, StatusCode::CREATED, "{}", group.body);
    let group_id = group.body["id"].as_str().expect("an id").to_owned();
    let person = scim(
        &server,
        "acme",
        &access,
        Method::GET,
        &format!("/Users/{id}"),
        None,
    )
    .await;
    assert_eq!(person.body["groups"][0]["value"], group_id.as_str());
    let found = scim(
        &server,
        "acme",
        &access,
        Method::GET,
        &format!("/Groups?filter=members%20eq%20%22{id}%22&sortBy=displayName"),
        None,
    )
    .await;
    assert_eq!(found.body["totalResults"], 1, "{}", found.body);
    let deleted = scim(
        &server,
        "acme",
        &access,
        Method::DELETE,
        &format!("/Groups/{group_id}"),
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);

    // Every change names the directory's client as its actor, and no
    // event carries what SCIM keeps.
    let events: Vec<(String, Value, Value)> = sqlx::query_as(
        "SELECT event_type, actor, payload FROM platform.outbox
         WHERE event_type LIKE 'identity.%' OR event_type LIKE 'provisioning.%'",
    )
    .fetch_all(database.owner())
    .await
    .expect("events");
    let changes: Vec<&(String, Value, Value)> = events.iter().collect();
    assert!(
        changes
            .iter()
            .any(|(kind, _, _)| kind == "identity.user_suspended")
    );
    assert!(
        changes
            .iter()
            .any(|(kind, _, _)| kind == "provisioning.user_attributes_changed")
    );
    for (kind, actor, payload) in &changes {
        assert_eq!(
            *actor,
            json!({ "kind": "client", "id": acme.directory.id }),
            "{kind}"
        );
        let payload = payload.to_string();
        for value in ["701984", "Tour Operations", "Jensen", "bjensen@example.com"] {
            assert!(!payload.contains(value), "{kind} carried {value}");
        }
    }

    // A token without the scope is refused; a revoked one at once.
    let auditor = token(&server, "acme", &acme.auditor, "scim:audit").await;
    let refused = scim(&server, "acme", &auditor, Method::GET, "/Users", None).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.body["status"], "403");
    assert!(
        refused
            .challenge
            .as_deref()
            .is_some_and(|challenge| challenge.contains("insufficient_scope"))
    );
    let revoked = reqwest::Client::new()
        .post(format!("{}/t/acme/oauth2/revoke", server.base))
        .header("authorization", basic(&acme.directory))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            form_urlencoded::Serializer::new(String::new())
                .append_pair("token", &access)
                .finish(),
        )
        .send()
        .await
        .expect("revocation");
    assert_eq!(revoked.status(), StatusCode::OK);
    let refused = scim(&server, "acme", &access, Method::GET, "/Users", None).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused.body["status"], "401");
    assert!(
        refused
            .challenge
            .is_some_and(|challenge| challenge.starts_with("Bearer"))
    );
}
