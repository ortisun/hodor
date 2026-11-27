//! The registration endpoint and the registration client address over
//! HTTP, with the OAuth context on its in-memory stores: what each refusal
//! answers, the answer of a registration, and reading, changing and
//! removing one with its registration access token.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "The registration
//! endpoint" and "Managing a registration".

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, DomainError, TenantContext, TenantId, Timestamp};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, ClientRegistrationService,
    NewInitialAccessToken, RegistrationSettings, RegistrationWay,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeDestinations, InMemoryStores, SectorDocuments, client_registration_service,
};
use hodor_protocol_http::{
    Limits, RegistrationState, ResolvedTenant, TenantResolver, TenantStatus, public_router,
    registration_routes,
};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;
use tower::ServiceExt as _;

struct Tenants {
    acme: TenantContext,
}

#[async_trait::async_trait]
impl TenantResolver for Tenants {
    async fn resolve(&self, slug: &str) -> Result<Option<ResolvedTenant>, DomainError> {
        match slug {
            "acme" => Ok(Some(ResolvedTenant {
                context: self.acme.clone(),
                status: TenantStatus::Active,
            })),
            _ => Ok(None),
        }
    }
}

struct World {
    router: Router,
    applications: ApplicationService,
    registration: ClientRegistrationService,
    acme: TenantContext,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let registration = client_registration_service(Arc::new(units.clone()), &stores, clock.clone());
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units),
        applications: Arc::new(stores.applications),
        clients: Arc::new(stores.clients),
        resource_servers: Arc::new(stores.resource_servers),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock,
    })
    .with_destinations(Arc::new(FakeDestinations))
    .with_sector_documents(Arc::new(SectorDocuments::default()));
    let acme = TenantContext::assume(TenantId::generate());
    let router = public_router(
        Arc::new(Tenants { acme: acme.clone() }),
        Router::new().nest(
            "/oauth2",
            registration_routes(RegistrationState {
                applications: applications.clone(),
                registration: registration.clone(),
                public_url: "https://login.example.com".to_owned(),
                digest: Arc::new(FakeDigest),
            }),
        ),
        Router::new(),
        Limits::default(),
    );
    World {
        router,
        applications,
        registration,
        acme,
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Reply {
    fn header(&self, name: header::HeaderName) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    fn refused_with(&self, status: StatusCode, error: &str) {
        assert_eq!(self.status, status, "{}", self.body);
        assert_eq!(self.body["error"], error, "{}", self.body);
        assert!(
            self.body["error_description"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "{}",
            self.body
        );
        assert_eq!(self.header(header::CACHE_CONTROL), "no-store");
    }
}

const ISSUER: &str = "https://login.example.com/t/acme";

impl World {
    async fn post(&self, token: Option<&str>, content_type: &str, body: &str) -> Reply {
        self.send(
            Method::POST,
            "/t/acme/oauth2/register",
            token,
            content_type,
            body,
        )
        .await
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        content_type: &str,
        body: &str,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "login.example.com")
            .header(header::CONTENT_TYPE, content_type);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, token);
        }
        let response = self
            .router
            .clone()
            .oneshot(request.body(Body::from(body.to_owned())).expect("request"))
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.expect("body").to_bytes();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }

    async fn register(&self, token: Option<&str>, body: &Value) -> Reply {
        let authorization = token.map(|token| format!("Bearer {token}"));
        self.post(
            authorization.as_deref(),
            "application/json",
            &body.to_string(),
        )
        .await
    }

    async fn turned_on(&self, ways: &[RegistrationWay]) {
        self.turned_on_for(ways, 1).await;
    }

    async fn turned_on_for(&self, ways: &[RegistrationWay], max_clients: u32) {
        let application = self
            .applications
            .create_application(
                &self.acme,
                ApplicationSettings {
                    name: "Partners".to_owned(),
                    first_party: false,
                },
                Caller::system(),
            )
            .await
            .expect("application");
        self.registration
            .replace(
                &self.acme,
                RegistrationSettings {
                    enabled: true,
                    application_id: Some(application.id()),
                    ways: ways.to_vec(),
                    max_clients,
                    ..RegistrationSettings::default()
                },
                Caller::system(),
            )
            .await
            .expect("on");
    }

    async fn token(&self) -> String {
        self.registration
            .issue_token(
                &self.acme,
                NewInitialAccessToken {
                    name: "Partner portal team".to_owned(),
                    lifetime: Duration::days(7),
                    max_registrations: 5,
                },
                Caller::system(),
            )
            .await
            .expect("token")
            .1
            .expose()
            .to_owned()
    }
}

fn body() -> Value {
    json!({
        "redirect_uris": ["https://portal.partner.example/callback"],
        "client_name": "Partner portal",
        "logo_uri": "https://portal.partner.example/logo.png",
        "contacts": ["ops@partner.example"]
    })
}

#[tokio::test]
async fn while_registration_is_off_the_address_is_one_that_does_not_exist() {
    let world = world();
    for token in [None, Some("Bearer anything"), Some("Basic YTpi")] {
        let reply = world
            .post(token, "application/json", &body().to_string())
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{token:?}");
        assert_eq!(reply.body["code"], "route.not_found");
    }
}

#[tokio::test]
async fn a_registration_is_answered_201_with_the_client_and_its_secret_once() {
    let world = world();
    world
        .turned_on(&[RegistrationWay::InitialAccessToken])
        .await;
    let token = world.token().await;
    let reply = world.register(Some(&token), &body()).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    assert_eq!(reply.header(header::CACHE_CONTROL), "no-store");
    assert_eq!(reply.header(header::PRAGMA), "no-cache");
    assert!(reply.body["client_id"].as_str().is_some());
    assert!(reply.body["client_id_issued_at"].as_i64().is_some());
    assert!(
        reply.body["client_secret"]
            .as_str()
            .is_some_and(|secret| secret.starts_with("hodor_cs_"))
    );
    assert!(reply.body["client_secret_expires_at"].as_i64().is_some());
    assert_eq!(reply.body["client_name"], "Partner portal");
    assert_eq!(
        reply.body["logo_uri"],
        "https://portal.partner.example/logo.png"
    );
    assert_eq!(
        reply.body["token_endpoint_auth_method"],
        "client_secret_basic"
    );
    assert_eq!(reply.body["id_token_signed_response_alg"], "RS256");
    assert_eq!(reply.body["response_types"], json!(["code"]));
    assert!(
        reply.body.get("contacts").is_none(),
        "not kept, not answered"
    );
    assert!(
        reply.body["registration_access_token"]
            .as_str()
            .is_some_and(|token| token.starts_with("hodor_rat_"))
    );
    assert_eq!(
        reply.body["registration_client_uri"],
        format!(
            "{ISSUER}/oauth2/register/{}",
            reply.body["client_id"].as_str().expect("an identifier")
        )
    );
}

#[tokio::test]
async fn a_missing_or_bad_initial_access_token_is_answered_401() {
    let world = world();
    world
        .turned_on(&[RegistrationWay::InitialAccessToken])
        .await;
    let reply = world.register(None, &body()).await;
    reply.refused_with(StatusCode::UNAUTHORIZED, "invalid_token");
    assert_eq!(
        reply.header(header::WWW_AUTHENTICATE),
        format!("Bearer realm=\"{ISSUER}\"")
    );
    for authorization in [
        "Bearer hodor_iat_0000000000000000000000000000000000000000000000000000000000000000",
        "Bearer not-a-token",
        "Basic YTpi",
    ] {
        let reply = world
            .post(Some(authorization), "application/json", &body().to_string())
            .await;
        reply.refused_with(StatusCode::UNAUTHORIZED, "invalid_token");
        assert_eq!(
            reply.header(header::WWW_AUTHENTICATE),
            format!("Bearer realm=\"{ISSUER}\", error=\"invalid_token\""),
            "{authorization}"
        );
    }
}

#[tokio::test]
async fn each_refusal_of_the_metadata_has_its_error_of_rfc_7591() {
    let world = world();
    world.turned_on(&[RegistrationWay::Open]).await;
    let with = |member: &str, value: Value| {
        let mut body = body();
        body[member] = value;
        body
    };
    for (body, error) in [
        (json!(["an array"]), "invalid_client_metadata"),
        (
            with("id_token_encrypted_response_alg", json!("RSA-OAEP")),
            "invalid_client_metadata",
        ),
        (
            // A key set address for a client that does not use
            // `private_key_jwt`.
            with("jwks_uri", json!("https://portal.partner.example/jwks")),
            "invalid_client_metadata",
        ),
        (
            with("response_types", json!(["code id_token token"])),
            "invalid_client_metadata",
        ),
        (
            with("scope", json!("openid groups")),
            "invalid_client_metadata",
        ),
        (
            with("logo_uri", json!("http://portal.partner.example/logo.png")),
            "invalid_client_metadata",
        ),
        (
            with(
                "redirect_uris",
                json!(["https://portal.partner.example/callback#fragment"]),
            ),
            "invalid_redirect_uri",
        ),
        (
            with("redirect_uris", json!(["http://127.0.0.1:8080/callback"])),
            "invalid_redirect_uri",
        ),
        (
            with("software_statement", json!("eyJhbGciOiJSUzI1NiJ9.e30.c2ln")),
            "unapproved_software_statement",
        ),
    ] {
        let reply = world.register(None, &body).await;
        reply.refused_with(StatusCode::BAD_REQUEST, error);
    }
    // A body that is not JSON, or not said to be.
    world
        .post(None, "application/json", "{not json")
        .await
        .refused_with(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    world
        .post(None, "application/x-www-form-urlencoded", "redirect_uris=x")
        .await
        .refused_with(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    // The description names the member.
    let reply = world
        .register(
            None,
            &with("id_token_encrypted_response_alg", json!("RSA-OAEP")),
        )
        .await;
    assert!(
        reply.body["error_description"]
            .as_str()
            .is_some_and(|text| text.contains("`id_token_encrypted_response_alg`")),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn the_bound_of_the_application_is_answered_403() {
    let world = world();
    world.turned_on(&[RegistrationWay::Open]).await;
    let first = world.register(None, &body()).await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.body);
    world
        .register(None, &body())
        .await
        .refused_with(StatusCode::FORBIDDEN, "access_denied");
}

#[tokio::test]
async fn the_bound_of_an_address_is_answered_429_with_the_wait() {
    let world = world();
    world.turned_on(&[RegistrationWay::Open]).await;
    // Without a known address, every request counts as one address; the
    // application's bound is lifted for the test.
    let application = world
        .registration
        .settings(&world.acme)
        .await
        .expect("settings")
        .settings;
    world
        .registration
        .replace(
            &world.acme,
            RegistrationSettings {
                max_clients: 100,
                ..application
            },
            Caller::system(),
        )
        .await
        .expect("bound lifted");
    for _ in 0..10 {
        let reply = world.register(None, &body()).await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    }
    let reply = world.register(None, &body()).await;
    reply.refused_with(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable");
    assert_eq!(reply.header(header::RETRY_AFTER), "60");
}

/// A client registered openly, with its registration client address as a
/// path of the router, and its registration access token.
async fn registered(world: &World, body: &Value) -> (Value, String, String) {
    world.turned_on_for(&[RegistrationWay::Open], 10).await;
    let reply = world.register(None, body).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let uri = reply.body["registration_client_uri"]
        .as_str()
        .expect("an address")
        .to_owned();
    let path = uri
        .strip_prefix("https://login.example.com")
        .expect("on this installation")
        .to_owned();
    let token = reply.body["registration_access_token"]
        .as_str()
        .expect("a token")
        .to_owned();
    (reply.body, path, token)
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

#[tokio::test]
async fn a_registration_is_read_with_its_token_and_the_same_token_answered() {
    let world = world();
    let (registered, path, token) = registered(&world, &body()).await;
    let reply = world
        .send(
            Method::GET,
            &path,
            Some(&bearer(&token)),
            "application/json",
            "",
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.header(header::CACHE_CONTROL), "no-store");
    assert!(
        reply
            .header(header::CONTENT_TYPE)
            .starts_with("application/json")
    );
    assert_eq!(reply.body["client_id"], registered["client_id"]);
    assert_eq!(reply.body["client_name"], "Partner portal");
    assert_eq!(reply.body["registration_access_token"], token);
    assert_eq!(
        reply.body["registration_client_uri"],
        registered["registration_client_uri"]
    );
    assert!(reply.body.get("client_secret").is_none(), "kept as a hash");
}

#[tokio::test]
async fn a_change_is_answered_with_a_new_token_and_the_old_one_is_refused() {
    let world = world();
    let (registered, path, token) = registered(&world, &body()).await;
    let mut change = body();
    change["client_id"] = registered["client_id"].clone();
    change["client_name"] = json!("Partner portal, renamed");
    change["initiate_login_uri"] = json!("https://portal.partner.example/start");
    let reply = world
        .send(
            Method::PUT,
            &path,
            Some(&bearer(&token)),
            "application/json",
            &change.to_string(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.header(header::CACHE_CONTROL), "no-store");
    assert_eq!(reply.body["client_name"], "Partner portal, renamed");
    assert_eq!(
        reply.body["initiate_login_uri"],
        "https://portal.partner.example/start"
    );
    let new = reply.body["registration_access_token"]
        .as_str()
        .expect("a new token")
        .to_owned();
    assert_ne!(new, token);
    assert!(reply.body.get("client_secret").is_none());

    let old = world
        .send(
            Method::GET,
            &path,
            Some(&bearer(&token)),
            "application/json",
            "",
        )
        .await;
    old.refused_with(StatusCode::UNAUTHORIZED, "invalid_token");
    assert_eq!(
        old.header(header::WWW_AUTHENTICATE),
        format!("Bearer realm=\"{ISSUER}\", error=\"invalid_token\"")
    );
    let read = world
        .send(
            Method::GET,
            &path,
            Some(&bearer(&new)),
            "application/json",
            "",
        )
        .await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body["client_name"], "Partner portal, renamed");
}

#[tokio::test]
async fn each_refusal_at_the_registration_client_address_has_its_answer() {
    let world = world();
    let (registered, path, token) = registered(&world, &body()).await;
    let (other, _, other_token) = {
        let reply = world.register(None, &body()).await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        (
            reply.body.clone(),
            (),
            reply.body["registration_access_token"]
                .as_str()
                .expect("a token")
                .to_owned(),
        )
    };
    assert_ne!(other["client_id"], registered["client_id"]);

    // No token: a challenge without an error, as RFC 6750 asks.
    let reply = world
        .send(Method::GET, &path, None, "application/json", "")
        .await;
    reply.refused_with(StatusCode::UNAUTHORIZED, "invalid_token");
    assert_eq!(
        reply.header(header::WWW_AUTHENTICATE),
        format!("Bearer realm=\"{ISSUER}\"")
    );
    // Every token that is not good, alike, for every method.
    for (path, authorization) in [
        (path.clone(), bearer(&other_token)),
        (path.clone(), bearer("hodor_rat_short")),
        (path.clone(), "Basic YTpi".to_owned()),
        (
            "/t/acme/oauth2/register/not-a-client".to_owned(),
            bearer(&token),
        ),
        (
            "/t/acme/oauth2/register/0193f1d0-7c2e-7b1a-9a3e-5f6d7e8f9a0b".to_owned(),
            bearer(&token),
        ),
    ] {
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            let reply = world
                .send(
                    method.clone(),
                    &path,
                    Some(&authorization),
                    "application/json",
                    "{}",
                )
                .await;
            reply.refused_with(StatusCode::UNAUTHORIZED, "invalid_token");
            assert_eq!(
                reply.header(header::WWW_AUTHENTICATE),
                format!("Bearer realm=\"{ISSUER}\", error=\"invalid_token\""),
                "{method} {path}"
            );
        }
    }

    // A change whose members are refused, as at the registration endpoint.
    let change = |change: &dyn Fn(&mut Value)| {
        let mut body = body();
        body["client_id"] = registered["client_id"].clone();
        change(&mut body);
        body.to_string()
    };
    for (body, status, error) in [
        (
            change(&|body| body["client_id"] = other["client_id"].clone()),
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
        ),
        (
            change(&|body| {
                body["initiate_login_uri"] = json!("http://portal.partner.example/start")
            }),
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
        ),
        (
            change(&|body| {
                body["redirect_uris"] = json!(["https://portal.partner.example/cb#here"]);
            }),
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
        ),
        (
            change(&|body| body["software_statement"] = json!("eyJ")),
            StatusCode::BAD_REQUEST,
            "unapproved_software_statement",
        ),
        (
            "not json".to_owned(),
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
        ),
    ] {
        let reply = world
            .send(
                Method::PUT,
                &path,
                Some(&bearer(&token)),
                "application/json",
                &body,
            )
            .await;
        reply.refused_with(status, error);
    }
    // Refused, the token still works.
    let reply = world
        .send(
            Method::GET,
            &path,
            Some(&bearer(&token)),
            "application/json",
            "",
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);

    // A method the address does not take.
    let reply = world
        .send(
            Method::POST,
            &path,
            Some(&bearer(&token)),
            "application/json",
            "{}",
        )
        .await;
    assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn a_removal_is_answered_204_and_the_client_is_gone() {
    let world = world();
    let (_, path, token) = registered(&world, &body()).await;
    let reply = world
        .send(
            Method::DELETE,
            &path,
            Some(&bearer(&token)),
            "application/json",
            "",
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(reply.header(header::CACHE_CONTROL), "no-store");
    for method in [Method::GET, Method::DELETE] {
        world
            .send(method, &path, Some(&bearer(&token)), "application/json", "")
            .await
            .refused_with(StatusCode::UNAUTHORIZED, "invalid_token");
    }
}

#[tokio::test]
async fn while_registration_is_off_the_registration_client_address_does_not_exist() {
    let world = world();
    let (_, path, token) = registered(&world, &body()).await;
    let application = world
        .registration
        .settings(&world.acme)
        .await
        .expect("settings")
        .settings
        .application_id;
    world
        .registration
        .replace(
            &world.acme,
            RegistrationSettings {
                enabled: false,
                application_id: application,
                ways: vec![RegistrationWay::Open],
                ..RegistrationSettings::default()
            },
            Caller::system(),
        )
        .await
        .expect("off");
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let reply = world
            .send(
                method,
                &path,
                Some(&bearer(&token)),
                "application/json",
                "{}",
            )
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_eq!(reply.body["code"], "route.not_found");
    }
}
