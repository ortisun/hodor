//! `hodor-ext-authz` against the real server binary and a real database:
//! its decisions are the ones `evaluate` gives for the same question, it
//! proves who it is with its mesh identity alone, it checks the signature
//! of a bearer token against the tenant's published key set before asking
//! Hodor anything, and every failure is a denial. The latency of a check
//! is measured by the ignored test `latency`.
//!
//! The tests connect from 127.0.0.1, which plays the proxy in front of
//! Hodor: the server trusts it for `X-Forwarded-Client-Cert`, and the
//! adapter's HTTP client adds the element the adapter's sidecar would.
//!
//! Tokens are signed with the tenant's own keys, through the keys context
//! and the same root key as the server, as Hodor signs its access tokens.
//!
//! Specified in `docs/operations/hodor-ext-authz.md`, Decision 0058 and
//! Decision 0082.

#![allow(
    clippy::print_stderr,
    reason = "the latency test prints what it measured"
)]

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use envoy_types::ext_authz::v3::pb::{CheckRequest, CheckResponse};
use envoy_types::pb::envoy::service::auth::v3::AttributeContext;
use envoy_types::pb::envoy::service::auth::v3::attribute_context::{HttpRequest, Peer, Request};
use envoy_types::pb::envoy::service::auth::v3::authorization_client::AuthorizationClient;
use hodor_adapters_crypto::{LocalKeyProvider, OsRandom, SecretKeys, Sha256Digest};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgAccessTokenStore, PgEngineBindingStore, PgKeyStore, PgNativeRoleStore, PgRoleAssignmentStore,
    PgTenantDirectory, PgTenantRepository, PgUserRepository,
};
use hodor_authorization::api::{
    AssignmentScope, Attributes, AuthorizationService, BindingSettings, EngineId, EngineRegistry,
    EvaluationService, Namespace, NativeEngine, PermissionName, Role, RoleContents, RoleKey,
    RoleName, RoleService, Subject, SubjectAttributeSource, SubjectKind, Validity,
};
use hodor_credential::api::AccessTokenService;
use hodor_ext_authz::{ExtAuthz, Settings};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, DomainError, Secret, SystemClock, TenantContext};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

mod support;
use support::{Server, start_server_with};

/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";
const API: &str = "urn:hodor:authorization";
const ORDERS_AUDIENCE: &str = "https://orders.example";
const INVOICES_AUDIENCE: &str = "https://invoices.example";
/// The adapter's own mesh identity.
const ADAPTER: &str = "spiffe://cluster.local/ns/hodor/sa/hodor-ext-authz";
/// The protected workloads.
const ORDERS: &str = "spiffe://cluster.local/ns/shop/sa/orders";
const INVOICES: &str = "spiffe://cluster.local/ns/shop/sa/invoices";
/// A calling workload whose service account holds the reader role.
const WEB: &str = "spiffe://cluster.local/ns/shop/sa/web";
/// A calling workload no client binds.
const STRANGER: &str = "spiffe://cluster.local/ns/shop/sa/stranger";

/// What Hodor knows of nobody: enough to bind, the server resolves for
/// real.
struct NoAttributes;

#[async_trait::async_trait]
impl SubjectAttributeSource for NoAttributes {
    async fn attributes_of(
        &self,
        _tenant: &TenantContext,
        _subject: &Subject,
    ) -> Result<Attributes, DomainError> {
        Ok(Attributes::none())
    }
}

struct World {
    server: Server,
    /// Kept alive for as long as the server runs.
    _database: TestDatabase,
    acme: TenantContext,
    /// Another tenant, with a signing key of its own.
    globex: TenantContext,
    administrator: String,
    /// Holds the reader role on Orders.
    ana: String,
    /// Holds nothing.
    bob: String,
    /// The adapter's clients, of Orders and of Invoices.
    orders_client: String,
    invoices_client: String,
}

fn units(database: &TestDatabase) -> Arc<hodor_adapters_postgres::Database> {
    Arc::new(database.app().clone())
}

/// The keys context, with the server's own root key.
fn keys(database: &TestDatabase) -> KeyService {
    let root = Arc::new(SecretKeys::parse(&Secret::from(ROOT_KEY.to_owned())).expect("root"));
    KeyService::new(
        units(database),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root)),
        Arc::new(SystemClock),
    )
}

fn encoded(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("json"))
}

/// A token of `claims` signed with the active ES256 key of `tenant`, as
/// Hodor signs an access token.
async fn signed(database: &TestDatabase, tenant: &TenantContext, claims: &Value) -> String {
    let payload = encoded(claims);
    let (message, signature) = keys(database)
        .sign_naming_key(tenant, KeyAlgorithm::Es256, |kid| {
            let header = json!({ "alg": "ES256", "typ": "at+jwt", "kid": kid.to_string() });
            format!("{}.{payload}", encoded(&header)).into_bytes()
        })
        .await
        .expect("signed");
    format!(
        "{}.{}",
        String::from_utf8(message).expect("text"),
        URL_SAFE_NO_PAD.encode(&signature.bytes)
    )
}

async fn tenant(database: &TestDatabase, slug: &str) -> TenantContext {
    let created = TenantService::new(
        units(database),
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
    TenantContext::assume(created.id())
}

async fn person(database: &TestDatabase, tenant: &TenantContext, email: &str) -> String {
    IdentityService::new(
        units(database),
        Arc::new(PgUserRepository),
        Arc::new(SystemClock),
    )
    .create(
        tenant,
        CreateUser {
            kind: UserKind::Human,
            identifiers: vec![(IdentifierKind::Email, email.to_owned())],
            profile: Profile::default(),
            confirmed: true,
        },
        Caller::system(),
    )
    .await
    .expect("a person")
    .id()
    .to_string()
}

/// The native engine answers `namespace`, where `reader` holds
/// `order:read`, given to each of `readers`.
async fn native_roles(
    database: &TestDatabase,
    tenant: &TenantContext,
    namespace: &str,
    readers: &[&str],
) {
    let clock = Arc::new(SystemClock);
    let roles = RoleService::new(units(database), Arc::new(PgNativeRoleStore), clock.clone());
    let namespace = Namespace::parse(namespace).expect("namespace");
    let read = PermissionName::parse("order:read").expect("permission");
    roles
        .declare_permission(
            tenant,
            namespace.clone(),
            read.clone(),
            "reads an order",
            Caller::system(),
        )
        .await
        .expect("permission");
    let reader = RoleKey::new(namespace.clone(), RoleName::parse("reader").expect("name"));
    roles
        .define_role(
            tenant,
            reader.clone(),
            RoleContents {
                description: String::new(),
                permissions: BTreeSet::from([read]),
                includes: BTreeSet::new(),
                conditions: BTreeMap::new(),
            },
            Caller::system(),
        )
        .await
        .expect("role");
    for user in readers {
        roles
            .assign(
                tenant,
                Subject::new(SubjectKind::User, user).expect("subject"),
                reader.clone(),
                AssignmentScope::Tenant,
                Validity::default(),
                Caller::system(),
            )
            .await
            .expect("assignment");
    }
    let mut registry = EngineRegistry::new();
    registry
        .register(Arc::new(NativeEngine::new(
            units(database),
            Arc::new(PgRoleAssignmentStore),
            Arc::new(PgNativeRoleStore),
            clock.clone(),
        )))
        .expect("register");
    EvaluationService::new(
        units(database),
        Arc::new(PgRoleAssignmentStore),
        Arc::new(PgEngineBindingStore),
        Arc::new(NoAttributes),
        registry,
        clock,
    )
    .bind(
        tenant,
        BindingSettings::new(namespace, EngineId::native()),
        Caller::system(),
    )
    .await
    .expect("binding");
}

impl World {
    async fn admin(&self, method: Method, path: &str, body: Option<Value>) -> Value {
        let mut request = Client::new()
            .request(
                method,
                format!("{}/t/acme/api/v1/admin{path}", self.server.base),
            )
            .bearer_auth(&self.administrator);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("response");
        let status = response.status();
        let answer = response.json().await.unwrap_or(Value::Null);
        assert!(status.is_success(), "{path}: {status} {answer}");
        answer
    }

    async fn id_of(&self, path: &str, body: Value) -> String {
        self.admin(Method::POST, path, Some(body)).await["id"]
            .as_str()
            .expect("id")
            .to_owned()
    }

    /// A client of `application`, of the client credentials grant, acting
    /// as `principal` and bound to `identity` with `spiffe_x509`.
    async fn bound_client(
        &self,
        application: &str,
        principal: &str,
        identity: &str,
        scopes: &[&str],
    ) -> String {
        self.id_of(
            &format!("/applications/{application}/clients"),
            json!({
                "name": "Bound", "type": "confidential",
                "authentication_method": "spiffe_x509", "spiffe_id": identity,
                "grant_types": ["client_credentials"], "allowed_scopes": scopes,
                "principal": principal,
            }),
        )
        .await
    }

    fn issuer(&self) -> String {
        format!("{}/t/acme", self.server.base)
    }

    /// A token of `claims` signed with the tenant's own key.
    async fn token(&self, claims: &Value) -> String {
        signed(&self._database, &self.acme, claims).await
    }

    /// An access token as Hodor would issue `user` for `audience`.
    async fn token_for(&self, user: &str, audience: &str) -> String {
        self.token(&json!({ "iss": self.issuer(), "aud": audience, "sub": user, "exp": later() }))
            .await
    }

    /// How many decisions Hodor has recorded.
    async fn decisions(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM \"authorization\".decision_log")
            .fetch_one(self._database.owner())
            .await
            .expect("the record of decisions")
    }

    /// The configuration of an adapter for Orders and Invoices, reaching
    /// Hodor at `url`.
    fn settings(&self, url: &str) -> Settings {
        Settings::from_json(
            &json!({
                "hodor": { "url": url, "tenant": "acme", "issuer": self.issuer() },
                "token": "bearer",
                "applications": [
                    { "destination": ORDERS, "client_id": self.orders_client, "audience": ORDERS_AUDIENCE, "routes": [
                        { "methods": ["GET"], "path": "/orders/{id}", "resource_type": "order", "action": "read" },
                        { "methods": ["POST"], "path": "/orders/{id}/approve", "resource_type": "order", "action": "approve" }
                    ] },
                    { "destination": INVOICES, "client_id": self.invoices_client, "audience": INVOICES_AUDIENCE, "routes": [
                        { "methods": ["GET"], "path": "/invoices/{id}", "resource_type": "order", "action": "read" }
                    ] }
                ]
            })
            .to_string(),
        )
        .expect("settings")
    }

    /// An access token of `client` for the Authorization API, asked as the
    /// adapter asks it: its identity forwarded by the proxy, nothing else.
    async fn token_of(&self, client: &str) -> String {
        let response = adapter_http()
            .post(format!("{}/oauth2/token", self.issuer()))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([
                        ("grant_type", "client_credentials"),
                        ("client_id", client),
                        ("resource", API),
                        ("scope", "authz:evaluate"),
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

    /// What `evaluate` itself decides about `question`, asked with `token`.
    async fn evaluate(&self, token: &str, question: &Value) -> Value {
        let response = Client::new()
            .post(format!("{}/api/v1/authorization/evaluate", self.issuer()))
            .bearer_auth(token)
            .json(question)
            .send()
            .await
            .expect("evaluate");
        let status = response.status();
        let body: Value = response.json().await.expect("decision");
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

/// The adapter's HTTP client, with the element its sidecar adds to
/// `X-Forwarded-Client-Cert` on the way to Hodor.
fn adapter_http() -> Client {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-client-cert",
        HeaderValue::from_str(&format!(
            "By=spiffe://cluster.local/ns/hodor/sa/hodor;URI={ADAPTER}"
        ))
        .expect("header"),
    );
    Client::builder()
        .default_headers(headers)
        .build()
        .expect("client")
}

/// The tenant `acme` behind a proxy that forwards identities: an
/// Authorization API, Orders and Invoices answered by the native engine,
/// the adapter's service account with a client bound to its identity in
/// each, Ana who reads orders, Bob who does not, and the workload `web`,
/// whose service account reads orders too. Beside it, the tenant `globex`.
async fn world() -> World {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let globex = tenant(&database, "globex").await;
    keys(&database)
        .rotate_now(
            &globex,
            KeyAlgorithm::Es256,
            &RotationPolicy::DEFAULT,
            Caller::system(),
        )
        .await
        .expect("a signing key of globex");
    let root = person(&database, &acme, "root@example.com").await;
    let clock = Arc::new(SystemClock);
    let root_id = hodor_kernel::UserId::from_uuid(root.parse().expect("uuid"));
    AuthorizationService::new(
        units(&database),
        Arc::new(PgRoleAssignmentStore),
        clock.clone(),
    )
    .assign(&acme, root_id, Role::TenantAdministrator, Caller::system())
    .await
    .expect("role");
    let (_, secret) = AccessTokenService::new(
        units(&database),
        Arc::new(PgAccessTokenStore),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        clock,
    )
    .issue(
        &acme,
        root_id,
        "external authorization",
        time::Duration::minutes(30),
        Caller::system(),
    )
    .await
    .expect("token");
    let ana = person(&database, &acme, "ana@example.com").await;
    let bob = person(&database, &acme, "bob@example.com").await;
    let server = start_server_with(
        &database,
        &[
            ("HODOR_SECRET_KEYS", ROOT_KEY),
            ("HODOR_TRUSTED_PROXIES", "127.0.0.1"),
            ("HODOR_FORWARDED_HEADER", "none"),
            ("HODOR_CLIENT_IDENTITY_HEADER", "x-forwarded-client-cert"),
        ],
    )
    .await;
    let mut world = World {
        server,
        acme: acme.clone(),
        globex,
        administrator: secret.expose().to_owned(),
        ana,
        bob,
        orders_client: String::new(),
        invoices_client: String::new(),
        _database: database,
    };
    world.admin(Method::POST, "/keys/sig:rotate", None).await;
    world
        .admin(
            Method::POST,
            "/trust-domains",
            Some(json!({ "name": "cluster.local", "source": "mesh" })),
        )
        .await;
    let api = world
        .id_of(
            "/applications",
            json!({ "name": "Authorization API", "first_party": true }),
        )
        .await;
    world
        .admin(
            Method::POST,
            "/resource-servers",
            Some(json!({
                "application_id": api, "audience": API, "name": "Authorization API",
                "scopes": [
                    { "name": "authz:evaluate", "description": "Evaluate" },
                    { "name": "authz:simulate", "description": "Simulate" },
                    { "name": "authz:explain", "description": "Explain" }
                ]
            })),
        )
        .await;
    let mut applications = Vec::new();
    for (name, audience) in [("Orders", ORDERS_AUDIENCE), ("Invoices", INVOICES_AUDIENCE)] {
        let application = world
            .id_of(
                "/applications",
                json!({ "name": name, "first_party": true }),
            )
            .await;
        world
            .admin(
                Method::POST,
                "/resource-servers",
                Some(json!({
                    "application_id": application, "audience": audience, "name": name,
                    "scopes": [{ "name": "read", "description": "Read" }]
                })),
            )
            .await;
        applications.push(application);
    }
    let adapter = world
        .id_of(
            "/service-accounts",
            json!({ "name": "hodor-ext-authz", "owners": [root] }),
        )
        .await;
    // One client per application, all of one service account, all bound
    // to the adapter's one identity (Decision 0058).
    world.orders_client = world
        .bound_client(&applications[0], &adapter, ADAPTER, &["authz:evaluate"])
        .await;
    world.invoices_client = world
        .bound_client(&applications[1], &adapter, ADAPTER, &["authz:evaluate"])
        .await;
    // The calling workload `web`: a service account whose client binds
    // its identity.
    let web = world
        .id_of(
            "/service-accounts",
            json!({ "name": "web", "owners": [root] }),
        )
        .await;
    world
        .bound_client(&applications[0], &web, WEB, &["read"])
        .await;
    native_roles(
        &world._database,
        &acme,
        ORDERS_AUDIENCE,
        &[&world.ana, &web],
    )
    .await;
    native_roles(&world._database, &acme, INVOICES_AUDIENCE, &[&world.bob]).await;
    world
}

/// The adapter, served on a port of its own until the sender is dropped.
async fn start_adapter(settings: Settings, http: Client) -> (SocketAddr, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(hodor_ext_authz::serve(
        listener,
        ExtAuthz::new(settings, http),
        async {
            let _ = stopped.await;
        },
    ));
    (address, stop)
}

async fn connect(address: SocketAddr) -> AuthorizationClient<tonic::transport::Channel> {
    AuthorizationClient::connect(format!("http://{address}"))
        .await
        .expect("connected")
}

fn later() -> f64 {
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
        + 300) as f64
}

/// A check as Envoy sends it: the caller's identity, the destination, the
/// method and path, and the bearer token, if any.
fn check(
    source: &str,
    destination: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
) -> CheckRequest {
    let headers = token
        .map(|token| HashMap::from([("authorization".to_owned(), format!("Bearer {token}"))]))
        .unwrap_or_default();
    CheckRequest {
        attributes: Some(AttributeContext {
            source: Some(Peer {
                principal: source.to_owned(),
                ..Peer::default()
            }),
            destination: Some(Peer {
                principal: destination.to_owned(),
                ..Peer::default()
            }),
            request: Some(Request {
                http: Some(HttpRequest {
                    method: method.to_owned(),
                    path: path.to_owned(),
                    headers,
                    ..HttpRequest::default()
                }),
                ..Request::default()
            }),
            ..AttributeContext::default()
        }),
    }
}

/// Whether the adapter allowed: `OK` with an OK response, or
/// `PERMISSION_DENIED` with a 403. Anything else fails the test.
fn allowed(response: &CheckResponse) -> bool {
    use envoy_types::ext_authz::v3::pb::HttpResponse;
    let code = response.status.as_ref().map(|status| status.code);
    match (&response.http_response, code) {
        (Some(HttpResponse::OkResponse(_)), Some(0)) => true,
        (Some(HttpResponse::DeniedResponse(denied)), Some(7)) => {
            assert_eq!(denied.status.as_ref().map(|status| status.code), Some(403));
            false
        }
        other => panic!("not an answer the proxy expects: {other:?}"),
    }
}

async fn ask(
    client: &mut AuthorizationClient<tonic::transport::Channel>,
    check: CheckRequest,
) -> bool {
    let response = client.check(check).await.expect("never a gRPC error");
    allowed(response.get_ref())
}

#[tokio::test]
async fn its_decisions_are_the_ones_evaluate_gives() {
    let world = world().await;
    let (address, _stop) = start_adapter(world.settings(&world.server.base), adapter_http()).await;
    let mut adapter = connect(address).await;
    let orders_token = world.token_of(&world.orders_client).await;
    let invoices_token = world.token_of(&world.invoices_client).await;
    let ana_orders = world.token_for(&world.ana, ORDERS_AUDIENCE).await;
    let bob_orders = world.token_for(&world.bob, ORDERS_AUDIENCE).await;
    let ana_invoices = world.token_for(&world.ana, INVOICES_AUDIENCE).await;
    let bob_invoices = world.token_for(&world.bob, INVOICES_AUDIENCE).await;

    // (the check, the token evaluate is asked with, the same question, what
    // Hodor must decide)
    let cases = [
        (
            check(WEB, ORDERS, "GET", "/orders/1", Some(ana_orders.as_str())),
            &orders_token,
            json!({ "subject": { "type": "user", "id": world.ana },
                    "resource": { "type": "order", "id": "1" }, "action": "read" }),
            true,
        ),
        (
            check(WEB, ORDERS, "GET", "/orders/1", Some(bob_orders.as_str())),
            &orders_token,
            json!({ "subject": { "type": "user", "id": world.bob },
                    "resource": { "type": "order", "id": "1" }, "action": "read" }),
            false,
        ),
        (
            check(
                WEB,
                ORDERS,
                "POST",
                "/orders/1/approve",
                Some(ana_orders.as_str()),
            ),
            &orders_token,
            json!({ "subject": { "type": "user", "id": world.ana },
                    "resource": { "type": "order", "id": "1" }, "action": "approve" }),
            false,
        ),
        // The destination chooses the client, and so the resource server:
        // on Invoices Bob reads and Ana does not.
        (
            check(
                WEB,
                INVOICES,
                "GET",
                "/invoices/9",
                Some(bob_invoices.as_str()),
            ),
            &invoices_token,
            json!({ "subject": { "type": "user", "id": world.bob },
                    "resource": { "type": "order", "id": "9" }, "action": "read" }),
            true,
        ),
        (
            check(
                WEB,
                INVOICES,
                "GET",
                "/invoices/9",
                Some(ana_invoices.as_str()),
            ),
            &invoices_token,
            json!({ "subject": { "type": "user", "id": world.ana },
                    "resource": { "type": "order", "id": "9" }, "action": "read" }),
            false,
        ),
        // No token: the caller's identity, resolved by Hodor to the
        // service account bound to it.
        (
            check(WEB, ORDERS, "GET", "/orders/1", None),
            &orders_token,
            json!({ "subject": { "type": "workload_identity", "id": WEB },
                    "resource": { "type": "order", "id": "1" }, "action": "read" }),
            true,
        ),
        (
            check(STRANGER, ORDERS, "GET", "/orders/1", None),
            &orders_token,
            json!({ "subject": { "type": "workload_identity", "id": STRANGER },
                    "resource": { "type": "order", "id": "1" }, "action": "read" }),
            false,
        ),
    ];
    for (check, token, question, expected) in cases {
        let decided = world.evaluate(token, &question).await;
        let by_evaluate = decided["decision"] == "ALLOW";
        assert_eq!(by_evaluate, expected, "evaluate: {question} {decided}");
        assert_eq!(
            ask(&mut adapter, check).await,
            by_evaluate,
            "the adapter differs from evaluate on {question}"
        );
    }
}

#[tokio::test]
async fn a_workload_named_by_its_identity_is_its_service_account() {
    let world = world().await;
    let token = world.token_of(&world.orders_client).await;
    let read = |subject: Value| json!({ "subject": subject, "resource": { "type": "order", "id": "1" }, "action": "read" });
    let by_identity = world
        .evaluate(
            &token,
            &read(json!({ "type": "workload_identity", "id": WEB })),
        )
        .await;
    assert_eq!(by_identity["decision"], "ALLOW", "{by_identity}");
    // A Linkerd identity no client binds is a subject Hodor does not know.
    let unknown = world
        .evaluate(
            &token,
            &read(json!({
                "type": "workload_identity",
                "id": "web.shop.serviceaccount.identity.linkerd.cluster.local"
            })),
        )
        .await;
    assert_eq!(unknown["decision"], "DENY", "{unknown}");
    // An identity that reads as neither is refused.
    let response = Client::new()
        .post(format!("{}/api/v1/authorization/evaluate", world.issuer()))
        .bearer_auth(&token)
        .json(&read(
            json!({ "type": "workload_identity", "id": "not an identity" }),
        ))
        .send()
        .await
        .expect("evaluate");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let problem: Value = response.json().await.expect("problem");
    assert_eq!(problem["code"], "authorization.workload_identity_invalid");
}

#[tokio::test]
async fn every_failure_is_a_denial() {
    let world = world().await;
    let (address, _stop) = start_adapter(world.settings(&world.server.base), adapter_http()).await;
    let mut adapter = connect(address).await;
    let ana = world.token_for(&world.ana, ORDERS_AUDIENCE).await;
    assert!(
        ask(
            &mut adapter,
            check(WEB, ORDERS, "GET", "/orders/1", Some(ana.as_str()))
        )
        .await,
        "allowed when nothing fails"
    );

    // A destination with no client.
    assert!(
        !ask(
            &mut adapter,
            check(
                WEB,
                "spiffe://cluster.local/ns/shop/sa/unknown",
                "GET",
                "/orders/1",
                Some(ana.as_str())
            ),
        )
        .await
    );
    // A route with no rule.
    for (method, path) in [
        ("DELETE", "/orders/1"),
        ("GET", "/orders"),
        ("GET", "/orders/../1"),
    ] {
        assert!(
            !ask(
                &mut adapter,
                check(WEB, ORDERS, method, path, Some(ana.as_str()))
            )
            .await,
            "{method} {path}"
        );
    }
    // A token of another tenant, for the same person's identifier, signed
    // with that tenant's key, which this tenant's set does not hold; the
    // same claims signed with this tenant's key, whose issuer is not this
    // tenant's; and a token that expired.
    let globex_claims = json!({ "iss": format!("{}/t/globex", world.server.base), "aud": ORDERS_AUDIENCE, "sub": world.ana, "exp": later() });
    let globex = signed(&world._database, &world.globex, &globex_claims).await;
    assert!(
        !ask(
            &mut adapter,
            check(WEB, ORDERS, "GET", "/orders/1", Some(globex.as_str()))
        )
        .await
    );
    let globex = world.token(&globex_claims).await;
    assert!(
        !ask(
            &mut adapter,
            check(WEB, ORDERS, "GET", "/orders/1", Some(globex.as_str()))
        )
        .await
    );
    let expired = world
        .token(
            &json!({ "iss": world.issuer(), "aud": ORDERS_AUDIENCE, "sub": world.ana, "exp": 1 }),
        )
        .await;
    assert!(
        !ask(
            &mut adapter,
            check(WEB, ORDERS, "GET", "/orders/1", Some(expired.as_str()))
        )
        .await
    );
    // Ana holds a role on Orders, but these tokens were not issued for
    // Orders: one for Invoices, replayed at Orders' proxy; one that named
    // no resource server; one with no audience; and an ID token, whose
    // audience is a client.
    for aud in [
        json!(INVOICES_AUDIENCE),
        json!([INVOICES_AUDIENCE, world.issuer()]),
        json!(world.issuer()),
        Value::Null,
        json!(world.orders_client),
    ] {
        let mut claims = json!({ "iss": world.issuer(), "sub": world.ana, "exp": later() });
        if !aud.is_null() {
            claims["aud"] = aud.clone();
        }
        let replayed = world.token(&claims).await;
        assert!(
            !ask(
                &mut adapter,
                check(WEB, ORDERS, "GET", "/orders/1", Some(replayed.as_str()))
            )
            .await,
            "a token for {aud} at Orders"
        );
    }
    // A token for both is good at each.
    let both = world
        .token(&json!({ "iss": world.issuer(), "aud": [INVOICES_AUDIENCE, ORDERS_AUDIENCE], "sub": world.ana, "exp": later() }))
        .await;
    assert!(
        ask(
            &mut adapter,
            check(WEB, ORDERS, "GET", "/orders/1", Some(both.as_str()))
        )
        .await
    );
    // Claims that fail are never replaced by the caller's identity, whose
    // service account reads orders.
    assert!(ask(&mut adapter, check(WEB, ORDERS, "GET", "/orders/1", None)).await);
    // No subject at all.
    assert!(!ask(&mut adapter, check("", ORDERS, "GET", "/orders/1", None)).await);

    // The adapter's request carries no identity: Hodor refuses its client.
    let (anonymous, _stop_anonymous) =
        start_adapter(world.settings(&world.server.base), Client::new()).await;
    let mut anonymous = connect(anonymous).await;
    assert!(
        !ask(
            &mut anonymous,
            check(WEB, ORDERS, "GET", "/orders/1", Some(ana.as_str()))
        )
        .await
    );

    // Hodor unreachable: nothing listens where the adapter looks for it.
    let closed = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let nowhere = format!("http://{}", closed.local_addr().expect("address"));
    drop(closed);
    let (unreachable, _stop_unreachable) =
        start_adapter(world.settings(&nowhere), adapter_http()).await;
    let mut unreachable = connect(unreachable).await;
    assert!(
        !ask(
            &mut unreachable,
            check(WEB, ORDERS, "GET", "/orders/1", Some(ana.as_str()))
        )
        .await
    );

    // Hodor too slow: a listener that never answers, past the timeout.
    let silent = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let silent_url = format!("http://{}", silent.local_addr().expect("address"));
    let mut slow = world.settings(&silent_url);
    slow.timeout = Duration::from_millis(200);
    let (slow, _stop_slow) = start_adapter(slow, adapter_http()).await;
    let mut slow = connect(slow).await;
    let started = Instant::now();
    assert!(
        !ask(
            &mut slow,
            check(WEB, ORDERS, "GET", "/orders/1", Some(ana.as_str()))
        )
        .await
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the timeout held"
    );
    drop(silent);
}

/// A workload inside the mesh reaches the check before any proxy checked
/// its token (Decision 0082): a token whose claims look right but that the
/// tenant did not sign is denied before Hodor is asked, so Hodor records
/// no decision about it, and the answer is the one Hodor's own denial gets.
#[tokio::test]
async fn a_forged_token_is_denied_and_hodor_records_no_decision() {
    let world = world().await;
    let (address, _stop) = start_adapter(world.settings(&world.server.base), adapter_http()).await;
    let mut adapter = connect(address).await;
    let claims =
        json!({ "iss": world.issuer(), "aud": ORDERS_AUDIENCE, "sub": world.ana, "exp": later() });
    let mut bob_claims = claims.clone();
    bob_claims["sub"] = json!(world.bob);

    // The tenant's own token is let through, whoever calls, and recorded.
    let genuine = world.token(&claims).await;
    assert!(
        ask(
            &mut adapter,
            check(STRANGER, ORDERS, "GET", "/orders/1", Some(genuine.as_str()))
        )
        .await
    );
    assert_eq!(world.decisions().await, 1);

    let parts: Vec<&str> = genuine.split('.').collect();
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("base64url"))
            .expect("header");
    let kid = header["kid"].as_str().expect("kid");
    // A key of the forger's own.
    let forger = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).expect("a key");
    let forge = |header: &Value| {
        let message = format!("{}.{}", encoded(header), encoded(&claims));
        let signature = forger
            .sign(&SystemRandom::new(), message.as_bytes())
            .expect("signed");
        format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    };
    // The tenant's published key, as a confused library would take it for
    // an HMAC secret.
    let published: Value = Client::new()
        .get(format!("{}/oauth2/jwks", world.issuer()))
        .send()
        .await
        .expect("the key set")
        .json()
        .await
        .expect("a key set");
    let public_key = published["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .find(|key| key["kid"] == kid)
        .expect("the signing key is published")
        .to_string();
    let hs256 = {
        let message = format!(
            "{}.{}",
            encoded(&json!({ "alg": "HS256", "kid": kid })),
            encoded(&claims)
        );
        let tag = aws_lc_rs::hmac::sign(
            &aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, public_key.as_bytes()),
            message.as_bytes(),
        );
        format!("{message}.{}", URL_SAFE_NO_PAD.encode(tag.as_ref()))
    };
    let forged = [
        // Signed by the forger under the tenant's `kid`, and under one of
        // its own.
        forge(&json!({ "alg": "ES256", "typ": "at+jwt", "kid": kid })),
        forge(&json!({ "alg": "ES256", "typ": "at+jwt", "kid": "forged" })),
        // No signature at all.
        format!(
            "{}.{}.",
            encoded(&json!({ "alg": "none" })),
            encoded(&claims)
        ),
        format!(
            "{}.{}.AA",
            encoded(&json!({ "alg": "none", "kid": kid })),
            encoded(&claims)
        ),
        hs256,
        // The tenant's signature, with Bob's claims in place of Ana's.
        format!("{}.{}.{}", parts[0], encoded(&bob_claims), parts[2]),
    ];
    for token in &forged {
        assert!(
            !ask(
                &mut adapter,
                check(STRANGER, ORDERS, "GET", "/orders/1", Some(token.as_str()))
            )
            .await,
            "{token}"
        );
    }
    assert_eq!(
        world.decisions().await,
        1,
        "Hodor recorded a decision about a forged token"
    );

    // Bob holds no role: Hodor denies, and records it. The answer is the
    // same as for a forged token.
    let bob = world.token(&bob_claims).await;
    let by_hodor = adapter
        .check(check(
            STRANGER,
            ORDERS,
            "GET",
            "/orders/1",
            Some(bob.as_str()),
        ))
        .await
        .expect("an answer")
        .into_inner();
    let before_hodor = adapter
        .check(check(
            STRANGER,
            ORDERS,
            "GET",
            "/orders/1",
            Some(forged[0].as_str()),
        ))
        .await
        .expect("an answer")
        .into_inner();
    assert!(!allowed(&by_hodor));
    assert_eq!(by_hodor, before_hodor, "the denials tell nothing apart");
    assert_eq!(world.decisions().await, 2);
}

/// The latency of a check through the adapter, and of `evaluate` alone,
/// at the 50th and 99th percentiles. Run with
/// `cargo test --release -p hodor-server --test ext_authz -- --ignored --nocapture latency`;
/// the numbers are published in `docs/operations/hodor-ext-authz.md`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement, run by hand and published"]
async fn latency() {
    const WARM_UP: usize = 200;
    const MEASURED: usize = 2000;
    let world = world().await;
    // A long timeout: this measures how long a decision takes, so a slow
    // one is counted rather than denied.
    let mut settings = world.settings(&world.server.base);
    settings.timeout = Duration::from_secs(30);
    let (address, _stop) = start_adapter(settings, adapter_http()).await;
    let mut adapter = connect(address).await;
    let token = world.token_of(&world.orders_client).await;
    let ana = world.token_for(&world.ana, ORDERS_AUDIENCE).await;
    let question = json!({ "subject": { "type": "user", "id": world.ana },
                           "resource": { "type": "order", "id": "1" }, "action": "read" });
    let http = Client::new();
    let evaluate = format!("{}/api/v1/authorization/evaluate", world.issuer());

    let mut through_adapter = Vec::with_capacity(MEASURED);
    let mut direct = Vec::with_capacity(MEASURED);
    for round in 0..WARM_UP + MEASURED {
        let started = Instant::now();
        assert!(
            ask(
                &mut adapter,
                check(WEB, ORDERS, "GET", "/orders/1", Some(ana.as_str()))
            )
            .await
        );
        let adapter_took = started.elapsed();
        let started = Instant::now();
        let response = http
            .post(&evaluate)
            .bearer_auth(&token)
            .json(&question)
            .send()
            .await
            .expect("evaluate");
        assert_eq!(response.status(), StatusCode::OK);
        let _ = response.bytes().await.expect("body");
        let direct_took = started.elapsed();
        if round >= WARM_UP {
            through_adapter.push(adapter_took);
            direct.push(direct_took);
        }
    }
    let percentile = |samples: &mut Vec<Duration>, rank: f64| {
        samples.sort();
        let index = ((samples.len() as f64) * rank).ceil() as usize - 1;
        samples[index.min(samples.len() - 1)].as_secs_f64() * 1000.0
    };
    eprintln!(
        "through hodor-ext-authz: 50th percentile {:.2} ms, 99th percentile {:.2} ms",
        percentile(&mut through_adapter, 0.50),
        percentile(&mut through_adapter, 0.99)
    );
    eprintln!(
        "evaluate called directly: 50th percentile {:.2} ms, 99th percentile {:.2} ms",
        percentile(&mut direct, 0.50),
        percentile(&mut direct, 0.99)
    );
}
