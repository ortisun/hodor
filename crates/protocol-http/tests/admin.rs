//! The administration interface, exercised over HTTP against the real
//! contexts running on their in-memory ports.
//!
//! The refusals are generated from the OpenAPI document: every operation
//! it lists is tried without a token, with tokens that are not good, with
//! a role that lacks the permission and with another tenant's token.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use hodor_audit::api::{AuditHandler, AuditService};
use hodor_audit::testing::InMemoryAuditLog;
use hodor_authorization::api::{AuthorizationService, Permission, Role};
use hodor_authorization::testing::InMemoryRoleAssignments;
use hodor_credential::api::AccessTokenService;
use hodor_credential::testing::InMemoryAccessTokens;
use hodor_federation::api::FederationService;
use hodor_federation::testing::InMemoryFederation;
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, DomainError, EventHandler, TenantContext, Timestamp, UnitOfWorkFactory, UserId,
};
use hodor_keys::api::{KeyService, RotationPolicy};
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_protocol_http::{
    ADMIN_OPENAPI, ADMIN_OPERATIONS, AdminState, Limits, ResolvedTenant, TenantResolver,
    TenantStatus, admin_routes, public_router,
};
use hodor_session::api::{
    Assurance, ClientInfo, SessionService, SessionTimeouts, SessionToken, StartSession,
};
use hodor_session::testing::{InMemorySessions, SequentialRandom};
use hodor_tenant::api::{CreateTenant, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use http_body_util::BodyExt as _;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::Duration;
use tower::ServiceExt as _;

struct Tenants {
    acme: TenantContext,
    globex: TenantContext,
}

#[async_trait::async_trait]
impl TenantResolver for Tenants {
    async fn resolve(&self, slug: &str) -> Result<Option<ResolvedTenant>, DomainError> {
        let context = match slug {
            "acme" => self.acme.clone(),
            "globex" => self.globex.clone(),
            _ => return Ok(None),
        };
        Ok(Some(ResolvedTenant {
            context,
            status: TenantStatus::Active,
        }))
    }
}

struct World {
    router: Router,
    clock: Arc<FixedClock>,
    units_of_work: InMemoryUnitOfWorkFactory,
    identity: IdentityService,
    tokens: AccessTokenService,
    authorization: AuthorizationService,
    sessions: SessionService,
    audit: AuditHandler,
    recorded: AtomicUsize,
    acme: TenantContext,
    globex: TenantContext,
    /// The administrator of Acme and their token.
    administrator: UserId,
    administrator_token: String,
}

/// The applications use cases on in-memory stores.
fn applications(
    units_of_work: &InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
) -> hodor_oauth::api::ApplicationService {
    let stores = hodor_oauth::testing::InMemoryStores::default();
    hodor_oauth::api::ApplicationService::new(hodor_oauth::api::ApplicationPorts {
        units_of_work: Arc::new(units_of_work.clone()),
        applications: Arc::new(stores.applications),
        clients: Arc::new(stores.clients),
        resource_servers: Arc::new(stores.resource_servers),
        digest: Arc::new(FakeDigest),
        random: Arc::new(hodor_oauth::testing::DistinctRandom),
        clock,
    })
}

async fn world() -> World {
    world_with_keys(true).await
}

async fn world_with_keys(with_keys: bool) -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let digest = Arc::new(FakeDigest);
    let units = || Arc::new(units_of_work.clone());

    let identity = IdentityService::new(units(), Arc::new(InMemoryUsers::default()), clock.clone());
    let tokens = AccessTokenService::new(
        units(),
        Arc::new(InMemoryAccessTokens::default()),
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    );
    let authorization = AuthorizationService::new(
        units(),
        Arc::new(InMemoryRoleAssignments::default()),
        clock.clone(),
    );
    let sessions = SessionService::new(
        units(),
        Arc::new(InMemorySessions::default()),
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    );
    let audit = AuditService::new(
        units(),
        Arc::new(InMemoryAuditLog::default()),
        digest,
        clock.clone(),
    );

    let providers = InMemoryFederation::default();
    let federation = FederationService::new(
        units(),
        Arc::new(providers.clone()),
        Arc::new(providers),
        Arc::new(FakeSecretBox),
        clock.clone(),
    )
    .allowing_directory_hosts(&["ldap.example.com:636".to_owned()]);

    let keys = with_keys.then(|| {
        KeyService::new(
            units(),
            Arc::new(InMemoryKeys::default()),
            Arc::new(FakeKeyProvider),
            clock.clone(),
        )
    });

    let tenant_rows = InMemoryTenants::default();
    let tenants = TenantService::new(
        units(),
        Arc::new(tenant_rows.clone()),
        Arc::new(tenant_rows),
        clock.clone(),
    );
    let mut contexts = Vec::new();
    for slug in ["acme", "globex"] {
        let created = tenants
            .create(
                CreateTenant {
                    slug: slug.to_owned(),
                    display_name: slug.to_uppercase(),
                    open_registration: false,
                    system: false,
                },
                Caller::system(),
            )
            .await
            .expect("tenant");
        contexts.push(TenantContext::assume(created.id()));
    }
    let (acme, globex) = (contexts[0].clone(), contexts[1].clone());
    let state = AdminState {
        tokens: tokens.clone(),
        authorization: authorization.clone(),
        identity: identity.clone(),
        sessions: sessions.clone(),
        audit: audit.clone(),
        federation: Some(federation),
        keys,
        key_rotation: RotationPolicy::DEFAULT,
        applications: applications(&units_of_work, clock.clone()),
        tenants,
        public_url: "https://auth.example".to_owned(),
    };
    let router = public_router(
        Arc::new(Tenants {
            acme: acme.clone(),
            globex: globex.clone(),
        }),
        Router::new().nest("/api/v1/admin", admin_routes(state)),
        Router::new(),
        Limits::default(),
    );

    let mut world = World {
        router,
        clock,
        units_of_work,
        identity,
        tokens,
        authorization,
        sessions,
        audit: AuditHandler::new(audit),
        recorded: AtomicUsize::new(0),
        acme,
        globex,
        administrator: UserId::generate(),
        administrator_token: String::new(),
    };
    let acme = world.acme.clone();
    let (administrator, token) = world
        .person(&acme, "root@example.com", &[Role::TenantAdministrator])
        .await;
    world.administrator = administrator;
    world.administrator_token = token;
    world
}

impl World {
    /// Creates a user in a tenant with the given roles and a token.
    async fn person(
        &self,
        tenant: &TenantContext,
        email: &str,
        roles: &[Role],
    ) -> (UserId, String) {
        let user = self
            .identity
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
            .expect("user")
            .id();
        for role in roles {
            self.authorization
                .assign(tenant, user, *role, Caller::system())
                .await
                .expect("role");
        }
        (user, self.token_for(tenant, user, Duration::hours(1)).await)
    }

    async fn token_for(&self, tenant: &TenantContext, user: UserId, lifetime: Duration) -> String {
        let (_, secret) = self
            .tokens
            .issue(tenant, user, "test", lifetime, Caller::system())
            .await
            .expect("token");
        secret.expose().to_owned()
    }

    async fn start_session(&self, user: UserId) -> SessionToken {
        self.sessions
            .start(
                &self.acme,
                StartSession {
                    user_id: user,
                    assurance: Assurance::SingleFactor,
                    methods: vec!["password".to_owned()],
                    timeouts: SessionTimeouts {
                        idle: Duration::minutes(30),
                        absolute: Duration::hours(12),
                    },
                    client: ClientInfo {
                        address: Some("203.0.113.9".to_owned()),
                        description: Some("Example Browser".to_owned()),
                    },
                },
                Caller::system(),
            )
            .await
            .expect("session")
            .1
    }

    /// Does the worker's part: turns the events announced so far into
    /// audit records.
    async fn record_audit(&self) {
        let events = self.units_of_work.committed_events();
        let from = self.recorded.swap(events.len(), Ordering::SeqCst);
        for event in &events[from..] {
            let tenant = TenantContext::assume(event.metadata.tenant_id);
            let mut uow = self.units_of_work.begin(&tenant).await.expect("begin");
            self.audit
                .handle(uow.as_mut(), event)
                .await
                .expect("recorded");
            uow.commit().await.expect("commit");
        }
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        authorization: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "auth.example");
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .expect("request");
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.expect("body").to_bytes();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        }
    }

    /// A request to Acme's interface as its administrator.
    async fn as_administrator(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Reply {
        self.send(
            method,
            &format!("/t/acme/api/v1/admin{path}"),
            Some(&format!("Bearer {}", self.administrator_token)),
            body,
        )
        .await
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: serde_json::Value,
}

impl Reply {
    fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or_default()
    }
}

/// One operation of the OpenAPI document.
struct Operation {
    method: Method,
    /// The path as the document writes it.
    template: String,
    permission: Permission,
}

impl Operation {
    /// A path that fits the template, naming things that do not exist.
    fn path(&self) -> String {
        format!(
            "/t/acme/api/v1/admin{}",
            self.template
                .replace("{user_id}", &UserId::generate().to_string())
                .replace("{session_id}", &UserId::generate().to_string())
                .replace("{provider_id}", &UserId::generate().to_string())
                .replace("{key_set}", "sig")
                .replace("{version_id}", &UserId::generate().to_string())
                .replace("{application_id}", &UserId::generate().to_string())
                .replace("{client_id}", &UserId::generate().to_string())
                .replace("{secret_id}", &UserId::generate().to_string())
                .replace("{key_id}", "a-key")
                .replace("{resource_server_id}", &UserId::generate().to_string())
        )
    }
}

fn documented_operations() -> Vec<Operation> {
    let document: serde_json::Value = serde_json::from_str(ADMIN_OPENAPI).expect("valid JSON");
    let mut operations = Vec::new();
    for (template, methods) in document["paths"].as_object().expect("paths") {
        for (method, operation) in methods.as_object().expect("operations") {
            let permission = operation["x-hodor-permission"]
                .as_str()
                .and_then(Permission::from_name)
                .unwrap_or_else(|| panic!("{method} {template} names no known permission"));
            operations.push(Operation {
                method: method.to_uppercase().parse().expect("method"),
                template: template.clone(),
                permission,
            });
        }
    }
    operations
}

#[test]
fn the_document_and_the_routes_list_the_same_operations_and_permissions() {
    let documented: BTreeSet<(String, String, &str)> = documented_operations()
        .iter()
        .map(|o| {
            (
                o.method.to_string(),
                o.template.clone(),
                o.permission.as_str(),
            )
        })
        .collect();
    let served: BTreeSet<(String, String, &str)> = ADMIN_OPERATIONS
        .iter()
        .map(|(method, path, permission)| {
            (
                (*method).to_owned(),
                (*path).to_owned(),
                permission.as_str(),
            )
        })
        .collect();
    assert_eq!(documented, served);
    assert_eq!(served.len(), 39);

    // Every operation says how it refuses.
    let document: serde_json::Value = serde_json::from_str(ADMIN_OPENAPI).expect("valid JSON");
    for (template, methods) in document["paths"].as_object().expect("paths") {
        for (method, operation) in methods.as_object().expect("operations") {
            for status in ["401", "403"] {
                assert!(
                    operation["responses"][status].is_object(),
                    "{method} {template} does not document {status}"
                );
            }
        }
    }
}

#[tokio::test]
async fn the_document_is_served_without_a_token() {
    let world = world().await;
    let reply = world
        .send(Method::GET, "/t/acme/api/v1/admin/openapi.json", None, None)
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body["openapi"], "3.1.0");
    assert_eq!(
        reply.body,
        serde_json::from_str::<serde_json::Value>(ADMIN_OPENAPI).expect("valid JSON")
    );
}

#[tokio::test]
async fn every_operation_refuses_a_request_that_is_not_authenticated_in_one_way() {
    let world = world().await;
    let (globex_administrator, globex_token) = world
        .person(
            &world.globex,
            "root@globex.example",
            &[Role::TenantAdministrator],
        )
        .await;
    let acme = world.acme.clone();
    // An administrator who was suspended, one whose token expired and one
    // whose token was revoked.
    let (suspended, suspended_token) = world
        .person(&acme, "gone@example.com", &[Role::TenantAdministrator])
        .await;
    world
        .identity
        .suspend(&acme, suspended, "left", Caller::system())
        .await
        .expect("suspended");
    let expired_token = world
        .token_for(&acme, world.administrator, Duration::minutes(1))
        .await;
    let (revoked, revoked_secret) = world
        .tokens
        .issue(
            &acme,
            world.administrator,
            "test",
            Duration::hours(1),
            Caller::system(),
        )
        .await
        .expect("token");
    world
        .tokens
        .revoke(&acme, revoked.id(), Caller::system())
        .await
        .expect("revoked");
    world.clock.advance(Duration::minutes(2));
    assert_ne!(globex_administrator, world.administrator);

    let not_good = [
        ("no token", None),
        ("an empty header", Some(String::new())),
        (
            "another scheme",
            Some(format!("Basic {}", world.administrator_token)),
        ),
        ("no scheme", Some(world.administrator_token.clone())),
        ("a malformed token", Some("Bearer not-a-token".to_owned())),
        (
            "an unknown token",
            Some(format!("Bearer hodor_at_{}", "0".repeat(64))),
        ),
        (
            "another tenant's token",
            Some(format!("Bearer {globex_token}")),
        ),
        (
            "a suspended user's token",
            Some(format!("Bearer {suspended_token}")),
        ),
        ("an expired token", Some(format!("Bearer {expired_token}"))),
        (
            "a revoked token",
            Some(format!("Bearer {}", revoked_secret.expose())),
        ),
    ];
    let mut answers = BTreeSet::new();
    for operation in documented_operations() {
        for (what, authorization) in &not_good {
            // A body that would be refused if it were read: it must not be.
            let reply = world
                .send(
                    operation.method.clone(),
                    &operation.path(),
                    authorization.as_deref(),
                    Some(serde_json::json!({ "unexpected": true })),
                )
                .await;
            let label = format!("{} {} with {what}", operation.method, operation.template);
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{label}");
            assert_eq!(reply.code(), "admin.not_authenticated", "{label}");
            assert_eq!(
                reply
                    .headers
                    .get(header::WWW_AUTHENTICATE)
                    .map(|v| v.as_bytes()),
                Some(b"Bearer".as_slice()),
                "{label}"
            );
            answers.insert(reply.body["detail"].to_string());
        }
    }
    assert_eq!(answers.len(), 1, "every refusal says the same: {answers:?}");
    // Nothing was done by any of them: the tenant still has the two users
    // this test made, and the one who was suspended is the only one.
    let users = world.as_administrator(Method::GET, "/users", None).await;
    assert_eq!(users.status, StatusCode::OK);
    let statuses: Vec<&str> = users.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|user| user["status"].as_str())
        .collect();
    assert_eq!(statuses, ["active", "suspended"]);
}

#[tokio::test]
async fn every_operation_is_refused_to_a_user_without_the_permission() {
    let world = world().await;
    let acme = world.acme.clone();
    let (_, nobody) = world.person(&acme, "nobody@example.com", &[]).await;
    let (_, auditor) = world
        .person(&acme, "auditor@example.com", &[Role::TenantAuditor])
        .await;
    // An administrator of another tenant who is also a user here, without
    // a role here: a role in one tenant means nothing in another.
    let (visitor, _) = world.person(&acme, "visitor@example.com", &[]).await;
    world
        .authorization
        .assign(
            &world.globex,
            visitor,
            Role::TenantAdministrator,
            Caller::system(),
        )
        .await
        .expect("role elsewhere");
    let visitor = world.token_for(&acme, visitor, Duration::hours(1)).await;

    for operation in documented_operations() {
        let label = format!("{} {}", operation.method, operation.template);
        for token in [&nobody, &visitor] {
            let reply = world
                .send(
                    operation.method.clone(),
                    &operation.path(),
                    Some(&format!("Bearer {token}")),
                    Some(serde_json::json!({ "unexpected": true })),
                )
                .await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{label}");
            assert_eq!(reply.code(), "admin.forbidden", "{label}");
        }

        // An auditor may read and may change nothing.
        let reply = world
            .send(
                operation.method.clone(),
                &operation.path(),
                Some(&format!("Bearer {auditor}")),
                None,
            )
            .await;
        if Role::TenantAuditor.allows(operation.permission) {
            assert_ne!(reply.status, StatusCode::FORBIDDEN, "{label}");
            assert_ne!(reply.status, StatusCode::UNAUTHORIZED, "{label}");
            assert_eq!(operation.method, Method::GET, "{label}");
        } else {
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{label}");
            assert_ne!(operation.method, Method::GET, "{label}");
        }
    }
}

#[tokio::test]
async fn every_documented_operation_is_answered_for_an_administrator() {
    let world = world().await;
    for operation in documented_operations() {
        let reply = world
            .send(
                operation.method.clone(),
                &operation.path(),
                Some(&format!("Bearer {}", world.administrator_token)),
                Some(serde_json::json!({ "email": "new@example.com", "reason": "test" })),
            )
            .await;
        let label = format!(
            "{} {}: {}",
            operation.method, operation.template, reply.status
        );
        assert_ne!(reply.status, StatusCode::UNAUTHORIZED, "{label}");
        assert_ne!(reply.status, StatusCode::FORBIDDEN, "{label}");
        assert_ne!(reply.status, StatusCode::METHOD_NOT_ALLOWED, "{label}");
        assert_ne!(reply.code(), "route.not_found", "{label}");
        assert!(!reply.status.is_server_error(), "{label}");
    }
}

#[tokio::test]
async fn an_administrator_creates_reads_and_suspends_a_user() {
    let world = world().await;

    let created = world
        .as_administrator(
            Method::POST,
            "/users",
            Some(serde_json::json!({
                "email": "Ana@Example.com", "display_name": "Ana Silva", "locale": "pt-BR"
            })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let user = &created.body;
    assert_eq!(user["status"], "active");
    assert_eq!(user["kind"], "human");
    assert_eq!(user["display_name"], "Ana Silva");
    assert_eq!(user["locale"], "pt-BR");
    assert_eq!(user["identifiers"][0]["kind"], "email");
    assert_eq!(user["identifiers"][0]["verified"], false);
    assert_eq!(user["identifiers"][0]["primary"], true);
    let id = user["id"].as_str().expect("identifier").to_owned();

    let read = world
        .as_administrator(Method::GET, &format!("/users/{id}"), None)
        .await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body, created.body);

    // The same address again is a conflict, and this interface may say so.
    let again = world
        .as_administrator(
            Method::POST,
            "/users",
            Some(serde_json::json!({ "email": "ana@example.com" })),
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.code(), "identity.identifier_taken");

    let suspended = world
        .as_administrator(
            Method::POST,
            &format!("/users/{id}:suspend"),
            Some(serde_json::json!({ "reason": "left the company" })),
        )
        .await;
    assert_eq!(suspended.status, StatusCode::OK);
    assert_eq!(suspended.body["status"], "suspended");
    assert_eq!(suspended.body["status_reason"], "left the company");

    let twice = world
        .as_administrator(
            Method::POST,
            &format!("/users/{id}:suspend"),
            Some(serde_json::json!({ "reason": "again" })),
        )
        .await;
    assert_eq!(twice.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn requests_that_are_allowed_and_wrong_are_refused_for_what_is_wrong() {
    let world = world().await;
    let missing = UserId::generate();
    let cases = [
        (
            Method::GET,
            format!("/users/{missing}"),
            None,
            404,
            "identity.user_not_found",
        ),
        (
            Method::GET,
            "/users/not-an-identifier".to_owned(),
            None,
            404,
            "identity.user_not_found",
        ),
        (
            Method::POST,
            format!("/users/{missing}:suspend"),
            Some(serde_json::json!({ "reason": "x" })),
            404,
            "identity.user_not_found",
        ),
        (
            Method::POST,
            format!("/users/{missing}:promote"),
            Some(serde_json::json!({})),
            404,
            "route.not_found",
        ),
        (
            Method::POST,
            format!("/users/{}:suspend", world.administrator),
            Some(serde_json::json!({})),
            422,
            "request.body_invalid",
        ),
        (
            Method::POST,
            "/users".to_owned(),
            Some(serde_json::json!({ "mail": "x" })),
            422,
            "request.body_invalid",
        ),
        (
            Method::GET,
            format!("/users/{missing}/sessions"),
            None,
            404,
            "identity.user_not_found",
        ),
        (
            Method::DELETE,
            format!("/sessions/{missing}"),
            None,
            404,
            "session.not_found",
        ),
        (
            Method::DELETE,
            "/sessions/nope".to_owned(),
            None,
            404,
            "session.not_found",
        ),
        (
            Method::GET,
            "/users?limit=0".to_owned(),
            None,
            422,
            "request.query_invalid",
        ),
        (
            Method::GET,
            "/users?limit=201".to_owned(),
            None,
            422,
            "request.query_invalid",
        ),
        (
            Method::GET,
            "/users?limit=many".to_owned(),
            None,
            422,
            "request.query_invalid",
        ),
        (
            Method::GET,
            "/users?cursor=nope".to_owned(),
            None,
            422,
            "request.cursor_invalid",
        ),
        (
            Method::GET,
            "/audit-records?cursor=nope".to_owned(),
            None,
            422,
            "request.cursor_invalid",
        ),
    ];
    for (method, path, body, status, code) in cases {
        let reply = world.as_administrator(method.clone(), &path, body).await;
        assert_eq!(reply.status.as_u16(), status, "{method} {path}");
        assert_eq!(reply.code(), code, "{method} {path}");
    }

    let invalid = world
        .as_administrator(
            Method::POST,
            "/users",
            Some(serde_json::json!({ "email": "not an address" })),
        )
        .await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn users_are_listed_a_page_at_a_time_in_the_order_they_were_created() {
    let world = world().await;
    for index in 0..4 {
        let created = world
            .as_administrator(
                Method::POST,
                "/users",
                Some(serde_json::json!({ "email": format!("person{index}@example.com") })),
            )
            .await;
        assert_eq!(created.status, StatusCode::CREATED);
    }
    // Another tenant's users are not this tenant's.
    world
        .person(&world.globex, "other@globex.example", &[])
        .await;

    let mut seen = Vec::new();
    let mut path = "/users?limit=2".to_owned();
    for _ in 0..10 {
        let page = world.as_administrator(Method::GET, &path, None).await;
        assert_eq!(page.status, StatusCode::OK);
        let items = page.body["items"].as_array().expect("items");
        assert!(items.len() <= 2);
        seen.extend(items.iter().map(|user| {
            user["identifiers"][0]["value"]
                .as_str()
                .expect("value")
                .to_owned()
        }));
        match page.body["next_cursor"].as_str() {
            Some(cursor) => path = format!("/users?limit=2&cursor={cursor}"),
            None => break,
        }
    }
    assert_eq!(
        seen,
        [
            "root@example.com",
            "person0@example.com",
            "person1@example.com",
            "person2@example.com",
            "person3@example.com"
        ]
    );
}

#[tokio::test]
async fn an_administrator_sees_and_ends_a_users_sessions() {
    let world = world().await;
    let acme = world.acme.clone();
    let (ana, _) = world.person(&acme, "ana@example.com", &[]).await;
    let token = world.start_session(ana).await;
    world.start_session(ana).await;

    let listed = world
        .as_administrator(Method::GET, &format!("/users/{ana}/sessions"), None)
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    let sessions = listed.body["items"].as_array().expect("items");
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0]["address"], "203.0.113.9");
    assert!(sessions[0].get("current").is_none());
    // No token of any session is in the list.
    assert!(!listed.body.to_string().contains(token.expose()));

    // The first session started is the last in the list.
    let first = sessions[1]["session_id"].as_str().expect("identifier");
    let ended = world
        .as_administrator(Method::DELETE, &format!("/sessions/{first}"), None)
        .await;
    assert_eq!(ended.status, StatusCode::NO_CONTENT);
    let found = world
        .sessions
        .find_by_token(&world.acme, token.expose())
        .await
        .expect("find");
    assert!(found.is_none(), "the session is ended");
    // Ending it again changes nothing.
    let again = world
        .as_administrator(Method::DELETE, &format!("/sessions/{first}"), None)
        .await;
    assert_eq!(again.status, StatusCode::NO_CONTENT);

    let remaining = world
        .as_administrator(Method::GET, &format!("/users/{ana}/sessions"), None)
        .await;
    assert_eq!(remaining.body["items"].as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn what_an_administrator_does_is_in_the_audit_log_under_their_name() {
    let world = world().await;
    let created = world
        .as_administrator(
            Method::POST,
            "/users",
            Some(serde_json::json!({ "email": "ana@example.com" })),
        )
        .await;
    let id = created.body["id"].as_str().expect("identifier").to_owned();
    world
        .as_administrator(
            Method::POST,
            &format!("/users/{id}:suspend"),
            Some(serde_json::json!({ "reason": "left the company" })),
        )
        .await;
    world.record_audit().await;

    let mut records = Vec::new();
    let mut path = "/audit-records?limit=3".to_owned();
    for _ in 0..20 {
        let page = world.as_administrator(Method::GET, &path, None).await;
        assert_eq!(page.status, StatusCode::OK);
        records.extend(page.body["items"].as_array().expect("items").clone());
        match page.body["next_cursor"].as_str() {
            Some(cursor) => path = format!("/audit-records?limit=3&cursor={cursor}"),
            None => break,
        }
    }

    // In order, without gaps, each following the one before.
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record["sequence"], index as u64 + 1);
        assert_eq!(record["hash"].as_str().map(str::len), Some(64));
        if index > 0 {
            assert_eq!(record["previous_hash"], records[index - 1]["hash"]);
        }
    }
    let suspended = records
        .iter()
        .find(|record| record["action"] == "identity.user_suspended")
        .expect("the suspension is recorded");
    assert_eq!(suspended["actor"]["kind"], "user");
    assert_eq!(suspended["actor"]["id"], world.administrator.to_string());
    assert_eq!(suspended["details"]["user_id"], id.as_str());
    assert_eq!(suspended["details"]["reason"], "left the company");
    // Issuing the administrator's token was recorded; the token was not.
    let everything = serde_json::Value::Array(records).to_string();
    assert!(everything.contains("credential.access_token_issued"));
    assert!(!everything.contains(&world.administrator_token));
    assert!(!everything.contains(&world.administrator_token[9..]));
    // Another tenant's log is not this tenant's.
    assert!(!everything.contains(&world.globex.tenant_id().to_string()));
}

const CLIENT_SECRET: &str = "the-client-secret-of-the-provider";

/// A change to the body that adds a provider.
type Change = fn(&mut serde_json::Value);

fn new_provider(alias: &str) -> serde_json::Value {
    serde_json::json!({
        "alias": alias,
        "display_name": "Example",
        "issuer": "https://accounts.example.com",
        "client_id": "hodor",
        "client_secret": CLIENT_SECRET,
    })
}

#[tokio::test]
async fn an_administrator_adds_changes_and_disables_an_identity_provider() {
    let world = world().await;

    let created = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(new_provider("example")),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let provider = &created.body;
    assert_eq!(provider["alias"], "example");
    assert_eq!(provider["kind"], "openid_connect");
    assert_eq!(provider["status"], "enabled");
    assert_eq!(provider["creates_users"], true);
    assert_eq!(
        provider["scopes"],
        serde_json::json!(["openid", "email", "profile"])
    );
    assert_eq!(
        provider["callback_address"],
        "https://auth.example/t/acme/account/providers/example/callback",
        "the address to register at the provider"
    );
    let id = provider["id"].as_str().expect("id").to_owned();
    let path = format!("/identity-providers/{id}");

    // What is left out of a change stays as it is.
    let changed = world
        .as_administrator(
            Method::PATCH,
            &path,
            Some(serde_json::json!({ "display_name": "Another name", "creates_users": false })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{:?}", changed.body);
    assert_eq!(changed.body["display_name"], "Another name");
    assert_eq!(changed.body["creates_users"], false);
    assert_eq!(changed.body["issuer"], "https://accounts.example.com");
    assert_eq!(changed.body["alias"], "example");

    let disabled = world
        .as_administrator(Method::POST, &format!("{path}:disable"), None)
        .await;
    assert_eq!(disabled.status, StatusCode::OK);
    assert_eq!(disabled.body["status"], "disabled");
    let enabled = world
        .as_administrator(Method::POST, &format!("{path}:enable"), None)
        .await;
    assert_eq!(enabled.body["status"], "enabled");

    let replaced = world
        .as_administrator(
            Method::PUT,
            &format!("{path}/client-secret"),
            Some(serde_json::json!({ "client_secret": "a brand new secret" })),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::NO_CONTENT);

    let read = world.as_administrator(Method::GET, &path, None).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body["display_name"], "Another name");
    let listed = world
        .as_administrator(Method::GET, "/identity-providers", None)
        .await;
    assert_eq!(listed.body["items"].as_array().expect("items").len(), 1);

    // Each change was made by the administrator, and is announced as theirs.
    let said = format!("{:?}", world.units_of_work.committed_events());
    for event in [
        "federation.provider_created",
        "federation.provider_changed",
        "federation.provider_disabled",
        "federation.provider_enabled",
        "federation.provider_secret_changed",
    ] {
        assert!(said.contains(event), "{event}");
    }
    assert!(said.contains(&world.administrator.to_string()));
}

#[tokio::test]
async fn a_client_secret_is_never_part_of_an_answer() {
    let world = world().await;
    let created = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(new_provider("example")),
        )
        .await;
    let id = created.body["id"].as_str().expect("id").to_owned();
    let path = format!("/identity-providers/{id}");

    let answers = [
        created,
        world.as_administrator(Method::GET, &path, None).await,
        world
            .as_administrator(Method::GET, "/identity-providers", None)
            .await,
        world
            .as_administrator(
                Method::PATCH,
                &path,
                Some(serde_json::json!({ "client_id": "other" })),
            )
            .await,
        world
            .as_administrator(Method::POST, &format!("{path}:disable"), None)
            .await,
        world
            .as_administrator(
                Method::PUT,
                &format!("{path}/client-secret"),
                Some(serde_json::json!({ "client_secret": "replaced-secret-value" })),
            )
            .await,
        world.as_administrator(Method::GET, &path, None).await,
    ];
    for answer in &answers {
        let body = answer.body.to_string();
        assert!(!body.contains(CLIENT_SECRET), "{body}");
        assert!(!body.contains("replaced-secret-value"), "{body}");
        assert!(
            !body.contains("secret"),
            "no field is named for it either: {body}"
        );
    }
    // Nor of what is announced.
    let said = format!("{:?}", world.units_of_work.committed_events());
    assert!(!said.contains(CLIENT_SECRET));
    assert!(!said.contains("replaced-secret-value"));

    // The secret cannot be slipped into a change of settings.
    let slipped = world
        .as_administrator(
            Method::PATCH,
            &path,
            Some(serde_json::json!({ "client_secret": "x", "alias": "renamed" })),
        )
        .await;
    assert_eq!(slipped.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn what_breaks_a_rule_of_identity_providers_is_refused_with_its_code() {
    let world = world().await;
    let with = |change: Change| {
        let mut body = new_provider("example");
        change(&mut body);
        body
    };
    let cases: [(Change, StatusCode, &str); 6] = [
        (
            |b| b["alias"] = "Not An Alias".into(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "federation.alias_invalid",
        ),
        (
            |b| b["issuer"] = "http://plain.example.com".into(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "federation.issuer_invalid",
        ),
        (
            |b| b["client_secret"] = "".into(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "federation.client_secret_invalid",
        ),
        (
            |b| b["scopes"] = serde_json::json!(["email"]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "federation.scopes_invalid",
        ),
        (
            |b| {
                b.as_object_mut().expect("object").remove("client_id");
            },
            // A SAML provider has none, so the body may leave it out; an
            // OpenID Connect provider is refused without one.
            StatusCode::UNPROCESSABLE_ENTITY,
            "federation.client_id_invalid",
        ),
        (
            |b| b["unexpected"] = true.into(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.body_invalid",
        ),
    ];
    for (change, status, code) in cases {
        let reply = world
            .as_administrator(Method::POST, "/identity-providers", Some(with(change)))
            .await;
        assert_eq!(reply.status, status, "{code}: {:?}", reply.body);
        assert_eq!(reply.code(), code);
    }

    let first = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(new_provider("example")),
        )
        .await;
    assert_eq!(first.status, StatusCode::CREATED);
    let again = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(new_provider("example")),
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.code(), "federation.alias_taken");

    for path in [
        format!("/identity-providers/{}", UserId::generate()),
        "/identity-providers/not-an-identifier".to_owned(),
        format!("/identity-providers/{}:disable", UserId::generate()),
    ] {
        let method = if path.ends_with(":disable") {
            Method::POST
        } else {
            Method::GET
        };
        let reply = world.as_administrator(method, &path, None).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(reply.code(), "federation.provider_not_found", "{path}");
    }
    let id = first.body["id"].as_str().expect("id");
    let unknown_action = world
        .as_administrator(
            Method::POST,
            &format!("/identity-providers/{id}:delete"),
            None,
        )
        .await;
    assert_eq!(unknown_action.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown_action.code(), "route.not_found");
}

#[tokio::test]
async fn the_identity_providers_of_one_tenant_do_not_exist_for_another() {
    let world = world().await;
    let created = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(new_provider("example")),
        )
        .await;
    let id = created.body["id"].as_str().expect("id").to_owned();
    let globex = world.globex.clone();
    let (_, theirs) = world
        .person(&globex, "root@globex.example", &[Role::TenantAdministrator])
        .await;
    let authorization = format!("Bearer {theirs}");

    let listed = world
        .send(
            Method::GET,
            "/t/globex/api/v1/admin/identity-providers",
            Some(&authorization),
            None,
        )
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["items"], serde_json::json!([]));
    for (method, suffix) in [
        (Method::GET, ""),
        (Method::POST, ":disable"),
        (Method::PATCH, ""),
    ] {
        let reply = world
            .send(
                method.clone(),
                &format!("/t/globex/api/v1/admin/identity-providers/{id}{suffix}"),
                Some(&authorization),
                Some(serde_json::json!({})),
            )
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {suffix}");
        assert_eq!(reply.code(), "federation.provider_not_found");
    }
    // The same alias is theirs to use.
    let own = world
        .send(
            Method::POST,
            "/t/globex/api/v1/admin/identity-providers",
            Some(&authorization),
            Some(new_provider("example")),
        )
        .await;
    assert_eq!(own.status, StatusCode::CREATED);
    assert_eq!(
        own.body["callback_address"],
        "https://auth.example/t/globex/account/providers/example/callback"
    );
    let still = world
        .as_administrator(Method::GET, &format!("/identity-providers/{id}"), None)
        .await;
    assert_eq!(still.body["status"], "enabled");
}

#[tokio::test]
async fn a_provider_is_of_a_kind_and_may_be_trusted_with_addresses() {
    let world = world().await;

    // GitHub has an issuer and scopes of its own.
    let github = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(serde_json::json!({
                "alias": "github", "kind": "github", "display_name": "GitHub",
                "client_id": "github-client", "client_secret": CLIENT_SECRET,
            })),
        )
        .await;
    assert_eq!(github.status, StatusCode::CREATED, "{:?}", github.body);
    assert_eq!(github.body["kind"], "github");
    assert_eq!(github.body["issuer"], "https://github.com");
    assert_eq!(
        github.body["scopes"],
        serde_json::json!(["read:user", "user:email"])
    );
    assert_eq!(github.body["trusts_email"], false);

    // An OpenID Connect provider has neither.
    let mut without_issuer = new_provider("example");
    without_issuer
        .as_object_mut()
        .expect("object")
        .remove("issuer");
    let refused = world
        .as_administrator(Method::POST, "/identity-providers", Some(without_issuer))
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.code(), "federation.issuer_invalid");
    let mut unknown = new_provider("example");
    unknown["kind"] = "kerberos".into();
    let refused = world
        .as_administrator(Method::POST, "/identity-providers", Some(unknown))
        .await;
    assert_eq!(refused.code(), "federation.kind_invalid");

    // Trust in addresses is off unless asked for, and can be changed.
    let mut trusted = new_provider("entra");
    trusted["trusts_email"] = true.into();
    let created = world
        .as_administrator(Method::POST, "/identity-providers", Some(trusted))
        .await;
    assert_eq!(created.body["trusts_email"], true);
    let id = created.body["id"].as_str().expect("id");
    let changed = world
        .as_administrator(
            Method::PATCH,
            &format!("/identity-providers/{id}"),
            Some(serde_json::json!({ "trusts_email": false })),
        )
        .await;
    assert_eq!(changed.body["trusts_email"], false);

    // The kind is not something a change can touch.
    let rekinded = world
        .as_administrator(
            Method::PATCH,
            &format!("/identity-providers/{id}"),
            Some(serde_json::json!({ "kind": "github" })),
        )
        .await;
    assert_eq!(rekinded.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn an_administrator_adds_and_changes_a_directory() {
    let world = world().await;
    let directory = |issuer: &str| {
        serde_json::json!({
            "alias": "company", "kind": "ldap", "display_name": "Company directory",
            "issuer": issuer,
            "client_id": "cn=hodor,ou=services,dc=example,dc=com",
            "client_secret": CLIENT_SECRET,
            "trusts_email": true,
            "directory": { "base": "ou=people,dc=example,dc=com", "filter": "(uid={identifier})" },
        })
    };

    // A directory that is not on the installation's list.
    let refused = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(directory("ldaps://ldap.elsewhere.example")),
        )
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{:?}", refused.body);
    assert_eq!(refused.code(), "federation.directory_not_allowed");

    let created = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(directory("ldaps://ldap.example.com")),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.body["kind"], "ldap");
    assert_eq!(created.body["callback_address"], serde_json::Value::Null);
    assert_eq!(created.body["scopes"], serde_json::json!([]));
    assert_eq!(
        created.body["directory"],
        serde_json::json!({
            "base": "ou=people,dc=example,dc=com", "filter": "(uid={identifier})",
            "subject_attribute": "entryUUID", "email_attribute": "mail", "name_attribute": "cn",
        })
    );
    assert!(!created.body.to_string().contains(CLIENT_SECRET));

    // A change of one field keeps the others.
    let id = created.body["id"].as_str().expect("id");
    let changed = world
        .as_administrator(
            Method::PATCH,
            &format!("/identity-providers/{id}"),
            Some(serde_json::json!({
                "directory": { "filter": "(sAMAccountName={identifier})", "subject_attribute": "objectGUID" }
            })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{:?}", changed.body);
    assert_eq!(
        changed.body["directory"]["filter"],
        "(sAMAccountName={identifier})"
    );
    assert_eq!(changed.body["directory"]["subject_attribute"], "objectGUID");
    assert_eq!(
        changed.body["directory"]["base"],
        "ou=people,dc=example,dc=com"
    );

    // A filter that would match without what is typed is refused.
    let broken = world
        .as_administrator(
            Method::PATCH,
            &format!("/identity-providers/{id}"),
            Some(serde_json::json!({ "directory": { "filter": "(objectClass=*)" } })),
        )
        .await;
    assert_eq!(broken.code(), "federation.directory_invalid");

    // Another kind cannot be given a directory, nor a directory left without one.
    let mut misplaced = new_provider("example");
    misplaced["directory"] = serde_json::json!({ "base": "dc=x", "filter": "(uid={identifier})" });
    let refused = world
        .as_administrator(Method::POST, "/identity-providers", Some(misplaced))
        .await;
    assert_eq!(refused.code(), "federation.directory_invalid");
    let mut bare = directory("ldaps://ldap.example.com");
    bare["alias"] = "bare".into();
    bare.as_object_mut().expect("object").remove("directory");
    let refused = world
        .as_administrator(Method::POST, "/identity-providers", Some(bare))
        .await;
    assert_eq!(refused.code(), "federation.directory_invalid");
}

#[tokio::test]
async fn an_administrator_adds_and_changes_a_saml_provider() {
    let world = world().await;
    let identity_provider = hodor_saml::testing::TestIdentityProvider::rsa("urn:corp:idp");
    let created = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(serde_json::json!({
                "alias": "corp",
                "kind": "saml",
                "display_name": "Corp",
                "issuer": "urn:corp:idp",
                "trusts_email": true,
                "saml": {
                    "single_sign_on_address": "https://idp.corp.example/sso",
                    "certificate": identity_provider.certificate_pem(),
                },
            })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.body["kind"], "saml");
    assert_eq!(created.body["client_id"], "");
    assert_eq!(created.body["saml"]["email_attribute"], "email");
    assert_eq!(created.body["saml"]["name_attribute"], "name");
    assert_eq!(
        created.body["metadata_address"],
        "https://auth.example/t/acme/interaction/sign-in/providers/corp/saml/metadata",
        "what to give the identity provider"
    );
    assert_eq!(
        created.body["callback_address"],
        serde_json::Value::Null,
        "a SAML provider is given Hodor's metadata, not a callback page"
    );
    let path = format!(
        "/identity-providers/{}",
        created.body["id"].as_str().expect("id")
    );

    // What is left out of a change stays as it is, its SAML settings too.
    let changed = world
        .as_administrator(
            Method::PATCH,
            &path,
            Some(serde_json::json!({
                "display_name": "Corp SSO",
                "trusts_email": false,
                "saml": { "email_attribute": "mail" },
            })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{:?}", changed.body);
    assert_eq!(changed.body["display_name"], "Corp SSO");
    assert_eq!(changed.body["trusts_email"], false);
    assert_eq!(changed.body["saml"]["email_attribute"], "mail");
    assert_eq!(
        changed.body["saml"]["single_sign_on_address"],
        "https://idp.corp.example/sso"
    );

    let broken = world
        .as_administrator(
            Method::PATCH,
            &path,
            Some(serde_json::json!({ "saml": { "certificate": "not a certificate" } })),
        )
        .await;
    assert_eq!(broken.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(broken.code(), "federation.saml_invalid");
    assert!(
        broken.body["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("certificate_unreadable")),
        "{:?}",
        broken.body
    );

    let secret = world
        .as_administrator(
            Method::PUT,
            &format!("{path}/client-secret"),
            Some(serde_json::json!({ "client_secret": "a secret" })),
        )
        .await;
    assert_eq!(secret.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(secret.code(), "federation.client_secret_invalid");
}

#[tokio::test]
async fn an_administrator_rotates_and_revokes_a_signing_key_and_it_is_audited() {
    let world = world().await;
    let empty = world.as_administrator(Method::GET, "/keys/sig", None).await;
    assert_eq!(empty.status, StatusCode::OK);
    assert_eq!(empty.body["items"], serde_json::json!([]));

    let first = world
        .as_administrator(Method::POST, "/keys/sig:rotate", None)
        .await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    assert_eq!(first.body["state"], "active");
    assert_eq!(first.body["algorithm"], "ES256");
    assert_eq!(first.body["key_use"], "sig");
    let first_id = first.body["id"].as_str().expect("id").to_owned();

    let second = world
        .as_administrator(
            Method::POST,
            "/keys/sig:rotate",
            Some(serde_json::json!({ "algorithm": "ES256" })),
        )
        .await;
    assert_eq!(second.status, StatusCode::OK);
    let listed = world.as_administrator(Method::GET, "/keys/sig", None).await;
    let items = listed.body["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["id"], second.body["id"]);
    assert_eq!(items[0]["state"], "active");
    assert_eq!(items[1]["id"], first_id.as_str());
    assert_eq!(items[1]["state"], "retiring");
    // A day of overlap, the installation's.
    assert_eq!(items[1]["retire_after"], "1970-01-02T00:00:00Z");

    let revoked = world
        .as_administrator(
            Method::POST,
            &format!("/keys/sig/versions/{first_id}:revoke"),
            Some(serde_json::json!({ "reason": "the laptop was stolen" })),
        )
        .await;
    assert_eq!(revoked.status, StatusCode::OK);
    assert_eq!(revoked.body["state"], "revoked");
    assert_eq!(revoked.body["revocation_reason"], "the laptop was stolen");

    // Nothing of a key is in any answer.
    for body in [&first.body, &second.body, &listed.body, &revoked.body] {
        let written = body.to_string();
        for member in ["material", "public", "\"x\"", "\"n\""] {
            assert!(!written.contains(member), "{member} in {written}");
        }
    }

    world.record_audit().await;
    let records = world
        .as_administrator(Method::GET, "/audit-records?limit=200", None)
        .await;
    let actions: Vec<&serde_json::Value> = records.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|record| {
            record["action"]
                .as_str()
                .is_some_and(|action| action.starts_with("keys."))
        })
        .collect();
    assert_eq!(actions.len(), 5, "two made, two activated, one revoked");
    for record in actions {
        assert_eq!(record["actor"]["id"], world.administrator.to_string());
    }
}

#[tokio::test]
async fn what_breaks_a_rule_of_keys_is_refused_with_its_code() {
    let world = world().await;
    let rotated = world
        .as_administrator(Method::POST, "/keys/sig:rotate", None)
        .await;
    let id = rotated.body["id"].as_str().expect("id").to_owned();
    let cases = [
        (
            Method::GET,
            "/keys/enc".to_owned(),
            None,
            StatusCode::NOT_FOUND,
            "keys.key_set_not_found",
        ),
        (
            Method::GET,
            "/keys/everything".to_owned(),
            None,
            StatusCode::NOT_FOUND,
            "keys.key_set_not_found",
        ),
        (
            Method::POST,
            "/keys/data:rotate".to_owned(),
            None,
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.rotation_not_offered",
        ),
        (
            Method::POST,
            "/keys/sig:explode".to_owned(),
            None,
            StatusCode::NOT_FOUND,
            "route.not_found",
        ),
        (
            Method::POST,
            "/keys/sig:rotate".to_owned(),
            Some(serde_json::json!({ "algorithm": "none" })),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.algorithm_unsuitable",
        ),
        (
            Method::POST,
            "/keys/sig:rotate".to_owned(),
            Some(serde_json::json!({ "algorithm": "A256GCM" })),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.algorithm_unsuitable",
        ),
        (
            Method::POST,
            "/keys/sig:rotate".to_owned(),
            Some(serde_json::json!({ "algorithm": "ES256", "overlap": 0 })),
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.body_invalid",
        ),
        (
            Method::POST,
            format!("/keys/sig/versions/{id}:revoke"),
            Some(serde_json::json!({ "reason": "" })),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.reason_invalid",
        ),
        (
            Method::POST,
            format!("/keys/sig/versions/{id}:revoke"),
            Some(serde_json::json!({ "reason": "x".repeat(201) })),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.reason_invalid",
        ),
        (
            Method::POST,
            format!("/keys/sig/versions/{id}:revoke"),
            None,
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.body_invalid",
        ),
        (
            Method::POST,
            format!("/keys/data/versions/{id}:revoke"),
            Some(serde_json::json!({ "reason": "wrong set" })),
            StatusCode::NOT_FOUND,
            "keys.version_not_found",
        ),
        (
            Method::POST,
            format!("/keys/sig/versions/{}:revoke", UserId::generate()),
            Some(serde_json::json!({ "reason": "unknown" })),
            StatusCode::NOT_FOUND,
            "keys.version_not_found",
        ),
        (
            Method::POST,
            "/keys/sig/versions/not-an-identifier:revoke".to_owned(),
            Some(serde_json::json!({ "reason": "malformed" })),
            StatusCode::NOT_FOUND,
            "keys.version_not_found",
        ),
        (
            Method::POST,
            format!("/keys/sig/versions/{id}:destroy"),
            Some(serde_json::json!({ "reason": "no such action" })),
            StatusCode::NOT_FOUND,
            "route.not_found",
        ),
    ];
    for (method, path, body, status, code) in cases {
        let reply = world.as_administrator(method.clone(), &path, body).await;
        assert_eq!(reply.status, status, "{method} {path}: {:?}", reply.body);
        assert_eq!(reply.code(), code, "{method} {path}");
    }
    // The version is still active: nothing above changed it.
    let listed = world.as_administrator(Method::GET, "/keys/sig", None).await;
    assert_eq!(listed.body["items"][0]["state"], "active");
}

#[tokio::test]
async fn the_keys_of_one_tenant_do_not_exist_for_another() {
    let world = world().await;
    let rotated = world
        .as_administrator(Method::POST, "/keys/sig:rotate", None)
        .await;
    let id = rotated.body["id"].as_str().expect("id").to_owned();
    let (_, globex) = world
        .person(
            &world.globex,
            "root@globex.example",
            &[Role::TenantAdministrator],
        )
        .await;
    let authorization = format!("Bearer {globex}");

    let listed = world
        .send(
            Method::GET,
            "/t/globex/api/v1/admin/keys/sig",
            Some(&authorization),
            None,
        )
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["items"], serde_json::json!([]));
    let revoked = world
        .send(
            Method::POST,
            &format!("/t/globex/api/v1/admin/keys/sig/versions/{id}:revoke"),
            Some(&authorization),
            Some(serde_json::json!({ "reason": "not ours" })),
        )
        .await;
    assert_eq!(revoked.status, StatusCode::NOT_FOUND);
    assert_eq!(revoked.code(), "keys.version_not_found");
    // Globex's token means nothing at Acme.
    let elsewhere = world
        .send(
            Method::GET,
            "/t/acme/api/v1/admin/keys/sig",
            Some(&authorization),
            None,
        )
        .await;
    assert_eq!(elsewhere.status, StatusCode::UNAUTHORIZED);

    let acme = world.as_administrator(Method::GET, "/keys/sig", None).await;
    assert_eq!(acme.body["items"][0]["state"], "active");
}

#[tokio::test]
async fn without_keys_to_wrap_them_with_the_key_routes_say_so() {
    let world = world_with_keys(false).await;
    for (method, path) in [
        (Method::GET, "/keys/sig".to_owned()),
        (Method::POST, "/keys/sig:rotate".to_owned()),
        (
            Method::POST,
            format!("/keys/sig/versions/{}:revoke", UserId::generate()),
        ),
    ] {
        let reply = world
            .as_administrator(
                method.clone(),
                &path,
                Some(serde_json::json!({ "reason": "test" })),
            )
            .await;
        assert_eq!(
            reply.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{method} {path}"
        );
        assert_eq!(reply.code(), "keys.not_configured", "{method} {path}");
    }
}

// Applications, clients and resource servers.

/// Registers an application in Acme and answers its identifier.
async fn new_application(world: &World, name: &str, first_party: bool) -> String {
    let created = world
        .as_administrator(
            Method::POST,
            "/applications",
            Some(serde_json::json!({ "name": name, "first_party": first_party })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    created.body["id"].as_str().expect("id").to_owned()
}

fn web_client() -> serde_json::Value {
    serde_json::json!({
        "name": "Billing web site",
        "type": "confidential",
        "grant_types": ["authorization_code", "refresh_token"],
        "redirect_uris": ["https://billing.example.com/callback"],
        "allowed_scopes": ["openid", "email"],
    })
}

#[tokio::test]
async fn an_administrator_registers_an_application_with_its_clients_and_resource_server() {
    let world = world().await;
    let application = new_application(&world, "Billing", true).await;
    let read = world
        .as_administrator(Method::GET, &format!("/applications/{application}"), None)
        .await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body["name"], "Billing");
    assert_eq!(read.body["first_party"], true);
    assert_eq!(read.body["status"], "enabled");

    // A change leaves out what stays.
    let changed = world
        .as_administrator(
            Method::PATCH,
            &format!("/applications/{application}"),
            Some(serde_json::json!({ "name": "Billing and invoices" })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK);
    assert_eq!(changed.body["name"], "Billing and invoices");
    assert_eq!(changed.body["first_party"], true);

    let created = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(web_client()),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["type"], "confidential");
    assert_eq!(created.body["authentication_method"], "client_secret_basic");
    assert_eq!(created.body["require_pkce"], true);
    assert_eq!(created.body["token_policy"]["access_token_seconds"], 300);
    assert!(
        created.body["client_secret"]
            .as_str()
            .is_some_and(|secret| secret.starts_with("hodor_cs_")),
        "the first secret, once: {}",
        created.body
    );
    let client = created.body["id"].as_str().expect("client").to_owned();

    let listed = world
        .as_administrator(
            Method::GET,
            &format!("/applications/{application}/clients"),
            None,
        )
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["items"][0]["id"], client.as_str());

    // Changed settings are checked as a whole; the token policy takes
    // any of its fields.
    let changed = world
        .as_administrator(
            Method::PATCH,
            &format!("/clients/{client}"),
            Some(serde_json::json!({
                "redirect_uris": ["https://billing.example.com/callback", "https://billing.example.com/other"],
                "post_logout_redirect_uris": ["https://billing.example.com/signed-out"],
                "token_policy": { "access_token_seconds": 600 },
            })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    assert_eq!(
        changed.body["redirect_uris"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        changed.body["post_logout_redirect_uris"],
        serde_json::json!(["https://billing.example.com/signed-out"])
    );
    assert_eq!(changed.body["token_policy"]["access_token_seconds"], 600);
    assert_eq!(changed.body["token_policy"]["id_token_seconds"], 300);

    // A new secret is shown once; the newest previous keeps working.
    let rotated = world
        .as_administrator(Method::POST, &format!("/clients/{client}/secrets"), None)
        .await;
    assert_eq!(rotated.status, StatusCode::CREATED, "{}", rotated.body);
    let new_secret = rotated.body["id"].as_str().expect("secret").to_owned();
    let now = world
        .as_administrator(Method::GET, &format!("/clients/{client}"), None)
        .await;
    assert_eq!(now.body["secrets"].as_array().map(Vec::len), Some(2));
    let revoked = world
        .as_administrator(
            Method::DELETE,
            &format!("/clients/{client}/secrets/{new_secret}"),
            None,
        )
        .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
    let now = world
        .as_administrator(Method::GET, &format!("/clients/{client}"), None)
        .await;
    assert_eq!(now.body["secrets"].as_array().map(Vec::len), Some(1));

    let disabled = world
        .as_administrator(Method::POST, &format!("/clients/{client}:disable"), None)
        .await;
    assert_eq!(disabled.body["status"], "disabled");
    let enabled = world
        .as_administrator(Method::POST, &format!("/clients/{client}:enable"), None)
        .await;
    assert_eq!(enabled.body["status"], "enabled");
    let disabled = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}:disable"),
            None,
        )
        .await;
    assert_eq!(disabled.body["status"], "disabled");
    let unknown = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}:archive"),
            None,
        )
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.code(), "route.not_found");

    let server = world
        .as_administrator(
            Method::POST,
            "/resource-servers",
            Some(serde_json::json!({
                "application_id": application,
                "audience": "https://api.billing.example.com",
                "name": "Billing interface",
                "scopes": [{ "name": "invoices:read", "description": "Read your invoices" }],
            })),
        )
        .await;
    assert_eq!(server.status, StatusCode::CREATED, "{}", server.body);
    let id = server.body["id"].as_str().expect("id").to_owned();
    let changed = world
        .as_administrator(
            Method::PATCH,
            &format!("/resource-servers/{id}"),
            Some(serde_json::json!({
                "scopes": [
                    { "name": "invoices:read", "description": "Read your invoices" },
                    { "name": "invoices:write" },
                ],
            })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    assert_eq!(changed.body["audience"], "https://api.billing.example.com");
    assert_eq!(changed.body["scopes"][1]["name"], "invoices:write");
    let listed = world
        .as_administrator(Method::GET, "/resource-servers", None)
        .await;
    assert_eq!(listed.body["items"][0]["id"], id.as_str());
    // The audience can never change: the field is not taken.
    let refused = world
        .as_administrator(
            Method::PATCH,
            &format!("/resource-servers/{id}"),
            Some(serde_json::json!({ "audience": "https://elsewhere.example.com" })),
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);

    // Every change is announced, under the administrator's name.
    world.record_audit().await;
    let records = world
        .as_administrator(Method::GET, "/audit-records?limit=200", None)
        .await;
    let said = records.body.to_string();
    for event in [
        "oauth.application_created",
        "oauth.application_changed",
        "oauth.application_disabled",
        "oauth.client_created",
        "oauth.client_changed",
        "oauth.client_secret_issued",
        "oauth.client_secret_revoked",
        "oauth.client_disabled",
        "oauth.client_enabled",
        "oauth.resource_server_created",
        "oauth.resource_server_changed",
    ] {
        assert!(said.contains(event), "{event}");
    }
    assert!(said.contains(&world.administrator.to_string()));
}

#[tokio::test]
async fn a_client_secret_is_shown_only_in_the_answers_that_make_it() {
    let world = world().await;
    let application = new_application(&world, "Billing", true).await;
    let created = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(web_client()),
        )
        .await;
    let first = created.body["client_secret"]
        .as_str()
        .expect("first secret")
        .to_owned();
    let client = created.body["id"].as_str().expect("client").to_owned();
    let rotated = world
        .as_administrator(
            Method::POST,
            &format!("/clients/{client}/secrets"),
            Some(serde_json::json!({ "lifetime_days": 30, "keep_previous_days": 0 })),
        )
        .await;
    assert_eq!(rotated.status, StatusCode::CREATED, "{}", rotated.body);
    let second = rotated.body["client_secret"]
        .as_str()
        .expect("second secret")
        .to_owned();
    assert_ne!(first, second);
    // Ending the previous at once leaves one secret.
    let path = format!("/clients/{client}");
    let now = world.as_administrator(Method::GET, &path, None).await;
    assert_eq!(now.body["secrets"].as_array().map(Vec::len), Some(1));

    let answers = [
        now,
        world
            .as_administrator(
                Method::GET,
                &format!("/applications/{application}/clients"),
                None,
            )
            .await,
        world
            .as_administrator(
                Method::PATCH,
                &path,
                Some(serde_json::json!({ "name": "Renamed" })),
            )
            .await,
        world
            .as_administrator(Method::POST, &format!("{path}:disable"), None)
            .await,
    ];
    for answer in &answers {
        let body = answer.body.to_string();
        assert_eq!(answer.status, StatusCode::OK, "{body}");
        assert!(!body.contains(&first), "{body}");
        assert!(!body.contains(&second), "{body}");
        assert!(!body.contains("\"client_secret\":"), "{body}");
        assert!(!body.contains("hash"), "{body}");
    }
    // Nor is either secret announced.
    let said = format!("{:?}", world.units_of_work.committed_events());
    assert!(!said.contains(&first));
    assert!(!said.contains(&second));

    // A public client has no secret, so its answer has none.
    let public = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(serde_json::json!({
                "name": "Billing mobile application",
                "type": "public",
                "grant_types": ["authorization_code"],
                "redirect_uris": ["com.example.billing:/callback"],
            })),
        )
        .await;
    assert_eq!(public.status, StatusCode::CREATED, "{}", public.body);
    assert_eq!(public.body["authentication_method"], "none");
    assert!(public.body.get("client_secret").is_none());
    let public_id = public.body["id"].as_str().expect("id").to_owned();
    let refused = world
        .as_administrator(Method::POST, &format!("/clients/{public_id}/secrets"), None)
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.code(), "oauth.client_secret_not_allowed");
}

#[tokio::test]
async fn keys_are_added_without_a_private_part_and_removed_by_their_kid() {
    let world = world().await;
    let application = new_application(&world, "Reports", true).await;
    let mut settings = web_client();
    settings["authentication_method"] = "private_key_jwt".into();
    let created = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(settings),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    // A client that proves itself with a key gets no secret.
    assert!(created.body.get("client_secret").is_none());
    let client = created.body["id"].as_str().expect("client").to_owned();
    let key = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": "2026/11+a",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    });
    let mut private = key.clone();
    private["d"] = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI".into();
    let refused = world
        .as_administrator(
            Method::POST,
            &format!("/clients/{client}/keys"),
            Some(serde_json::json!({ "jwk": private })),
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.code(), "oauth.client_key_invalid");

    let added = world
        .as_administrator(
            Method::POST,
            &format!("/clients/{client}/keys"),
            Some(serde_json::json!({ "jwk": key })),
        )
        .await;
    assert_eq!(added.status, StatusCode::CREATED, "{}", added.body);
    assert_eq!(added.body["keys"][0]["kid"], "2026/11+a");
    assert_eq!(added.body["keys"][0]["jwk"]["crv"], "P-256");
    let again = world
        .as_administrator(
            Method::POST,
            &format!("/clients/{client}/keys"),
            Some(serde_json::json!({ "jwk": key })),
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.code(), "oauth.client_key_taken");

    // The `kid` is written in the path with percent-encoding.
    let removed = world
        .as_administrator(
            Method::DELETE,
            &format!("/clients/{client}/keys/2026%2F11%2Ba"),
            None,
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let now = world
        .as_administrator(Method::GET, &format!("/clients/{client}"), None)
        .await;
    assert_eq!(now.body["keys"].as_array().map(Vec::len), Some(0));
    let gone = world
        .as_administrator(
            Method::DELETE,
            &format!("/clients/{client}/keys/2026%2F11%2Ba"),
            None,
        )
        .await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    assert_eq!(gone.code(), "oauth.client_key_not_found");
}

#[tokio::test]
async fn what_breaks_a_rule_of_a_client_is_refused_with_its_code() {
    let world = world().await;
    let application = new_application(&world, "Billing", true).await;
    let path = format!("/applications/{application}/clients");
    let cases: [(&str, Change, &str); 6] = [
        (
            "a kind of client that does not exist",
            |body| body["type"] = "trusted".into(),
            "oauth.client_type_invalid",
        ),
        (
            "a public client with a secret",
            |body| {
                body["type"] = "public".into();
                body["authentication_method"] = "client_secret_basic".into();
            },
            "oauth.client_authentication_method_invalid",
        ),
        (
            "a redirect address over plain HTTP",
            |body| {
                body["redirect_uris"] = serde_json::json!(["http://billing.example.com/callback"])
            },
            "oauth.client_redirect_uri_invalid",
        ),
        (
            "a grant that does not exist",
            |body| body["grant_types"] = serde_json::json!(["password"]),
            "oauth.client_grants_invalid",
        ),
        (
            "an access token that lives a day",
            |body| body["token_policy"] = serde_json::json!({ "access_token_seconds": 86400 }),
            "oauth.token_policy_invalid",
        ),
        (
            "a secret that lives ten years",
            |body| body["secret_lifetime_days"] = 3650.into(),
            "oauth.client_secret_lifetime_invalid",
        ),
    ];
    for (what, change, code) in cases {
        let mut body = web_client();
        change(&mut body);
        let reply = world
            .as_administrator(Method::POST, &path, Some(body))
            .await;
        assert_eq!(
            reply.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{what}: {}",
            reply.body
        );
        assert_eq!(reply.code(), code, "{what}");
    }
    // Nothing was created by any of them.
    let listed = world.as_administrator(Method::GET, &path, None).await;
    assert_eq!(listed.body["items"].as_array().map(Vec::len), Some(0));

    // Whether an application is first party is never assumed.
    let missing = world
        .as_administrator(
            Method::POST,
            "/applications",
            Some(serde_json::json!({ "name": "Billing" })),
        )
        .await;
    assert_eq!(missing.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(missing.code(), "request.body_invalid");
}

#[tokio::test]
async fn the_applications_of_one_tenant_do_not_exist_for_another() {
    let world = world().await;
    let application = new_application(&world, "Billing", true).await;
    let created = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(web_client()),
        )
        .await;
    let client = created.body["id"].as_str().expect("client").to_owned();
    let (_, globex_token) = world
        .person(
            &world.globex,
            "root@globex.example",
            &[Role::TenantAdministrator],
        )
        .await;
    let as_globex = |method: Method, path: String, body: Option<serde_json::Value>| {
        let token = format!("Bearer {globex_token}");
        let world = &world;
        async move {
            world
                .send(
                    method,
                    &format!("/t/globex/api/v1/admin{path}"),
                    Some(&token),
                    body,
                )
                .await
        }
    };
    for (method, path, code) in [
        (
            Method::GET,
            format!("/applications/{application}"),
            "oauth.application_not_found",
        ),
        (
            Method::POST,
            format!("/applications/{application}:disable"),
            "oauth.application_not_found",
        ),
        (
            Method::GET,
            format!("/applications/{application}/clients"),
            "oauth.application_not_found",
        ),
        (
            Method::GET,
            format!("/clients/{client}"),
            "oauth.client_not_found",
        ),
        (
            Method::POST,
            format!("/clients/{client}/secrets"),
            "oauth.client_not_found",
        ),
        (
            Method::POST,
            format!("/clients/{client}:disable"),
            "oauth.client_not_found",
        ),
    ] {
        let reply = as_globex(method.clone(), path.clone(), None).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(reply.code(), code, "{method} {path}");
    }
    let listed = as_globex(Method::GET, "/applications".to_owned(), None).await;
    assert_eq!(listed.body["items"].as_array().map(Vec::len), Some(0));
    // A client of Globex cannot be put in Acme's application either.
    let foreign = as_globex(
        Method::POST,
        format!("/applications/{application}/clients"),
        Some(web_client()),
    )
    .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    // And Acme's client is as it was.
    let still = world
        .as_administrator(Method::GET, &format!("/clients/{client}"), None)
        .await;
    assert_eq!(still.body["status"], "enabled");
    assert_eq!(still.body["secrets"].as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn an_administrator_reads_and_replaces_the_assurance_levels_of_their_tenant_only() {
    let world = world().await;
    let defaults = world
        .as_administrator(Method::GET, "/assurance-levels", None)
        .await;
    assert_eq!(defaults.status, StatusCode::OK, "{:?}", defaults.body);
    assert_eq!(
        defaults.body,
        serde_json::json!({ "levels": [
            { "acr": "urn:hodor:acr:single-factor", "requirement": "single_factor" },
            { "acr": "urn:hodor:acr:mfa", "requirement": "multi_factor" },
        ]})
    );

    let replaced = world
        .as_administrator(
            Method::PUT,
            "/assurance-levels",
            Some(serde_json::json!({ "levels": [
                { "acr": "urn:acme:strong", "requirement": "phishing_resistant" },
                { "acr": "urn:acme:mfa", "requirement": "multi_factor" },
            ]})),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::OK, "{:?}", replaced.body);
    assert_eq!(
        replaced.body["levels"][0]["acr"], "urn:acme:mfa",
        "weakest first"
    );
    let read = world
        .as_administrator(Method::GET, "/assurance-levels", None)
        .await;
    assert_eq!(read.body, replaced.body);

    // Globex keeps its own.
    let (_, globex) = world
        .person(
            &world.globex,
            "root@globex.example",
            &[Role::TenantAdministrator],
        )
        .await;
    let theirs = world
        .send(
            Method::GET,
            "/t/globex/api/v1/admin/assurance-levels",
            Some(&format!("Bearer {globex}")),
            None,
        )
        .await;
    assert_eq!(theirs.body, defaults.body);

    world.record_audit().await;
    let records = world
        .as_administrator(Method::GET, "/audit-records", None)
        .await;
    assert!(
        records.body["items"]
            .as_array()
            .expect("items")
            .iter()
            .any(|record| record["action"] == "tenant.settings_changed"),
        "{:?}",
        records.body
    );
}

#[tokio::test]
async fn levels_that_break_a_rule_are_refused_and_an_auditor_only_reads_them() {
    let world = world().await;
    for levels in [
        serde_json::json!({ "levels": [] }),
        serde_json::json!({ "levels": [{ "acr": "has space", "requirement": "single_factor" }] }),
        serde_json::json!({ "levels": [
            { "acr": "same", "requirement": "single_factor" },
            { "acr": "same", "requirement": "multi_factor" },
        ]}),
    ] {
        let refused = world
            .as_administrator(Method::PUT, "/assurance-levels", Some(levels))
            .await;
        assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(refused.code(), "tenant.settings_invalid");
    }
    let unknown = world
        .as_administrator(
            Method::PUT,
            "/assurance-levels",
            Some(serde_json::json!({ "levels": [{ "acr": "x", "requirement": "very_strong" }] })),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(unknown.code(), "request.body_invalid");

    let acme = world.acme.clone();
    let (_, auditor) = world
        .person(&acme, "auditor@example.com", &[Role::TenantAuditor])
        .await;
    let authorization = format!("Bearer {auditor}");
    let read = world
        .send(
            Method::GET,
            "/t/acme/api/v1/admin/assurance-levels",
            Some(&authorization),
            None,
        )
        .await;
    assert_eq!(read.status, StatusCode::OK);
    let written = world
        .send(
            Method::PUT,
            "/t/acme/api/v1/admin/assurance-levels",
            Some(&authorization),
            Some(serde_json::json!({ "levels": [{ "acr": "x", "requirement": "single_factor" }] })),
        )
        .await;
    assert_eq!(written.status, StatusCode::FORBIDDEN);
}
