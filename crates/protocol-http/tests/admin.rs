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
    Caller, DomainError, EventHandler, TenantContext, TenantId, Timestamp, UnitOfWorkFactory,
    UserId,
};
use hodor_protocol_http::{
    ADMIN_OPENAPI, ADMIN_OPERATIONS, AdminState, Limits, ResolvedTenant, TenantResolver,
    TenantStatus, admin_routes, public_router,
};
use hodor_session::api::{
    Assurance, ClientInfo, SessionService, SessionTimeouts, SessionToken, StartSession,
};
use hodor_session::testing::{InMemorySessions, SequentialRandom};
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

async fn world() -> World {
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
    );

    let acme = TenantContext::assume(TenantId::generate());
    let globex = TenantContext::assume(TenantId::generate());
    let state = AdminState {
        tokens: tokens.clone(),
        authorization: authorization.clone(),
        identity: identity.clone(),
        sessions: sessions.clone(),
        audit: audit.clone(),
        federation: Some(federation),
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
    assert_eq!(served.len(), 14);

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
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.body_invalid",
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
    unknown["kind"] = "saml".into();
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
