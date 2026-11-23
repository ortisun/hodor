//! The console interface, exercised over HTTP against the real contexts
//! running on their in-memory ports.
//!
//! It has the routes of the administration interface and knows who is
//! asking by their session. What is tested here is that difference: the
//! handlers behind the routes are tested in `admin.rs`.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use hodor_audit::api::AuditService;
use hodor_audit::testing::InMemoryAuditLog;
use hodor_authorization::api::{AuthorizationService, Role};
use hodor_authorization::testing::InMemoryRoleAssignments;
use hodor_credential::api::AccessTokenService;
use hodor_credential::testing::InMemoryAccessTokens;
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, DomainError, TenantContext, TenantId, Timestamp, UserId};
use hodor_protocol_http::{
    ADMIN_OPERATIONS, AdminState, CONSOLE_SESSION_HOURS, ConsoleState, Limits, ResolvedTenant,
    TenantResolver, TenantStatus, admin_routes, console_routes, public_router,
};
use hodor_session::api::{Assurance, ClientInfo, SessionService, SessionTimeouts, StartSession};
use hodor_session::testing::{InMemorySessions, SequentialRandom};
use hodor_tenant::api::TenantService;
use hodor_tenant::testing::InMemoryTenants;
use http_body_util::BodyExt as _;
use std::sync::Arc;
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
    identity: IdentityService,
    tokens: AccessTokenService,
    authorization: AuthorizationService,
    sessions: SessionService,
    acme: TenantContext,
    globex: TenantContext,
}

/// Someone signed in: the cookie their browser sends and the CSRF token
/// the console read from `/me`.
struct SignedIn {
    user: UserId,
    cookie: String,
    csrf_token: String,
}

/// The applications use cases on in-memory stores.
fn applications(
    units_of_work: &InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
) -> (
    hodor_oauth::api::ApplicationService,
    hodor_oauth::api::ConsentService,
) {
    let stores = hodor_oauth::testing::InMemoryStores::default();
    let consents = hodor_oauth::testing::consent_service(
        Arc::new(units_of_work.clone()),
        &stores,
        clock.clone(),
    );
    let applications =
        hodor_oauth::api::ApplicationService::new(hodor_oauth::api::ApplicationPorts {
            units_of_work: Arc::new(units_of_work.clone()),
            applications: Arc::new(stores.applications),
            clients: Arc::new(stores.clients),
            resource_servers: Arc::new(stores.resource_servers),
            digest: Arc::new(FakeDigest),
            random: Arc::new(hodor_oauth::testing::DistinctRandom),
            clock,
        });
    (applications, consents)
}

/// The use cases of people's factors on in-memory stores, with
/// authenticator applications. Returns the key store too, for a test to
/// give someone a key as a finished registration would.
fn factors(
    units_of_work: &InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    identity: &IdentityService,
    tenants: &hodor_tenant::api::TenantService,
) -> (
    hodor_authentication::api::FactorService,
    hodor_credential::testing::InMemoryWebAuthn,
    hodor_credential::api::TotpService,
) {
    let units = || Arc::new(units_of_work.clone());
    let keys = hodor_credential::testing::InMemoryWebAuthn::default();
    let webauthn = hodor_credential::api::WebAuthnService::new(
        units(),
        Arc::new(keys.clone()),
        hodor_credential::api::RelyingParty::from_public_address("https://auth.example")
            .expect("valid"),
        Arc::new(hodor_adapters_crypto::Sha256Digest),
        Arc::new(hodor_adapters_crypto::AwsLcVerifier),
        Arc::new(hodor_adapters_crypto::OsRandom),
        clock.clone(),
    );
    let recovery_codes = hodor_credential::api::RecoveryCodeService::new(
        units(),
        Arc::new(hodor_credential::testing::InMemoryRecoveryCodes::default()),
        Arc::new(hodor_adapters_crypto::Sha256Digest),
        Arc::new(hodor_adapters_crypto::OsRandom),
        clock.clone(),
    );
    let totp = hodor_credential::api::TotpService::new(
        units(),
        Arc::new(hodor_credential::testing::InMemoryTotps::default()),
        Arc::new(hodor_kernel::sealing::testing::FakeSecretBox),
        Arc::new(hodor_credential::testing::FakeHmacSha1),
        Arc::new(hodor_adapters_crypto::OsRandom),
        clock,
    );
    let service = hodor_authentication::api::FactorService::new(
        identity.clone(),
        tenants.clone(),
        webauthn,
        recovery_codes,
    )
    .with_totp(totp.clone());
    (service, keys, totp)
}

fn world() -> World {
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
        digest.clone(),
        clock.clone(),
    );

    let acme = TenantContext::assume(TenantId::generate());
    let globex = TenantContext::assume(TenantId::generate());
    let oauth = applications(&units_of_work, clock.clone());
    let administration = AdminState {
        tokens: tokens.clone(),
        authorization: authorization.clone(),
        identity: identity.clone(),
        sessions: sessions.clone(),
        audit,
        // Identity providers are tested in `admin.rs`; here they are not configured.
        federation: None,
        keys: None,
        key_rotation: hodor_keys::api::RotationPolicy::DEFAULT,
        applications: oauth.0,
        consents: oauth.1,
        tenants: TenantService::new(
            Arc::new(units_of_work.clone()),
            Arc::new(InMemoryTenants::default()),
            Arc::new(InMemoryTenants::default()),
            clock.clone(),
        ),
        // People's factors are tested in `admin.rs`; here no tenant has a
        // row, so only the routes' refusals are reached.
        factors: factors(
            &units_of_work,
            clock.clone(),
            &identity,
            &hodor_tenant::api::TenantService::new(
                units(),
                Arc::new(hodor_tenant::testing::InMemoryTenants::default()),
                Arc::new(hodor_tenant::testing::InMemoryTenants::default()),
                clock.clone(),
            ),
        )
        .0,
        decisions: hodor_authorization::api::DecisionLog::new(
            Arc::new(units_of_work.clone()),
            Arc::new(hodor_authorization::testing::InMemoryDecisionLog::default()),
            Arc::new(SequentialRandom::default()),
            clock.clone(),
        ),
        public_url: "https://auth.example".to_owned(),
    };
    let router = public_router(
        Arc::new(Tenants {
            acme: acme.clone(),
            globex: globex.clone(),
        }),
        Router::new()
            .nest("/api/v1/admin", admin_routes(administration.clone()))
            .nest(
                "/console/api",
                console_routes(ConsoleState {
                    administration,
                    digest,
                    clock: clock.clone(),
                }),
            ),
        Router::new(),
        Limits::default(),
    );

    World {
        router,
        clock,
        identity,
        tokens,
        authorization,
        sessions,
        acme,
        globex,
    }
}

struct Reply {
    status: StatusCode,
    body: serde_json::Value,
}

impl Reply {
    fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or_default()
    }
}

/// What a request carries besides its method and path.
#[derive(Default)]
struct With<'a> {
    cookie: Option<&'a str>,
    csrf_token: Option<&'a str>,
    origin: Option<&'a str>,
    authorization: Option<&'a str>,
    body: Option<serde_json::Value>,
}

impl World {
    async fn user(&self, tenant: &TenantContext, email: &str, roles: &[Role]) -> UserId {
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
        user
    }

    /// Signs a user in, with a session the tenant lets live for a day.
    async fn cookie_for(&self, tenant: &TenantContext, user: UserId) -> String {
        let token = self
            .sessions
            .start(
                tenant,
                StartSession {
                    user_id: user,
                    assurance: Assurance::SingleFactor,
                    methods: vec!["password".to_owned()],
                    timeouts: SessionTimeouts {
                        idle: Duration::hours(24),
                        absolute: Duration::hours(24),
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
            .1;
        format!("__Secure-hodor_session={}", token.expose())
    }

    /// A person of Acme with the given roles, signed in, as the console
    /// knows them after asking `/me`.
    async fn signed_in(&self, email: &str, roles: &[Role]) -> SignedIn {
        let user = self.user(&self.acme, email, roles).await;
        let cookie = self.cookie_for(&self.acme, user).await;
        let me = self
            .send(
                Method::GET,
                "/t/acme/console/api/me",
                With {
                    cookie: Some(&cookie),
                    ..With::default()
                },
            )
            .await;
        assert_eq!(me.status, StatusCode::OK, "{}", me.body);
        SignedIn {
            user,
            cookie,
            csrf_token: me.body["csrf_token"].as_str().expect("token").to_owned(),
        }
    }

    async fn send(&self, method: Method, path: &str, with: With<'_>) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "auth.example");
        if let Some(cookie) = with.cookie {
            request = request.header(header::COOKIE, cookie);
        }
        if let Some(token) = with.csrf_token {
            request = request.header("x-csrf-token", token);
        }
        if let Some(origin) = with.origin {
            request = request.header(header::ORIGIN, origin);
        }
        if let Some(value) = with.authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        let request = match with.body {
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
            body: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        }
    }
}

/// A path of the table of operations, with identifiers in place of its
/// parameters.
fn concrete(path: &str) -> String {
    path.replace("{user_id}", &UserId::generate().to_string())
        .replace("{session_id}", "0193f1c2-0000-7000-8000-000000000000")
}

fn console(path: &str) -> String {
    format!("/t/acme/console/api{path}")
}

fn new_user() -> Option<serde_json::Value> {
    Some(serde_json::json!({ "email": "new@example.com" }))
}

#[tokio::test]
async fn every_operation_is_refused_without_a_session() {
    let world = world();
    for (method, path, _) in ADMIN_OPERATIONS {
        let method: Method = method.parse().expect("method");
        let reply = world
            .send(method.clone(), &console(&concrete(path)), With::default())
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(reply.code(), "console.not_authenticated", "{method} {path}");
    }
    let me = world
        .send(Method::GET, &console("/me"), With::default())
        .await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    assert_eq!(me.code(), "console.not_authenticated");
}

#[tokio::test]
async fn me_says_who_the_person_is_and_what_they_may_do() {
    let world = world();
    let ana = world
        .signed_in("ana@example.com", &[Role::TenantAuditor])
        .await;

    let me = world
        .send(
            Method::GET,
            &console("/me"),
            With {
                cookie: Some(&ana.cookie),
                ..With::default()
            },
        )
        .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["user"]["id"], ana.user.to_string());
    assert_eq!(me.body["roles"], serde_json::json!(["tenant_auditor"]));
    let permissions: Vec<&str> = me.body["permissions"]
        .as_array()
        .expect("permissions")
        .iter()
        .filter_map(|permission| permission.as_str())
        .collect();
    assert!(permissions.contains(&"audit:read"), "{permissions:?}");
    assert!(!permissions.contains(&"users:write"), "{permissions:?}");
    assert_eq!(me.body["signed_in_at"], "1970-01-01T00:00:00Z");
    // The tenant lets the session live for a day; the console does not.
    assert_eq!(me.body["console_until"], "1970-01-01T12:00:00Z");
}

#[tokio::test]
async fn a_person_without_a_role_is_known_and_may_do_nothing() {
    let world = world();
    let bia = world.signed_in("bia@example.com", &[]).await;

    let me = world
        .send(
            Method::GET,
            &console("/me"),
            With {
                cookie: Some(&bia.cookie),
                ..With::default()
            },
        )
        .await;
    assert_eq!(me.body["roles"], serde_json::json!([]));
    assert_eq!(me.body["permissions"], serde_json::json!([]));

    let users = world
        .send(
            Method::GET,
            &console("/users"),
            With {
                cookie: Some(&bia.cookie),
                ..With::default()
            },
        )
        .await;
    assert_eq!(users.status, StatusCode::FORBIDDEN);
    assert_eq!(users.code(), "admin.forbidden");
}

#[tokio::test]
async fn a_session_reads_and_with_its_token_changes() {
    let world = world();
    let root = world
        .signed_in("root@example.com", &[Role::TenantAdministrator])
        .await;

    let users = world
        .send(
            Method::GET,
            &console("/users"),
            With {
                cookie: Some(&root.cookie),
                ..With::default()
            },
        )
        .await;
    assert_eq!(users.status, StatusCode::OK, "{}", users.body);
    assert_eq!(users.body["items"].as_array().map(Vec::len), Some(1));

    let created = world
        .send(
            Method::POST,
            &console("/users"),
            With {
                cookie: Some(&root.cookie),
                csrf_token: Some(&root.csrf_token),
                origin: Some("https://auth.example"),
                body: new_user(),
                ..With::default()
            },
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["identifiers"][0]["value"], "new@example.com");
}

#[tokio::test]
async fn a_change_without_the_token_of_the_session_is_refused() {
    let world = world();
    let root = world
        .signed_in("root@example.com", &[Role::TenantAdministrator])
        .await;

    for csrf_token in [None, Some("not-the-token")] {
        let reply = world
            .send(
                Method::POST,
                &console("/users"),
                With {
                    cookie: Some(&root.cookie),
                    csrf_token,
                    body: new_user(),
                    ..With::default()
                },
            )
            .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{csrf_token:?}");
        assert_eq!(reply.code(), "request.csrf_token_invalid", "{csrf_token:?}");
    }

    let users = world
        .send(
            Method::GET,
            &console("/users"),
            With {
                cookie: Some(&root.cookie),
                ..With::default()
            },
        )
        .await;
    assert_eq!(
        users.body["items"].as_array().map(Vec::len),
        Some(1),
        "nobody was created"
    );
}

#[tokio::test]
async fn a_change_from_another_site_is_refused_even_with_the_token() {
    let world = world();
    let root = world
        .signed_in("root@example.com", &[Role::TenantAdministrator])
        .await;

    let reply = world
        .send(
            Method::POST,
            &console("/users"),
            With {
                cookie: Some(&root.cookie),
                csrf_token: Some(&root.csrf_token),
                origin: Some("https://elsewhere.example"),
                body: new_user(),
                ..With::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.code(), "request.cross_origin");
}

#[tokio::test]
async fn a_role_without_the_permission_is_refused() {
    let world = world();
    let auditor = world
        .signed_in("auditor@example.com", &[Role::TenantAuditor])
        .await;

    let reply = world
        .send(
            Method::POST,
            &console("/users"),
            With {
                cookie: Some(&auditor.cookie),
                csrf_token: Some(&auditor.csrf_token),
                body: new_user(),
                ..With::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.code(), "admin.forbidden");
}

#[tokio::test]
async fn a_sign_in_older_than_the_console_allows_is_refused() {
    let world = world();
    let root = world
        .signed_in("root@example.com", &[Role::TenantAdministrator])
        .await;
    let with = || With {
        cookie: Some(&root.cookie),
        ..With::default()
    };

    world
        .clock
        .advance(Duration::hours(CONSOLE_SESSION_HOURS) - Duration::seconds(1));
    let still = world.send(Method::GET, &console("/users"), with()).await;
    assert_eq!(still.status, StatusCode::OK);

    world.clock.advance(Duration::seconds(1));
    for path in ["/users", "/me"] {
        let late = world.send(Method::GET, &console(path), with()).await;
        assert_eq!(late.status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(late.code(), "console.not_authenticated", "{path}");
    }
}

#[tokio::test]
async fn a_session_of_another_tenant_is_not_known_here() {
    let world = world();
    let user = world
        .user(
            &world.globex,
            "root@example.com",
            &[Role::TenantAdministrator],
        )
        .await;
    let cookie = world.cookie_for(&world.globex, user).await;

    let there = world
        .send(
            Method::GET,
            "/t/globex/console/api/users",
            With {
                cookie: Some(&cookie),
                ..With::default()
            },
        )
        .await;
    assert_eq!(there.status, StatusCode::OK);

    let here = world
        .send(
            Method::GET,
            &console("/users"),
            With {
                cookie: Some(&cookie),
                ..With::default()
            },
        )
        .await;
    assert_eq!(here.status, StatusCode::UNAUTHORIZED);
    assert_eq!(here.code(), "console.not_authenticated");
}

#[tokio::test]
async fn a_suspended_administrator_loses_the_console() {
    let world = world();
    let root = world
        .signed_in("root@example.com", &[Role::TenantAdministrator])
        .await;
    let other = world
        .signed_in("other@example.com", &[Role::TenantAdministrator])
        .await;

    let suspended = world
        .send(
            Method::POST,
            &console(&format!("/users/{}:suspend", other.user)),
            With {
                cookie: Some(&root.cookie),
                csrf_token: Some(&root.csrf_token),
                body: Some(serde_json::json!({ "reason": "left the company" })),
                ..With::default()
            },
        )
        .await;
    assert_eq!(suspended.status, StatusCode::OK, "{}", suspended.body);

    let reply = world
        .send(
            Method::GET,
            &console("/me"),
            With {
                cookie: Some(&other.cookie),
                ..With::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.code(), "console.not_authenticated");
}

#[tokio::test]
async fn each_interface_knows_people_in_its_own_way_only() {
    let world = world();
    let root = world
        .signed_in("root@example.com", &[Role::TenantAdministrator])
        .await;
    let (_, secret) = world
        .tokens
        .issue(
            &world.acme,
            root.user,
            "test",
            Duration::hours(1),
            Caller::system(),
        )
        .await
        .expect("token");
    let bearer = format!("Bearer {}", secret.expose());

    // An access token opens the administration interface, not the console's.
    let reply = world
        .send(
            Method::GET,
            &console("/users"),
            With {
                authorization: Some(&bearer),
                ..With::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.code(), "console.not_authenticated");

    // A session opens the console's, not the administration interface.
    let reply = world
        .send(
            Method::GET,
            "/t/acme/api/v1/admin/users",
            With {
                cookie: Some(&root.cookie),
                ..With::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.code(), "admin.not_authenticated");

    // Who is asking is a question for the console interface alone, and the
    // description for programs is served to programs.
    for path in [
        "/t/acme/api/v1/admin/me",
        "/t/acme/console/api/openapi.json",
    ] {
        let reply = world
            .send(
                Method::GET,
                path,
                With {
                    cookie: Some(&root.cookie),
                    authorization: Some(&bearer),
                    ..With::default()
                },
            )
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
    }
}
