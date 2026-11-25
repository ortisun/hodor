//! The cross-tenant suite: everything that works in one tenant is
//! presented to another, which must refuse it.
//!
//! Specified in `docs/architecture/multi-tenancy.md`, "The cross-tenant
//! suite". Two tenants are set up to be as alike as two tenants can be: a
//! person with the same email address and the same password in each, and
//! an administrator in each. The real server binary answers, against a
//! real database.

use hodor_adapters_crypto::{
    Argon2Parameters, Argon2idHasher, HashingLimits, OsRandom, Sha256Digest,
};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    OutboxDispatcher, PgAccessTokenStore, PgAuditLog, PgDeliveryStore, PgEndpointStore,
    PgPasswordStore, PgRoleAssignmentStore, PgTenantDirectory, PgTenantRepository,
    PgUserRepository,
};
use hodor_audit::api::{AuditHandler, AuditService};
use hodor_authorization::api::{AuthorizationService, Role};
use hodor_credential::api::{AccessTokenService, CredentialService, NewPassword, PasswordRules};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, Secret, SystemClock, TenantContext, UserId};
use hodor_tenant::api::{CreateTenant, TenantService};
use hodor_webhooks::api::WebhookFanOut;
use reqwest::header::COOKIE;
use reqwest::{Client, Method, StatusCode};
use std::sync::Arc;

mod support;
use support::{Browser, MEMORY_KIBIBYTES, PASSES, Server, start_server, start_server_with};

const EMAIL: &str = "ana@example.com";
const PASSWORD: &str = "correct horse battery staple";
const SESSION_COOKIE: &str = "__Secure-hodor_session";

/// One of the two tenants, with its person and its administrator.
struct Tenant {
    slug: &'static str,
    context: TenantContext,
    /// The person with the shared email address and password.
    ana: UserId,
    administrator: UserId,
    administrator_token: String,
}

async fn create_tenant(database: &TestDatabase, slug: &'static str) -> Tenant {
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(SystemClock);
    let created = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        clock.clone(),
    )
    .create(
        CreateTenant {
            slug: slug.to_owned(),
            display_name: slug.to_owned(),
            open_registration: true,
            system: false,
        },
        Caller::system(),
    )
    .await
    .expect("tenant");
    let context = TenantContext::assume(created.id());

    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone());
    let mut people = Vec::new();
    for email in [EMAIL, "root@example.com"] {
        let user = identity
            .create(
                &context,
                CreateUser {
                    kind: UserKind::Human,
                    identifiers: vec![(IdentifierKind::Email, email.to_owned())],
                    profile: Profile::default(),
                    confirmed: true,
                },
                Caller::system(),
            )
            .await
            .expect("user");
        people.push(user.id());
    }
    let (ana, administrator) = (people[0], people[1]);

    let hasher = Argon2idHasher::new(
        Argon2Parameters {
            memory_kibibytes: MEMORY_KIBIBYTES,
            passes: PASSES,
            lanes: 1,
        },
        HashingLimits {
            concurrent: 2,
            queued: 8,
        },
        Arc::new(OsRandom),
    )
    .expect("hasher");
    let password = Secret::from(PASSWORD.to_owned());
    CredentialService::new(
        units(),
        Arc::new(PgPasswordStore),
        Arc::new(hasher),
        clock.clone(),
    )
    .set_password(
        &context,
        ana,
        NewPassword {
            password: &password,
            rules: PasswordRules {
                min_length: 12,
                max_length: 128,
                history_depth: 5,
            },
            own_names: &[],
        },
        false,
        Caller::system(),
    )
    .await
    .expect("password");

    AuthorizationService::new(units(), Arc::new(PgRoleAssignmentStore), clock.clone())
        .assign(
            &context,
            administrator,
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
        &context,
        administrator,
        "cross-tenant suite",
        std::time::Duration::from_secs(1800)
            .try_into()
            .expect("duration"),
        Caller::system(),
    )
    .await
    .expect("token");

    Tenant {
        slug,
        context,
        ana,
        administrator,
        administrator_token: secret.expose().to_owned(),
    }
}

struct World {
    database: TestDatabase,
    server: Server,
    acme: Tenant,
    globex: Tenant,
}

async fn world() -> World {
    world_with(&[]).await
}

async fn world_with(settings: &[(&str, &str)]) -> World {
    let database = TestDatabase::start().await;
    let acme = create_tenant(&database, "acme").await;
    let globex = create_tenant(&database, "globex").await;
    let server = if settings.is_empty() {
        start_server(&database).await
    } else {
        start_server_with(&database, settings).await
    };
    World {
        database,
        server,
        acme,
        globex,
    }
}

impl World {
    /// A request to a tenant's administration interface with a token.
    async fn admin(
        &self,
        tenant: &Tenant,
        token: &str,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let url = format!("{}/t/{}/api/v1/admin{path}", self.server.base, tenant.slug);
        let mut request = Client::new().request(method, url).bearer_auth(token);
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

    /// A request carrying a session cookie that the caller chose, whatever
    /// a browser would have sent.
    async fn with_session_cookie(
        &self,
        tenant: &Tenant,
        method: Method,
        path: &str,
        cookie: &str,
        csrf_token: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let url = format!("{}/t/{}/interaction{path}", self.server.base, tenant.slug);
        let mut request = Client::new()
            .request(method, url)
            .header(COOKIE, format!("{SESSION_COOKIE}={cookie}"));
        if let Some(token) = csrf_token {
            request = request.header("x-csrf-token", token);
        }
        let response = request.send().await.expect("response");
        let status = response.status();
        (
            status,
            response.json().await.unwrap_or(serde_json::Value::Null),
        )
    }

    /// The token in the newest link sent to the shared address in a tenant.
    async fn newest_link_token(&self, tenant: &Tenant) -> String {
        let link: String = sqlx::query_scalar(
            "SELECT variables->>'link' FROM notification.message
             WHERE tenant_id = $1 AND variables ? 'link'
             ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(tenant.context.tenant_id().as_uuid())
        .fetch_one(self.database.owner())
        .await
        .expect("a message with a link");
        link.split_once("#token=").expect("token").1.to_owned()
    }

    /// Does the worker's part: turns every waiting event into an audit
    /// record.
    async fn record_events(&self) {
        let audit = AuditService::new(
            Arc::new(self.database.app().clone()),
            Arc::new(PgAuditLog),
            Arc::new(Sha256Digest),
            Arc::new(SystemClock),
        );
        let dispatcher = OutboxDispatcher::new(
            self.database.platform().clone(),
            self.database.app().clone(),
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

    async fn post(
        &self,
        tenant: &Tenant,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        Browser::new(&self.server)
            .send(
                Method::POST,
                &format!("/t/{}/interaction/{path}", tenant.slug),
                Some(body),
            )
            .await
    }
}

/// Signs the shared person in to a tenant and returns the browser, its
/// session's identifier and its CSRF token.
async fn signed_in(world: &World, tenant: &Tenant) -> (Browser, String, String) {
    let mut browser = Browser::new(&world.server);
    let (_, body) = browser.sign_in(tenant.slug, EMAIL, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");
    let (status, body) = browser
        .send(
            Method::GET,
            &format!("/t/{}/interaction/session", tenant.slug),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let session = body["session_id"].as_str().expect("session").to_owned();
    let csrf = body["csrf_token"].as_str().expect("token").to_owned();
    (browser, session, csrf)
}

#[tokio::test]
async fn a_session_of_one_tenant_is_no_session_in_another() {
    let world = world().await;
    let (acme, globex) = (&world.acme, &world.globex);
    let (browser, session, csrf) = signed_in(&world, acme).await;
    let (other_browser, other_session, _) = signed_in(&world, globex).await;
    let cookie = browser.cookies[SESSION_COOKIE].clone();

    // Every route for a signed-in person, with Acme's cookie and Acme's
    // CSRF token, presented to Globex.
    let end_one = format!("/sessions/{session}");
    let end_theirs = format!("/sessions/{other_session}");
    let routes = [
        (Method::GET, "/session"),
        (Method::GET, "/sessions"),
        (Method::DELETE, "/sessions"),
        (Method::DELETE, end_one.as_str()),
        // Even naming a session that does exist in Globex.
        (Method::DELETE, end_theirs.as_str()),
        (Method::DELETE, "/session"),
    ];
    for (method, path) in &routes {
        let (status, body) = world
            .with_session_cookie(globex, method.clone(), path, &cookie, Some(&csrf))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(body["code"], "session.not_authenticated", "{method} {path}");
    }

    // Both people are still signed in where they signed in, as themselves.
    let (status, body) = world
        .with_session_cookie(acme, Method::GET, "/session", &cookie, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"], acme.ana.to_string());
    let other_cookie = &other_browser.cookies[SESSION_COOKIE];
    let (status, body) = world
        .with_session_cookie(globex, Method::GET, "/session", other_cookie, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"], globex.ana.to_string());
    assert_ne!(
        acme.ana, globex.ana,
        "the same address, two different people"
    );
}

#[tokio::test]
async fn a_sign_in_started_in_one_tenant_cannot_be_continued_in_another() {
    let world = world().await;
    let (acme, globex) = (&world.acme, &world.globex);
    let mut browser = Browser::new(&world.server);
    let (status, _) = browser
        .send(Method::POST, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, body) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/sign-in/steps/identifier",
            Some(serde_json::json!({ "identifier": EMAIL })),
        )
        .await;
    assert_eq!(body["step"], "password");

    // The same browser, cookie and CSRF token, on Globex's paths. The
    // password is right in Globex too.
    for (method, path, body) in [
        (Method::GET, "/sign-in", None),
        (
            Method::POST,
            "/sign-in/steps/password",
            Some(serde_json::json!({ "password": PASSWORD })),
        ),
        (
            Method::POST,
            "/sign-in/steps/identifier",
            Some(serde_json::json!({ "identifier": EMAIL })),
        ),
        (Method::DELETE, "/sign-in", None),
    ] {
        let (status, answer) = browser
            .send(
                method.clone(),
                &format!("/t/{}/interaction{path}", globex.slug),
                body,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(
            answer["code"], "authentication.transaction_not_found",
            "{method} {path}"
        );
    }
    assert!(!browser.cookies.contains_key(SESSION_COOKIE));

    // It continues where it belongs, and signs Acme's person in.
    let (_, body) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/sign-in/steps/password",
            Some(serde_json::json!({ "password": PASSWORD })),
        )
        .await;
    assert_eq!(body["status"], "completed");
    let (_, body) = browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(body["user_id"], acme.ana.to_string());
}

#[tokio::test]
async fn an_administrators_token_is_refused_by_every_operation_of_another_tenant() {
    // With keys and the certificate authority on, so that every operation
    // the interface has is routed.
    let world = world_with(&[
        ("HODOR_SECRET_KEYS", ROOT_KEY),
        ("HODOR_CERTIFICATE_AUTHORITY", "development"),
    ])
    .await;
    let (acme, globex) = (&world.acme, &world.globex);
    let (status, document) = world
        .admin(acme, "", Method::GET, "/openapi.json", None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let mut tried = 0;
    for (template, methods) in document["paths"].as_object().expect("paths") {
        for method in methods.as_object().expect("operations").keys() {
            // Name things that exist in Globex, so that only the token is
            // wrong.
            let path = template
                .replace("{user_id}", &globex.ana.to_string())
                .replace("{session_id}", &globex.ana.to_string())
                .replace("{provider_id}", &globex.ana.to_string())
                .replace("{key_set}", "sig")
                .replace("{version_id}", &globex.ana.to_string())
                .replace("{application_id}", &globex.ana.to_string())
                .replace("{client_id}", &globex.ana.to_string())
                .replace("{claim_mapper_id}", &globex.ana.to_string())
                .replace("{secret_id}", &globex.ana.to_string())
                .replace("{key_id}", "a-key")
                .replace("{resource_server_id}", &globex.ana.to_string())
                .replace("{group_id}", &globex.ana.to_string())
                .replace("{organization_id}", &globex.ana.to_string())
                .replace("{unit_id}", &globex.ana.to_string())
                .replace("{invitation_id}", &globex.ana.to_string())
                .replace("{permission}", "document:read")
                .replace("{role}", "editor")
                .replace("{number}", "1")
                .replace("{simulation_id}", &globex.ana.to_string())
                .replace("{service_account_id}", &globex.ana.to_string())
                .replace("{agent_id}", &globex.ana.to_string())
                .replace("{endpoint_id}", &globex.ana.to_string())
                .replace("{delivery_id}", &globex.ana.to_string())
                .replace("{api_key_id}", &globex.ana.to_string())
                .replace("{entry_id}", &globex.ana.to_string())
                .replace("{trust_domain_id}", &globex.ana.to_string())
                .replace("{intermediate_id}", &globex.ana.to_string());
            let method: Method = method.to_uppercase().parse().expect("method");
            let (status, body) = world
                .admin(
                    globex,
                    &acme.administrator_token,
                    method.clone(),
                    &path,
                    Some(serde_json::json!({ "email": "new@example.com", "reason": "x" })),
                )
                .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {template}");
            assert_eq!(
                body["code"], "admin.not_authenticated",
                "{method} {template}"
            );
            tried += 1;
        }
    }
    assert_eq!(tried, 154, "every documented operation was tried");

    // The token is good where it belongs, and nothing happened in Globex:
    // it has its two users, both active.
    let (status, _) = world
        .admin(acme, &acme.administrator_token, Method::GET, "/users", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, users) = world
        .admin(
            globex,
            &globex.administrator_token,
            Method::GET,
            "/users",
            None,
        )
        .await;
    let statuses: Vec<&str> = users["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|user| user["status"].as_str())
        .collect();
    assert_eq!(statuses, ["active", "active"]);
}

#[tokio::test]
async fn an_administrator_cannot_reach_another_tenants_users_or_sessions_by_naming_them() {
    let world = world().await;
    let (acme, globex) = (&world.acme, &world.globex);
    let (browser, session, _) = signed_in(&world, acme).await;
    let token = &globex.administrator_token;

    // Globex's administrator, with a good token, names Acme's person and
    // Acme's session.
    for (method, path, body, code) in [
        (
            Method::GET,
            format!("/users/{}", acme.ana),
            None,
            "identity.user_not_found",
        ),
        (
            Method::POST,
            format!("/users/{}:suspend", acme.ana),
            Some(serde_json::json!({ "reason": "not mine to suspend" })),
            "identity.user_not_found",
        ),
        (
            Method::GET,
            format!("/users/{}/sessions", acme.ana),
            None,
            "identity.user_not_found",
        ),
        (
            Method::DELETE,
            format!("/sessions/{session}"),
            None,
            "session.not_found",
        ),
    ] {
        let (status, answer) = world
            .admin(globex, token, method.clone(), &path, body)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(answer["code"], code, "{method} {path}");
    }

    // Acme's person is still active and still signed in.
    let (_, user) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::GET,
            &format!("/users/{}", acme.ana),
            None,
        )
        .await;
    assert_eq!(user["status"], "active");
    let cookie = &browser.cookies[SESSION_COOKIE];
    let (status, _) = world
        .with_session_cookie(acme, Method::GET, "/session", cookie, None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_link_sent_in_one_tenant_does_not_work_in_another() {
    let world = world().await;
    let (acme, globex) = (&world.acme, &world.globex);
    let new_password = "a different long passphrase";

    // A recovery link for Acme's person. The same address has an account
    // in Globex, with the same password.
    let (status, _) = world
        .post(acme, "recovery", serde_json::json!({ "email": EMAIL }))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let recovery = world.newest_link_token(acme).await;
    let (status, body) = world
        .post(
            globex,
            "recovery/complete",
            serde_json::json!({ "token": recovery, "password": new_password }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "authentication.verification_token_invalid");

    // A registration link for an address that has no account in either.
    let (status, _) = world
        .post(
            acme,
            "registration",
            serde_json::json!({ "email": "bia@example.com" }),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let registration = world.newest_link_token(acme).await;
    let (status, body) = world
        .post(
            globex,
            "registration/complete",
            serde_json::json!({ "token": registration, "password": PASSWORD }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "authentication.verification_token_invalid");

    // Nothing changed in Globex: the old password still signs its person
    // in, and nobody was registered there.
    let (_, body) = Browser::new(&world.server)
        .sign_in(globex.slug, EMAIL, PASSWORD)
        .await;
    assert_eq!(body["status"], "completed");
    let (_, body) = Browser::new(&world.server)
        .sign_in(globex.slug, "bia@example.com", PASSWORD)
        .await;
    assert_eq!(body["status"], "rejected");

    // Both links still work where they belong.
    let (status, _) = world
        .post(
            acme,
            "recovery/complete",
            serde_json::json!({ "token": recovery, "password": new_password }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = world
        .post(
            acme,
            "registration/complete",
            serde_json::json!({ "token": registration, "password": PASSWORD }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // And changing the password in Acme changed nothing in Globex.
    let (_, body) = Browser::new(&world.server)
        .sign_in(globex.slug, EMAIL, PASSWORD)
        .await;
    assert_eq!(body["status"], "completed");
    let (_, body) = Browser::new(&world.server)
        .sign_in(acme.slug, EMAIL, PASSWORD)
        .await;
    assert_eq!(body["status"], "rejected");
}

#[tokio::test]
async fn being_locked_out_in_one_tenant_does_not_lock_the_same_address_out_in_another() {
    let world = world().await;
    let (acme, globex) = (&world.acme, &world.globex);

    // Wrong passwords for the shared address in Acme until it is limited.
    let mut limited = false;
    for _ in 0..4 {
        let mut browser = Browser::new(&world.server);
        for _ in 0..3 {
            let (status, body) = browser.sign_in(acme.slug, EMAIL, "not the password").await;
            if status == StatusCode::TOO_MANY_REQUESTS {
                assert_eq!(body["code"], "authentication.too_many_attempts");
                limited = true;
            }
        }
    }
    assert!(limited, "the address was locked out in Acme");
    let (status, _) = Browser::new(&world.server)
        .sign_in(acme.slug, EMAIL, PASSWORD)
        .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "even the right password waits in Acme"
    );

    // The person with the same address in Globex signs in at once.
    let (status, body) = Browser::new(&world.server)
        .sign_in(globex.slug, EMAIL, PASSWORD)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "completed");
}

#[tokio::test]
async fn one_tenants_users_and_audit_log_name_nothing_of_another() {
    let world = world().await;
    let (acme, globex) = (&world.acme, &world.globex);
    // Something happens in each tenant, by each administrator.
    for tenant in [acme, globex] {
        let (status, _) = world
            .admin(
                tenant,
                &tenant.administrator_token,
                Method::POST,
                "/users",
                Some(serde_json::json!({ "email": format!("new@{}.example", tenant.slug) })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    world.record_events().await;

    for (tenant, other) in [(acme, globex), (globex, acme)] {
        let token = &tenant.administrator_token;
        let (_, users) = world
            .admin(tenant, token, Method::GET, "/users", None)
            .await;
        let (_, log) = world
            .admin(tenant, token, Method::GET, "/audit-records?limit=200", None)
            .await;
        let (users, log) = (users.to_string(), log.to_string());

        // Its own people and its own administrator's doings are there.
        assert!(users.contains(&tenant.ana.to_string()));
        assert!(users.contains(&format!("new@{}.example", tenant.slug)));
        assert!(log.contains(&tenant.administrator.to_string()));
        assert!(log.contains("identity.user_created"));

        // Nothing of the other tenant is: not its people, not its
        // administrator, not its own identifier.
        for foreign in [
            other.ana.to_string(),
            other.administrator.to_string(),
            other.context.tenant_id().to_string(),
            format!("new@{}.example", other.slug),
        ] {
            assert!(!users.contains(&foreign), "{} lists {foreign}", tenant.slug);
            assert!(
                !log.contains(&foreign),
                "{}'s log names {foreign}",
                tenant.slug
            );
        }
    }
}

/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";

#[tokio::test]
async fn a_tenants_key_set_names_none_of_another_tenants_keys() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let key_set = |tenant: &Tenant| {
        let url = format!("{}/t/{}/oauth2/jwks", world.server.base, tenant.slug);
        async move {
            let response = Client::new().get(url).send().await.expect("response");
            assert_eq!(response.status(), StatusCode::OK);
            let body: serde_json::Value = response.json().await.expect("JSON");
            body["keys"]
                .as_array()
                .expect("keys")
                .iter()
                .map(|key| key["kid"].as_str().expect("kid").to_owned())
                .collect::<Vec<_>>()
        }
    };
    // The first read gives each tenant keys of its own.
    let (first_acme, first_globex) = (key_set(acme).await, key_set(globex).await);
    assert!(first_acme.iter().all(|key| !first_globex.contains(key)));

    let mut made = Vec::new();
    for tenant in [acme, globex] {
        let (status, version) = world
            .admin(
                tenant,
                &tenant.administrator_token,
                Method::POST,
                "/keys/sig:rotate",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{version}");
        made.push(version["id"].as_str().expect("id").to_owned());
    }
    let (acme_keys, globex_keys) = (key_set(acme).await, key_set(globex).await);
    assert!(acme_keys.contains(&made[0]) && !acme_keys.contains(&made[1]));
    assert!(globex_keys.contains(&made[1]) && !globex_keys.contains(&made[0]));

    // Acme's administrator cannot rotate or revoke Globex's keys, and a
    // version of Acme's is not found in Globex.
    let (status, _) = world
        .admin(
            globex,
            &acme.administrator_token,
            Method::POST,
            &format!("/keys/sig/versions/{}:revoke", made[1]),
            Some(serde_json::json!({ "reason": "not mine" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = world
        .admin(
            globex,
            &globex.administrator_token,
            Method::POST,
            &format!("/keys/sig/versions/{}:revoke", made[0]),
            Some(serde_json::json!({ "reason": "not ours" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "keys.version_not_found");
    assert!(
        key_set(acme).await.contains(&made[0]),
        "Acme's key is untouched"
    );
}

/// A code of an authenticator application with this secret, for a moment
/// `steps` periods of thirty seconds from now. The server's window takes
/// one period either way, and refuses a period it has seen.
fn application_code(secret: &[u8], steps: i64) -> String {
    use hodor_adapters_crypto::AwsLcHmacSha1;
    use hodor_credential::api::totp_code_at;
    let moment = hodor_kernel::Clock::now(&SystemClock) + time::Duration::seconds(30 * steps);
    totp_code_at(&AwsLcHmacSha1, secret, moment)
}

/// Puts an authenticator application in use for the signed-in person, the
/// way the person's own pages do, and answers its secret and the recovery
/// codes that came with it.
async fn enroll_application(browser: &mut Browser, tenant: &Tenant) -> (Vec<u8>, Vec<String>) {
    let base = format!(
        "/t/{}/interaction/factors/authenticator-application",
        tenant.slug
    );
    let (status, begun) = browser.send(Method::POST, &base, None).await;
    assert_eq!(status, StatusCode::CREATED, "{begun}");
    let secret = support::base32(begun["secret"].as_str().expect("secret"));
    let (status, confirmed) = browser
        .send(
            Method::POST,
            &format!("{base}/confirmation"),
            Some(serde_json::json!({ "code": application_code(&secret, 0) })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{confirmed}");
    let codes = confirmed["recovery_codes"]
        .as_array()
        .expect("recovery codes")
        .iter()
        .map(|code| code.as_str().expect("code").to_owned())
        .collect();
    (secret, codes)
}

/// Registers a WebAuthn credential for the signed-in person with a
/// software authenticator, and answers the credential's identifier.
async fn register_key(
    browser: &mut Browser,
    tenant: &Tenant,
    authenticator: &hodor_adapters_crypto::testing::webauthn::SoftwareAuthenticator,
    passkey: bool,
) -> String {
    let base = format!("/t/{}/interaction/webauthn/registrations", tenant.slug);
    let (status, begun) = browser
        .send(
            Method::POST,
            &base,
            Some(serde_json::json!({ "passkey": passkey })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{begun}");
    let registration = begun["registration_id"].as_str().expect("registration");
    let (status, made) = browser
        .send(
            Method::POST,
            &format!("{base}/{registration}"),
            Some(authenticator.register(&begun["public_key"])),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    made["id"].as_str().expect("id").to_owned()
}

/// Signs the shared person in up to the step after the password.
async fn waiting_after_password(world: &World, tenant: &Tenant) -> (Browser, serde_json::Value) {
    let mut browser = Browser::new(&world.server);
    let (_, body) = browser.sign_in(tenant.slug, EMAIL, PASSWORD).await;
    (browser, body)
}

#[tokio::test]
async fn an_authenticator_application_and_recovery_codes_of_one_tenant_mean_nothing_in_another() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);

    // In Acme the application is in use, and a recovery code stands in for
    // its code.
    let (mut browser, _, _) = signed_in(&world, acme).await;
    let (acme_secret, acme_codes) = enroll_application(&mut browser, acme).await;
    let (mut browser, body) = waiting_after_password(&world, acme).await;
    assert_eq!(body["step"], "totp", "{body}");
    let (_, body) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/sign-in/steps/recovery_code",
            Some(serde_json::json!({ "code": acme_codes[0] })),
        )
        .await;
    assert_eq!(body["status"], "completed", "{body}");

    // Globex knows nothing of it: the same person signs in with the
    // password alone.
    let (mut browser, body) = waiting_after_password(&world, globex).await;
    assert_eq!(body["status"], "completed", "{body}");
    let (_, session) = browser
        .send(Method::GET, "/t/globex/interaction/session", None)
        .await;
    assert_eq!(session["methods"], serde_json::json!(["password"]));

    // With an application of its own, Globex asks for a code, and refuses
    // Acme's codes and Acme's recovery codes.
    let (globex_secret, _) = enroll_application(&mut browser, globex).await;
    assert_ne!(acme_secret, globex_secret);
    let (mut browser, body) = waiting_after_password(&world, globex).await;
    assert_eq!(body["step"], "totp", "{body}");
    for (step, code) in [
        ("recovery_code", acme_codes[1].clone()),
        ("totp", application_code(&acme_secret, 1)),
    ] {
        let (status, body) = browser
            .send(
                Method::POST,
                &format!("/t/globex/interaction/sign-in/steps/{step}"),
                Some(serde_json::json!({ "code": code })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "rejected", "{step}: {body}");
    }

    // The factors of a person are reached only in their own tenant.
    let path = |user: UserId| format!("/users/{}/factors", user.as_uuid());
    let (status, _) = world
        .admin(
            globex,
            &acme.administrator_token,
            Method::GET,
            &path(globex.ana),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = world
        .admin(
            globex,
            &globex.administrator_token,
            Method::DELETE,
            &format!("{}/authenticator-application", path(acme.ana)),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "identity.user_not_found");

    // Acme is as it was: its application in use, nine codes left, and the
    // codes Globex refused still good here.
    let (status, factors) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::GET,
            &path(acme.ana),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{factors}");
    assert_eq!(factors["authenticator_application"]["in_use"], true);
    assert_eq!(factors["recovery_codes"]["remaining"], 9);
    let (mut browser, _) = waiting_after_password(&world, acme).await;
    let (_, body) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/sign-in/steps/recovery_code",
            Some(serde_json::json!({ "code": acme_codes[1] })),
        )
        .await;
    assert_eq!(body["status"], "completed", "{body}");
}

#[tokio::test]
async fn a_passkey_or_a_security_key_of_one_tenant_is_refused_by_another() {
    use hodor_adapters_crypto::testing::webauthn::SoftwareAuthenticator;
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    // The relying party of the server, as `HODOR_PUBLIC_URL` leaves it.
    let origin = "http://localhost:8080";
    let passkey = SoftwareAuthenticator::passkey(origin);
    let acme_key = SoftwareAuthenticator::new(origin);
    let globex_key = SoftwareAuthenticator::new(origin);

    let (mut browser, _, _) = signed_in(&world, acme).await;
    register_key(&mut browser, acme, &passkey, true).await;
    let acme_key_id = register_key(&mut browser, acme, &acme_key, false).await;
    let (mut browser, _, _) = signed_in(&world, globex).await;
    register_key(&mut browser, globex, &globex_key, false).await;

    let with_passkey = |tenant: &'static str| {
        let mut browser = Browser::new(&world.server);
        let passkey = &passkey;
        async move {
            browser
                .send(
                    Method::POST,
                    &format!("/t/{tenant}/interaction/sign-in"),
                    None,
                )
                .await;
            let (_, options) = browser
                .send(
                    Method::POST,
                    &format!("/t/{tenant}/interaction/sign-in/steps/passkey/options"),
                    None,
                )
                .await;
            let (_, body) = browser
                .send(
                    Method::POST,
                    &format!("/t/{tenant}/interaction/sign-in/steps/passkey"),
                    Some(passkey.answer(&options["public_key"])),
                )
                .await;
            body
        }
    };
    assert_eq!(with_passkey("acme").await["status"], "completed");
    let refused = with_passkey("globex").await;
    assert_eq!(refused["status"], "rejected", "{refused}");
    assert_eq!(refused["step"], "identifier", "{refused}");

    // Globex offers only its own key, and refuses Acme's key's answer.
    let (mut browser, body) = waiting_after_password(&world, globex).await;
    assert_eq!(body["step"], "webauthn", "{body}");
    let (_, options) = browser
        .send(
            Method::POST,
            "/t/globex/interaction/sign-in/steps/webauthn/options",
            None,
        )
        .await;
    let offered: Vec<&str> = options["public_key"]["allowCredentials"]
        .as_array()
        .expect("credentials")
        .iter()
        .map(|credential| credential["id"].as_str().expect("id"))
        .collect();
    assert_eq!(offered, vec![globex_key.credential_id().as_str()]);
    let (_, body) = browser
        .send(
            Method::POST,
            "/t/globex/interaction/sign-in/steps/webauthn",
            Some(acme_key.answer(&options["public_key"])),
        )
        .await;
    assert_eq!(body["status"], "rejected", "{body}");

    // Globex's administrator cannot remove Acme's key by naming it.
    let (status, body) = world
        .admin(
            globex,
            &globex.administrator_token,
            Method::DELETE,
            &format!("/users/{}/factors/keys/{acme_key_id}", globex.ana.as_uuid()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "credential.webauthn_credential_not_found");

    // Acme's key still answers in Acme.
    let (mut browser, body) = waiting_after_password(&world, acme).await;
    assert_eq!(body["step"], "webauthn", "{body}");
    let (_, options) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/sign-in/steps/webauthn/options",
            None,
        )
        .await;
    let (_, body) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/sign-in/steps/webauthn",
            Some(acme_key.answer(&options["public_key"])),
        )
        .await;
    assert_eq!(body["status"], "completed", "{body}");
}

#[tokio::test]
async fn one_tenants_assurance_levels_are_not_another_tenants() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let levels = serde_json::json!({ "levels": [
        { "acr": "urn:hodor:acr:mfa", "requirement": "multi_factor" },
        { "acr": "urn:acme:strong", "requirement": "phishing_resistant" },
    ] });
    let (status, body) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::PUT,
            "/assurance-levels",
            Some(levels.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = world
        .admin(
            globex,
            &acme.administrator_token,
            Method::PUT,
            "/assurance-levels",
            Some(levels),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let supported = |tenant: &'static str| {
        let url = format!(
            "{}/t/{tenant}/.well-known/openid-configuration",
            world.server.base
        );
        async move {
            let body: serde_json::Value = Client::new()
                .get(url)
                .send()
                .await
                .expect("response")
                .json()
                .await
                .expect("JSON");
            body["acr_values_supported"].clone()
        }
    };
    assert_eq!(
        supported("acme").await,
        serde_json::json!(["urn:hodor:acr:mfa", "urn:acme:strong"])
    );
    assert_eq!(
        supported("globex").await,
        serde_json::json!(["urn:hodor:acr:single-factor", "urn:hodor:acr:mfa"])
    );
}

const REDIRECT: &str = "https://billing.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const AUDIENCE: &str = "https://api.billing.example.com";

/// A third-party application of a tenant, with a resource server and a
/// confidential client allowed a code, refresh tokens and a token for
/// itself. Answers the client's identifier and its secret.
async fn third_party_client(world: &World, tenant: &Tenant) -> (String, String) {
    client_of(world, tenant, false).await
}

/// As [`third_party_client`], for an application of the tenant's own, whose
/// people are never asked for consent.
async fn first_party_client(world: &World, tenant: &Tenant) -> (String, String) {
    client_of(world, tenant, true).await
}

async fn client_of(world: &World, tenant: &Tenant, first_party: bool) -> (String, String) {
    use hodor_adapters_postgres::{PgApplicationStore, PgClientStore, PgResourceServerStore};
    use hodor_oauth::api::{
        ApplicationPorts, ApplicationService, ApplicationSettings, ClientSettings, ClientType,
        CreateClient, CreateResourceServer, GrantType, ResourceServerSettings, ScopeDefinition,
    };
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(world.database.app().clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    });
    let application = applications
        .create_application(
            &tenant.context,
            ApplicationSettings {
                name: "Billing".to_owned(),
                first_party,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    applications
        .create_resource_server(
            &tenant.context,
            CreateResourceServer {
                application_id: application.id(),
                audience: AUDIENCE.to_owned(),
                settings: ResourceServerSettings {
                    name: "Invoices".to_owned(),
                    scopes: vec![ScopeDefinition {
                        name: "invoices:read".to_owned(),
                        description: "Read your invoices".to_owned(),
                    }],
                },
            },
            Caller::system(),
        )
        .await
        .expect("resource server");
    let mut settings = ClientSettings::new(
        "Billing web",
        ClientType::Confidential,
        vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
        ],
        vec![REDIRECT.to_owned()],
    );
    settings.allowed_scopes = vec![
        "openid".to_owned(),
        "offline_access".to_owned(),
        "invoices:read".to_owned(),
    ];
    let (client, secret) = applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    (
        client.id().to_string(),
        secret.expect("a secret").expose().to_owned(),
    )
}

fn authorize_path(slug: &str, client_id: &str) -> String {
    authorize_path_with(slug, client_id, &[])
}

/// As [`authorize_path`], with more parameters, such as `organization`.
fn authorize_path_with(slug: &str, client_id: &str, more: &[(&str, &str)]) -> String {
    let challenge = hodor_oauth::api::s256_challenge(VERIFIER, &Sha256Digest);
    format!(
        "/t/{slug}/oauth2/authorize?{}",
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", REDIRECT),
                ("scope", "openid offline_access invoices:read"),
                ("state", "the state"),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
            ])
            .extend_pairs(more)
            .finish()
    )
}

/// A form sent to one of a tenant's OAuth endpoints, with a client's
/// identifier and secret as Basic authentication.
async fn oauth_form(
    world: &World,
    tenant: &Tenant,
    endpoint: &str,
    client: (&str, &str),
    pairs: &[(&str, &str)],
) -> (StatusCode, serde_json::Value) {
    use base64::Engine as _;
    let basic =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", client.0, client.1));
    let response = Client::new()
        .post(format!(
            "{}/t/{}/oauth2/{endpoint}",
            world.server.base, tenant.slug
        ))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", format!("Basic {basic}"))
        .body(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish(),
        )
        .send()
        .await
        .expect("response");
    let status = response.status();
    (
        status,
        response.json().await.unwrap_or(serde_json::Value::Null),
    )
}

async fn userinfo(world: &World, tenant: &Tenant, access: &str) -> StatusCode {
    Client::new()
        .get(format!(
            "{}/t/{}/oauth2/userinfo",
            world.server.base, tenant.slug
        ))
        .bearer_auth(access)
        .send()
        .await
        .expect("response")
        .status()
}

/// Whether a tenant's client is told a token is active.
async fn active(world: &World, tenant: &Tenant, client: (&str, &str), token: &str) -> bool {
    let (status, body) = oauth_form(world, tenant, "introspect", client, &[("token", token)]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    if body["active"] == true {
        true
    } else {
        assert_eq!(body, serde_json::json!({ "active": false }), "nothing more");
        false
    }
}

#[tokio::test]
async fn an_applications_codes_tokens_clients_and_consents_mean_nothing_in_another_tenant() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let (acme_client, acme_secret) = third_party_client(&world, acme).await;
    let (globex_client, globex_secret) = third_party_client(&world, globex).await;
    let acme_pair = (acme_client.as_str(), acme_secret.as_str());
    let globex_pair = (globex_client.as_str(), globex_secret.as_str());

    // The client of Acme is no client in Globex: an error page of Hodor's,
    // never a redirect to the address it names.
    let mut stranger = Browser::not_following(&world.server);
    let (_, body) = stranger.sign_in(globex.slug, EMAIL, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");
    let (status, location, _) = stranger
        .navigate(
            Method::GET,
            &authorize_path(globex.slug, &acme_client),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(location, None, "nothing is sent to the client's address");
    // Nor posted to it, when the request asks for `form_post`.
    let (status, location, page) = stranger
        .navigate(
            Method::GET,
            &authorize_path_with(globex.slug, &acme_client, &[("response_mode", "form_post")]),
            None,
        )
        .await;
    assert_eq!((status, location), (StatusCode::BAD_REQUEST, None));
    assert!(
        page.contains("oauth.authorization_client_unknown"),
        "{page}"
    );
    assert!(
        !page.contains("<form") && !page.contains(REDIRECT),
        "{page}"
    );

    // In Acme, the person agrees and the application gets a code.
    let mut browser = Browser::not_following(&world.server);
    let (_, body) = browser.sign_in(acme.slug, EMAIL, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");
    let (status, location, _) = browser
        .navigate(Method::GET, &authorize_path(acme.slug, &acme_client), None)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location.as_deref(), Some("/t/acme/account/consent"));
    let (status, question) = browser
        .send(Method::GET, "/t/acme/interaction/consent", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{question}");
    let (status, answer) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/consent",
            Some(serde_json::json!({ "decision": "allow" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (status, location, _) = browser
        .navigate(Method::GET, "/t/acme/oauth2/authorize/resume", None)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let location = location.expect("a redirect");
    let (address, query) = location.split_once('?').expect("a query");
    assert_eq!(address, REDIRECT);
    let code = form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == "code")
        .expect("a code")
        .1
        .into_owned();
    let redeem = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
    ];

    // Acme's code at Globex: with Acme's client, which Globex does not
    // know, and with Globex's own client, to which it was not issued.
    let (status, body) = oauth_form(&world, globex, "token", acme_pair, &redeem).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    let (status, body) = oauth_form(&world, globex, "token", globex_pair, &redeem).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");

    // The code still redeems where it belongs, once.
    let (status, tokens) = oauth_form(&world, acme, "token", acme_pair, &redeem).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let access = tokens["access_token"].as_str().expect("access").to_owned();
    let refresh = tokens["refresh_token"]
        .as_str()
        .expect("refresh")
        .to_owned();

    // The access token: refused by Globex's UserInfo, not active for
    // Globex's client, and still good in Acme.
    assert_eq!(
        userinfo(&world, globex, &access).await,
        StatusCode::UNAUTHORIZED
    );
    assert!(!active(&world, globex, globex_pair, &access).await);
    assert_eq!(userinfo(&world, acme, &access).await, StatusCode::OK);
    assert!(active(&world, acme, acme_pair, &access).await);

    // The refresh token: Globex refuses it, revokes nothing with it, and
    // does not call it active.
    let refreshing = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh.as_str()),
    ];
    let (status, body) = oauth_form(&world, globex, "token", globex_pair, &refreshing).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    let (status, _) = oauth_form(
        &world,
        globex,
        "revoke",
        globex_pair,
        &[("token", &refresh)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same empty answer as for any token"
    );
    let (status, _) =
        oauth_form(&world, globex, "revoke", globex_pair, &[("token", &access)]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!active(&world, globex, globex_pair, &refresh).await);
    assert!(active(&world, acme, acme_pair, &refresh).await);
    assert!(
        active(&world, acme, acme_pair, &access).await,
        "nothing was revoked"
    );
    let (status, refreshed) = oauth_form(&world, acme, "token", acme_pair, &refreshing).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "it still refreshes in Acme: {refreshed}"
    );

    // A token for the client itself: Acme's secret means nothing in Globex.
    let itself = [
        ("grant_type", "client_credentials"),
        ("scope", "invoices:read"),
    ];
    let (status, body) = oauth_form(&world, acme, "token", acme_pair, &itself).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = oauth_form(&world, globex, "token", acme_pair, &itself).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");

    // The consent: neither the person nor the administrator of Globex can
    // withdraw it, and it still stands in Acme. The page reads the session
    // first, which gives it the session's CSRF token.
    let (status, _) = stranger
        .send(Method::GET, "/t/globex/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = stranger
        .send(
            Method::DELETE,
            &format!("/t/globex/interaction/consents/{acme_client}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["code"], "oauth.consent_not_found");
    let (status, body) = world
        .admin(
            globex,
            &globex.administrator_token,
            Method::DELETE,
            &format!("/users/{}/consents/{acme_client}", acme.ana),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, _) = world
        .admin(
            globex,
            &acme.administrator_token,
            Method::GET,
            &format!("/users/{}/consents", acme.ana),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, consents) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::GET,
            &format!("/users/{}/consents", acme.ana),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{consents}");
    assert!(
        consents.to_string().contains(&acme_client),
        "the consent stands in Acme: {consents}"
    );
}

/// A request of the tenant's own administrator, through the
/// administration interface.
async fn call(
    world: &World,
    tenant: &Tenant,
    method: Method,
    path: String,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    world
        .admin(tenant, &tenant.administrator_token, method, &path, body)
        .await
}

#[tokio::test]
async fn one_tenants_roles_bindings_and_policies_are_invisible_and_unusable_from_another() {
    let world = world().await;
    let (acme, globex) = (&world.acme, &world.globex);
    let (status, application) = call(
        &world,
        acme,
        Method::POST,
        "/applications".to_owned(),
        Some(serde_json::json!({ "name": "Documents", "first_party": true })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{application}");
    let application = application["id"].as_str().expect("id").to_owned();
    let (status, server) = call(
        &world,
        acme,
        Method::POST,
        "/resource-servers".to_owned(),
        Some(serde_json::json!({
            "application_id": application,
            "audience": "https://api.documents.example.com",
            "name": "Documents interface",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{server}");
    let server = server["id"].as_str().expect("id").to_owned();
    let namespace = "https://api.documents.example.com";
    for (method, path, body) in [
        (
            Method::PUT,
            format!("/resource-servers/{server}/permissions/document:read"),
            serde_json::json!({ "description": "Read" }),
        ),
        (
            Method::PUT,
            format!("/resource-servers/{server}/roles/reader"),
            serde_json::json!({ "permissions": [{ "name": "document:read" }] }),
        ),
        (
            Method::POST,
            "/role-assignments".to_owned(),
            serde_json::json!({
                "principal": { "kind": "user", "id": acme.ana.to_string() },
                "role": { "namespace": namespace, "name": "reader" },
            }),
        ),
        (
            Method::PUT,
            format!("/resource-servers/{server}/binding"),
            serde_json::json!({ "engine": "native" }),
        ),
    ] {
        let (status, body) = call(&world, acme, method, path.clone(), Some(body)).await;
        assert!(status.is_success(), "{path}: {status} {body}");
    }

    // Globex's administrator, naming Acme's resource server and Acme's
    // person, reaches nothing of them.
    for path in [
        format!("/resource-servers/{server}/permissions"),
        format!("/resource-servers/{server}/roles/reader"),
        format!("/resource-servers/{server}/binding"),
        format!("/users/{}/role-assignments", acme.ana),
    ] {
        let (status, body) = call(&world, globex, Method::GET, path.clone(), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
    }
    let (status, _) = call(
        &world,
        globex,
        Method::PUT,
        format!("/resource-servers/{server}/roles/reader"),
        Some(serde_json::json!({ "permissions": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &world,
        globex,
        Method::POST,
        "/role-assignments:revoke".to_owned(),
        Some(serde_json::json!({
            "principal": { "kind": "user", "id": acme.ana.to_string() },
            "role": { "namespace": namespace, "name": "reader" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A role of Globex's own cannot be given to Acme's person.
    let (status, _) = call(
        &world,
        globex,
        Method::POST,
        "/role-assignments".to_owned(),
        Some(serde_json::json!({
            "principal": { "kind": "user", "id": acme.ana.to_string() },
            "role": { "namespace": namespace, "name": "reader" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    for path in ["/roles", "/bindings", "/policy-versions"] {
        let (status, body) = call(&world, globex, Method::GET, path.to_owned(), None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        assert_eq!(body["items"], serde_json::json!([]), "{path}");
    }

    // A policy version of Acme's is no version of Globex's.
    let (status, drafted) = call(
        &world,
        acme,
        Method::POST,
        "/policy-versions".to_owned(),
        Some(serde_json::json!({ "files": [{
            "path": "policy.rego",
            "contents": format!(
                "package hodor.tenants.t{}\n\ndefault allow := false\n",
                acme.context.tenant_id().to_string().replace('-', "")
            ),
        }] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{drafted}");
    let number = drafted["number"].as_u64().expect("number");
    let (status, _) = call(
        &world,
        globex,
        Method::GET,
        format!("/policy-versions/{number}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &world,
        globex,
        Method::POST,
        format!("/policy-versions/{number}:validate"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A directory's client of a tenant that opened SCIM: the resource server
/// `urn:hodor:scim` and a client allowed the scope `scim`. Answers a token
/// the client got for itself.
async fn scim_token(world: &World, tenant: &Tenant) -> String {
    use base64::Engine as _;
    use hodor_adapters_postgres::{PgApplicationStore, PgClientStore, PgResourceServerStore};
    use hodor_oauth::api::{
        ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
        ClientSettings, ClientType, CreateClient, CreateResourceServer, GrantType,
        ResourceServerSettings, ScopeDefinition,
    };
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(world.database.app().clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    });
    let application = applications
        .create_application(
            &tenant.context,
            ApplicationSettings {
                name: "SCIM".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    applications
        .create_resource_server(
            &tenant.context,
            CreateResourceServer {
                application_id: application.id(),
                audience: "urn:hodor:scim".to_owned(),
                settings: ResourceServerSettings {
                    name: "SCIM".to_owned(),
                    scopes: vec![ScopeDefinition {
                        name: "scim".to_owned(),
                        description: "Provision users and groups".to_owned(),
                    }],
                },
            },
            Caller::system(),
        )
        .await
        .expect("resource server");
    let mut settings = ClientSettings::new(
        "Directory",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    settings.authentication_method = AuthenticationMethod::ClientSecretBasic;
    settings.allowed_scopes = vec!["scim".to_owned()];
    let (client, secret) = applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    let basic = base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        client.id(),
        secret.expect("a secret").expose()
    ));
    let response = Client::new()
        .post(format!(
            "{}/t/{}/oauth2/token",
            world.server.base, tenant.slug
        ))
        .header("authorization", format!("Basic {basic}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("grant_type", "client_credentials"),
                    ("resource", "urn:hodor:scim"),
                    ("scope", "scim"),
                ])
                .finish(),
        )
        .send()
        .await
        .expect("token response");
    let body: serde_json::Value = response.json().await.expect("token body");
    body["access_token"].as_str().expect("a token").to_owned()
}

/// A request to a tenant's SCIM server. Answers the status, the challenge
/// and the body.
async fn scim(
    world: &World,
    tenant: &Tenant,
    token: &str,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, Option<String>, serde_json::Value) {
    let mut request = Client::new()
        .request(
            method,
            format!("{}/t/{}/scim/v2{path}", world.server.base, tenant.slug),
        )
        .bearer_auth(token);
    if let Some(body) = body {
        request = request
            .header("content-type", "application/scim+json")
            .body(body.to_string());
    }
    let response = request.send().await.expect("response");
    let challenge = response
        .headers()
        .get("www-authenticate")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let status = response.status();
    (
        status,
        challenge,
        response.json().await.unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn a_scim_clients_token_and_identifiers_mean_nothing_in_another_tenant() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let acme_token = scim_token(&world, acme).await;
    let globex_token = scim_token(&world, globex).await;
    let user = |name: &str| serde_json::json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": name });
    let group = |name: &str, members: serde_json::Value| {
        serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": name,
            "members": members,
        })
    };

    // In Acme, its directory sees its person and puts them in a group.
    let (status, _, person) = scim(
        &world,
        acme,
        &acme_token,
        Method::GET,
        &format!("/Users/{}", acme.ana),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{person}");
    assert_eq!(person["userName"], EMAIL);
    let (status, _, made) = scim(
        &world,
        acme,
        &acme_token,
        Method::POST,
        "/Groups",
        Some(group(
            "finance",
            serde_json::json!([{ "value": acme.ana.to_string() }]),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    let acme_group = made["id"].as_str().expect("an id").to_owned();

    // Acme's token is not authenticated by Globex, on any route.
    let ana = acme.ana.to_string();
    let patch = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "replace", "path": "displayName", "value": "intruder" }]
    });
    let routes = [
        (Method::PATCH, format!("/Users/{ana}"), Some(patch.clone())),
        (Method::DELETE, format!("/Users/{ana}"), None),
        (
            Method::PATCH,
            format!("/Groups/{acme_group}"),
            Some(patch.clone()),
        ),
        (
            Method::POST,
            "/Bulk".to_owned(),
            Some(
                serde_json::json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [] }),
            ),
        ),
        (Method::GET, "/ServiceProviderConfig".to_owned(), None),
        (Method::GET, "/ResourceTypes".to_owned(), None),
        (Method::GET, "/Schemas".to_owned(), None),
        (Method::GET, "/Users".to_owned(), None),
        (Method::POST, "/Users".to_owned(), Some(user("intruder"))),
        (Method::GET, format!("/Users/{ana}"), None),
        (Method::PUT, format!("/Users/{ana}"), Some(user("intruder"))),
        (Method::GET, "/Groups".to_owned(), None),
        (
            Method::POST,
            "/Groups".to_owned(),
            Some(group("intruders", serde_json::json!([]))),
        ),
        (Method::GET, format!("/Groups/{acme_group}"), None),
        (
            Method::PUT,
            format!("/Groups/{acme_group}"),
            Some(group("intruders", serde_json::json!([]))),
        ),
        (Method::DELETE, format!("/Groups/{acme_group}"), None),
    ];
    for (method, path, body) in &routes {
        let (status, challenge, answer) = scim(
            &world,
            globex,
            &acme_token,
            method.clone(),
            path,
            body.clone(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {path}: {answer}"
        );
        assert_eq!(
            challenge.as_deref(),
            Some("Bearer error=\"invalid_token\""),
            "{method} {path}"
        );
        assert_eq!(answer["status"], "401");
    }

    // Globex's own directory does not find Acme's person or group by
    // naming them, and cannot make Acme's person a member.
    for (method, path, body) in [
        (Method::GET, format!("/Users/{ana}"), None),
        (Method::PATCH, format!("/Users/{ana}"), Some(patch.clone())),
        (Method::DELETE, format!("/Users/{ana}"), None),
        (
            Method::PATCH,
            format!("/Groups/{acme_group}"),
            Some(patch.clone()),
        ),
        (
            Method::PUT,
            format!("/Users/{ana}"),
            Some(user("ana.silva")),
        ),
        (Method::GET, format!("/Groups/{acme_group}"), None),
        (
            Method::PUT,
            format!("/Groups/{acme_group}"),
            Some(group("finance", serde_json::json!([]))),
        ),
        (Method::DELETE, format!("/Groups/{acme_group}"), None),
    ] {
        let (status, _, answer) =
            scim(&world, globex, &globex_token, method.clone(), &path, body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {answer}");
    }
    let (status, _, answer) = scim(
        &world,
        globex,
        &globex_token,
        Method::POST,
        "/Groups",
        Some(group("finance", serde_json::json!([{ "value": ana }]))),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["scimType"], "invalidValue");

    // Nor in a bulk request.
    let (status, _, answer) = scim(
        &world,
        globex,
        &globex_token,
        Method::POST,
        "/Bulk",
        Some(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": [
                { "method": "PATCH", "path": format!("/Users/{ana}"), "data": patch },
                { "method": "DELETE", "path": format!("/Groups/{acme_group}") },
                { "method": "POST", "path": "/Groups", "bulkId": "g", "data": group("finance", serde_json::json!([{ "value": ana }])) }
            ]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let statuses: Vec<&str> = answer["Operations"]
        .as_array()
        .expect("results")
        .iter()
        .map(|result| result["status"].as_str().expect("a status"))
        .collect();
    assert_eq!(statuses, ["404", "404", "400"]);

    // Globex finds its own person by the shared address, never Acme's.
    let (status, _, found) = scim(
        &world,
        globex,
        &globex_token,
        Method::GET,
        &format!("/Users?filter=userName%20eq%20%22{EMAIL}%22"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{found}");
    assert_eq!(found["totalResults"], 1);
    assert_eq!(found["Resources"][0]["id"], globex.ana.to_string());

    // Both tenants are as they were.
    let (status, _, kept) = scim(
        &world,
        acme,
        &acme_token,
        Method::GET,
        &format!("/Groups/{acme_group}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(kept["displayName"], "finance");
    assert_eq!(kept["members"][0]["value"], ana);
    let (_, _, groups) = scim(&world, globex, &globex_token, Method::GET, "/Groups", None).await;
    assert_eq!(groups["totalResults"], 0);
}

/// A service account of a tenant, owned by its person, with a client of an
/// application whose resource server defines `read`, bound to it. Answers
/// the service account and the client's identifier and secret, made
/// through the tenant's own administration interface.
async fn service_account_with_a_client(
    world: &World,
    tenant: &Tenant,
) -> (String, (String, String)) {
    let token = &tenant.administrator_token;
    let (status, account) = world
        .admin(
            tenant,
            token,
            Method::POST,
            "/service-accounts",
            Some(serde_json::json!({
                "name": "Nightly export", "owners": [tenant.ana.to_string()]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{account}");
    let account = account["id"].as_str().expect("id").to_owned();
    let (_, application) = world
        .admin(
            tenant,
            token,
            Method::POST,
            "/applications",
            Some(serde_json::json!({ "name": "Exports", "first_party": true })),
        )
        .await;
    let application = application["id"].as_str().expect("id").to_owned();
    let (status, _) = world
        .admin(
            tenant,
            token,
            Method::POST,
            "/resource-servers",
            Some(serde_json::json!({
                "application_id": application, "audience": "urn:example:exports",
                "name": "Exports", "scopes": [{ "name": "read", "description": "Read" }]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, client) = world
        .admin(
            tenant,
            token,
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(serde_json::json!({
                "name": "Nightly export", "type": "confidential",
                "grant_types": ["client_credentials"], "allowed_scopes": ["read"],
                "principal": account
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{client}");
    (
        account,
        (
            client["id"].as_str().expect("id").to_owned(),
            client["client_secret"].as_str().expect("secret").to_owned(),
        ),
    )
}

#[tokio::test]
async fn a_service_account_of_one_tenant_and_its_tokens_mean_nothing_in_another() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let (account, client) = service_account_with_a_client(&world, acme).await;
    let (_, theirs) = service_account_with_a_client(&world, globex).await;
    let (status, issued) = oauth_form(
        &world,
        acme,
        "token",
        (&client.0, &client.1),
        &[("grant_type", "client_credentials"), ("scope", "read")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let token = issued["access_token"].as_str().expect("a token").to_owned();
    assert!(active(&world, acme, (&client.0, &client.1), &token).await);

    // Globex's administrator names Acme's service account on every
    // operation of an item, under both kinds' paths.
    let globex_token = &globex.administrator_token;
    for (method, path) in [
        (Method::GET, format!("/service-accounts/{account}")),
        (Method::PATCH, format!("/service-accounts/{account}")),
        (Method::POST, format!("/service-accounts/{account}:disable")),
        (Method::POST, format!("/service-accounts/{account}:enable")),
        (Method::DELETE, format!("/service-accounts/{account}")),
        (Method::GET, format!("/agents/{account}")),
    ] {
        let (status, body) = world
            .admin(
                globex,
                globex_token,
                method.clone(),
                &path,
                Some(serde_json::json!({ "name": "Taken over" })),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(
            body["code"], "identity.workload_not_found",
            "{method} {path}"
        );
    }
    // Nor can it make Acme's person an owner, or bind a client to Acme's
    // service account.
    let (status, body) = world
        .admin(
            globex,
            globex_token,
            Method::POST,
            "/service-accounts",
            Some(serde_json::json!({ "name": "Spy", "owners": [acme.ana.to_string()] })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "identity.user_not_found");
    let (_, application) = world
        .admin(
            globex,
            globex_token,
            Method::POST,
            "/applications",
            Some(serde_json::json!({ "name": "Spy", "first_party": true })),
        )
        .await;
    let (status, body) = world
        .admin(
            globex,
            globex_token,
            Method::POST,
            &format!(
                "/applications/{}/clients",
                application["id"].as_str().expect("id")
            ),
            Some(serde_json::json!({
                "name": "Spy", "type": "confidential",
                "grant_types": ["client_credentials"], "principal": account
            })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "oauth.client_principal_invalid");

    // Acme's token is nothing to Globex: not active at introspection by
    // Globex's own client, not authenticated at its Authorization API.
    assert!(!active(&world, globex, (&theirs.0, &theirs.1), &token).await);
    let response = Client::new()
        .post(format!(
            "{}/t/{}/api/v1/authorization/evaluate",
            world.server.base, globex.slug
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "subject": { "type": "user", "id": account },
            "resource": { "type": "export", "id": "1" },
            "action": "read"
        }))
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Everything still works where it belongs.
    let (status, read) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::GET,
            &format!("/service-accounts/{account}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read["status"], "active");
    assert_eq!(read["name"], "Nightly export");
    assert!(active(&world, acme, (&client.0, &client.1), &token).await);
}

/// Something a tenant's administrator creates, by its path and body.
/// Answers its identifier.
async fn created(world: &World, tenant: &Tenant, path: &str, body: serde_json::Value) -> String {
    let (status, made) = call(world, tenant, Method::POST, path.to_owned(), Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{path}: {made}");
    made["id"].as_str().expect("an id").to_owned()
}

/// A resource server of the tenant's own, the same in both tenants, with a
/// `reader` role. Answers the role's namespace.
async fn reader_role(world: &World, tenant: &Tenant) -> &'static str {
    let namespace = "https://api.documents.example.com";
    let application = created(
        world,
        tenant,
        "/applications",
        serde_json::json!({ "name": "Documents", "first_party": true }),
    )
    .await;
    let server = created(
        world,
        tenant,
        "/resource-servers",
        serde_json::json!({
            "application_id": application,
            "audience": namespace,
            "name": "Documents interface",
        }),
    )
    .await;
    for (path, body) in [
        (
            format!("/resource-servers/{server}/permissions/document:read"),
            serde_json::json!({ "description": "Read" }),
        ),
        (
            format!("/resource-servers/{server}/roles/reader"),
            serde_json::json!({ "permissions": [{ "name": "document:read" }] }),
        ),
    ] {
        let (status, body) = call(world, tenant, Method::PUT, path.clone(), Some(body)).await;
        assert!(status.is_success(), "{path}: {status} {body}");
    }
    namespace
}

#[tokio::test]
async fn one_tenants_groups_and_the_roles_they_hold_are_out_of_reach_of_another() {
    let world = world().await;
    let (acme, globex) = (&world.acme, &world.globex);
    let namespace = reader_role(&world, acme).await;
    reader_role(&world, globex).await;

    // In Acme, `finance` is inside `staff`, Ana is in `finance`, and
    // `staff` holds the reader role.
    let staff = created(
        &world,
        acme,
        "/groups",
        serde_json::json!({ "name": "staff" }),
    )
    .await;
    let finance = created(
        &world,
        acme,
        "/groups",
        serde_json::json!({ "name": "finance" }),
    )
    .await;
    let reader = serde_json::json!({ "namespace": namespace, "name": "reader" });
    for (path, body) in [
        (
            format!("/groups/{staff}/members"),
            serde_json::json!({ "kind": "group", "id": finance }),
        ),
        (
            format!("/groups/{finance}/members"),
            serde_json::json!({ "kind": "user", "id": acme.ana.to_string() }),
        ),
        (
            "/role-assignments".to_owned(),
            serde_json::json!({ "principal": { "kind": "group", "id": staff }, "role": reader }),
        ),
    ] {
        let (status, body) = call(&world, acme, Method::POST, path.clone(), Some(body)).await;
        assert!(status.is_success(), "{path}: {status} {body}");
    }
    let (status, groups) = call(
        &world,
        acme,
        Method::GET,
        format!("/users/{}/groups", acme.ana),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{groups}");
    assert_eq!(groups["items"].as_array().expect("items").len(), 2);

    // Globex's administrator, naming Acme's groups, finds no such group,
    // whatever it asks of them.
    for (method, path, body) in [
        (Method::GET, format!("/groups/{staff}"), None),
        (
            Method::PATCH,
            format!("/groups/{staff}"),
            Some(serde_json::json!({ "name": "taken over" })),
        ),
        (Method::DELETE, format!("/groups/{staff}"), None),
        (Method::GET, format!("/groups/{staff}/members"), None),
        (
            Method::POST,
            format!("/groups/{staff}/members"),
            Some(serde_json::json!({ "kind": "user", "id": globex.ana.to_string() })),
        ),
        (
            Method::POST,
            format!("/groups/{finance}/members:remove"),
            Some(serde_json::json!({ "kind": "user", "id": acme.ana.to_string() })),
        ),
        (
            Method::GET,
            format!("/groups/{staff}/role-assignments"),
            None,
        ),
        (
            Method::POST,
            "/role-assignments".to_owned(),
            Some(
                serde_json::json!({ "principal": { "kind": "group", "id": staff }, "role": reader }),
            ),
        ),
        (
            Method::POST,
            "/role-assignments:revoke".to_owned(),
            Some(
                serde_json::json!({ "principal": { "kind": "group", "id": staff }, "role": reader }),
            ),
        ),
    ] {
        let (status, answer) = call(&world, globex, method.clone(), path.clone(), body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {answer}");
        assert_eq!(
            answer["code"], "identity.group_not_found",
            "{method} {path}"
        );
    }
    let (status, answer) = call(
        &world,
        globex,
        Method::GET,
        format!("/users/{}/groups", acme.ana),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(answer["code"], "identity.user_not_found");

    // Nor can Acme's person or Acme's group become a member of a group of
    // Globex's own.
    let theirs = created(
        &world,
        globex,
        "/groups",
        serde_json::json!({ "name": "staff" }),
    )
    .await;
    for (member, code) in [
        (
            serde_json::json!({ "kind": "user", "id": acme.ana.to_string() }),
            "identity.user_not_found",
        ),
        (
            serde_json::json!({ "kind": "group", "id": finance }),
            "identity.group_not_found",
        ),
    ] {
        let (status, answer) = call(
            &world,
            globex,
            Method::POST,
            format!("/groups/{theirs}/members"),
            Some(member.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{member}: {answer}");
        assert_eq!(answer["code"], code, "{member}");
    }

    // Globex's lists name only its own group, which has no member.
    let (_, listed) = call(&world, globex, Method::GET, "/groups".to_owned(), None).await;
    let names: Vec<&str> = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|group| group["id"].as_str())
        .collect();
    assert_eq!(names, [theirs.as_str()]);
    let (_, members) = call(
        &world,
        globex,
        Method::GET,
        format!("/groups/{theirs}/members"),
        None,
    )
    .await;
    assert_eq!(members["items"], serde_json::json!([]));

    // Acme's groups are as they were: Ana still in both, the role still
    // held by `staff`.
    let (_, groups) = call(
        &world,
        acme,
        Method::GET,
        format!("/users/{}/groups", acme.ana),
        None,
    )
    .await;
    assert_eq!(groups["items"].as_array().expect("items").len(), 2);
    let (_, held) = call(
        &world,
        acme,
        Method::GET,
        format!("/groups/{staff}/role-assignments"),
        None,
    )
    .await;
    assert_eq!(held["items"][0]["role"]["name"], "reader", "{held}");
    let (status, kept) = call(&world, acme, Method::GET, format!("/groups/{staff}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(kept["name"], "staff");
}

/// The claims of a signed token, unchecked: the token came straight from
/// the token endpoint.
fn claims_of(token: &str) -> serde_json::Value {
    use base64::Engine as _;
    let payload = token.split('.').nth(1).expect("a payload");
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url"),
    )
    .expect("JSON")
}

/// Where the authorization endpoint sends a signed-in browser, and the
/// parameters it adds to the redirect address.
async fn authorized(
    browser: &mut Browser,
    path: &str,
) -> std::collections::BTreeMap<String, String> {
    let (status, location, page) = browser.navigate(Method::GET, path, None).await;
    assert_eq!(status, StatusCode::FOUND, "{page}");
    let location = location.expect("a redirect");
    let (address, query) = location.split_once('?').expect("a query");
    assert_eq!(address, REDIRECT);
    form_urlencoded::parse(query.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

#[tokio::test]
async fn one_tenants_organizations_and_invitations_mean_nothing_in_another() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let namespace = reader_role(&world, globex).await;

    // In Acme, an organization with a department invites the shared
    // address. Globex has an organization of the same name.
    let initech = created(
        &world,
        acme,
        "/organizations",
        serde_json::json!({ "name": "Initech" }),
    )
    .await;
    let engineering = created(
        &world,
        acme,
        &format!("/organizations/{initech}/units"),
        serde_json::json!({ "parent_id": null, "name": "Engineering", "kind": "department" }),
    )
    .await;
    let (status, answer) = call(
        &world,
        acme,
        Method::POST,
        format!("/organizations/{initech}/invitations"),
        Some(serde_json::json!({ "email": EMAIL, "unit_ids": [engineering] })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{answer}");
    let token = world.newest_link_token(acme).await;
    let (_, pending) = call(
        &world,
        acme,
        Method::GET,
        format!("/organizations/{initech}/invitations"),
        None,
    )
    .await;
    let invitation = pending["items"][0]["id"]
        .as_str()
        .expect("a pending invitation")
        .to_owned();
    let theirs = created(
        &world,
        globex,
        "/organizations",
        serde_json::json!({ "name": "Initech" }),
    )
    .await;

    // Globex's administrator, naming Acme's organization, finds no such
    // organization, whatever it asks of it.
    let unit = serde_json::json!({ "parent_id": null, "name": "Taken over", "kind": "unit" });
    for (method, path, body) in [
        (Method::GET, format!("/organizations/{initech}"), None),
        (
            Method::PATCH,
            format!("/organizations/{initech}"),
            Some(serde_json::json!({ "name": "Taken over" })),
        ),
        (Method::DELETE, format!("/organizations/{initech}"), None),
        (Method::GET, format!("/organizations/{initech}/units"), None),
        (
            Method::POST,
            format!("/organizations/{initech}/units"),
            Some(unit.clone()),
        ),
        (
            Method::PUT,
            format!("/organizations/{initech}/units/{engineering}"),
            Some(unit.clone()),
        ),
        (
            Method::DELETE,
            format!("/organizations/{initech}/units/{engineering}"),
            None,
        ),
        (
            Method::GET,
            format!("/organizations/{initech}/members"),
            None,
        ),
        (
            Method::PUT,
            format!("/organizations/{initech}/members/{}", globex.ana),
            Some(serde_json::json!({ "unit_ids": [] })),
        ),
        (
            Method::DELETE,
            format!("/organizations/{initech}/members/{}", acme.ana),
            None,
        ),
        (
            Method::GET,
            format!("/organizations/{initech}/invitations"),
            None,
        ),
        (
            Method::POST,
            format!("/organizations/{initech}/invitations"),
            Some(serde_json::json!({ "email": EMAIL, "unit_ids": [] })),
        ),
        (
            Method::DELETE,
            format!("/organizations/{initech}/invitations/{invitation}"),
            None,
        ),
        (
            Method::POST,
            "/role-assignments".to_owned(),
            Some(serde_json::json!({
                "principal": { "kind": "user", "id": globex.ana.to_string() },
                "role": { "namespace": namespace, "name": "reader" },
                "organization_id": initech,
            })),
        ),
    ] {
        let (status, answer) = call(&world, globex, method.clone(), path.clone(), body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {answer}");
        assert_eq!(
            answer["code"], "identity.organization_not_found",
            "{method} {path}"
        );
    }

    // Nor can Acme's person become a member of Globex's own organization,
    // or Globex's person be put in Acme's department.
    for (path, body, code) in [
        (
            format!("/organizations/{theirs}/members/{}", acme.ana),
            serde_json::json!({ "unit_ids": [] }),
            "identity.user_not_found",
        ),
        (
            format!("/organizations/{theirs}/members/{}", globex.ana),
            serde_json::json!({ "unit_ids": [engineering] }),
            "identity.unit_not_found",
        ),
    ] {
        let (status, answer) = call(&world, globex, Method::PUT, path.clone(), Some(body)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {answer}");
        assert_eq!(answer["code"], code, "{path}");
    }
    let (status, answer) = call(
        &world,
        globex,
        Method::GET,
        format!("/users/{}/organizations", acme.ana),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(answer["code"], "identity.user_not_found");

    // Acme's link does not work at Globex: described, accepted with a
    // password, or accepted by the signed-in person who has the invited
    // address there.
    let (status, answer) = world
        .post(
            globex,
            "invitations/describe",
            serde_json::json!({ "token": token }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["code"], "identity.invitation_invalid");
    let (status, answer) = world
        .post(
            globex,
            "invitations/accept",
            serde_json::json!({ "token": token, "password": "a password of its own" }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["code"], "identity.invitation_invalid");
    let (mut there, _, _) = signed_in(&world, globex).await;
    let (status, answer) = there
        .send(
            Method::POST,
            "/t/globex/interaction/invitations/accept",
            Some(serde_json::json!({ "token": token })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["code"], "identity.invitation_invalid");

    // Where it belongs, the link works, once.
    let (status, described) = world
        .post(
            acme,
            "invitations/describe",
            serde_json::json!({ "token": token }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{described}");
    assert_eq!(described["organization_name"], "Initech");
    assert_eq!(described["has_account"], true);
    let (mut here, _, _) = signed_in(&world, acme).await;
    let accept = serde_json::json!({ "token": token });
    let (status, answer) = here
        .send(
            Method::POST,
            "/t/acme/interaction/invitations/accept",
            Some(accept.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");
    let (status, _) = here
        .send(
            Method::POST,
            "/t/acme/interaction/invitations/accept",
            Some(accept),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, memberships) = call(
        &world,
        acme,
        Method::GET,
        format!("/users/{}/organizations", acme.ana),
        None,
    )
    .await;
    assert_eq!(
        memberships["items"].as_array().expect("items").len(),
        1,
        "{memberships}"
    );

    // Asked for at Globex's authorization endpoint, Acme's organization is
    // one the person is not a member of. In Acme the tokens carry it.
    let (globex_client, _) = first_party_client(&world, globex).await;
    let named = [("organization", initech.as_str())];
    let mut stranger = Browser::not_following(&world.server);
    let (_, body) = stranger.sign_in(globex.slug, EMAIL, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");
    let back = authorized(
        &mut stranger,
        &authorize_path_with(globex.slug, &globex_client, &named),
    )
    .await;
    assert_eq!(back.get("error").map(String::as_str), Some("access_denied"));
    assert!(!back.contains_key("code"));
    let (acme_client, acme_secret) = first_party_client(&world, acme).await;
    let mut member = Browser::not_following(&world.server);
    let (_, body) = member.sign_in(acme.slug, EMAIL, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");
    let back = authorized(
        &mut member,
        &authorize_path_with(acme.slug, &acme_client, &named),
    )
    .await;
    let code = back.get("code").expect("a code");
    let (status, tokens) = oauth_form(
        &world,
        acme,
        "token",
        (&acme_client, &acme_secret),
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    for token in ["access_token", "id_token"] {
        let claims = claims_of(tokens[token].as_str().expect("a token"));
        assert_eq!(claims["org_id"], initech.as_str(), "{token}");
    }

    // Globex's lists name only its own organization, which has no member.
    let (_, listed) = call(
        &world,
        globex,
        Method::GET,
        "/organizations".to_owned(),
        None,
    )
    .await;
    let organizations: Vec<&str> = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|organization| organization["id"].as_str())
        .collect();
    assert_eq!(organizations, [theirs.as_str()]);
    let (_, members) = call(
        &world,
        globex,
        Method::GET,
        format!("/organizations/{theirs}/members"),
        None,
    )
    .await;
    assert_eq!(members["items"], serde_json::json!([]));
}

#[tokio::test]
async fn a_person_deactivated_through_scim_in_one_tenant_stays_signed_in_to_another() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let acme_token = scim_token(&world, acme).await;
    let (here, _, _) = signed_in(&world, acme).await;
    let (there, _, _) = signed_in(&world, globex).await;

    // Acme's directory deactivates its person.
    let (status, _, answer) = scim(
        &world,
        acme,
        &acme_token,
        Method::PATCH,
        &format!("/Users/{}", acme.ana),
        Some(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{ "op": "replace", "path": "active", "value": false }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["active"], false);

    // Her session in Acme ended; the person with the same address in
    // Globex is still signed in, and still signs in.
    let (status, _) = world
        .with_session_cookie(
            acme,
            Method::GET,
            "/session",
            &here.cookies[SESSION_COOKIE],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = world
        .with_session_cookie(
            globex,
            Method::GET,
            "/session",
            &there.cookies[SESSION_COOKIE],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = Browser::new(&world.server)
        .sign_in(globex.slug, EMAIL, PASSWORD)
        .await;
    assert_eq!(body["status"], "completed", "{body}");
    let (_, body) = Browser::new(&world.server)
        .sign_in(acme.slug, EMAIL, PASSWORD)
        .await;
    assert_ne!(body["status"], "completed", "{body}");
}

#[tokio::test]
async fn a_service_accounts_api_key_of_one_tenant_means_nothing_in_another() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let (account, _) = service_account_with_a_client(&world, acme).await;
    let (theirs, _) = service_account_with_a_client(&world, globex).await;
    let (status, made) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::POST,
            &format!("/service-accounts/{account}/api-keys"),
            Some(serde_json::json!({ "name": "Reports", "scopes": ["users:read"] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    let key = made["api_key"].as_str().expect("the key").to_owned();
    let key_id = made["id"].as_str().expect("id").to_owned();
    AuthorizationService::new(
        Arc::new(world.database.app().clone()),
        Arc::new(PgRoleAssignmentStore),
        Arc::new(SystemClock),
    )
    .assign(
        &acme.context,
        account.parse().expect("an identifier"),
        Role::TenantAuditor,
        Caller::system(),
    )
    .await
    .expect("a role");
    let (status, _) = world.admin(acme, &key, Method::GET, "/users", None).await;
    assert_eq!(status, StatusCode::OK, "it works where it belongs");

    // Presented to Globex, at its administration interface and at its
    // Authorization API, it is not known.
    let (status, body) = world.admin(globex, &key, Method::GET, "/users", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "admin.not_authenticated");
    let response = Client::new()
        .post(format!(
            "{}/t/{}/api/v1/authorization/evaluate",
            world.server.base, globex.slug
        ))
        .bearer_auth(&key)
        .json(&serde_json::json!({
            "subject": { "type": "user", "id": account },
            "resource": { "type": "export", "id": "1" },
            "action": "read"
        }))
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Globex's administrator cannot list, rotate or revoke it, under
    // Acme's workload or its own.
    let globex_token = &globex.administrator_token;
    for (method, path) in [
        (Method::GET, format!("/service-accounts/{account}/api-keys")),
        (
            Method::POST,
            format!("/service-accounts/{account}/api-keys/{key_id}:rotate"),
        ),
        (
            Method::DELETE,
            format!("/service-accounts/{account}/api-keys/{key_id}"),
        ),
        (
            Method::POST,
            format!("/service-accounts/{theirs}/api-keys/{key_id}:rotate"),
        ),
        (
            Method::DELETE,
            format!("/service-accounts/{theirs}/api-keys/{key_id}"),
        ),
    ] {
        let (status, body) = world
            .admin(globex, globex_token, method.clone(), &path, None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        assert!(
            body["code"] == "identity.workload_not_found"
                || body["code"] == "credential.api_key_not_found",
            "{method} {path}: {body}"
        );
    }

    // Nor make one for Acme's workload.
    let (status, body) = world
        .admin(
            globex,
            globex_token,
            Method::POST,
            &format!("/service-accounts/{account}/api-keys"),
            Some(serde_json::json!({ "name": "Mine now", "scopes": ["users:read"] })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["code"], "identity.workload_not_found");
    let (_, keys) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::GET,
            &format!("/service-accounts/{account}/api-keys"),
            None,
        )
        .await;
    assert_eq!(keys["items"].as_array().map(Vec::len), Some(1), "{keys}");

    // And it still works where it belongs.
    let (status, _) = world.admin(acme, &key, Method::GET, "/users", None).await;
    assert_eq!(status, StatusCode::OK);
}

/// The person's access token in a tenant, from a code of its third-party
/// application, which they agree to.
async fn person_access_token(world: &World, tenant: &Tenant) -> String {
    let (client, secret) = third_party_client(world, tenant).await;
    let mut browser = Browser::not_following(&world.server);
    let (_, body) = browser.sign_in(tenant.slug, EMAIL, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");
    let (status, _, _) = browser
        .navigate(Method::GET, &authorize_path(tenant.slug, &client), None)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let (status, question) = browser
        .send(
            Method::GET,
            &format!("/t/{}/interaction/consent", tenant.slug),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{question}");
    let (status, answer) = browser
        .send(
            Method::POST,
            &format!("/t/{}/interaction/consent", tenant.slug),
            Some(serde_json::json!({ "decision": "allow" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (_, location, _) = browser
        .navigate(
            Method::GET,
            &format!("/t/{}/oauth2/authorize/resume", tenant.slug),
            None,
        )
        .await;
    let location = location.expect("a redirect");
    let (_, query) = location.split_once('?').expect("a query");
    let code = form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == "code")
        .expect("a code")
        .1
        .into_owned();
    let (status, tokens) = oauth_form(
        world,
        tenant,
        "token",
        (&client, &secret),
        &[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    tokens["access_token"].as_str().expect("access").to_owned()
}

/// An agent of the tenant with a client that exchanges the person's
/// tokens for the invoices interface, and the agent's own token. Answers
/// the client's identifier and secret and the agent's token.
async fn agent_with_its_token(world: &World, tenant: &Tenant) -> ((String, String), String) {
    let token = &tenant.administrator_token;
    let (status, agent) = world
        .admin(
            tenant,
            token,
            Method::POST,
            "/agents",
            Some(serde_json::json!({ "name": "Assistant", "owners": [tenant.ana.to_string()] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{agent}");
    let (_, application) = world
        .admin(
            tenant,
            token,
            Method::POST,
            "/applications",
            Some(serde_json::json!({ "name": "Assistant", "first_party": true })),
        )
        .await;
    let (status, client) = world
        .admin(
            tenant,
            token,
            Method::POST,
            &format!(
                "/applications/{}/clients",
                application["id"].as_str().expect("id")
            ),
            Some(serde_json::json!({
                "name": "Assistant", "type": "confidential",
                "grant_types": [
                    "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"
                ],
                "allowed_scopes": ["invoices:read"],
                "principal": agent["id"],
                "exchange_rules": [{ "subject_audience": AUDIENCE, "audience": AUDIENCE }]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{client}");
    let pair = (
        client["id"].as_str().expect("id").to_owned(),
        client["client_secret"].as_str().expect("secret").to_owned(),
    );
    let (status, own) = oauth_form(
        world,
        tenant,
        "token",
        (&pair.0, &pair.1),
        &[("grant_type", "client_credentials")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{own}");
    (
        pair,
        own["access_token"].as_str().expect("token").to_owned(),
    )
}

#[tokio::test]
async fn a_token_of_one_tenant_is_refused_by_another_as_subject_and_as_actor_of_an_exchange() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let acme_person = person_access_token(&world, acme).await;
    let globex_person = person_access_token(&world, globex).await;
    let (acme_agent, acme_actor) = agent_with_its_token(&world, acme).await;
    let (globex_agent, globex_actor) = agent_with_its_token(&world, globex).await;
    let exchange = |subject: &str, actor: &str| {
        vec![
            (
                "grant_type".to_owned(),
                "urn:ietf:params:oauth:grant-type:token-exchange".to_owned(),
            ),
            ("subject_token".to_owned(), subject.to_owned()),
            (
                "subject_token_type".to_owned(),
                "urn:ietf:params:oauth:token-type:access_token".to_owned(),
            ),
            ("actor_token".to_owned(), actor.to_owned()),
            (
                "actor_token_type".to_owned(),
                "urn:ietf:params:oauth:token-type:access_token".to_owned(),
            ),
            ("audience".to_owned(), AUDIENCE.to_owned()),
        ]
    };

    // Where they belong, the exchange works.
    let pairs = exchange(&acme_person, &acme_actor);
    let pairs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let (status, body) = oauth_form(
        &world,
        acme,
        "token",
        (&acme_agent.0, &acme_agent.1),
        &pairs,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Globex's agent presents Acme's person as subject, or Acme's agent's
    // token as actor: each is refused.
    for (subject, actor) in [
        (acme_person.as_str(), globex_actor.as_str()),
        (globex_person.as_str(), acme_actor.as_str()),
    ] {
        let form = exchange(subject, actor);
        let pairs: Vec<(&str, &str)> = form.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
        let (status, body) = oauth_form(
            &world,
            globex,
            "token",
            (&globex_agent.0, &globex_agent.1),
            &pairs,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request", "{body}");
    }
    // And Globex's own pair works there, so the refusals were the tenant's.
    let form = exchange(&globex_person, &globex_actor);
    let pairs: Vec<(&str, &str)> = form.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
    let (status, body) = oauth_form(
        &world,
        globex,
        "token",
        (&globex_agent.0, &globex_agent.1),
        &pairs,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The documents of a tenant, answered by the native engine, the same in
/// both tenants: a resource server with the permission `document:read`,
/// and a client allowed to ask the tenant's Authorization API. Answers
/// the resource server and the client's identifier and secret.
async fn shared_documents(world: &World, tenant: &Tenant) -> (String, (String, String)) {
    let api = created(
        world,
        tenant,
        "/applications",
        serde_json::json!({ "name": "Authorization API", "first_party": true }),
    )
    .await;
    created(
        world,
        tenant,
        "/resource-servers",
        serde_json::json!({
            "application_id": api, "audience": "urn:hodor:authorization",
            "name": "Authorization API",
            "scopes": [{ "name": "authz:evaluate", "description": "Ask" }]
        }),
    )
    .await;
    let application = created(
        world,
        tenant,
        "/applications",
        serde_json::json!({ "name": "Documents", "first_party": true }),
    )
    .await;
    let server = created(
        world,
        tenant,
        "/resource-servers",
        serde_json::json!({
            "application_id": application, "audience": "urn:example:documents",
            "name": "Documents"
        }),
    )
    .await;
    for (path, body) in [
        (
            format!("/resource-servers/{server}/permissions/document:read"),
            serde_json::json!({ "description": "Read" }),
        ),
        (
            format!("/resource-servers/{server}/binding"),
            serde_json::json!({ "engine": "native" }),
        ),
    ] {
        let (status, body) = call(world, tenant, Method::PUT, path.clone(), Some(body)).await;
        assert!(status.is_success(), "{path}: {status} {body}");
    }
    let (status, client) = call(
        world,
        tenant,
        Method::POST,
        format!("/applications/{application}/clients"),
        Some(serde_json::json!({
            "name": "Documents back end", "type": "confidential",
            "grant_types": ["client_credentials"], "allowed_scopes": ["authz:evaluate"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{client}");
    (
        server,
        (
            client["id"].as_str().expect("id").to_owned(),
            client["client_secret"].as_str().expect("secret").to_owned(),
        ),
    )
}

/// Whether the tenant's Authorization API lets `subject` read `document`,
/// asked with a token of the tenant's own client.
async fn reads_document(
    world: &World,
    tenant: &Tenant,
    client: &(String, String),
    subject: &str,
    document: &str,
) -> String {
    let (status, issued) = oauth_form(
        world,
        tenant,
        "token",
        (&client.0, &client.1),
        &[
            ("grant_type", "client_credentials"),
            ("resource", "urn:hodor:authorization"),
            ("scope", "authz:evaluate"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let response = Client::new()
        .post(format!(
            "{}/t/{}/api/v1/authorization/evaluate",
            world.server.base, tenant.slug
        ))
        .bearer_auth(issued["access_token"].as_str().expect("a token"))
        .json(&serde_json::json!({
            "subject": { "type": "user", "id": subject },
            "resource": { "type": "document", "id": document },
            "action": "read"
        }))
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let answer: serde_json::Value = response.json().await.expect("JSON");
    answer["decision"].as_str().unwrap_or_default().to_owned()
}

#[tokio::test]
async fn one_tenants_access_control_lists_are_never_read_or_reached_from_another() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let (acme_server, acme_client) = shared_documents(&world, acme).await;
    let (globex_server, globex_client) = shared_documents(&world, globex).await;
    let ana = acme.ana.to_string();
    let entry = created(
        &world,
        acme,
        &format!("/resource-servers/{acme_server}/access-entries"),
        serde_json::json!({
            "permission": "document:read", "resource_id": "d-42",
            "principal": { "kind": "user", "id": ana }
        }),
    )
    .await;
    let finance = created(
        &world,
        acme,
        "/groups",
        serde_json::json!({ "name": "finance" }),
    )
    .await;
    assert_eq!(
        reads_document(&world, acme, &acme_client, &ana, "d-42").await,
        "ALLOW"
    );

    // Globex asks about the same resource server, permission, resource
    // and principal: Acme's entry is never read there.
    assert_eq!(
        reads_document(&world, globex, &globex_client, &ana, "d-42").await,
        "DENY"
    );

    // Globex's administrator names Acme's entry: no such entry.
    for method in [Method::GET, Method::DELETE] {
        let (status, body) = call(
            &world,
            globex,
            method.clone(),
            format!("/access-entries/{entry}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method}");
        assert_eq!(body["code"], "authorization.access_entry_not_found");
    }
    // Nor Acme's resource server, nor Acme's person or group as the
    // principal of an entry of its own.
    let (status, body) = call(
        &world,
        globex,
        Method::GET,
        format!("/resource-servers/{acme_server}/access-entries"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    for (principal, code) in [
        (
            serde_json::json!({ "kind": "user", "id": ana }),
            "identity.user_not_found",
        ),
        (
            serde_json::json!({ "kind": "group", "id": finance }),
            "identity.group_not_found",
        ),
    ] {
        let (status, body) = call(
            &world,
            globex,
            Method::POST,
            format!("/resource-servers/{globex_server}/access-entries"),
            Some(serde_json::json!({
                "permission": "document:read", "resource_id": "d-42", "principal": principal
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["code"], code);
    }
    let (status, theirs) = call(
        &world,
        globex,
        Method::GET,
        format!("/resource-servers/{globex_server}/access-entries"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(theirs["items"], serde_json::json!([]));

    // Everything still stands where it belongs.
    let (status, kept) = call(
        &world,
        acme,
        Method::GET,
        format!("/access-entries/{entry}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(kept["resource_id"], "d-42");
    assert_eq!(
        reads_document(&world, acme, &acme_client, &ana, "d-42").await,
        "ALLOW"
    );
}

/// Where both tenants' endpoints point: a development exception nothing
/// listens on, since no delivery is sent in this suite.
const RECEIVER: &str = "127.0.0.1:9";

/// Registers an endpoint of a tenant subscribed to `session.started`, and
/// answers its identifier and what the answer said of its secrets.
async fn endpoint_of(world: &World, tenant: &Tenant) -> (String, serde_json::Value) {
    let (status, made) = world
        .admin(
            tenant,
            &tenant.administrator_token,
            Method::POST,
            "/webhook-endpoints",
            Some(serde_json::json!({
                "url": format!("http://{RECEIVER}/{}", tenant.slug),
                "event_types": ["session.started"],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    (
        made["endpoint"]["id"].as_str().expect("id").to_owned(),
        made["endpoint"]["secrets"].clone(),
    )
}

/// Does the worker's part for webhooks: every waiting event goes to the
/// audit log and is fanned out to the endpoints subscribed to it.
async fn fan_out(world: &World) {
    let audit = AuditService::new(
        Arc::new(world.database.app().clone()),
        Arc::new(PgAuditLog),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
    );
    let dispatcher = OutboxDispatcher::new(
        world.database.platform().clone(),
        world.database.app().clone(),
        vec![
            Arc::new(AuditHandler::new(audit)),
            Arc::new(WebhookFanOut::new(
                Arc::new(PgEndpointStore),
                Arc::new(PgDeliveryStore),
                Arc::new(SystemClock),
            )),
        ],
    );
    while dispatcher
        .dispatch_batch(100)
        .await
        .expect("dispatch")
        .delivered
        > 0
    {}
}

#[tokio::test]
async fn one_tenants_webhooks_and_their_deliveries_are_out_of_reach_of_another() {
    let world = world_with(&[
        ("HODOR_SECRET_KEYS", ROOT_KEY),
        ("HODOR_OUTBOUND_DEVELOPMENT_HOSTS", RECEIVER),
    ])
    .await;
    let (acme, globex) = (&world.acme, &world.globex);
    let (endpoint, secrets) = endpoint_of(&world, acme).await;
    let (theirs, _) = endpoint_of(&world, globex).await;

    // The person signs in to Acme: the event is Acme's, and only Acme's
    // endpoint gets a delivery of it, though Globex's is subscribed to the
    // same type.
    signed_in(&world, acme).await;
    fan_out(&world).await;
    let (status, listed) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::GET,
            &format!("/webhook-deliveries?endpoint_id={endpoint}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let deliveries = listed["items"].as_array().expect("items").clone();
    assert_eq!(deliveries.len(), 1, "{listed}");
    assert_eq!(deliveries[0]["event_type"], "session.started");
    let delivery = deliveries[0]["id"].as_str().expect("id").to_owned();
    let globex_token = &globex.administrator_token;
    let (_, theirs_listed) = world
        .admin(
            globex,
            globex_token,
            Method::GET,
            "/webhook-deliveries",
            None,
        )
        .await;
    assert_eq!(
        theirs_listed["items"],
        serde_json::json!([]),
        "{theirs_listed}"
    );

    // Globex's administrator names Acme's endpoint and Acme's delivery.
    for (method, path, body) in [
        (Method::GET, format!("/webhook-endpoints/{endpoint}"), None),
        (
            Method::PUT,
            format!("/webhook-endpoints/{endpoint}/subscriptions"),
            Some(serde_json::json!({ "event_types": ["identity.user_created"] })),
        ),
        (
            Method::POST,
            format!("/webhook-endpoints/{endpoint}:rotate-secret"),
            None,
        ),
        (
            Method::DELETE,
            format!("/webhook-endpoints/{endpoint}"),
            None,
        ),
        (
            Method::POST,
            format!("/webhook-deliveries/{delivery}:redeliver"),
            None,
        ),
    ] {
        let (status, answer) = world
            .admin(globex, globex_token, method.clone(), &path, body)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {answer}");
        assert!(
            answer["code"] == "webhooks.endpoint_not_found"
                || answer["code"] == "webhooks.delivery_not_found",
            "{method} {path}: {answer}"
        );
    }
    let (status, named) = world
        .admin(
            globex,
            globex_token,
            Method::GET,
            &format!("/webhook-deliveries?endpoint_id={endpoint}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(named["items"], serde_json::json!([]), "{named}");
    let (_, endpoints) = world
        .admin(
            globex,
            globex_token,
            Method::GET,
            "/webhook-endpoints",
            None,
        )
        .await;
    let ids: Vec<&str> = endpoints["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    assert_eq!(ids, [theirs.as_str()], "only its own endpoint");

    // Acme's endpoint, its secret and its delivery are as they were.
    let (status, kept) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::GET,
            &format!("/webhook-endpoints/{endpoint}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(kept["event_types"], serde_json::json!(["session.started"]));
    assert_eq!(kept["secrets"], secrets);
    let (_, still) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::GET,
            &format!("/webhook-deliveries?endpoint_id={endpoint}"),
            None,
        )
        .await;
    assert_eq!(still["items"], listed["items"]);
}

/// Turns on both ways of signing in by email in a tenant.
async fn offer_by_email(world: &World, tenant: &Tenant) {
    let tenants = TenantService::new(
        Arc::new(world.database.app().clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(world.database.app().clone())),
        Arc::new(SystemClock),
    );
    let mut settings = tenants
        .get(&tenant.context)
        .await
        .expect("tenant")
        .snapshot()
        .settings
        .clone();
    settings.authentication.email_sign_in.code = true;
    settings.authentication.email_sign_in.link = true;
    tenants
        .change_settings(&tenant.context, settings, Caller::system())
        .await
        .expect("settings");
}

/// A browser that started a sign-in in a tenant and asked for `step` for
/// the shared address, and what the message carries.
async fn asked_by_email(
    world: &World,
    tenant: &Tenant,
    step: &str,
    variable: &str,
) -> (Browser, String) {
    let mut browser = Browser::new(&world.server);
    browser
        .send(
            Method::POST,
            &format!("/t/{}/interaction/sign-in", tenant.slug),
            None,
        )
        .await;
    let (status, _) = browser
        .send(
            Method::POST,
            &format!("/t/{}/interaction/sign-in/steps/{step}/send", tenant.slug),
            Some(serde_json::json!({ "email": EMAIL })),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let sent: String = sqlx::query_scalar(
        "SELECT variables->>$2 FROM notification.message
         WHERE tenant_id = $1 AND variables ? $2
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(tenant.context.tenant_id().as_uuid())
    .bind(variable)
    .fetch_one(world.database.owner())
    .await
    .expect("a message");
    let sent = match variable {
        "link" => sent.split_once("#token=").expect("a token").1.to_owned(),
        _ => sent,
    };
    (browser, sent)
}

async fn present_by_email(
    browser: &mut Browser,
    tenant: &Tenant,
    step: &str,
    field: &str,
    value: &str,
) -> (StatusCode, serde_json::Value) {
    browser
        .send(
            Method::POST,
            &format!("/t/{}/interaction/sign-in/steps/{step}", tenant.slug),
            Some(serde_json::json!({ field: value })),
        )
        .await
}

#[tokio::test]
async fn a_code_or_a_link_sent_in_one_tenant_signs_nobody_in_at_another() {
    let world = world().await;
    let (acme, globex) = (&world.acme, &world.globex);
    offer_by_email(&world, acme).await;
    offer_by_email(&world, globex).await;

    for (step, field, variable) in [
        ("email_code", "code", "code"),
        ("email_link", "token", "link"),
    ] {
        let (mut in_acme, acme_sent) = asked_by_email(&world, acme, step, variable).await;
        // Globex's own sign-in asked for the same address.
        let (mut in_globex, globex_sent) = asked_by_email(&world, globex, step, variable).await;

        // Acme's code or token, presented to Globex's sign-in.
        if acme_sent != globex_sent {
            let (_, body) = present_by_email(&mut in_globex, globex, step, field, &acme_sent).await;
            assert_eq!(body["status"], "rejected", "{step}: {body}");
        }
        // Acme's browser, cookie and CSRF token, on Globex's path.
        let (status, body) = present_by_email(&mut in_acme, globex, step, field, &acme_sent).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{step}");
        assert_eq!(body["code"], "authentication.transaction_not_found");
        assert!(!in_globex.cookies.contains_key(SESSION_COOKIE));

        // Each still signs its own person in where it belongs.
        for (browser, tenant, sent, person) in [
            (&mut in_acme, acme, &acme_sent, acme.ana),
            (&mut in_globex, globex, &globex_sent, globex.ana),
        ] {
            let (_, body) = present_by_email(browser, tenant, step, field, sent).await;
            assert_eq!(body["status"], "completed", "{step}: {body}");
            let (_, who) = browser
                .send(
                    Method::GET,
                    &format!("/t/{}/interaction/session", tenant.slug),
                    None,
                )
                .await;
            assert_eq!(who["user_id"], person.to_string());
        }
    }
}

/// Makes a tenant require a second factor of everyone who signs in.
async fn require_second_factor(world: &World, tenant: &Tenant) {
    let tenants = TenantService::new(
        Arc::new(world.database.app().clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(world.database.app().clone())),
        Arc::new(SystemClock),
    );
    let mut settings = tenants
        .get(&tenant.context)
        .await
        .expect("tenant")
        .snapshot()
        .settings
        .clone();
    settings.authentication.second_factor = hodor_tenant::api::SecondFactorPolicy::Required;
    tenants
        .change_settings(&tenant.context, settings, Caller::system())
        .await
        .expect("settings");
}

async fn enrollment(
    browser: &mut Browser,
    tenant: &Tenant,
    what: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    browser
        .send(
            Method::POST,
            &format!(
                "/t/{}/interaction/sign-in/steps/enrollment{what}",
                tenant.slug
            ),
            Some(body),
        )
        .await
}

#[tokio::test]
async fn an_enrollment_begun_in_one_tenant_cannot_be_finished_in_another() {
    use hodor_adapters_crypto::testing::webauthn::SoftwareAuthenticator;
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    require_second_factor(&world, acme).await;
    require_second_factor(&world, globex).await;

    // In Acme, the shared person reaches the enrollment step and begins
    // an application.
    let (mut in_acme, body) = waiting_after_password(&world, acme).await;
    assert_eq!(body["step"], "enrollment", "{body}");
    let (status, application) = enrollment(
        &mut in_acme,
        acme,
        "/options",
        serde_json::json!({ "kind": "authenticator_application" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{application}");
    let acme_secret = support::base32(application["secret"].as_str().expect("secret"));

    // Acme's sign-in does not exist at Globex, whatever is asked of it.
    let mut carried = Browser::new(&world.server);
    carried.cookies = in_acme.cookies.clone();
    carried.csrf_token = in_acme.csrf_token.clone();
    for (what, body) in [
        (
            "/options",
            serde_json::json!({ "kind": "authenticator_application" }),
        ),
        (
            "",
            serde_json::json!({ "code": application_code(&acme_secret, 0) }),
        ),
    ] {
        let (status, body) = enrollment(&mut carried, globex, what, body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["code"], "authentication.transaction_not_found");
    }

    // Globex's own sign-in of the same person has begun nothing: the code
    // of Acme's secret, and the answer to a registration Acme began, are
    // rejections there.
    let (mut in_globex, body) = waiting_after_password(&world, globex).await;
    assert_eq!(body["step"], "enrollment", "{body}");
    let (_, body) = enrollment(
        &mut in_globex,
        globex,
        "",
        serde_json::json!({ "code": application_code(&acme_secret, 0) }),
    )
    .await;
    assert_eq!(body["status"], "rejected", "{body}");
    let (status, begun) = enrollment(
        &mut in_acme,
        acme,
        "/options",
        serde_json::json!({ "kind": "security_key" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{begun}");
    // The relying party of the server, as `HODOR_PUBLIC_URL` leaves it.
    let key = SoftwareAuthenticator::new("http://localhost:8080");
    let acme_answer = key.register(&begun["public_key"]);
    let (status, _) = enrollment(
        &mut in_globex,
        globex,
        "/options",
        serde_json::json!({ "kind": "security_key" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = enrollment(&mut in_globex, globex, "", acme_answer.clone()).await;
    assert_eq!(body["status"], "rejected", "{body}");

    // Acme finishes its own, and its factor means nothing at Globex: the
    // person there still has none, and sets one up of Globex's own.
    let (_, body) = enrollment(&mut in_acme, acme, "", acme_answer).await;
    assert_eq!(body["status"], "completed", "{body}");
    let (_, body) = enrollment(
        &mut in_globex,
        globex,
        "/options",
        serde_json::json!({ "kind": "authenticator_application" }),
    )
    .await;
    let globex_secret = support::base32(body["secret"].as_str().expect("secret"));
    assert_ne!(globex_secret, acme_secret);
    let (_, body) = enrollment(
        &mut in_globex,
        globex,
        "",
        serde_json::json!({ "code": application_code(&globex_secret, 0) }),
    )
    .await;
    assert_eq!(body["status"], "completed", "{body}");

    // Each tenant asks for its own factor at the next sign-in.
    let (_, body) = waiting_after_password(&world, acme).await;
    assert_eq!(body["step"], "webauthn", "{body}");
    let (_, body) = waiting_after_password(&world, globex).await;
    assert_eq!(body["step"], "totp", "{body}");
}

#[tokio::test]
async fn wrong_codes_by_email_in_one_tenant_do_not_lock_the_same_address_out_in_another() {
    let world = world().await;
    let (acme, globex) = (&world.acme, &world.globex);
    offer_by_email(&world, acme).await;
    offer_by_email(&world, globex).await;

    // Five wrong codes for the shared address in Acme, in two sign-ins,
    // after which even the right password waits there.
    for tries in [4, 1] {
        let (mut browser, sent) = asked_by_email(&world, acme, "email_code", "code").await;
        let wrong = if sent == "000000" { "000001" } else { "000000" };
        for _ in 0..tries {
            let (_, body) = present_by_email(&mut browser, acme, "email_code", "code", wrong).await;
            assert_eq!(body["status"], "rejected", "{body}");
        }
    }
    let (status, body) = Browser::new(&world.server)
        .sign_in(acme.slug, EMAIL, PASSWORD)
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["code"], "authentication.too_many_attempts");

    // The person with the same address in Globex signs in at once, with
    // the password and with a code.
    let (status, body) = Browser::new(&world.server)
        .sign_in(globex.slug, EMAIL, PASSWORD)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "completed", "{body}");
    let (mut browser, sent) = asked_by_email(&world, globex, "email_code", "code").await;
    let (_, body) = present_by_email(&mut browser, globex, "email_code", "code", &sent).await;
    assert_eq!(body["status"], "completed", "{body}");
}

/// A first-party client of a new application of `tenant` that is told
/// when a session it signed a person in with ends.
async fn client_told_of_sign_outs(world: &World, tenant: &Tenant, address: &str) -> String {
    use hodor_adapters_postgres::{PgApplicationStore, PgClientStore, PgResourceServerStore};
    use hodor_oauth::api::{
        ApplicationPorts, ApplicationService, ApplicationSettings, ClientSettings, ClientType,
        CreateClient, GrantType,
    };
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(world.database.app().clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    })
    .with_destinations(Arc::new(hodor_oauth::testing::FakeDestinations));
    let application = applications
        .create_application(
            &tenant.context,
            ApplicationSettings {
                name: "Billing".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    let mut settings = ClientSettings::new(
        "Billing web",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.allowed_scopes = vec!["openid".to_owned()];
    settings.backchannel_logout_uri = Some(address.to_owned());
    applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client")
        .0
        .id()
        .to_string()
}

/// The person signs in to `tenant` and is sent back to `client` with a
/// code; answers the browser, still signed in.
async fn signed_in_to(world: &World, tenant: &Tenant, client: &str) -> Browser {
    let mut browser = Browser::not_following(&world.server);
    let (_, body) = browser.sign_in(tenant.slug, EMAIL, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");
    let challenge = hodor_oauth::api::s256_challenge(VERIFIER, &Sha256Digest);
    let path = format!(
        "/t/{}/oauth2/authorize?{}",
        tenant.slug,
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", client),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
            ])
            .finish()
    );
    let (status, location, _) = browser.navigate(Method::GET, &path, None).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location
            .as_deref()
            .is_some_and(|location| location.starts_with(REDIRECT) && location.contains("code=")),
        "{location:?}"
    );
    browser
}

#[tokio::test]
async fn a_sign_out_in_one_tenant_tells_none_of_another_tenants_clients() {
    let world = world().await;
    let (acme, globex) = (&world.acme, &world.globex);
    let acme_client =
        client_told_of_sign_outs(&world, acme, "https://billing.acme.example/logout").await;
    let globex_client =
        client_told_of_sign_outs(&world, globex, "https://billing.globex.example/logout").await;
    let mut in_acme = signed_in_to(&world, acme, &acme_client).await;
    let _in_globex = signed_in_to(&world, globex, &globex_client).await;

    // Signing out, as the account page does: with the session's CSRF
    // token.
    let (status, _) = in_acme
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = in_acme
        .send(Method::DELETE, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The worker's part: the outbox hands the end of the session to the
    // OAuth context, in the session's tenant.
    let dispatcher = OutboxDispatcher::new(
        world.database.platform().clone(),
        world.database.app().clone(),
        vec![Arc::new(hodor_oauth::api::BackChannelLogoutFanOut::new(
            Arc::new(hodor_adapters_postgres::PgSessionClients),
            Arc::new(hodor_adapters_postgres::PgClientStore),
            Arc::new(hodor_adapters_postgres::PgApplicationStore),
            Arc::new(hodor_adapters_postgres::PgLogoutDeliveryStore),
            Arc::new(SystemClock),
        ))],
    );
    while dispatcher
        .dispatch_batch(100)
        .await
        .expect("dispatch")
        .delivered
        > 0
    {}
    let made: Vec<(String, String)> =
        sqlx::query_as("SELECT tenant_id::text, client_id::text FROM oauth.logout_delivery")
            .fetch_all(world.database.owner())
            .await
            .expect("deliveries");
    assert_eq!(
        made,
        [(acme.context.tenant_id().to_string(), acme_client)],
        "Acme's client alone is told; Globex's session goes on"
    );
    let ended_in_globex: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM session.session WHERE tenant_id = $1 AND revoked_at IS NOT NULL",
    )
    .bind(globex.context.tenant_id().as_uuid())
    .fetch_one(world.database.owner())
    .await
    .expect("sessions");
    assert_eq!(ended_in_globex, 0);
}

/// A pairwise client of a new first-party application of `tenant`, whose
/// sector is the host of `REDIRECT`, and the tokens the person gets from
/// it. Answers the client's identifier and secret, the tokens, and the
/// browser, still signed in.
async fn pairwise_tokens(
    world: &World,
    tenant: &Tenant,
) -> ((String, String), serde_json::Value, Browser) {
    use hodor_adapters_postgres::{PgApplicationStore, PgClientStore, PgResourceServerStore};
    use hodor_oauth::api::{
        ApplicationPorts, ApplicationService, ApplicationSettings, ClientSettings, ClientType,
        CreateClient, GrantType, SubjectType,
    };
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(world.database.app().clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    });
    let application = applications
        .create_application(
            &tenant.context,
            ApplicationSettings {
                name: "Travel".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    let mut settings = ClientSettings::new(
        "Travel web",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.allowed_scopes = vec!["openid".to_owned()];
    settings.subject_type = SubjectType::Pairwise;
    let (client, secret) = applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    let pair = (
        client.id().to_string(),
        secret.expect("a secret").expose().to_owned(),
    );
    let mut browser = Browser::not_following(&world.server);
    let (_, body) = browser.sign_in(tenant.slug, EMAIL, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");
    let challenge = hodor_oauth::api::s256_challenge(VERIFIER, &Sha256Digest);
    let path = format!(
        "/t/{}/oauth2/authorize?{}",
        tenant.slug,
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", pair.0.as_str()),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
            ])
            .finish()
    );
    let (status, location, _) = browser.navigate(Method::GET, &path, None).await;
    assert_eq!(status, StatusCode::FOUND);
    let location = location.expect("a redirect");
    let (_, query) = location.split_once('?').expect("a query");
    let code = form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == "code")
        .expect("a code")
        .1
        .into_owned();
    let (status, tokens) = oauth_form(
        world,
        tenant,
        "token",
        (&pair.0, &pair.1),
        &[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    (pair, tokens, browser)
}

fn id_token_claims(tokens: &serde_json::Value) -> serde_json::Value {
    use base64::Engine as _;
    let token = tokens["id_token"].as_str().expect("an ID token");
    let payload = token.split('.').nth(1).expect("claims");
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url"),
    )
    .expect("JSON")
}

#[tokio::test]
async fn one_sector_in_two_tenants_knows_the_same_address_by_two_identifiers() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let (acme_client, in_acme, _) = pairwise_tokens(&world, acme).await;
    let (globex_client, in_globex, _) = pairwise_tokens(&world, globex).await;
    let acme_sub = id_token_claims(&in_acme)["sub"].clone();
    let globex_sub = id_token_claims(&in_globex)["sub"].clone();
    // The same address, the same sector, two tenants: two identifiers, and
    // neither is the person's user identifier there.
    assert_ne!(acme_sub, globex_sub);
    assert_ne!(acme_sub, acme.ana.to_string());
    assert_ne!(globex_sub, globex.ana.to_string());
    let secrets: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth.pairwise_secret")
        .fetch_one(world.database.owner())
        .await
        .expect("secrets");
    assert_eq!(secrets, 2, "a secret per tenant");

    // Acme's access token: the `sub` of the ID token at Acme's UserInfo,
    // nothing at Globex's, and not active for Globex's client.
    let access = in_acme["access_token"].as_str().expect("access");
    let answer: serde_json::Value = Client::new()
        .get(format!("{}/t/acme/oauth2/userinfo", world.server.base))
        .bearer_auth(access)
        .send()
        .await
        .expect("response")
        .json()
        .await
        .expect("JSON");
    assert_eq!(answer["sub"], acme_sub);
    assert_eq!(
        userinfo(&world, globex, access).await,
        StatusCode::UNAUTHORIZED
    );
    assert!(!active(&world, globex, (&globex_client.0, &globex_client.1), access).await);
    let (status, introspected) = oauth_form(
        &world,
        acme,
        "introspect",
        (&acme_client.0, &acme_client.1),
        &[("token", access)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(introspected["sub"], acme_sub);
}

/// The end-session endpoint of a tenant, with an ID token as the hint.
fn end_session_path(slug: &str, hint: &str) -> String {
    format!(
        "/t/{slug}/oauth2/logout?{}",
        form_urlencoded::Serializer::new(String::new())
            .append_pair("id_token_hint", hint)
            .finish()
    )
}

#[tokio::test]
async fn a_pairwise_id_token_of_one_tenant_ends_no_session_at_another() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    // The person is signed in to a pairwise client of the same sector in
    // each tenant.
    let (_, in_acme, mut acme_browser) = pairwise_tokens(&world, acme).await;
    let (_, _, mut globex_browser) = pairwise_tokens(&world, globex).await;
    let hint = in_acme["id_token"].as_str().expect("an ID token");

    // Acme's ID token, the hint of Globex's end-session endpoint in the
    // browser signed in to Globex: not an ID token of Globex, never a
    // redirect, and Globex's session goes on.
    let (status, location, body) = globex_browser
        .navigate(Method::GET, &end_session_path(globex.slug, hint), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(location, None);
    assert!(
        body.contains("oauth.logout_id_token_hint_invalid"),
        "{body}"
    );
    let (status, _) = globex_browser
        .send(Method::GET, "/t/globex/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::OK, "Globex's session goes on");
    // Acme's own browser, carried to Globex's path with its cookies: the
    // same refusal.
    let (status, location, _) = acme_browser
        .navigate(Method::GET, &end_session_path(globex.slug, hint), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(location, None);

    // Where it belongs, its pairwise `sub` and `sid` name the session, which
    // ends without asking; Globex's still goes on.
    let (status, location, _) = acme_browser
        .navigate(Method::GET, &end_session_path(acme.slug, hint), None)
        .await;
    assert!(status.is_redirection(), "{status}");
    assert!(
        location
            .as_deref()
            .is_some_and(|location| !location.contains("/account/sign-out")),
        "ended without asking: {location:?}"
    );
    let (status, _) = acme_browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_ne!(status, StatusCode::OK, "Acme's session ended");
    let (status, _) = globex_browser
        .send(Method::GET, "/t/globex/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::OK, "Globex's session goes on");
}

/// The ID token and the access token a person gets at a tenant's
/// first-party client, signed in with the shared address.
async fn first_party_tokens(
    world: &World,
    tenant: &Tenant,
    client: (&str, &str),
) -> (serde_json::Value, serde_json::Value) {
    let mut browser = Browser::not_following(&world.server);
    let (_, body) = browser.sign_in(tenant.slug, EMAIL, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");
    let back = authorized(&mut browser, &authorize_path(tenant.slug, client.0)).await;
    let code = back.get("code").expect("a code");
    let (status, tokens) = oauth_form(
        world,
        tenant,
        "token",
        client,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    (
        claims_of(tokens["id_token"].as_str().expect("an ID token")),
        claims_of(tokens["access_token"].as_str().expect("an access token")),
    )
}

#[tokio::test]
async fn one_tenants_claim_mappers_are_out_of_reach_of_another_and_read_only_their_own_tenant() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let finance = created(
        &world,
        acme,
        "/groups",
        serde_json::json!({ "name": "finance" }),
    )
    .await;
    let (status, _) = call(
        &world,
        acme,
        Method::POST,
        format!("/groups/{finance}/members"),
        Some(serde_json::json!({ "kind": "user", "id": acme.ana.to_string() })),
    )
    .await;
    assert!(status.is_success(), "{status}");
    let (acme_client, acme_secret) = first_party_client(&world, acme).await;
    let (globex_client, globex_secret) = first_party_client(&world, globex).await;
    let mappers = format!("/clients/{acme_client}/claim-mappers");
    let mapper = created(
        &world,
        acme,
        &mappers,
        serde_json::json!({
            "claim": "in_finance",
            "targets": ["id_token", "access_token"],
            "source": { "kind": "group_member", "group_id": finance },
        }),
    )
    .await;

    // Globex's administrator, naming Acme's client and mapper at Globex,
    // finds no such client.
    let replacement = serde_json::json!({
        "claim": "plan",
        "targets": ["userinfo"],
        "source": { "kind": "constant", "value": "gold" },
    });
    for (method, path, body) in [
        (Method::GET, mappers.clone(), None),
        (Method::POST, mappers.clone(), Some(replacement.clone())),
        (Method::GET, format!("{mappers}/{mapper}"), None),
        (
            Method::PUT,
            format!("{mappers}/{mapper}"),
            Some(replacement.clone()),
        ),
        (Method::DELETE, format!("{mappers}/{mapper}"), None),
    ] {
        let (status, answer) = call(&world, globex, method.clone(), path.clone(), body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {answer}");
        assert_eq!(answer["code"], "oauth.client_not_found", "{method} {path}");
    }
    // Acme's mapper, named under Globex's own client, is not one of it.
    let (status, answer) = call(
        &world,
        globex,
        Method::GET,
        format!("/clients/{globex_client}/claim-mappers/{mapper}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["code"], "oauth.claim_mapper_not_found");
    // A mapper of Globex cannot name Acme's group.
    let globex_mappers = format!("/clients/{globex_client}/claim-mappers");
    let (status, answer) = call(
        &world,
        globex,
        Method::POST,
        globex_mappers.clone(),
        Some(serde_json::json!({
            "claim": "in_finance",
            "targets": ["id_token"],
            "source": { "kind": "group_member", "group_id": finance },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(answer["code"], "oauth.claim_mapper_group_unknown");

    // Globex's own mapper of the person's groups reads Globex's groups
    // only: the person with the same address is in none there.
    created(
        &world,
        globex,
        &globex_mappers,
        serde_json::json!({
            "claim": "teams",
            "targets": ["id_token", "access_token"],
            "source": { "kind": "groups" },
        }),
    )
    .await;
    let (identity, access) =
        first_party_tokens(&world, globex, (&globex_client, &globex_secret)).await;
    assert_eq!(identity["teams"], serde_json::json!([]));
    assert_eq!(access["teams"], serde_json::json!([]));
    assert!(
        identity.get("in_finance").is_none(),
        "Acme's mapper is Acme's"
    );

    // Where it belongs, the mapper writes the group, unchanged.
    let (identity, access) = first_party_tokens(&world, acme, (&acme_client, &acme_secret)).await;
    assert_eq!(identity["in_finance"], true);
    assert_eq!(access["in_finance"], true);
    assert!(
        identity.get("teams").is_none(),
        "Globex's mapper is Globex's"
    );
    let (_, listed) = call(&world, acme, Method::GET, mappers, None).await;
    assert_eq!(listed["items"][0]["id"], mapper.as_str());
    assert_eq!(listed["items"][0]["claim"], "in_finance");
}

#[tokio::test]
async fn one_tenants_second_factor_policy_asks_no_enrollment_of_another() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    require_second_factor(&world, acme).await;

    // In Acme the shared person, who has no second factor, is asked to set
    // one up after the password, and nobody is signed in yet.
    let (in_acme, body) = waiting_after_password(&world, acme).await;
    assert_eq!(
        (body["status"].as_str(), body["step"].as_str()),
        (Some("pending"), Some("enrollment")),
        "{body}"
    );
    assert!(!in_acme.cookies.contains_key(SESSION_COOKIE));

    // In Globex, which requires nothing more, the person with the same
    // address signs in with the password alone.
    let (mut in_globex, body) = waiting_after_password(&world, globex).await;
    assert_eq!(body["status"], "completed", "{body}");
    let (status, who) = in_globex
        .send(Method::GET, "/t/globex/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(who["methods"], serde_json::json!(["password"]));

    // Acme's sign-in, still waiting, is finished only by enrolling there.
    let mut carried = Browser::new(&world.server);
    carried.cookies = in_acme.cookies.clone();
    carried.csrf_token = in_acme.csrf_token.clone();
    let (status, body) = carried
        .send(Method::GET, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["step"], "enrollment", "{body}");
}

/// A bundle of one `jwt-svid` key named `key_id`, for a trust domain.
fn bundle_naming(key_id: &str) -> serde_json::Value {
    serde_json::json!({
        "spiffe_sequence": 1,
        "keys": [{
            "use": "jwt-svid",
            "kty": "EC",
            "crv": "P-256",
            "kid": key_id,
            "x": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "y": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
        }],
    })
}

#[tokio::test]
async fn one_tenants_trust_domain_is_never_read_for_another_even_under_the_same_name() {
    let world = world().await;
    let (acme, globex) = (&world.acme, &world.globex);
    let mut ids = Vec::new();
    for (tenant, key_id) in [(acme, "acme-key"), (globex, "globex-key")] {
        let (status, added) = world
            .admin(
                tenant,
                &tenant.administrator_token,
                Method::POST,
                "/trust-domains",
                Some(serde_json::json!({
                    "name": "cluster.local",
                    "source": "uploaded",
                    "bundle": bundle_naming(key_id),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{added}");
        ids.push(added["id"].as_str().expect("id").to_owned());
    }
    let (ours, theirs) = (&ids[0], &ids[1]);

    // Each tenant lists its own trust domain of that name, with its own
    // bundle, and nothing of the other's.
    for (tenant, own, other_key) in [(acme, ours, "globex-key"), (globex, theirs, "acme-key")] {
        let (status, listed) = world
            .admin(
                tenant,
                &tenant.administrator_token,
                Method::GET,
                "/trust-domains",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let items = listed["items"].as_array().expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"].as_str(), Some(own.as_str()));
        assert!(!listed.to_string().contains(other_key));
    }

    // Globex's administrator names Acme's trust domain: it does not exist.
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let (status, body) = world
            .admin(
                globex,
                &globex.administrator_token,
                method.clone(),
                &format!("/trust-domains/{ours}"),
                Some(serde_json::json!({ "source": "mesh" })),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method}");
        assert_eq!(body["code"], "keys.trust_domain_not_found", "{method}");
    }
    // Replacing and removing its own changes nothing of Acme's.
    let (status, _) = world
        .admin(
            globex,
            &globex.administrator_token,
            Method::PUT,
            &format!("/trust-domains/{theirs}"),
            Some(serde_json::json!({ "source": "mesh" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = world
        .admin(
            globex,
            &globex.administrator_token,
            Method::DELETE,
            &format!("/trust-domains/{theirs}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, kept) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::GET,
            &format!("/trust-domains/{ours}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(kept["source"], "uploaded");
    assert_eq!(kept["bundle"]["keys"][0]["kid"], "acme-key");

    // Globex may add `cluster.local` again: the name is Acme's only in Acme.
    let (status, _) = world
        .admin(
            globex,
            &globex.administrator_token,
            Method::POST,
            "/trust-domains",
            Some(serde_json::json!({ "name": "cluster.local", "source": "mesh" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // A bundle endpoint at a private address is refused, in either tenant,
    // and nothing is stored.
    for url in [
        "https://127.0.0.1/bundle",
        "https://10.1.2.3/bundle",
        "https://169.254.169.254/latest",
        "https://localhost/bundle",
    ] {
        let (status, body) = world
            .admin(
                acme,
                &acme.administrator_token,
                Method::POST,
                "/trust-domains",
                Some(serde_json::json!({
                    "name": "private.example",
                    "source": "bundle_endpoint",
                    "bundle_endpoint_url": url,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{url}");
        assert!(
            body["code"] == "keys.bundle_endpoint_forbidden"
                || body["code"] == "keys.bundle_endpoint_unresolvable",
            "{url}: {body}"
        );
    }
    let (_, listed) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::GET,
            "/trust-domains",
            None,
        )
        .await;
    assert_eq!(listed["items"].as_array().map(Vec::len), Some(1));
}

/// An authority of a tenant's `cluster.local`: a P-256 key made here, as
/// SPIRE would sign JWT-SVIDs with, under the same `kid` in both tenants.
struct SvidAuthority {
    pkcs8: Vec<u8>,
    public: Vec<u8>,
}

impl SvidAuthority {
    const KID: &'static str = "cluster-2026-11";

    fn new() -> Self {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("a key");
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .expect("the key reads");
        Self {
            pkcs8: pkcs8.as_ref().to_vec(),
            public: pair.public_key().as_ref().to_vec(),
        }
    }

    fn bundle(&self) -> serde_json::Value {
        use base64::Engine as _;
        let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let (x, y) = self.public[1..].split_at(32);
        serde_json::json!({ "keys": [{
            "use": "jwt-svid", "kty": "EC", "crv": "P-256", "kid": Self::KID,
            "x": encode(x), "y": encode(y),
        }] })
    }

    /// A JWT-SVID of `subject` for `audience`, made distinct by `nonce`.
    fn svid(&self, subject: &str, audience: &str, nonce: &str) -> String {
        self.svid_for(subject, &serde_json::json!(audience), nonce)
    }

    /// A JWT-SVID of `subject` whose `aud` is `audience` as given: one
    /// text, or an array.
    fn svid_for(&self, subject: &str, audience: &serde_json::Value, nonce: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(Self::KID.to_owned());
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "sub": subject, "aud": audience, "iat": now, "exp": now + 300, "x-nonce": nonce,
            }),
            &jsonwebtoken::EncodingKey::from_ec_der(&self.pkcs8),
        )
        .expect("a JWT-SVID")
    }
}

/// A tenant trusting its own `cluster.local`, signed by `authority`, with
/// a service account's client bound to `spiffe_id` there. Answers the
/// client's identifier and the tenant's issuer.
async fn workload_bound_to(
    world: &World,
    tenant: &Tenant,
    authority: &SvidAuthority,
    spiffe_id: &str,
) -> (String, String) {
    let token = &tenant.administrator_token;
    let (status, added) = world
        .admin(
            tenant,
            token,
            Method::POST,
            "/trust-domains",
            Some(serde_json::json!({
                "name": "cluster.local", "source": "uploaded", "bundle": authority.bundle(),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{added}");
    let (account, _) = service_account_with_a_client(world, tenant).await;
    let (_, applications) = world
        .admin(tenant, token, Method::GET, "/applications", None)
        .await;
    let application = applications["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["name"] == "Exports")
        .and_then(|item| item["id"].as_str())
        .expect("the application")
        .to_owned();
    let (status, client) = world
        .admin(
            tenant,
            token,
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(serde_json::json!({
                "name": "Nightly export", "type": "confidential",
                "authentication_method": "spiffe_jwt", "spiffe_id": spiffe_id,
                "grant_types": ["client_credentials"], "allowed_scopes": ["read"],
                "principal": account
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{client}");
    let discovery: serde_json::Value = reqwest::get(format!(
        "{}/t/{}/.well-known/openid-configuration",
        world.server.base, tenant.slug
    ))
    .await
    .expect("response")
    .json()
    .await
    .expect("JSON");
    (
        client["id"].as_str().expect("id").to_owned(),
        discovery["issuer"].as_str().expect("issuer").to_owned(),
    )
}

/// A token request of `client` at `tenant`, proven with `svid`.
async fn token_with_svid(
    world: &World,
    tenant: &Tenant,
    client: &str,
    svid: &str,
) -> (StatusCode, serde_json::Value) {
    let response = Client::new()
        .post(format!(
            "{}/t/{}/oauth2/token",
            world.server.base, tenant.slug
        ))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("grant_type", "client_credentials"),
                    ("client_id", client),
                    (
                        "client_assertion_type",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe",
                    ),
                    ("client_assertion", svid),
                ])
                .finish(),
        )
        .send()
        .await
        .expect("response");
    let status = response.status();
    (
        status,
        response.json().await.unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn a_jwt_svid_for_one_tenant_is_refused_by_another_under_the_same_trust_domain_name() {
    const EXPORT: &str = "spiffe://cluster.local/ns/payroll/sa/export";
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let (acme_authority, globex_authority) = (SvidAuthority::new(), SvidAuthority::new());
    // Both tenants trust a `cluster.local` and bind the same identifier.
    let (acme_client, acme_issuer) = workload_bound_to(&world, acme, &acme_authority, EXPORT).await;
    let (globex_client, globex_issuer) =
        workload_bound_to(&world, globex, &globex_authority, EXPORT).await;

    // Acme's JWT-SVID, for Acme, at Globex: for Globex's client and for
    // Acme's, which Globex does not have.
    let for_acme = acme_authority.svid(EXPORT, &acme_issuer, "one");
    for client in [&globex_client, &acme_client] {
        let (status, body) = token_with_svid(&world, globex, client, &for_acme).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"], "invalid_client");
    }
    // Acme's authority, even for Globex's issuer and under the same kid:
    // Globex's `cluster.local` is its own.
    let forged = acme_authority.svid(EXPORT, &globex_issuer, "two");
    let (status, _) = token_with_svid(&world, globex, &globex_client, &forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Globex's own JWT-SVID, at Acme.
    let for_globex = globex_authority.svid(EXPORT, &globex_issuer, "three");
    let (status, _) = token_with_svid(&world, acme, &acme_client, &for_globex).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Each passes at its own tenant, the refusals elsewhere notwithstanding.
    let (status, body) = token_with_svid(&world, acme, &acme_client, &for_acme).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = token_with_svid(&world, globex, &globex_client, &for_globex).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A tenant's application with the scope `read`, a trust domain
/// `cluster.local` trusting `authority` when one is given, and a client of
/// `spiffe_x509` bound to `identity`. Answers the client's identifier.
async fn workload_client_trusting(
    world: &World,
    tenant: &Tenant,
    authority: Option<&hodor_adapters_crypto::testing::certificates::TestAuthority>,
    identity: &str,
) -> String {
    use hodor_adapters_crypto::testing::certificates::bundle;
    let token = &tenant.administrator_token;
    let (status, _) = world
        .admin(tenant, token, Method::POST, "/keys/sig:rotate", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, application) = world
        .admin(
            tenant,
            token,
            Method::POST,
            "/applications",
            Some(serde_json::json!({ "name": "Shop", "first_party": true })),
        )
        .await;
    let (status, _) = world
        .admin(
            tenant,
            token,
            Method::POST,
            "/resource-servers",
            Some(serde_json::json!({
                "application_id": application["id"],
                "audience": "https://api.shop.example",
                "name": "Shop interface",
                "scopes": [{ "name": "read", "description": "Reads orders" }]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    if let Some(authority) = authority {
        let (status, added) = world
            .admin(
                tenant,
                token,
                Method::POST,
                "/trust-domains",
                Some(serde_json::json!({
                    "name": "cluster.local",
                    "source": "uploaded",
                    "bundle": bundle(&[authority.bundle_element()]),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{added}");
    }
    let (status, account) = world
        .admin(
            tenant,
            token,
            Method::POST,
            "/service-accounts",
            Some(serde_json::json!({ "name": "Shop web", "owners": [tenant.ana] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{account}");
    let (status, client) = world
        .admin(
            tenant,
            token,
            Method::POST,
            &format!(
                "/applications/{}/clients",
                application["id"].as_str().expect("id")
            ),
            Some(serde_json::json!({
                "name": "Web",
                "type": "confidential",
                "authentication_method": "spiffe_x509",
                "spiffe_id": identity,
                "principal": account["id"],
                "grant_types": ["client_credentials"],
                "allowed_scopes": ["read"],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{client}");
    client["id"].as_str().expect("id").to_owned()
}

/// Asks a tenant's token endpoint for client credentials with the client's
/// identifier alone and a certificate in `Client-Cert`, as the trusted
/// proxy in front of Hodor would forward it.
async fn token_with_certificate(
    world: &World,
    tenant: &Tenant,
    client: &str,
    certificate: &[u8],
) -> StatusCode {
    token_with_chain(world, tenant, client, certificate, None).await
}

/// The same, with a certificate above it in `Client-Cert-Chain`.
async fn token_with_chain(
    world: &World,
    tenant: &Tenant,
    client: &str,
    certificate: &[u8],
    chain: Option<&[u8]>,
) -> StatusCode {
    use base64::Engine as _;
    let encoded = |der: &[u8]| {
        format!(
            ":{}:",
            base64::engine::general_purpose::STANDARD.encode(der)
        )
    };
    let mut request = Client::new()
        .post(format!(
            "{}/t/{}/oauth2/token",
            world.server.base, tenant.slug
        ))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("client-cert", encoded(certificate));
    if let Some(chain) = chain {
        request = request.header("client-cert-chain", encoded(chain));
    }
    request
        .body(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("grant_type", "client_credentials"),
                    ("client_id", client),
                    ("scope", "read"),
                ])
                .finish(),
        )
        .send()
        .await
        .expect("response")
        .status()
}

#[tokio::test]
async fn a_certificate_of_one_tenants_trust_domain_is_refused_by_another_under_the_same_name() {
    use hodor_adapters_crypto::testing::certificates::{Leaf, TestAuthority};
    let world = world_with(&[
        ("HODOR_SECRET_KEYS", ROOT_KEY),
        ("HODOR_TRUSTED_PROXIES", "127.0.0.1"),
        ("HODOR_FORWARDED_HEADER", "none"),
        ("HODOR_CLIENT_IDENTITY_HEADER", "client-cert"),
    ])
    .await;
    let (acme, globex) = (&world.acme, &world.globex);
    let identity = "spiffe://cluster.local/ns/shop/sa/web";
    // Two meshes, each named `cluster.local`, each with an authority of its
    // own, and a client in each bound to the same identifier.
    let (acme_mesh, globex_mesh) = (TestAuthority::root("mesh"), TestAuthority::root("mesh"));
    let acme_client = workload_client_trusting(&world, acme, Some(&acme_mesh), identity).await;
    let globex_client =
        workload_client_trusting(&world, globex, Some(&globex_mesh), identity).await;
    let acme_certificate = acme_mesh.issue(&Leaf::uri(identity));
    let globex_certificate = globex_mesh.issue(&Leaf::uri(identity));

    // Each certificate proves its own tenant's client.
    for (tenant, client, certificate) in [
        (acme, &acme_client, &acme_certificate),
        (globex, &globex_client, &globex_certificate),
    ] {
        assert_eq!(
            token_with_certificate(&world, tenant, client, certificate).await,
            StatusCode::OK
        );
    }
    // Acme's certificate is refused by Globex's client of the same
    // identifier, under Globex's trust domain of the same name, and the
    // other way round.
    assert_eq!(
        token_with_certificate(&world, globex, &globex_client, &acme_certificate).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        token_with_certificate(&world, acme, &acme_client, &globex_certificate).await,
        StatusCode::UNAUTHORIZED
    );
    // Acme's client is unknown at Globex, whatever certificate comes with it.
    for certificate in [&acme_certificate, &globex_certificate] {
        assert_eq!(
            token_with_certificate(&world, globex, &acme_client, certificate).await,
            StatusCode::UNAUTHORIZED
        );
    }
}

/// A first-party client of `tenant` that signs its request objects with a
/// P-256 key of its own, `kid` `signing` in every tenant; the private half
/// is returned.
async fn request_object_client(world: &World, tenant: &Tenant) -> (String, Vec<u8>) {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use hodor_adapters_postgres::{PgApplicationStore, PgClientStore, PgResourceServerStore};
    use hodor_oauth::api::{
        ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
        ClientSettings, ClientType, CreateClient, GrantType,
    };
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(world.database.app().clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    });
    let application = applications
        .create_application(
            &tenant.context,
            ApplicationSettings {
                name: "Billing".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    let mut settings = ClientSettings::new(
        "Billing web",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.authentication_method = AuthenticationMethod::PrivateKeyJwt;
    settings.allowed_scopes = vec!["openid".to_owned()];
    let (client, _) = applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .expect("key");
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).expect("pair");
    let point = pair.public_key().as_ref();
    let jwk = serde_json::json!({
        "kty": "EC", "crv": "P-256", "kid": "signing",
        "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
    });
    applications
        .add_client_key(
            &tenant.context,
            client.id(),
            &jwk.to_string(),
            Caller::system(),
        )
        .await
        .expect("key");
    (client.id().to_string(), pkcs8.as_ref().to_vec())
}

/// A request object of `client` for `audience`, signed with `key`.
fn request_object(client: &str, audience: &str, key: &[u8]) -> String {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs();
    let encode = |value: serde_json::Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let input = format!(
        "{}.{}",
        encode(serde_json::json!({"alg": "ES256", "kid": "signing"})),
        encode(serde_json::json!({
            "iss": client,
            "aud": audience,
            "exp": now + 300,
            "client_id": client,
            "response_type": "code",
            "redirect_uri": REDIRECT,
            "scope": "openid",
            "state": "inside",
            "code_challenge": hodor_oauth::api::s256_challenge(VERIFIER, &Sha256Digest),
            "code_challenge_method": "S256",
        }))
    );
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key).expect("pair");
    let signature = pair
        .sign(&SystemRandom::new(), input.as_bytes())
        .expect("signature");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
}

/// Where the authorization endpoint of `tenant` sends a signed-in browser
/// for `client` with `object`: the status, and the query of the redirect.
async fn with_request_object(
    browser: &mut Browser,
    tenant: &Tenant,
    client: &str,
    object: &str,
) -> (StatusCode, Option<String>) {
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("client_id", client),
            ("response_type", "code"),
            ("scope", "openid"),
            ("redirect_uri", REDIRECT),
            ("request", object),
        ])
        .finish();
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!("/t/{}/oauth2/authorize?{query}", tenant.slug),
            None,
        )
        .await;
    (status, location)
}

#[tokio::test]
async fn a_request_object_signed_for_one_tenant_is_refused_by_another() {
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    let (acme_client, acme_key) = request_object_client(&world, acme).await;
    let (globex_client, globex_key) = request_object_client(&world, globex).await;
    let acme_issuer = "http://localhost:8080/t/acme";
    let globex_issuer = "http://localhost:8080/t/globex";
    let object = request_object(&acme_client, acme_issuer, &acme_key);

    // At Acme, the object is the request.
    let mut at_acme = Browser::not_following(&world.server);
    let (_, body) = at_acme.sign_in(acme.slug, EMAIL, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");
    let (status, location) = with_request_object(&mut at_acme, acme, &acme_client, &object).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location.as_deref().is_some_and(|to| to.contains("code=")),
        "{location:?}"
    );

    let mut at_globex = Browser::not_following(&world.server);
    let (_, body) = at_globex.sign_in(globex.slug, EMAIL, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");

    // At Globex, Acme's client is nobody: Hodor's own page, and nothing is
    // checked or sent to an address.
    let (status, location) =
        with_request_object(&mut at_globex, globex, &acme_client, &object).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(location, None);

    // Named for Globex's own client, Acme's object is signed by a key
    // Globex's client does not have.
    let (status, location) =
        with_request_object(&mut at_globex, globex, &globex_client, &object).await;
    assert_eq!(status, StatusCode::FOUND);
    let location = location.expect("a redirect");
    assert!(
        location.contains("error=invalid_request_object") && !location.contains("code="),
        "{location}"
    );

    // Globex's client's own object, made for Acme's issuer, is not for
    // Globex either; for Globex's issuer it is the request.
    let for_acme = request_object(&globex_client, acme_issuer, &globex_key);
    let (_, location) =
        with_request_object(&mut at_globex, globex, &globex_client, &for_acme).await;
    assert!(
        location
            .as_deref()
            .is_some_and(|to| to.contains("error=invalid_request_object")),
        "{location:?}"
    );
    let for_globex = request_object(&globex_client, globex_issuer, &globex_key);
    let (_, location) =
        with_request_object(&mut at_globex, globex, &globex_client, &for_globex).await;
    assert!(
        location.as_deref().is_some_and(|to| to.contains("code=")),
        "{location:?}"
    );
}

/// A client of a tenant that asks for certificate-bound tokens, of an
/// application with a resource server, allowed to ask the Authorization
/// API, which the tenant opens. Answers the client's identifier and secret.
async fn bound_client(world: &World, tenant: &Tenant) -> (String, String) {
    let token = &tenant.administrator_token;
    let (status, _) = world
        .admin(tenant, token, Method::POST, "/keys/sig:rotate", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let mut shop = String::new();
    for (name, audience, scope) in [
        (
            "Authorization API",
            "urn:hodor:authorization",
            "authz:evaluate",
        ),
        ("Shop", "https://api.shop.example", "read"),
    ] {
        let (_, application) = world
            .admin(
                tenant,
                token,
                Method::POST,
                "/applications",
                Some(serde_json::json!({ "name": name, "first_party": true })),
            )
            .await;
        let (status, _) = world
            .admin(
                tenant,
                token,
                Method::POST,
                "/resource-servers",
                Some(serde_json::json!({
                    "application_id": application["id"],
                    "audience": audience,
                    "name": name,
                    "scopes": [{ "name": scope, "description": "A scope" }]
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
        shop = application["id"].as_str().expect("id").to_owned();
    }
    let (status, client) = world
        .admin(
            tenant,
            token,
            Method::POST,
            &format!("/applications/{shop}/clients"),
            Some(serde_json::json!({
                "name": "Shop back end",
                "type": "confidential",
                "grant_types": ["client_credentials"],
                "allowed_scopes": ["authz:evaluate"],
                "tls_client_certificate_bound_access_tokens": true,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{client}");
    (
        client["id"].as_str().expect("id").to_owned(),
        client["client_secret"]
            .as_str()
            .expect("a secret")
            .to_owned(),
    )
}

/// A form to a tenant's OAuth endpoint from a client of a secret, with the
/// certificate the trusted proxy forwards in `Client-Cert`, if any.
async fn bound_request(
    world: &World,
    tenant: &Tenant,
    endpoint: &str,
    client: &(String, String),
    pairs: &[(&str, &str)],
    certificate: Option<&[u8]>,
) -> serde_json::Value {
    use base64::Engine as _;
    let mut request = Client::new()
        .post(format!(
            "{}/t/{}/oauth2/{endpoint}",
            world.server.base, tenant.slug
        ))
        .basic_auth(&client.0, Some(&client.1))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish(),
        );
    if let Some(certificate) = certificate {
        request = request.header(
            "client-cert",
            format!(
                ":{}:",
                base64::engine::general_purpose::STANDARD.encode(certificate)
            ),
        );
    }
    let response = request.send().await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.expect("JSON")
}

/// Asks a tenant's Authorization API with `token` and the certificate the
/// trusted proxy forwards, if any.
async fn evaluate_with(
    world: &World,
    tenant: &Tenant,
    token: &str,
    certificate: Option<&[u8]>,
) -> StatusCode {
    use base64::Engine as _;
    let mut request = Client::new()
        .post(format!(
            "{}/t/{}/api/v1/authorization/evaluate",
            world.server.base, tenant.slug
        ))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "subject": { "type": "user", "id": tenant.ana.to_string() },
            "resource": { "type": "order", "id": "order-1" },
            "action": "read",
        }));
    if let Some(certificate) = certificate {
        request = request.header(
            "client-cert",
            format!(
                ":{}:",
                base64::engine::general_purpose::STANDARD.encode(certificate)
            ),
        );
    }
    request.send().await.expect("response").status()
}

#[tokio::test]
async fn a_bound_token_of_one_tenant_is_refused_by_another_even_with_its_certificate() {
    use hodor_adapters_crypto::testing::certificates::{Leaf, TestAuthority};
    let world = world_with(&[
        ("HODOR_SECRET_KEYS", ROOT_KEY),
        ("HODOR_TRUSTED_PROXIES", "127.0.0.1"),
        ("HODOR_FORWARDED_HEADER", "none"),
        ("HODOR_CLIENT_IDENTITY_HEADER", "client-cert"),
    ])
    .await;
    let (acme, globex) = (&world.acme, &world.globex);
    let acme_client = bound_client(&world, acme).await;
    let globex_client = bound_client(&world, globex).await;
    let certificate =
        TestAuthority::root("mesh").issue(&Leaf::uri("spiffe://cluster.local/ns/shop/sa/web"));
    let issued = bound_request(
        &world,
        acme,
        "token",
        &acme_client,
        &[
            ("grant_type", "client_credentials"),
            ("scope", "authz:evaluate"),
        ],
        Some(&certificate),
    )
    .await;
    let token = issued["access_token"].as_str().expect("a token");

    // Where it belongs, it is taken with its certificate alone, and
    // introspection answers its `cnf`.
    assert_ne!(
        evaluate_with(&world, acme, token, Some(&certificate)).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        evaluate_with(&world, acme, token, None).await,
        StatusCode::UNAUTHORIZED
    );
    let answer = bound_request(
        &world,
        acme,
        "introspect",
        &acme_client,
        &[("token", token)],
        None,
    )
    .await;
    assert_eq!(answer["active"], true, "{answer}");
    assert!(answer["cnf"]["x5t#S256"].is_string(), "{answer}");

    // The other tenant refuses it, with the certificate it is bound to.
    assert_eq!(
        evaluate_with(&world, globex, token, Some(&certificate)).await,
        StatusCode::UNAUTHORIZED
    );
    let answer = bound_request(
        &world,
        globex,
        "introspect",
        &globex_client,
        &[("token", token)],
        Some(&certificate),
    )
    .await;
    assert_eq!(answer, serde_json::json!({ "active": false }));
}

/// A bundle of one `jwt-svid` key named `key_id`, at `sequence`.
fn bundle_numbered(key_id: &str, sequence: u64) -> serde_json::Value {
    let mut bundle = bundle_naming(key_id);
    bundle["spiffe_sequence"] = serde_json::json!(sequence);
    bundle
}

/// SPIFFE bundle endpoints on this machine, one a path: each answers the
/// bundle it was last given, and every path asked for is kept.
#[derive(Clone, Default)]
struct BundleEndpoints {
    bundles: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    asked: Arc<std::sync::Mutex<Vec<String>>>,
}

impl BundleEndpoints {
    /// Starts answering, and answers the host and port they are at.
    async fn start(&self) -> String {
        use axum::extract::State;
        use axum::http::Uri;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address").to_string();
        let app = axum::Router::new()
            .fallback(axum::routing::get(
                |State(endpoints): State<Self>, uri: Uri| async move {
                    let path = uri.path().to_owned();
                    endpoints
                        .asked
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(path.clone());
                    endpoints
                        .bundles
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&path)
                        .cloned()
                        .map_or((StatusCode::NOT_FOUND, String::new()), |bundle| {
                            (StatusCode::OK, bundle)
                        })
                },
            ))
            .with_state(self.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        address
    }

    fn serve(&self, path: &str, bundle: &serde_json::Value) {
        self.bundles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(path.to_owned(), bundle.to_string());
    }

    /// The paths asked for since the last time, and forgets them.
    fn asked(&self) -> Vec<String> {
        std::mem::take(&mut *self.asked.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

#[tokio::test]
async fn one_tenants_bundle_endpoint_is_fetched_and_refreshed_for_that_tenant_alone() {
    use hodor_adapters_http::{GuardedHttpClient, OutboundPolicy};
    use hodor_adapters_postgres::{PgDueRefreshes, PgTrustDomainStore};
    use hodor_keys::api::{BundleRefresher, TrustDomainPorts, TrustDomainService};
    const NAME: &str = "spire.example.org";
    let endpoints = BundleEndpoints::default();
    let address = endpoints.start().await;
    endpoints.serve("/acme", &bundle_numbered("acme-key", 1));
    endpoints.serve("/globex", &bundle_numbered("globex-key", 1));
    let world = world_with(&[("HODOR_OUTBOUND_DEVELOPMENT_HOSTS", address.as_str())]).await;
    let (acme, globex) = (&world.acme, &world.globex);

    // Each tenant trusts a SPIRE of the same name, through its own bundle
    // endpoint, fetched when it is saved.
    for tenant in [acme, globex] {
        let (status, added) = world
            .admin(
                tenant,
                &tenant.administrator_token,
                Method::POST,
                "/trust-domains",
                Some(serde_json::json!({
                    "name": NAME,
                    "source": "bundle_endpoint",
                    "bundle_endpoint_url": format!("http://{address}/{}", tenant.slug),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{added}");
        assert_eq!(
            added["bundle"]["keys"][0]["kid"],
            format!("{}-key", tenant.slug)
        );
    }
    assert_eq!(endpoints.asked(), ["/acme", "/globex"]);

    // Acme's SPIRE rotates its authority. Both are due, and the worker's
    // refresher, which finds due trust domains across tenants, fetches
    // each from its own tenant's endpoint and records it in that tenant.
    endpoints.serve("/acme", &bundle_numbered("acme-key-2", 2));
    sqlx::query("UPDATE keys.trust_domain SET next_refresh_at = now() - interval '1 second'")
        .execute(world.database.owner())
        .await
        .expect("due");
    let guarded = || {
        Arc::new(
            GuardedHttpClient::new(OutboundPolicy {
                development_hosts: vec![address.clone()],
                ..OutboundPolicy::default()
            })
            .expect("client"),
        )
    };
    let refresher = BundleRefresher::new(
        TrustDomainService::new(TrustDomainPorts {
            units_of_work: Arc::new(world.database.app().clone()),
            store: Arc::new(PgTrustDomainStore),
            destinations: guarded(),
            http: guarded(),
            digest: Arc::new(Sha256Digest),
            clock: Arc::new(SystemClock),
        }),
        Arc::new(PgDueRefreshes::new(world.database.platform().clone())),
    );
    let leases = refresher.lease_due(10).await.expect("leases");
    assert_eq!(leases.len(), 2);
    for lease in leases {
        refresher.refresh(lease).await.expect("a refresh");
    }
    let mut asked = endpoints.asked();
    asked.sort();
    assert_eq!(asked, ["/acme", "/globex"]);

    // Acme's bundle changed, Globex's did not, and neither holds the
    // other's keys.
    for (tenant, key, other) in [
        (acme, "acme-key-2", "globex-key"),
        (globex, "globex-key", "acme-key"),
    ] {
        let (_, listed) = world
            .admin(
                tenant,
                &tenant.administrator_token,
                Method::GET,
                "/trust-domains",
                None,
            )
            .await;
        let items = listed["items"].as_array().expect("items");
        assert_eq!(items.len(), 1, "{listed}");
        assert_eq!(items[0]["bundle"]["keys"][0]["kid"], key, "{listed}");
        assert!(items[0]["refresh"]["failing_since"].is_null(), "{listed}");
        assert!(!listed.to_string().contains(other), "{listed}");
    }

    // The refresh is in Acme's audit log alone.
    world.record_events().await;
    for (tenant, refreshed) in [(acme, true), (globex, false)] {
        let (_, log) = world
            .admin(
                tenant,
                &tenant.administrator_token,
                Method::GET,
                "/audit-records?limit=200",
                None,
            )
            .await;
        let log = log.to_string();
        assert!(log.contains("keys.trust_domain_added"), "{}", tenant.slug);
        assert_eq!(
            log.contains("keys.trust_bundle_refreshed"),
            refreshed,
            "{}",
            tenant.slug
        );
    }

    // When Acme's endpoint stops answering, Acme's fetch fails and keeps
    // its bundle; Globex's, due at the same time, reads.
    endpoints
        .bundles
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove("/acme");
    sqlx::query("UPDATE keys.trust_domain SET next_refresh_at = now() - interval '1 second'")
        .execute(world.database.owner())
        .await
        .expect("due");
    for lease in refresher.lease_due(10).await.expect("leases") {
        refresher.refresh(lease).await.expect("a refresh");
    }
    for (tenant, failing) in [(acme, true), (globex, false)] {
        let (_, listed) = world
            .admin(
                tenant,
                &tenant.administrator_token,
                Method::GET,
                "/trust-domains",
                None,
            )
            .await;
        let item = &listed["items"][0];
        assert_eq!(
            item["refresh"]["failing_since"].is_string(),
            failing,
            "{listed}"
        );
        assert!(item["bundle"]["keys"][0]["kid"].is_string(), "{listed}");
    }
}

#[tokio::test]
async fn one_authority_two_tenants_trust_proves_a_workload_to_the_tenant_its_jwt_svid_names_alone()
{
    const EXPORT: &str = "spiffe://cluster.local/ns/payroll/sa/export";
    let world = world_with(&[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    let (acme, globex) = (&world.acme, &world.globex);
    // One SPIRE, trusted by both tenants with the same bundle, and the
    // same identifier bound in each: only the audience tells them apart.
    let authority = SvidAuthority::new();
    let (acme_client, acme_issuer) = workload_bound_to(&world, acme, &authority, EXPORT).await;
    let (globex_client, globex_issuer) =
        workload_bound_to(&world, globex, &authority, EXPORT).await;

    // A JWT-SVID for Globex is refused by Acme, and that refusal does not
    // use it up: Globex then takes it.
    let for_globex = authority.svid(EXPORT, &globex_issuer, "one");
    let (status, body) = token_with_svid(&world, acme, &acme_client, &for_globex).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    let (status, body) = token_with_svid(&world, globex, &globex_client, &for_globex).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The other way round.
    let for_acme = authority.svid(EXPORT, &acme_issuer, "two");
    let (status, _) = token_with_svid(&world, globex, &globex_client, &for_acme).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = token_with_svid(&world, acme, &acme_client, &for_acme).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Used once, at its own tenant; and still refused by the other.
    let (status, _) = token_with_svid(&world, acme, &acme_client, &for_acme).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = token_with_svid(&world, globex, &globex_client, &for_acme).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A JWT-SVID for both issuers is for neither.
    let for_both = authority.svid_for(
        EXPORT,
        &serde_json::json!([acme_issuer, globex_issuer]),
        "three",
    );
    for (tenant, client) in [(acme, &acme_client), (globex, &globex_client)] {
        let (status, _) = token_with_svid(&world, tenant, client, &for_both).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", tenant.slug);
    }
}

/// A tenant's client of `spiffe_x509` bound to `identity`, asking for
/// certificate-bound tokens for the Authorization API, which the tenant
/// opens; its `cluster.local` is given by `trust`. Answers the client's
/// identifier.
async fn mesh_client(
    world: &World,
    tenant: &Tenant,
    identity: &str,
    trust: serde_json::Value,
) -> String {
    let token = &tenant.administrator_token;
    let (status, _) = world
        .admin(tenant, token, Method::POST, "/keys/sig:rotate", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, added) = world
        .admin(tenant, token, Method::POST, "/trust-domains", Some(trust))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{added}");
    let (_, application) = world
        .admin(
            tenant,
            token,
            Method::POST,
            "/applications",
            Some(serde_json::json!({ "name": "Authorization API", "first_party": true })),
        )
        .await;
    let (status, _) = world
        .admin(
            tenant,
            token,
            Method::POST,
            "/resource-servers",
            Some(serde_json::json!({
                "application_id": application["id"],
                "audience": "urn:hodor:authorization",
                "name": "Authorization API",
                "scopes": [{ "name": "authz:evaluate", "description": "Asks for decisions" }]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, account) = world
        .admin(
            tenant,
            token,
            Method::POST,
            "/service-accounts",
            Some(serde_json::json!({ "name": "Shop web", "owners": [tenant.ana] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{account}");
    let (status, client) = world
        .admin(
            tenant,
            token,
            Method::POST,
            &format!(
                "/applications/{}/clients",
                application["id"].as_str().expect("id")
            ),
            Some(serde_json::json!({
                "name": "Web",
                "type": "confidential",
                "authentication_method": "spiffe_x509",
                "spiffe_id": identity,
                "principal": account["id"],
                "grant_types": ["client_credentials"],
                "allowed_scopes": ["authz:evaluate"],
                "tls_client_certificate_bound_access_tokens": true,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{client}");
    client["id"].as_str().expect("id").to_owned()
}

/// What Istio's sidecar writes in front of Hodor for a caller whose
/// certificate names `identity` and has the SHA-256 `hash`: its names and
/// `Hash`, without the certificate.
fn sidecar_header(identity: &str, hash: &str) -> String {
    format!("By=spiffe://cluster.local/ns/hodor/sa/hodor;Hash={hash};Subject=\"\";URI={identity}")
}

/// A token request of `client` at `tenant` with its identifier alone and
/// the header a sidecar wrote.
async fn token_through_the_mesh(
    world: &World,
    tenant: &Tenant,
    client: &str,
    header: &str,
) -> (StatusCode, serde_json::Value) {
    let response = Client::new()
        .post(format!(
            "{}/t/{}/oauth2/token",
            world.server.base, tenant.slug
        ))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-forwarded-client-cert", header)
        .body(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("grant_type", "client_credentials"),
                    ("client_id", client),
                    ("resource", "urn:hodor:authorization"),
                    ("scope", "authz:evaluate"),
                ])
                .finish(),
        )
        .send()
        .await
        .expect("response");
    let status = response.status();
    (
        status,
        response.json().await.unwrap_or(serde_json::Value::Null),
    )
}

/// Asks a tenant's Authorization API with `token` and the header a sidecar
/// wrote.
async fn evaluated_through_the_mesh(
    world: &World,
    tenant: &Tenant,
    token: &str,
    header: &str,
) -> StatusCode {
    Client::new()
        .post(format!(
            "{}/t/{}/api/v1/authorization/evaluate",
            world.server.base, tenant.slug
        ))
        .bearer_auth(token)
        .header("x-forwarded-client-cert", header)
        .json(&serde_json::json!({
            "subject": { "type": "user", "id": tenant.ana.to_string() },
            "resource": { "type": "order", "id": "order-1" },
            "action": "read",
        }))
        .send()
        .await
        .expect("response")
        .status()
}

#[tokio::test]
async fn a_mesh_one_tenant_trusts_forwards_identities_and_binds_tokens_for_that_tenant_alone() {
    use base64::Engine as _;
    const WEB: &str = "spiffe://cluster.local/ns/shop/sa/web";
    const HASH: &str = "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4";
    const OTHER_HASH: &str = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
    let world = world_with(&[
        ("HODOR_SECRET_KEYS", ROOT_KEY),
        ("HODOR_TRUSTED_PROXIES", "127.0.0.1"),
        ("HODOR_FORWARDED_HEADER", "none"),
        ("HODOR_CLIENT_IDENTITY_HEADER", "x-forwarded-client-cert"),
    ])
    .await;
    let (acme, globex) = (&world.acme, &world.globex);
    // Acme trusts its mesh to check certificates; Globex trusts a
    // `cluster.local` of the same name by a bundle, and binds the same
    // identifier.
    let acme_client = mesh_client(
        &world,
        acme,
        WEB,
        serde_json::json!({ "name": "cluster.local", "source": "mesh" }),
    )
    .await;
    let globex_client = mesh_client(
        &world,
        globex,
        WEB,
        serde_json::json!({
            "name": "cluster.local", "source": "uploaded", "bundle": bundle_naming("globex-key"),
        }),
    )
    .await;
    let header = sidecar_header(WEB, HASH);

    // Acme takes the names its mesh forwards, and binds the token to the
    // certificate's hash.
    let (status, issued) = token_through_the_mesh(&world, acme, &acme_client, &header).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let token = issued["access_token"].as_str().expect("a token");
    let thumbprint = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        (0..HASH.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&HASH[at..at + 2], 16).expect("hexadecimal"))
            .collect::<Vec<_>>(),
    );
    assert_eq!(claims_of(token)["cnf"]["x5t#S256"], thumbprint);

    // Globex does not: its own `cluster.local` is not checked by a mesh,
    // so names forwarded without a certificate prove nothing there; and
    // Acme's client is unknown to it.
    for client in [&globex_client, &acme_client] {
        let (status, body) = token_through_the_mesh(&world, globex, client, &header).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"], "invalid_client");
    }

    // Acme's bound token is taken by Acme with the certificate it is bound
    // to, and refused by Acme with another; Globex refuses it with either.
    assert_ne!(
        evaluated_through_the_mesh(&world, acme, token, &header).await,
        StatusCode::UNAUTHORIZED
    );
    let other = sidecar_header(WEB, OTHER_HASH);
    assert_eq!(
        evaluated_through_the_mesh(&world, acme, token, &other).await,
        StatusCode::UNAUTHORIZED
    );
    for forwarded in [&header, &other] {
        assert_eq!(
            evaluated_through_the_mesh(&world, globex, token, forwarded).await,
            StatusCode::UNAUTHORIZED
        );
    }

    // Once Globex trusts its own mesh too, it takes its own client's
    // identity, and Acme's token is still refused there.
    let (_, listed) = world
        .admin(
            globex,
            &globex.administrator_token,
            Method::GET,
            "/trust-domains",
            None,
        )
        .await;
    let id = listed["items"][0]["id"].as_str().expect("id").to_owned();
    let (status, _) = world
        .admin(
            globex,
            &globex.administrator_token,
            Method::PUT,
            &format!("/trust-domains/{id}"),
            Some(serde_json::json!({ "source": "mesh" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = token_through_the_mesh(&world, globex, &globex_client, &header).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        evaluated_through_the_mesh(&world, globex, token, &header).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn one_tenants_certificate_authority_is_never_read_published_or_used_for_another() {
    let world = world_with(&[
        ("HODOR_SECRET_KEYS", ROOT_KEY),
        ("HODOR_CERTIFICATE_AUTHORITY", "development"),
    ])
    .await;
    let (acme, globex) = (&world.acme, &world.globex);
    let request = serde_json::json!({ "kind": "root", "trust_domains": ["cluster.local"] });
    let (status, created) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::POST,
            "/certificate-authority",
            Some(request.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let bundle = |tenant: &Tenant| {
        let url = format!(
            "{}/t/{}/certificate-authority/bundle",
            world.server.base, tenant.slug
        );
        async move {
            let response = Client::new().get(url).send().await.expect("response");
            let status = response.status();
            (
                status,
                response
                    .json::<serde_json::Value>()
                    .await
                    .unwrap_or_default(),
            )
        }
    };

    // Globex has none: not to read, publish, install or remove, with its
    // own administrator's token.
    let token = &globex.administrator_token;
    for (method, path) in [
        (Method::GET, "/certificate-authority"),
        (Method::DELETE, "/certificate-authority"),
    ] {
        let (status, body) = world.admin(globex, token, method.clone(), path, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(body["code"], "keys.authority_not_found", "{method} {path}");
    }
    let (status, body) = world
        .admin(
            globex,
            token,
            Method::POST,
            "/certificate-authority:install",
            Some(serde_json::json!({ "certificate": created["certificate"] })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "keys.authority_not_found");
    let (status, _) = bundle(globex).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, domains) = world
        .admin(globex, token, Method::GET, "/trust-domains", None)
        .await;
    assert_eq!(domains["items"], serde_json::json!([]));

    // Globex makes its own for a trust domain of the same name: another
    // key, another certificate, another bundle, and Acme's stays.
    let (status, theirs) = world
        .admin(
            globex,
            token,
            Method::POST,
            "/certificate-authority",
            Some(request),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{theirs}");
    assert_ne!(theirs["key"]["id"], created["key"]["id"]);
    assert_ne!(theirs["certificate"], created["certificate"]);
    let ((_, acme_bundle), (_, globex_bundle)) = (bundle(acme).await, bundle(globex).await);
    assert_ne!(acme_bundle, globex_bundle);
    let (_, read) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::GET,
            "/certificate-authority",
            None,
        )
        .await;
    assert_eq!(read, created);

    // Globex removes its own; Acme's is untouched.
    let (status, _) = world
        .admin(
            globex,
            token,
            Method::DELETE,
            "/certificate-authority",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, kept) = bundle(acme).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(kept, acme_bundle);
    let (_, domains) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::GET,
            "/trust-domains",
            None,
        )
        .await;
    assert_eq!(domains["items"][0]["name"], "cluster.local");
    assert_eq!(domains["items"][0]["bundle"], acme_bundle);
}

#[tokio::test]
async fn an_intermediate_of_one_tenants_authority_is_never_read_withdrawn_or_trusted_by_another() {
    use base64::Engine as _;
    use hodor_adapters_crypto::testing::certificates::{Leaf, MeshIntermediate, MeshRequest};
    let world = world_with(&[
        ("HODOR_SECRET_KEYS", ROOT_KEY),
        ("HODOR_CERTIFICATE_AUTHORITY", "development"),
        ("HODOR_TRUSTED_PROXIES", "127.0.0.1"),
        ("HODOR_FORWARDED_HEADER", "none"),
        ("HODOR_CLIENT_IDENTITY_HEADER", "client-cert"),
    ])
    .await;
    let (acme, globex) = (&world.acme, &world.globex);
    let identity = "spiffe://cluster.local/ns/shop/sa/web";
    // Each tenant has its own authority for a trust domain of the same
    // name, and a client bound to the same identifier.
    for tenant in [acme, globex] {
        let (status, created) = world
            .admin(
                tenant,
                &tenant.administrator_token,
                Method::POST,
                "/certificate-authority",
                Some(serde_json::json!({ "kind": "root", "trust_domains": ["cluster.local"] })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
    }
    let acme_client = workload_client_trusting(&world, acme, None, identity).await;
    let globex_client = workload_client_trusting(&world, globex, None, identity).await;

    // Acme's authority signs a mesh's intermediate.
    let mesh = MeshIntermediate::new(&MeshRequest::authority("istio-ca"));
    async fn sign(
        world: &World,
        tenant: &Tenant,
        request: &str,
    ) -> (StatusCode, serde_json::Value) {
        world
            .admin(
                tenant,
                &tenant.administrator_token,
                Method::POST,
                "/certificate-authority/intermediates",
                Some(serde_json::json!({ "certificate_signing_request": request })),
            )
            .await
    }
    let (status, signed) = sign(&world, acme, mesh.request()).await;
    assert_eq!(status, StatusCode::CREATED, "{signed}");
    let id = signed["id"].as_str().expect("id").to_owned();
    let der = |answer: &serde_json::Value| {
        let body: String = answer["certificate"]
            .as_str()
            .expect("PEM")
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .expect("base64")
    };
    let acme_intermediate = der(&signed);
    let workload = mesh.issue(&Leaf::uri(identity));

    // Trusted by Acme; never by Globex, whose authority of the same name
    // did not sign it.
    assert_eq!(
        token_with_chain(
            &world,
            acme,
            &acme_client,
            &workload,
            Some(&acme_intermediate)
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        token_with_chain(
            &world,
            globex,
            &globex_client,
            &workload,
            Some(&acme_intermediate)
        )
        .await,
        StatusCode::UNAUTHORIZED
    );

    // Globex neither reads, lists nor withdraws Acme's intermediate.
    let token = &globex.administrator_token;
    let path = format!("/certificate-authority/intermediates/{id}");
    let (status, body) = world.admin(globex, token, Method::GET, &path, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "keys.intermediate_not_found");
    let (status, body) = world
        .admin(
            globex,
            token,
            Method::POST,
            &format!("{path}:withdraw"),
            Some(serde_json::json!({ "reason": "not ours" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "keys.intermediate_not_found");
    let (_, listed) = world
        .admin(
            globex,
            token,
            Method::GET,
            "/certificate-authority/intermediates",
            None,
        )
        .await;
    assert_eq!(listed["items"], serde_json::json!([]));

    // Acme withdraws it: refused at Acme from the next request. The
    // withdrawal is Acme's alone: Globex signs the same key and trusts it.
    let (status, _) = world
        .admin(
            acme,
            &acme.administrator_token,
            Method::POST,
            &format!("{path}:withdraw"),
            Some(serde_json::json!({ "reason": "leaked" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        token_with_chain(
            &world,
            acme,
            &acme_client,
            &workload,
            Some(&acme_intermediate)
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    let (status, theirs) = sign(&world, globex, mesh.request()).await;
    assert_eq!(status, StatusCode::CREATED, "{theirs}");
    assert_eq!(
        token_with_chain(
            &world,
            globex,
            &globex_client,
            &workload,
            Some(&der(&theirs))
        )
        .await,
        StatusCode::OK
    );
    let (status, refused) = sign(&world, acme, mesh.request()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refused["code"], "keys.intermediate_key_withdrawn");
}
