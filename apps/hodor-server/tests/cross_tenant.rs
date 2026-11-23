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
    OutboxDispatcher, PgAccessTokenStore, PgAuditLog, PgPasswordStore, PgRoleAssignmentStore,
    PgTenantDirectory, PgTenantRepository, PgUserRepository,
};
use hodor_audit::api::{AuditHandler, AuditService};
use hodor_authorization::api::{AuthorizationService, Role};
use hodor_credential::api::{AccessTokenService, CredentialService, NewPassword, PasswordRules};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, Secret, SystemClock, TenantContext, UserId};
use hodor_tenant::api::{CreateTenant, TenantService};
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
    let world = world().await;
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
                .replace("{secret_id}", &globex.ana.to_string())
                .replace("{key_id}", "a-key")
                .replace("{resource_server_id}", &globex.ana.to_string())
                .replace("{permission}", "document:read")
                .replace("{role}", "editor")
                .replace("{number}", "1")
                .replace("{simulation_id}", &globex.ana.to_string());
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
    assert_eq!(tried, 71, "every documented operation was tried");

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
                first_party: false,
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
