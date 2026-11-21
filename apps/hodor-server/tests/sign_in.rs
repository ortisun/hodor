//! A person signs in to the real server binary over HTTP, against a real
//! database. Nothing is faked.

use hodor_adapters_crypto::{Argon2Parameters, Argon2idHasher, HashingLimits, OsRandom};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgPasswordStore, PgTenantDirectory, PgTenantRepository, PgUserRepository,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, Secret, SystemClock, TenantContext, UserId};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::header::COOKIE;
use reqwest::{Method, StatusCode};
use std::sync::Arc;

mod support;
use support::{Browser, MEMORY_KIBIBYTES, PASSES, start_server};

const PASSWORD: &str = "correct horse battery staple";
/// Creates a tenant with one confirmed person who has a password, the way
/// registration will once it exists.
async fn tenant_with_ana(database: &TestDatabase, slug: &str) -> UserId {
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(SystemClock);
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        clock.clone(),
    );
    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone());
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
    let credentials =
        CredentialService::new(units(), Arc::new(PgPasswordStore), Arc::new(hasher), clock);

    let created = tenants
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
    let tenant = TenantContext::assume(created.id());
    let ana = identity
        .create(
            &tenant,
            CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, "ana@example.com".to_owned())],
                profile: Profile::default(),
                confirmed: true,
            },
            Caller::system(),
        )
        .await
        .expect("user")
        .id();
    let password = Secret::from(PASSWORD.to_owned());
    let new = NewPassword {
        password: &password,
        rules: PasswordRules {
            min_length: 12,
            max_length: 128,
            history_depth: 5,
        },
        own_names: &[],
    };
    credentials
        .set_password(&tenant, ana, new, false, Caller::system())
        .await
        .expect("password");
    ana
}

#[tokio::test]
async fn a_person_signs_in_to_the_running_server() {
    let database = TestDatabase::start().await;
    let ana = tenant_with_ana(&database, "acme").await;
    let other_ana = tenant_with_ana(&database, "globex").await;
    let server = start_server(&database).await;
    let mut browser = Browser::new(&server);

    // Nobody is signed in to begin with.
    let (status, body) = browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("session.not_authenticated"))
    );

    // A wrong password first: a normal answer, and no session.
    let (status, body) = browser
        .sign_in("acme", "ana@example.com", "not the password")
        .await;
    assert_eq!(
        (status, body["status"].as_str()),
        (StatusCode::OK, Some("rejected"))
    );
    assert!(!browser.cookies.contains_key("__Secure-hodor_session"));

    // The same sign-in continues with the right one.
    let (status, body) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/sign-in/steps/password",
            Some(serde_json::json!({ "password": PASSWORD })),
        )
        .await;
    assert_eq!(
        (status, body["status"].as_str()),
        (StatusCode::OK, Some("completed"))
    );
    assert!(
        !browser.cookies.contains_key("__Secure-hodor_signin"),
        "the sign-in cookie is gone"
    );

    // The browser is signed in to this tenant as Ana...
    let (status, body) = browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"], ana.to_string());
    assert_eq!(body["methods"], serde_json::json!(["password"]));

    // ...and to no other tenant, even one with a person of the same email
    // address and password.
    let (status, _) = browser
        .send(Method::GET, "/t/globex/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let mut elsewhere = Browser::new(&server);
    let (_, body) = elsewhere
        .sign_in("globex", "ana@example.com", PASSWORD)
        .await;
    assert_eq!(body["status"], "completed");
    let (_, body) = elsewhere
        .send(Method::GET, "/t/globex/interaction/session", None)
        .await;
    assert_eq!(body["user_id"], other_ana.to_string());
    assert_ne!(ana, other_ana, "two tenants, two different people");

    // The session token is in the browser and nowhere in the database.
    let token = &browser.cookies["__Secure-hodor_session"];
    let everything: String = sqlx::query_scalar(
        r#"SELECT concat(
               (SELECT string_agg(to_jsonb(t)::text, '') FROM session.session t),
               (SELECT string_agg(to_jsonb(t)::text, '') FROM authentication.transaction t),
               (SELECT string_agg(to_jsonb(t)::text, '') FROM platform.outbox t))"#,
    )
    .fetch_one(database.owner())
    .await
    .expect("dump");
    assert!(!everything.contains(token.as_str()));
    assert!(!everything.contains(PASSWORD));
}

#[tokio::test]
async fn the_running_server_refuses_forged_and_excessive_requests() {
    let database = TestDatabase::start().await;
    tenant_with_ana(&database, "acme").await;
    let server = start_server(&database).await;

    // Without the CSRF token a step is refused.
    let mut browser = Browser::new(&server);
    browser
        .send(Method::POST, "/t/acme/interaction/sign-in", None)
        .await;
    browser.csrf_token = None;
    let (status, body) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/sign-in/steps/identifier",
            Some(serde_json::json!({ "identifier": "ana@example.com" })),
        )
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("request.csrf_token_invalid"))
    );

    // After five wrong passwords the sixth attempt is limited, with the
    // time to wait, even though the password is right.
    for _ in 0..5 {
        let (_, body) = Browser::new(&server)
            .sign_in("acme", "ana@example.com", "a wrong guess")
            .await;
        assert_eq!(body["status"], "rejected");
    }
    let mut limited = Browser::new(&server);
    let base = "/t/acme/interaction/sign-in";
    limited.send(Method::POST, base, None).await;
    limited
        .send(
            Method::POST,
            &format!("{base}/steps/identifier"),
            Some(serde_json::json!({ "identifier": "ana@example.com" })),
        )
        .await;
    let response = limited
        .client
        .post(format!("{}{base}/steps/password", server.base))
        .header(
            COOKIE,
            format!(
                "__Secure-hodor_signin={}",
                limited.cookies["__Secure-hodor_signin"]
            ),
        )
        .header("x-csrf-token", limited.csrf_token.clone().expect("token"))
        .json(&serde_json::json!({ "password": PASSWORD }))
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let wait: u64 = response.headers()["retry-after"]
        .to_str()
        .expect("ascii")
        .parse()
        .expect("seconds");
    assert!((1..=60).contains(&wait), "{wait}");
}
