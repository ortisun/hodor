//! A person signs in to the real server binary with a code and then with
//! a link sent by email, against a real database; each is refused the
//! second time, and a link opened in another browser signs nobody in.

use hodor_adapters_crypto::{Argon2Parameters, Argon2idHasher, HashingLimits, OsRandom};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgPasswordStore, PgTenantDirectory, PgTenantRepository, PgUserRepository,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, Secret, SystemClock, TenantContext, UserId};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Method, StatusCode};
use std::sync::Arc;

mod support;
use support::{Browser, MEMORY_KIBIBYTES, PASSES, Server, start_server};

const ANA: &str = "ana@example.com";
const PASSWORD: &str = "correct horse battery staple";

/// A tenant that offers both ways of signing in by email, with one person
/// who also has a password.
async fn tenant_with_ana(database: &TestDatabase, slug: &str) -> (TenantContext, UserId) {
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
    let mut settings = created.snapshot().settings.clone();
    settings.authentication.email_sign_in.code = true;
    settings.authentication.email_sign_in.link = true;
    tenants
        .change_settings(&tenant, settings, Caller::system())
        .await
        .expect("settings");
    let ana = identity
        .create(
            &tenant,
            CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, ANA.to_owned())],
                profile: Profile::default(),
                confirmed: true,
            },
            Caller::system(),
        )
        .await
        .expect("user")
        .id();
    let password = Secret::from(PASSWORD.to_owned());
    credentials
        .set_password(
            &tenant,
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
    (tenant, ana)
}

/// What the newest message of the tenant that has `variable` carries, as
/// the person would read it in their mailbox.
async fn newest(database: &TestDatabase, tenant: &TenantContext, variable: &str) -> String {
    sqlx::query_scalar(
        "SELECT variables->>$2 FROM notification.message
         WHERE tenant_id = $1 AND variables ? $2
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(tenant.tenant_id().as_uuid())
    .bind(variable)
    .fetch_one(database.owner())
    .await
    .expect("a message")
}

/// A browser that started a sign-in at Acme and asked for `step`.
async fn asked(server: &Server, step: &str) -> Browser {
    let mut browser = Browser::new(server);
    let (status, _) = browser
        .send(Method::POST, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = browser
        .send(
            Method::POST,
            &format!("/t/acme/interaction/sign-in/steps/{step}/send"),
            Some(serde_json::json!({ "email": ANA })),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    browser
}

async fn present(
    browser: &mut Browser,
    step: &str,
    field: &str,
    value: &str,
) -> (StatusCode, serde_json::Value) {
    browser
        .send(
            Method::POST,
            &format!("/t/acme/interaction/sign-in/steps/{step}"),
            Some(serde_json::json!({ field: value })),
        )
        .await
}

#[tokio::test]
async fn a_person_signs_in_with_a_code_then_with_a_link_and_each_is_refused_the_second_time() {
    let database = TestDatabase::start().await;
    let (tenant, ana) = tenant_with_ana(&database, "acme").await;
    let server = start_server(&database).await;

    let mut lookout = Browser::new(&server);
    let (_, offered) = lookout
        .send(
            Method::GET,
            "/t/acme/interaction/sign-in/alternatives",
            None,
        )
        .await;
    assert_eq!(
        offered["alternatives"],
        serde_json::json!(["passkey", "email_code", "email_link"])
    );

    // A code.
    let mut browser = asked(&server, "email_code").await;
    let code = newest(&database, &tenant, "code").await;
    let (status, body) = present(&mut browser, "email_code", "code", &code).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "completed", "{body}");
    let (_, who) = browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(who["user_id"], ana.to_string());
    assert_eq!(who["methods"], serde_json::json!(["email_code"]));
    // The second time: the browser's sign-in is over, and another sign-in
    // never asked for it.
    let (status, _) = present(&mut browser, "email_code", "code", &code).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let mut again = Browser::new(&server);
    again
        .send(Method::POST, "/t/acme/interaction/sign-in", None)
        .await;
    let (_, body) = present(&mut again, "email_code", "code", &code).await;
    assert_eq!(body["status"], "rejected");

    // A link.
    let mut browser = asked(&server, "email_link").await;
    let link = newest(&database, &tenant, "link").await;
    let (page, token) = link.split_once("#token=").expect("a token");
    assert!(page.ends_with("/t/acme/account/sign-in-link"), "{page}");
    let (_, body) = present(&mut browser, "email_link", "token", token).await;
    assert_eq!(body["status"], "completed", "{body}");
    let (_, who) = browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(who["methods"], serde_json::json!(["email_link"]));
    let (status, _) = present(&mut browser, "email_link", "token", token).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Nothing of the code, the link or the address is in the events.
    let carried: Vec<String> =
        sqlx::query_scalar("SELECT payload::text FROM platform.outbox WHERE tenant_id = $1")
            .bind(tenant.tenant_id().as_uuid())
            .fetch_all(database.owner())
            .await
            .expect("events");
    assert!(carried.iter().all(|payload| !payload.contains(&code)
        && !payload.contains(token)
        && !payload.contains(ANA)));
    let sent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM platform.outbox
         WHERE tenant_id = $1 AND event_type = 'authentication.email_sign_in_sent'",
    )
    .bind(tenant.tenant_id().as_uuid())
    .fetch_one(database.owner())
    .await
    .expect("events");
    assert_eq!(sent, 2);
}

#[tokio::test]
async fn a_link_opened_in_another_browser_does_not_sign_that_browser_in() {
    let database = TestDatabase::start().await;
    let (tenant, _) = tenant_with_ana(&database, "acme").await;
    let server = start_server(&database).await;
    let mut asking = asked(&server, "email_link").await;
    let link = newest(&database, &tenant, "link").await;
    let token = link.split_once("#token=").expect("a token").1.to_owned();

    // The page of the link, in a browser with no sign-in, finds none and
    // sends nothing; were it sent, it would be refused all the same.
    let mut elsewhere = Browser::new(&server);
    let (status, body) = elsewhere
        .send(Method::GET, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "authentication.transaction_not_found");
    let (status, _) = present(&mut elsewhere, "email_link", "token", &token).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A browser in the middle of a sign-in of its own is rejected.
    elsewhere
        .send(Method::POST, "/t/acme/interaction/sign-in", None)
        .await;
    let (_, body) = present(&mut elsewhere, "email_link", "token", &token).await;
    assert_eq!(body["status"], "rejected");
    assert!(!elsewhere.cookies.contains_key("__Secure-hodor_session"));

    // The browser that asked reads its sign-in, as the page does, and
    // finishes it.
    let (status, body) = asking
        .send(Method::GET, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["step"], "identifier");
    let (_, body) = present(&mut asking, "email_link", "token", &token).await;
    assert_eq!(body["status"], "completed", "{body}");
    assert!(asking.cookies.contains_key("__Secure-hodor_session"));
}

#[tokio::test]
async fn asking_answers_the_same_and_wrong_codes_lock_the_password_out_too() {
    let database = TestDatabase::start().await;
    let (tenant, _) = tenant_with_ana(&database, "acme").await;
    let server = start_server(&database).await;

    let mut answers = Vec::new();
    for address in [ANA, "nobody@example.com", "not an address"] {
        let mut browser = Browser::new(&server);
        browser
            .send(Method::POST, "/t/acme/interaction/sign-in", None)
            .await;
        answers.push(
            browser
                .send(
                    Method::POST,
                    "/t/acme/interaction/sign-in/steps/email_code/send",
                    Some(serde_json::json!({ "email": address })),
                )
                .await,
        );
    }
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "{answers:?}"
    );
    let messages: i64 =
        sqlx::query_scalar("SELECT count(*) FROM notification.message WHERE tenant_id = $1")
            .bind(tenant.tenant_id().as_uuid())
            .fetch_one(database.owner())
            .await
            .expect("messages");
    assert_eq!(messages, 1, "only the person's address gets a message");

    // Five wrong codes for Ana's address, in two sign-ins.
    let code = newest(&database, &tenant, "code").await;
    let wrong = if code == "000000" { "000001" } else { "000000" };
    for tries in [4, 1] {
        let mut browser = asked(&server, "email_code").await;
        for _ in 0..tries {
            let (_, body) = present(&mut browser, "email_code", "code", wrong).await;
            assert_eq!(body["status"], "rejected", "{body}");
        }
    }
    let mut browser = Browser::new(&server);
    let (status, body) = browser.sign_in("acme", ANA, PASSWORD).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["code"], "authentication.too_many_attempts");
}
