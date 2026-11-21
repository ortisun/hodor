//! A person registers, signs in, forgets the password and recovers it, on
//! the real server binary over HTTP against a real database. The mailbox
//! is the message queue, read as the worker would read it.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgTenantDirectory, PgTenantRepository};
use hodor_kernel::{Caller, SystemClock};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Method, StatusCode};
use std::sync::Arc;

mod support;
use support::{Browser, start_server};

const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "a different long passphrase";

async fn create_tenant(database: &TestDatabase, slug: &str, open_registration: bool) {
    TenantService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        Arc::new(SystemClock),
    )
    .create(
        CreateTenant {
            slug: slug.to_owned(),
            display_name: "Acme".to_owned(),
            open_registration,
            system: false,
        },
        Caller::system(),
    )
    .await
    .expect("tenant");
}

/// The newest message waiting for an address: its template and, when it
/// has one, its link.
async fn newest_message(database: &TestDatabase, recipient: &str) -> (String, Option<String>) {
    sqlx::query_as(
        "SELECT template, variables->>'link' FROM notification.message
         WHERE recipient = $1 ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(recipient)
    .fetch_one(database.owner())
    .await
    .expect("a message for the address")
}

fn token_of(link: Option<String>) -> String {
    let link = link.expect("a link");
    link.split_once("#token=")
        .expect("token in the fragment")
        .1
        .to_owned()
}

async fn post(browser: &mut Browser, path: &str, body: serde_json::Value) -> StatusCode {
    browser
        .send(
            Method::POST,
            &format!("/t/acme/interaction/{path}"),
            Some(body),
        )
        .await
        .0
}

#[tokio::test]
async fn a_person_registers_signs_in_and_recovers_a_forgotten_password() {
    let database = TestDatabase::start().await;
    create_tenant(&database, "acme", true).await;
    let server = start_server(&database).await;
    let mut browser = Browser::new(&server);

    // Registering: ask, read the mailbox, finish.
    let asked = post(
        &mut browser,
        "registration",
        serde_json::json!({ "email": "ana@example.com", "locale": "pt-BR" }),
    )
    .await;
    assert_eq!(asked, StatusCode::ACCEPTED);
    let (template, link) = newest_message(&database, "ana@example.com").await;
    assert_eq!(template, "email_verification");
    assert!(
        link.as_deref()
            .is_some_and(|link| link.contains("/t/acme/account/complete-registration#token="))
    );
    let finished = post(
        &mut browser,
        "registration/complete",
        serde_json::json!({ "token": token_of(link), "password": PASSWORD, "display_name": "Ana" }),
    )
    .await;
    assert_eq!(finished, StatusCode::NO_CONTENT);

    // The person signs in with the password they chose.
    let (_, body) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(body["status"], "completed");
    let (status, _) = browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Registering the same address again answers the same and only tells
    // the mailbox.
    let again = post(
        &mut Browser::new(&server),
        "registration",
        serde_json::json!({ "email": "ana@example.com" }),
    )
    .await;
    assert_eq!(again, StatusCode::ACCEPTED);
    let (template, link) = newest_message(&database, "ana@example.com").await;
    assert_eq!((template.as_str(), link), ("already_registered", None));

    // Forgetting the password: ask, read the mailbox, choose a new one.
    let mut forgetful = Browser::new(&server);
    let asked = post(
        &mut forgetful,
        "recovery",
        serde_json::json!({ "email": "ana@example.com" }),
    )
    .await;
    assert_eq!(asked, StatusCode::ACCEPTED);
    let (template, link) = newest_message(&database, "ana@example.com").await;
    assert_eq!(template, "password_recovery");
    let reset = post(
        &mut forgetful,
        "recovery/complete",
        serde_json::json!({ "token": token_of(link), "password": NEW_PASSWORD }),
    )
    .await;
    assert_eq!(reset, StatusCode::NO_CONTENT);

    // The browser that was signed in no longer is; the old password no
    // longer works and the new one does.
    let (status, _) = browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, body) = Browser::new(&server)
        .sign_in("acme", "ana@example.com", PASSWORD)
        .await;
    assert_eq!(body["status"], "rejected");
    let (_, body) = Browser::new(&server)
        .sign_in("acme", "ana@example.com", NEW_PASSWORD)
        .await;
    assert_eq!(body["status"], "completed");
    let (template, _) = newest_message(&database, "ana@example.com").await;
    assert_eq!(template, "password_changed");

    // No password and no token is stored where it could be read back,
    // apart from the links in messages still waiting to be sent.
    let kept: String = sqlx::query_scalar(
        r#"SELECT concat(
               (SELECT string_agg(to_jsonb(t)::text, '') FROM authentication.verification_token t),
               (SELECT string_agg(to_jsonb(t)::text, '') FROM credential.password t),
               (SELECT string_agg(to_jsonb(t)::text, '') FROM platform.outbox t))"#,
    )
    .fetch_one(database.owner())
    .await
    .expect("dump");
    let links: Vec<String> = sqlx::query_scalar(
        "SELECT variables->>'link' FROM notification.message WHERE variables ? 'link'",
    )
    .fetch_all(database.owner())
    .await
    .expect("links");
    assert_eq!(links.len(), 2);
    for link in links {
        let token = token_of(Some(link));
        assert!(!kept.contains(&token), "a token is stored in the clear");
    }
    assert!(!kept.contains(PASSWORD) && !kept.contains(NEW_PASSWORD));
}

#[tokio::test]
async fn the_running_server_refuses_registration_where_it_is_closed() {
    let database = TestDatabase::start().await;
    create_tenant(&database, "acme", false).await;
    let server = start_server(&database).await;

    let (status, body) = Browser::new(&server)
        .send(
            Method::POST,
            "/t/acme/interaction/registration",
            Some(serde_json::json!({ "email": "ana@example.com" })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "authentication.registration_closed");
    let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM notification.message")
        .fetch_one(database.owner())
        .await
        .expect("count");
    assert_eq!(queued, 0);
}
