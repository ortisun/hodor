//! An application signs a person out of Hodor through the end-session
//! endpoint, at the real server binary against a real database: the
//! session ends, the person goes back only to an address the client
//! registered, and a request that does not prove the session asks first.

use hodor_adapters_crypto::{
    Argon2Parameters, Argon2idHasher, HashingLimits, LocalKeyProvider, OsRandom, SecretKeys,
    Sha256Digest,
};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgApplicationStore, PgClientStore, PgKeyStore, PgPasswordStore, PgResourceServerStore,
    PgTenantDirectory, PgTenantRepository, PgUserRepository,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, Secret, SystemClock, TenantContext};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, ClientId, ClientSettings,
    ClientType, CreateClient, GrantType, s256_challenge,
};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

mod support;
use support::{Browser, MEMORY_KIBIBYTES, PASSES, Server, start_server_with};

const PASSWORD: &str = "correct horse battery staple";
const REDIRECT: &str = "https://payroll.example.com/callback";
const OUT: &str = "https://payroll.example.com/signed-out";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";

/// A tenant with Ana, who has a password, an active signing key, and a
/// public client of a first-party application that may send people back
/// to `OUT` after they sign out.
async fn tenant(database: &TestDatabase, slug: &str) -> ClientId {
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
            open_registration: false,
            system: false,
        },
        Caller::system(),
    )
    .await
    .expect("tenant");
    let context = TenantContext::assume(created.id());
    let ana = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
        .create(
            &context,
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
            password: &Secret::from(PASSWORD.to_owned()),
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
    let root = Arc::new(SecretKeys::parse(&Secret::from(ROOT_KEY.to_owned())).expect("root"));
    KeyService::new(
        units(),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root)),
        clock.clone(),
    )
    .rotate_now(
        &context,
        KeyAlgorithm::Es256,
        &RotationPolicy::DEFAULT,
        Caller::system(),
    )
    .await
    .expect("a signing key");

    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: units(),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock,
    });
    let application = applications
        .create_application(
            &context,
            ApplicationSettings {
                name: "Payroll".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    let mut settings = ClientSettings::new(
        "Payroll",
        ClientType::Public,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.post_logout_redirect_uris = vec![OUT.to_owned()];
    settings.allowed_scopes = vec!["openid".to_owned()];
    let (client, _) = applications
        .create_client(
            &context,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Public,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    client.id()
}

async fn server(database: &TestDatabase) -> Server {
    start_server_with(database, &[("HODOR_SECRET_KEYS", ROOT_KEY)]).await
}

fn query(pairs: &[(&str, &str)]) -> String {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

fn query_of(location: &str) -> BTreeMap<String, String> {
    let (_, query) = location.split_once('?').unwrap_or((location, ""));
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

/// Signs Ana in and gets an ID token for `client_id` from her session.
async fn signed_in(
    browser: &mut Browser,
    server: &Server,
    slug: &str,
    client_id: ClientId,
) -> String {
    let (_, answer) = browser.sign_in(slug, "ana@example.com", PASSWORD).await;
    assert_eq!(answer["status"], "completed", "{answer}");
    let id = client_id.to_string();
    let challenge = s256_challenge(VERIFIER, &Sha256Digest);
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/{slug}/oauth2/authorize?{}",
                query(&[
                    ("response_type", "code"),
                    ("client_id", &id),
                    ("redirect_uri", REDIRECT),
                    ("scope", "openid"),
                    ("code_challenge", &challenge),
                    ("code_challenge_method", "S256"),
                ])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    let code = query_of(&location.expect("a redirect"))["code"].clone();
    let tokens: Value = reqwest::Client::new()
        .post(format!("{}/t/{slug}/oauth2/token", server.base))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(query(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("client_id", &id),
        ]))
        .send()
        .await
        .expect("response")
        .json()
        .await
        .expect("JSON");
    tokens["id_token"].as_str().expect("an ID token").to_owned()
}

async fn still_signed_in(browser: &mut Browser, slug: &str) -> bool {
    let (status, _) = browser
        .send(Method::GET, &format!("/t/{slug}/interaction/session"), None)
        .await;
    status == StatusCode::OK
}

#[tokio::test]
async fn an_application_signs_the_person_out_and_gets_them_back() {
    let database = TestDatabase::start().await;
    let client_id = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    let hint = signed_in(&mut browser, &server, "acme", client_id).await;
    assert!(still_signed_in(&mut browser, "acme").await);

    let response = browser
        .client
        .get(format!(
            "{}/t/acme/oauth2/logout?{}",
            server.base,
            query(&[
                ("id_token_hint", &hint),
                ("post_logout_redirect_uri", OUT),
                ("state", "af0ifjsldkj"),
            ])
        ))
        .header(
            "cookie",
            browser
                .cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.headers()["location"],
        format!("{OUT}?state=af0ifjsldkj"),
        "back to the application, with its state"
    );
    let forgets_the_session = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|cookie| {
            cookie.starts_with("__Secure-hodor_session=;") && cookie.contains("Max-Age=0")
        });
    assert!(
        forgets_the_session,
        "the browser is told to forget the session"
    );

    // The session ended on the server, so a copy of its cookie is refused.
    assert!(
        !still_signed_in(&mut browser, "acme").await,
        "the session ended"
    );

    // Signing out again with the same hint: nobody to sign out, so straight
    // back.
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/logout?{}",
                query(&[("id_token_hint", &hint), ("post_logout_redirect_uri", OUT)])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location.as_deref(), Some(OUT));

    // Without a return address, to Hodor's sign-in page, which says so.
    let (status, location, _) = browser
        .navigate(Method::GET, "/t/acme/oauth2/logout", None)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location.as_deref(),
        Some("/t/acme/account/sign-in?notice=signed-out")
    );
}

#[tokio::test]
async fn a_request_that_does_not_prove_the_session_asks_first() {
    let database = TestDatabase::start().await;
    let client_id = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    signed_in(&mut browser, &server, "acme", client_id).await;
    let id = client_id.to_string();

    // By client_id alone: the person is asked, in the languages asked for.
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/logout?{}",
                query(&[
                    ("client_id", &id),
                    ("post_logout_redirect_uri", OUT),
                    ("state", "s1"),
                    ("ui_locales", "pt-BR"),
                ])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location.as_deref(),
        Some("/t/acme/account/sign-out?ui_locales=pt-BR")
    );
    assert!(browser.cookies.contains_key("__Secure-hodor_logout"));
    assert!(
        still_signed_in(&mut browser, "acme").await,
        "nothing ends before the person says so"
    );

    // The person chose to stay: the finish sends them to their account.
    let (status, location, _) = browser
        .navigate(Method::GET, "/t/acme/oauth2/logout/finish", None)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location.as_deref(), Some("/t/acme/account"));
    assert!(!browser.cookies.contains_key("__Secure-hodor_logout"));
    assert!(still_signed_in(&mut browser, "acme").await);

    // Asked again; this time the page signs out, then finishes.
    browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/logout?{}",
                query(&[
                    ("client_id", &id),
                    ("post_logout_redirect_uri", OUT),
                    ("state", "s2"),
                ])
            ),
            None,
        )
        .await;
    let (status, _) = browser
        .send(Method::DELETE, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, location, _) = browser
        .navigate(Method::GET, "/t/acme/oauth2/logout/finish", None)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location.as_deref(),
        Some(format!("{OUT}?state=s2").as_str())
    );

    // A form always asks, even with a hint that names the session: a form
    // another site posts carries no session cookie.
    let hint = signed_in(&mut browser, &server, "acme", client_id).await;
    let (status, location, _) = browser
        .navigate(
            Method::POST,
            "/t/acme/oauth2/logout",
            Some(&query(&[("id_token_hint", &hint)])),
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location.as_deref(), Some("/t/acme/account/sign-out"));
    assert!(still_signed_in(&mut browser, "acme").await);

    // The hint of an older session asks too.
    let older = hint;
    let (_, signed_again) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(signed_again["status"], "completed");
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/logout?{}",
                query(&[("id_token_hint", &older)])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location.as_deref(), Some("/t/acme/account/sign-out"));
    assert!(still_signed_in(&mut browser, "acme").await);
}

#[tokio::test]
async fn a_request_that_cannot_be_trusted_is_answered_with_hodors_own_page() {
    let database = TestDatabase::start().await;
    let acme_client = tenant(&database, "acme").await;
    let globex_client = tenant(&database, "globex").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    let acme_hint = signed_in(&mut browser, &server, "acme", acme_client).await;
    let acme = acme_client.to_string();
    let globex = globex_client.to_string();

    let cases: Vec<(&str, String, &str)> = vec![
        (
            "an address the client did not register",
            query(&[
                ("client_id", &acme),
                ("post_logout_redirect_uri", "https://evil.example.com/"),
            ]),
            "oauth.logout_redirect_uri_unregistered",
        ),
        (
            "the client's redirect address is not a post-logout one",
            query(&[("client_id", &acme), ("post_logout_redirect_uri", REDIRECT)]),
            "oauth.logout_redirect_uri_unregistered",
        ),
        (
            "an address without a client",
            query(&[("post_logout_redirect_uri", OUT)]),
            "oauth.logout_client_unknown",
        ),
        (
            "a client of another tenant",
            query(&[("client_id", &globex), ("post_logout_redirect_uri", OUT)]),
            "oauth.logout_client_unknown",
        ),
        (
            "a client other than the hint's",
            query(&[("id_token_hint", &acme_hint), ("client_id", &globex)]),
            "oauth.logout_client_mismatch",
        ),
        (
            "a hint that is not an ID token",
            query(&[("id_token_hint", "a.b.c")]),
            "oauth.logout_id_token_hint_invalid",
        ),
        (
            "a parameter given twice",
            format!("{}&state=b", query(&[("state", "a")])),
            "oauth.logout_request_invalid",
        ),
    ];
    for (name, request, code) in cases {
        let (status, location, body) = browser
            .navigate(
                Method::GET,
                &format!("/t/acme/oauth2/logout?{request}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(location, None, "{name}: never redirected");
        assert!(body.contains(code), "{name}: {body}");
    }

    // An ID token of Acme names no session of Globex: at Globex it is not
    // one of the tenant's ID tokens.
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/globex/oauth2/logout?{}",
                query(&[
                    ("id_token_hint", &acme_hint),
                    ("post_logout_redirect_uri", OUT)
                ])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(location, None);
    assert!(
        body.contains("oauth.logout_id_token_hint_invalid"),
        "{body}"
    );
    assert!(
        still_signed_in(&mut browser, "acme").await,
        "nothing refused ends anything"
    );
}
