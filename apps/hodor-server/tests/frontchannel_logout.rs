//! Front-channel logout at the real server binary against a real database:
//! a person signed in to two applications, one of them pairwise, signs
//! out, and the signed-out page is given a frame for each, with the `iss`
//! and `sid` each knows, and a policy that allows those sites alone. A
//! session ended without the browser makes no frame.

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
use hodor_kernel::{Caller, Secret, SystemClock, TenantContext, TenantId};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, ClientId, ClientSettings,
    ClientType, CreateClient, GrantType, SubjectType, s256_challenge,
};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

mod support;
use support::{Browser, MEMORY_KIBIBYTES, PASSES, Server, start_server_with};

const PASSWORD: &str = "correct horse battery staple";
const PAYROLL: &str = "https://payroll.example.com/callback";
const REPORTS: &str = "https://reports.example.com/callback";
const OUT: &str = "https://payroll.example.com/signed-out";
const PAYROLL_FRAME: &str = "https://payroll.example.com/frontchannel-logout";
const REPORTS_FRAME: &str = "https://reports.example.com/logout?from=hodor";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const INDEX: &str = "<!doctype html><title>the hosted pages</title>";
/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";

/// A directory in the shape the build of the pages leaves, removed when
/// the test ends.
struct Built(PathBuf);

impl Built {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("hodor-signed-out-{}", TenantId::generate()));
        std::fs::create_dir_all(directory.join("assets")).expect("directory");
        std::fs::write(directory.join("index.html"), INDEX).expect("index");
        Self(directory)
    }

    fn path(&self) -> &str {
        self.0.to_str().expect("a UTF-8 path")
    }
}

impl Drop for Built {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The three clients of the tenant.
struct Clients {
    /// Public subjects, with a front-channel logout address and a return
    /// address.
    payroll: ClientId,
    /// Pairwise, with a front-channel logout address that has a query.
    reports: ClientId,
    /// No front-channel logout address.
    billing: ClientId,
}

/// A tenant with Ana, who has a password, an active signing key, and three
/// public clients of first-party applications.
async fn tenant(database: &TestDatabase, slug: &str) -> (TenantContext, Clients) {
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
    let mut made = Vec::new();
    for (name, redirect, frame, subject_type) in [
        ("Payroll", PAYROLL, Some(PAYROLL_FRAME), SubjectType::Public),
        (
            "Reports",
            REPORTS,
            Some(REPORTS_FRAME),
            SubjectType::Pairwise,
        ),
        (
            "Billing",
            "https://billing.example.com/callback",
            None,
            SubjectType::Public,
        ),
    ] {
        let application = applications
            .create_application(
                &context,
                ApplicationSettings {
                    name: name.to_owned(),
                    first_party: true,
                },
                Caller::system(),
            )
            .await
            .expect("application");
        let mut settings = ClientSettings::new(
            name,
            ClientType::Public,
            vec![GrantType::AuthorizationCode],
            vec![redirect.to_owned()],
        );
        if name == "Payroll" {
            settings.post_logout_redirect_uris = vec![OUT.to_owned()];
        }
        settings.allowed_scopes = vec!["openid".to_owned()];
        settings.frontchannel_logout_uri = frame.map(str::to_owned);
        settings.frontchannel_logout_session_required = frame.is_some();
        settings.subject_type = subject_type;
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
        made.push(client.id());
    }
    (
        context,
        Clients {
            payroll: made[0],
            reports: made[1],
            billing: made[2],
        },
    )
}

async fn server(database: &TestDatabase, pages: &Built) -> Server {
    start_server_with(
        database,
        &[
            ("HODOR_SECRET_KEYS", ROOT_KEY),
            ("HODOR_PAGES_DIRECTORY", pages.path()),
        ],
    )
    .await
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

fn claims_of(token: &str) -> Value {
    use base64::Engine as _;
    let payload = token.split('.').nth(1).expect("claims");
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url"),
    )
    .expect("JSON")
}

/// Gets an ID token for `client_id`, at `redirect`, from the session the
/// browser holds, and answers its claims and the token.
async fn id_token(
    browser: &mut Browser,
    server: &Server,
    client_id: ClientId,
    redirect: &str,
) -> (Value, String) {
    let id = client_id.to_string();
    let challenge = s256_challenge(VERIFIER, &Sha256Digest);
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/authorize?{}",
                query(&[
                    ("response_type", "code"),
                    ("client_id", &id),
                    ("redirect_uri", redirect),
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
        .post(format!("{}/t/acme/oauth2/token", server.base))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(query(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect),
            ("code_verifier", VERIFIER),
            ("client_id", &id),
        ]))
        .send()
        .await
        .expect("response")
        .json()
        .await
        .expect("JSON");
    let token = tokens["id_token"].as_str().expect("an ID token").to_owned();
    (claims_of(&token), token)
}

/// Signs Ana in to all three clients in one session.
async fn signed_in_everywhere(
    browser: &mut Browser,
    server: &Server,
    clients: &Clients,
) -> (Value, String, Value) {
    let (_, answer) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(answer["status"], "completed", "{answer}");
    // As the pages do, for the session's CSRF token.
    let (status, _) = browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (payroll, hint) = id_token(browser, server, clients.payroll, PAYROLL).await;
    let (reports, _) = id_token(browser, server, clients.reports, REPORTS).await;
    id_token(
        browser,
        server,
        clients.billing,
        "https://billing.example.com/callback",
    )
    .await;
    (payroll, hint, reports)
}

/// The frames the signed-out page is given, and the policy it is sent
/// with, for the cookies the browser holds.
async fn signed_out_page(browser: &mut Browser, server: &Server) -> (Vec<String>, String) {
    let cookies = browser
        .cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    let page = reqwest::Client::new()
        .get(format!("{}/t/acme/account/signed-out", server.base))
        .header("cookie", &cookies)
        .send()
        .await
        .expect("page");
    assert_eq!(page.status(), StatusCode::OK);
    let policy = page.headers()["content-security-policy"]
        .to_str()
        .expect("policy")
        .to_owned();
    assert_eq!(page.headers()["cache-control"], "no-store");
    assert_eq!(page.text().await.expect("body"), INDEX);
    let (status, body) = browser
        .send(Method::GET, "/t/acme/interaction/signed-out", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let frames = body["frames"]
        .as_array()
        .expect("frames")
        .iter()
        .map(|frame| frame.as_str().expect("an address").to_owned())
        .collect();
    (frames, policy)
}

/// The value of one directive of a policy.
fn directive<'a>(policy: &'a str, name: &str) -> Option<&'a str> {
    policy
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(name).map(str::trim))
}

#[tokio::test]
async fn signing_out_of_two_applications_frames_both_with_the_iss_and_sid_each_knows() {
    let database = TestDatabase::start().await;
    let (_, clients) = tenant(&database, "acme").await;
    let pages = Built::new();
    let server = server(&database, &pages).await;
    let mut browser = Browser::not_following(&server);
    let (payroll, hint, reports) = signed_in_everywhere(&mut browser, &server, &clients).await;
    assert_ne!(
        payroll["sid"], reports["sid"],
        "the pairwise client knows the session by an identifier of its own"
    );

    // The application signs the person out with a hint that proves the
    // session: it ends at once, and the browser goes to the signed-out page
    // before it goes back.
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/logout?{}",
                query(&[
                    ("id_token_hint", &hint),
                    ("post_logout_redirect_uri", OUT),
                    ("state", "af0ifjsldkj"),
                    ("ui_locales", "pt-BR"),
                ])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location.as_deref(),
        Some("/t/acme/account/signed-out?continue=logout&ui_locales=pt-BR")
    );
    assert!(browser.cookies.contains_key("__Secure-hodor_signed_out"));
    assert!(browser.cookies.contains_key("__Secure-hodor_logout"));
    assert!(!browser.cookies.contains_key("__Secure-hodor_session"));

    let (frames, policy) = signed_out_page(&mut browser, &server).await;
    assert_eq!(frames.len(), 2, "billing has no address: {frames:?}");
    for (frame, address, claims) in [
        (
            frames.iter().find(|f| f.starts_with(PAYROLL_FRAME)),
            PAYROLL_FRAME,
            &payroll,
        ),
        (
            frames.iter().find(|f| f.starts_with(REPORTS_FRAME)),
            REPORTS_FRAME,
            &reports,
        ),
    ] {
        let frame = frame.expect("a frame for each application");
        let parameters = query_of(frame);
        assert_eq!(parameters["iss"], claims["iss"].as_str().expect("iss"));
        assert_eq!(
            parameters["sid"],
            claims["sid"].as_str().expect("sid"),
            "{address} gets the sid of its own ID tokens"
        );
    }
    assert_eq!(
        query_of(
            frames
                .iter()
                .find(|f| f.starts_with(REPORTS_FRAME))
                .expect("frame")
        )["from"],
        "hodor",
        "the address's own query is kept"
    );
    assert_eq!(
        directive(&policy, "frame-src"),
        Some("https://payroll.example.com https://reports.example.com")
    );
    assert_eq!(directive(&policy, "frame-ancestors"), Some("'none'"));
    assert_eq!(directive(&policy, "default-src"), Some("'none'"));

    // The page goes on to the finish, which sends the person back with the
    // state.
    let (status, location, _) = browser
        .navigate(Method::GET, "/t/acme/oauth2/logout/finish", None)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location, Some(format!("{OUT}?state=af0ifjsldkj")));

    // The page never takes an address from the browser: a cookie it made
    // up finds no frame and no site.
    let mut forger = Browser::not_following(&server);
    forger.cookies.insert(
        "__Secure-hodor_signed_out".to_owned(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
    );
    let (frames, policy) = signed_out_page(&mut forger, &server).await;
    assert!(frames.is_empty());
    assert_eq!(directive(&policy, "frame-src"), None, "{policy}");
    let (status, body) = forger
        .send(
            Method::GET,
            "/t/acme/interaction/signed-out?frames=https%3A%2F%2Fevil.example.net%2F",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["frames"], serde_json::json!([]));
}

#[tokio::test]
async fn signing_out_on_the_account_page_frames_the_clients_and_a_session_ended_elsewhere_none() {
    let database = TestDatabase::start().await;
    let (_, clients) = tenant(&database, "acme").await;
    let pages = Built::new();
    let server = server(&database, &pages).await;

    // Signing out on the account page.
    let mut browser = Browser::not_following(&server);
    let (payroll, _, _) = signed_in_everywhere(&mut browser, &server, &clients).await;
    let (status, _) = browser
        .send(Method::DELETE, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (frames, policy) = signed_out_page(&mut browser, &server).await;
    assert_eq!(frames.len(), 2, "{frames:?}");
    assert!(frames.iter().any(|frame| frame
        == &format!(
            "{PAYROLL_FRAME}?{}",
            query(&[
                ("iss", payroll["iss"].as_str().expect("iss")),
                ("sid", payroll["sid"].as_str().expect("sid")),
            ])
        )));
    assert!(directive(&policy, "frame-src").is_some());

    // Ending another of the person's sessions from this browser frames
    // nothing here: that session's browser is elsewhere.
    let mut elsewhere = Browser::not_following(&server);
    signed_in_everywhere(&mut elsewhere, &server, &clients).await;
    let mut here = Browser::not_following(&server);
    let (_, answer) = here.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(answer["status"], "completed");
    let (_, sessions) = here
        .send(Method::GET, "/t/acme/interaction/sessions", None)
        .await;
    let (_, current) = here
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    let other = sessions["sessions"]
        .as_array()
        .expect("sessions")
        .iter()
        .map(|session| session["session_id"].as_str().expect("id").to_owned())
        .find(|id| id != current["session_id"].as_str().expect("current"))
        .expect("another session");
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth.frontchannel_logout")
        .fetch_one(database.owner())
        .await
        .expect("count");
    let (status, _) = here
        .send(
            Method::DELETE,
            &format!("/t/acme/interaction/sessions/{other}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!here.cookies.contains_key("__Secure-hodor_signed_out"));
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth.frontchannel_logout")
        .fetch_one(database.owner())
        .await
        .expect("count");
    assert_eq!(
        after, before,
        "a session ended without its browser makes no frame"
    );
    let (status, _) = elsewhere
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "that session ended");
    let (frames, _) = signed_out_page(&mut elsewhere, &server).await;
    assert!(frames.is_empty());

    // A sign-out of a session that reached no client with an address frames
    // nothing, and tells the browser to forget an older cookie.
    let (status, _) = here
        .send(Method::DELETE, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!here.cookies.contains_key("__Secure-hodor_signed_out"));
    let (frames, policy) = signed_out_page(&mut here, &server).await;
    assert!(frames.is_empty());
    assert_eq!(directive(&policy, "frame-src"), None);
}
