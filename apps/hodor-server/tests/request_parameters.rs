//! The parameters of a request completed by Issue-125, at the real server
//! binary against a real database: `id_token_hint` at the authorization
//! endpoint, `prompt=create`, `display`, a client's defaults for a sign-in,
//! and the access token in a form body at UserInfo.

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
    ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod, ClientId,
    ClientSettings, ClientType, CreateClient, GrantType, s256_challenge,
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
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";
const ANA: &str = "ana@example.com";
const BRUNO: &str = "bruno@example.com";

/// A tenant, open to registration or not, with Ana and Bruno, who have a
/// password, an active signing key, and two public clients of a
/// first-party application: the second one with a default max age of
/// zero. Answers the two clients.
async fn tenant(database: &TestDatabase, slug: &str, open: bool) -> (ClientId, ClientId) {
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
            open_registration: open,
            system: false,
        },
        Caller::system(),
    )
    .await
    .expect("tenant");
    let context = TenantContext::assume(created.id());
    let hasher = Arc::new(
        Argon2idHasher::new(
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
        .expect("hasher"),
    );
    for email in [ANA, BRUNO] {
        let user = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
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
            .expect("user")
            .id();
        CredentialService::new(
            units(),
            Arc::new(PgPasswordStore),
            hasher.clone(),
            clock.clone(),
        )
        .set_password(
            &context,
            user,
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
    }
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
    let mut clients = Vec::new();
    for default_max_age in [None, Some(0)] {
        let mut settings = ClientSettings::new(
            "Payroll",
            ClientType::Public,
            vec![GrantType::AuthorizationCode],
            vec![REDIRECT.to_owned()],
        );
        settings.authentication_method = AuthenticationMethod::None;
        settings.allowed_scopes = vec!["openid".to_owned(), "profile".to_owned()];
        settings.default_max_age = default_max_age;
        settings.require_auth_time = default_max_age.is_some();
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
        clients.push(client.id());
    }
    (clients[0], clients[1])
}

async fn server(database: &TestDatabase) -> Server {
    start_server_with(database, &[("HODOR_SECRET_KEYS", ROOT_KEY)]).await
}

fn authorize(slug: &str, client_id: ClientId, extra: &[(&str, &str)]) -> String {
    let challenge = s256_challenge(VERIFIER, &Sha256Digest);
    let id = client_id.to_string();
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", id.as_str()),
        ("redirect_uri", REDIRECT),
        ("scope", "openid profile"),
        ("state", "the state"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    pairs.extend_from_slice(extra);
    format!(
        "/t/{slug}/oauth2/authorize?{}",
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish()
    )
}

/// What the browser is sent to: the redirect address with its parameters,
/// or one of Hodor's pages.
enum Sent {
    Back(BTreeMap<String, String>),
    Page(String),
}

async fn go(browser: &mut Browser, path: &str) -> Sent {
    let (status, location, body) = browser.navigate(Method::GET, path, None).await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    let location = location.expect("a redirect");
    match location.strip_prefix(REDIRECT) {
        Some(query) => Sent::Back(
            form_urlencoded::parse(query.trim_start_matches('?').as_bytes())
                .into_owned()
                .collect(),
        ),
        None => Sent::Page(location),
    }
}

fn back(sent: Sent) -> BTreeMap<String, String> {
    match sent {
        Sent::Back(answer) => answer,
        Sent::Page(page) => panic!("expected the redirect address, got {page}"),
    }
}

fn page(sent: Sent) -> String {
    match sent {
        Sent::Page(page) => page,
        Sent::Back(answer) => panic!("expected one of Hodor's pages, got {answer:?}"),
    }
}

async fn signed_in(server: &Server, slug: &str, email: &str) -> Browser {
    let mut browser = Browser::not_following(server);
    let (_, body) = browser.sign_in(slug, email, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");
    browser
}

/// Signs in again in `browser` while a request waits, and follows the
/// answer's `continue` back to the authorization endpoint.
async fn sign_in_and_resume(browser: &mut Browser, slug: &str, email: &str) -> Sent {
    let (_, body) = browser.sign_in(slug, email, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");
    let resume = body["continue"].as_str().expect("continue").to_owned();
    go(browser, &resume).await
}

async fn tokens(server: &Server, slug: &str, client_id: ClientId, code: &str) -> Value {
    let id = client_id.to_string();
    let response = reqwest::Client::new()
        .post(format!("{}/t/{slug}/oauth2/token", server.base))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", REDIRECT),
                    ("code_verifier", VERIFIER),
                    ("client_id", id.as_str()),
                ])
                .finish(),
        )
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.expect("JSON")
}

#[tokio::test]
async fn an_id_token_hint_decides_whose_session_answers_the_request() {
    let database = TestDatabase::start().await;
    let (payroll, _) = tenant(&database, "acme", false).await;
    let server = server(&database).await;
    let mut ana = signed_in(&server, "acme", ANA).await;
    let answer = back(go(&mut ana, &authorize("acme", payroll, &[])).await);
    let issued = tokens(&server, "acme", payroll, &answer["code"]).await;
    let hint = issued["id_token"].as_str().expect("an ID token").to_owned();
    let hinted = |more: &[(&str, &str)]| {
        let mut pairs = vec![("id_token_hint", hint.as_str())];
        pairs.extend_from_slice(more);
        authorize("acme", payroll, &pairs)
    };

    // Ana's own session answers her hint, without a page.
    let answer = back(go(&mut ana, &hinted(&[("prompt", "none")])).await);
    assert!(answer.contains_key("code"), "{answer:?}");

    // Bruno's session does not: `login_required` with `prompt=none`...
    let mut bruno = signed_in(&server, "acme", BRUNO).await;
    let answer = back(go(&mut bruno, &hinted(&[("prompt", "none")])).await);
    assert_eq!(answer["error"], "login_required");
    assert_eq!(
        answer["error_description"],
        "the person signed in is not the one id_token_hint names"
    );
    assert_eq!(answer["state"], "the state");
    // ...and a new sign-in otherwise, which answers only as Ana.
    let sign_in = page(go(&mut bruno, &hinted(&[])).await);
    assert!(
        sign_in.starts_with("/t/acme/account/sign-in?continue=authorization"),
        "{sign_in}"
    );
    let answer = back(sign_in_and_resume(&mut bruno, "acme", BRUNO).await);
    assert_eq!(answer["error"], "login_required");
    page(go(&mut bruno, &hinted(&[])).await);
    let answer = back(sign_in_and_resume(&mut bruno, "acme", ANA).await);
    assert!(answer.contains_key("code"), "{answer:?}");

    // A hint that is not an ID token of the tenant: `invalid_request`.
    for broken in ["not.a.token", &format!("{hint}x")] {
        let answer = back(
            go(
                &mut ana,
                &authorize("acme", payroll, &[("id_token_hint", broken)]),
            )
            .await,
        );
        assert_eq!(answer["error"], "invalid_request", "{broken}");
    }
}

#[tokio::test]
async fn prompt_create_opens_registration_where_the_tenant_accepts_it() {
    let database = TestDatabase::start().await;
    let (closed_client, _) = tenant(&database, "acme", false).await;
    let (open_client, _) = tenant(&database, "globex", true).await;
    let server = server(&database).await;
    let http = reqwest::Client::new();
    let prompts = |slug: &'static str| {
        let http = http.clone();
        let base = server.base.clone();
        async move {
            let document: Value = http
                .get(format!("{base}/t/{slug}/.well-known/openid-configuration"))
                .send()
                .await
                .expect("response")
                .json()
                .await
                .expect("JSON");
            assert_eq!(
                document["display_values_supported"],
                serde_json::json!(["page", "popup", "touch"])
            );
            document["prompt_values_supported"].clone()
        }
    };
    assert_eq!(
        prompts("acme").await,
        serde_json::json!(["none", "login", "consent", "select_account"])
    );
    assert_eq!(
        prompts("globex").await,
        serde_json::json!(["none", "login", "consent", "select_account", "create"])
    );

    // Closed to registration: the value is not supported.
    let mut browser = Browser::not_following(&server);
    let answer = back(
        go(
            &mut browser,
            &authorize("acme", closed_client, &[("prompt", "create")]),
        )
        .await,
    );
    assert_eq!(answer["error"], "invalid_request");
    assert!(
        answer["error_description"].contains("prompt=create"),
        "{answer:?}"
    );
    assert_eq!(answer["state"], "the state");
    assert!(!browser.cookies.contains_key("__Secure-hodor_authorization"));

    // Open: the registration page, told that the request waits, even for a
    // browser signed in already, which must sign in again.
    let mut ana = signed_in(&server, "globex", ANA).await;
    let register = page(
        go(
            &mut ana,
            &authorize(
                "globex",
                open_client,
                &[("prompt", "create"), ("ui_locales", "pt-BR")],
            ),
        )
        .await,
    );
    assert_eq!(
        register,
        "/t/globex/account/register?continue=authorization&ui_locales=pt-BR"
    );
    assert!(ana.cookies.contains_key("__Secure-hodor_authorization"));
    let answer = back(sign_in_and_resume(&mut ana, "globex", ANA).await);
    assert!(answer.contains_key("code"), "{answer:?}");
    // With `none`, `create` is refused.
    let answer = back(
        go(
            &mut ana,
            &authorize("globex", open_client, &[("prompt", "none create")]),
        )
        .await,
    );
    assert_eq!(answer["error"], "invalid_request");
}

#[tokio::test]
async fn display_and_a_client_s_default_max_age_are_honored() {
    let database = TestDatabase::start().await;
    let (payroll, strict) = tenant(&database, "acme", false).await;
    let server = server(&database).await;
    let mut ana = signed_in(&server, "acme", ANA).await;
    for display in ["page", "popup", "touch"] {
        let answer = back(
            go(
                &mut ana,
                &authorize("acme", payroll, &[("display", display)]),
            )
            .await,
        );
        assert!(answer.contains_key("code"), "{display}: {answer:?}");
    }
    let answer = back(go(&mut ana, &authorize("acme", payroll, &[("display", "wap")])).await);
    assert_eq!(answer["error"], "invalid_request");

    // The strict client's default max age of zero asks for the password
    // again, as `max_age=0` would; its own `max_age` wins.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let sign_in = page(go(&mut ana, &authorize("acme", strict, &[])).await);
    assert!(sign_in.starts_with("/t/acme/account/sign-in"), "{sign_in}");
    let (_, waiting) = ana
        .send(Method::GET, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(waiting["step"], "password", "{waiting}");
    let answer = back(go(&mut ana, &authorize("acme", strict, &[("max_age", "3600")])).await);
    assert!(answer.contains_key("code"), "{answer:?}");
    // With `prompt=none`, the default max age is not met.
    let answer = back(go(&mut ana, &authorize("acme", strict, &[("prompt", "none")])).await);
    assert_eq!(answer["error"], "login_required");
}

/// The fields the page of `form_post` posts to the redirect address, for
/// an answer of `browser` at `path`: `200` with the page, never a redirect.
async fn posted(browser: &mut Browser, path: &str) -> BTreeMap<String, String> {
    let (status, location, body) = browser.navigate(Method::GET, path, None).await;
    assert_eq!(status, StatusCode::OK, "{location:?} {body}");
    assert!(
        body.contains(&format!("<form method=\"post\" action=\"{REDIRECT}\"")),
        "{body}"
    );
    let unescaped = |text: &str| {
        text.replace("&quot;", "\"")
            .replace("&#x27;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    };
    body.lines()
        .filter_map(|line| line.strip_prefix("<input type=\"hidden\" name=\""))
        .map(|rest| {
            let (name, rest) = rest.split_once("\" value=\"").expect("a value");
            let value = rest.strip_suffix("\">").expect("the end of the field");
            (unescaped(name), unescaped(value))
        })
        .collect()
}

#[tokio::test]
async fn the_refusals_of_these_parameters_come_in_the_request_s_response_mode() {
    let database = TestDatabase::start().await;
    let (payroll, _) = tenant(&database, "acme", false).await;
    let server = server(&database).await;
    let mut ana = signed_in(&server, "acme", ANA).await;
    let answer = back(go(&mut ana, &authorize("acme", payroll, &[])).await);
    let issued = tokens(&server, "acme", payroll, &answer["code"]).await;
    let hint = issued["id_token"].as_str().expect("an ID token").to_owned();
    let form_post = |more: &[(&str, &str)]| {
        let mut pairs = vec![("response_mode", "form_post")];
        pairs.extend_from_slice(more);
        authorize("acme", payroll, &pairs)
    };

    // `display` outside the three, `prompt=create` in a tenant closed to
    // registration, and a hint that is no ID token of the tenant: each
    // `invalid_request`, posted to the client.
    let broken = format!("{hint}x");
    for refused in [
        vec![("display", "wap")],
        vec![("prompt", "create")],
        vec![("id_token_hint", broken.as_str())],
    ] {
        let answer = posted(&mut ana, &form_post(&refused)).await;
        assert_eq!(answer["error"], "invalid_request", "{refused:?}");
        assert_eq!(answer["state"], "the state", "{refused:?}");
        assert!(answer["iss"].ends_with("/t/acme"), "{answer:?}");
    }

    // A session of another person than the hint names, with `prompt=none`.
    let mut bruno = signed_in(&server, "acme", BRUNO).await;
    let hinted = |more: &[(&str, &str)]| {
        let mut pairs = vec![("id_token_hint", hint.as_str())];
        pairs.extend_from_slice(more);
        form_post(&pairs)
    };
    let answer = posted(&mut bruno, &hinted(&[("prompt", "none")])).await;
    assert_eq!(answer["error"], "login_required");
    assert_eq!(
        answer["error_description"],
        "the person signed in is not the one id_token_hint names"
    );

    // And at the resume, after a sign-in as someone else than the hint's
    // person: the request kept its mode.
    page(go(&mut bruno, &hinted(&[])).await);
    let (_, body) = bruno.sign_in("acme", BRUNO, PASSWORD).await;
    assert_eq!(body["status"], "completed", "{body}");
    let resume = body["continue"].as_str().expect("continue").to_owned();
    let answer = posted(&mut bruno, &resume).await;
    assert_eq!(answer["error"], "login_required");
    assert_eq!(answer["state"], "the state");
}

#[tokio::test]
async fn userinfo_reads_the_access_token_from_a_form_body() {
    let database = TestDatabase::start().await;
    let (payroll, _) = tenant(&database, "acme", false).await;
    let server = server(&database).await;
    let mut ana = signed_in(&server, "acme", ANA).await;
    let answer = back(go(&mut ana, &authorize("acme", payroll, &[])).await);
    let issued = tokens(&server, "acme", payroll, &answer["code"]).await;
    let access = issued["access_token"].as_str().expect("access token");
    let address = format!("{}/t/acme/oauth2/userinfo", server.base);
    let http = reqwest::Client::new();
    let form = |body: String| {
        http.post(&address)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
    };
    let challenge = |response: &reqwest::Response| {
        response
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };

    let response = form(format!("access_token={access}"))
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let claims: Value = response.json().await.expect("JSON");
    assert!(claims["sub"].is_string(), "{claims}");

    // Both ways at once, or twice in the form: `invalid_request`.
    for request in [
        form(format!("access_token={access}")).bearer_auth(access),
        form(format!("access_token={access}&access_token={access}")),
    ] {
        let response = request.send().await.expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            challenge(&response).as_deref(),
            Some("Bearer error=\"invalid_request\"")
        );
    }
    // A token that is not one: refused as from the header.
    let response = form("access_token=nothing".to_owned())
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenge(&response).as_deref(),
        Some("Bearer error=\"invalid_token\"")
    );
    // In the query, or in a body that is not a form: not read.
    let response = http
        .get(format!("{address}?access_token={access}"))
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(challenge(&response).as_deref(), Some("Bearer"));
    let response = http
        .post(&address)
        .header("content-type", "application/json")
        .body(format!("{{\"access_token\":\"{access}\"}}"))
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
