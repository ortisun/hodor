//! A person is asked before a third-party application gets access, on the
//! real server binary against a real database: the consent page's routes,
//! the answer, and withdrawing a consent.

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
    ClientType, CreateClient, CreateResourceServer, GrantType, ResourceServerSettings,
    ScopeDefinition, s256_challenge,
};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

mod support;
use support::{Browser, MEMORY_KIBIBYTES, PASSES, Server, start_server_with};

const PASSWORD: &str = "correct horse battery staple";
const REDIRECT: &str = "https://billing.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const AUDIENCE: &str = "https://api.billing.example.com";
/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";

async fn person(units: &TestDatabase, tenant: &TenantContext, email: &str) {
    let clock = Arc::new(SystemClock);
    let user = IdentityService::new(
        Arc::new(units.app().clone()),
        Arc::new(PgUserRepository),
        clock.clone(),
    )
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
        Arc::new(units.app().clone()),
        Arc::new(PgPasswordStore),
        Arc::new(hasher),
        clock,
    )
    .set_password(
        tenant,
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

/// A tenant with Ana and Bruno, who have passwords, an active signing key,
/// and a third-party application with a public client allowed refresh
/// tokens and a resource server. Returns the client.
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
    person(database, &context, "ana@example.com").await;
    person(database, &context, "bruno@example.com").await;
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
                name: "Billing".to_owned(),
                first_party: false,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    applications
        .create_resource_server(
            &context,
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
        ClientType::Public,
        vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        vec![REDIRECT.to_owned()],
    );
    settings.allowed_scopes = vec![
        "openid".to_owned(),
        "offline_access".to_owned(),
        "invoices:read".to_owned(),
    ];
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

fn authorize(slug: &str, client_id: ClientId, scope: &str, extra: &[(&str, &str)]) -> String {
    let challenge = s256_challenge(VERIFIER, &Sha256Digest);
    let client_id = client_id.to_string();
    let mut pairs: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
        ("state", "the state"),
        ("code_challenge", &challenge),
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

/// The parameters a redirect to the client carries.
fn sent_back(location: &str) -> BTreeMap<String, String> {
    let (address, query) = location.split_once('?').expect("a query");
    assert_eq!(address, REDIRECT, "sent to the registered address only");
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

/// A browser of `email`, signed in to acme.
async fn signed_in(server: &Server, email: &str) -> Browser {
    let mut browser = Browser::not_following(server);
    let (_, body) = browser.sign_in("acme", email, PASSWORD).await;
    assert_eq!(body["status"], "completed");
    browser
}

/// Asks for `scope`, is sent to the consent page, and answers `decision`.
/// Answers where the authorization endpoint then sends the browser.
async fn asked_and_answered(
    browser: &mut Browser,
    client_id: ClientId,
    scope: &str,
    decision: &str,
) -> BTreeMap<String, String> {
    let (status, location, _) = browser
        .navigate(Method::GET, &authorize("acme", client_id, scope, &[]), None)
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
            Some(json!({ "decision": decision })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["continue"], "/t/acme/oauth2/authorize/resume");
    let (status, location, _) = browser
        .navigate(Method::GET, "/t/acme/oauth2/authorize/resume", None)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    sent_back(&location.expect("a redirect"))
}

async fn token(server: &Server, pairs: &[(&str, &str)]) -> (StatusCode, Value) {
    let response = reqwest::Client::new()
        .post(format!("{}/t/acme/oauth2/token", server.base))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish(),
        )
        .send()
        .await
        .expect("response");
    let status = response.status();
    (status, response.json().await.unwrap_or(Value::Null))
}

/// The status UserInfo answers an access token with.
async fn userinfo(server: &Server, access: &str) -> StatusCode {
    reqwest::Client::new()
        .get(format!("{}/t/acme/oauth2/userinfo", server.base))
        .bearer_auth(access)
        .send()
        .await
        .expect("response")
        .status()
}

#[tokio::test]
async fn a_third_party_application_asks_once_and_the_person_agrees() {
    let database = TestDatabase::start().await;
    let client_id = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = signed_in(&server, "ana@example.com").await;

    // Signed in, the person is still asked: the application is not the tenant's.
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &authorize("acme", client_id, "openid invoices:read", &[]),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location.as_deref(), Some("/t/acme/account/consent"));
    assert!(browser.cookies.contains_key("__Secure-hodor_authorization"));

    // The page learns what to show: the application, and the scopes.
    let (status, question) = browser
        .send(Method::GET, "/t/acme/interaction/consent", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{question}");
    assert_eq!(question["application"], "Billing");
    assert_eq!(question["offline_access"], false);
    assert_eq!(
        question["scopes"],
        json!([
            { "scope": "openid", "kind": "openid" },
            {
                "scope": "invoices:read",
                "kind": "resource",
                "description": "Read your invoices",
                "resource_server": "Invoices"
            }
        ])
    );
    assert!(question["csrf_token"].is_string());

    // Without the session's CSRF token, the answer is refused.
    let token = browser.csrf_token.take();
    let (status, refused) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/consent",
            Some(json!({ "decision": "allow" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(refused["code"], "request.csrf_token_invalid");
    browser.csrf_token = token;

    let (status, answer) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/consent",
            Some(json!({ "decision": "allow" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (status, again) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/consent",
            Some(json!({ "decision": "deny" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "answered once");
    assert_eq!(again["code"], "oauth.consent_request_not_found");

    let (status, location, _) = browser
        .navigate(Method::GET, "/t/acme/oauth2/authorize/resume", None)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let answer = sent_back(&location.expect("a redirect"));
    assert!(answer.contains_key("code"), "{answer:?}");
    assert_eq!(answer["state"], "the state");
    assert!(!browser.cookies.contains_key("__Secure-hodor_authorization"));

    // What was agreed to is not asked again.
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &authorize("acme", client_id, "openid invoices:read", &[]),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(sent_back(&location.expect("a redirect")).contains_key("code"));

    // prompt=consent asks again; offline access is asked every time, and
    // with prompt=none that is consent_required.
    let (_, location, _) = browser
        .navigate(
            Method::GET,
            &authorize("acme", client_id, "openid", &[("prompt", "consent")]),
            None,
        )
        .await;
    assert_eq!(location.as_deref(), Some("/t/acme/account/consent"));
    let (_, location, _) = browser
        .navigate(
            Method::GET,
            &authorize(
                "acme",
                client_id,
                "openid offline_access",
                &[("prompt", "none")],
            ),
            None,
        )
        .await;
    let answer = sent_back(&location.expect("a redirect"));
    assert_eq!(answer["error"], "consent_required");

    // The person sees what they agreed to.
    let (status, listed) = browser
        .send(Method::GET, "/t/acme/interaction/consents", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let consents = listed["consents"].as_array().expect("consents");
    assert_eq!(consents.len(), 1);
    assert_eq!(consents[0]["application"], "Billing");
    assert_eq!(consents[0]["scopes"], json!(["openid", "invoices:read"]));
}

#[tokio::test]
async fn a_refusal_is_access_denied_and_the_request_is_only_the_asked_persons() {
    let database = TestDatabase::start().await;
    let client_id = tenant(&database, "acme").await;
    tenant(&database, "globex").await;
    let server = server(&database).await;
    let mut ana = signed_in(&server, "ana@example.com").await;

    let (_, location, _) = ana
        .navigate(
            Method::GET,
            &authorize("acme", client_id, "openid", &[]),
            None,
        )
        .await;
    assert_eq!(location.as_deref(), Some("/t/acme/account/consent"));
    let kept = ana.cookies["__Secure-hodor_authorization"].clone();

    // Bruno, with Ana's request in his browser, is not who was asked.
    let mut bruno = signed_in(&server, "bruno@example.com").await;
    bruno
        .cookies
        .insert("__Secure-hodor_authorization".to_owned(), kept.clone());
    let (status, body) = bruno
        .send(Method::GET, "/t/acme/interaction/consent", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "oauth.consent_request_not_found");
    // Nor is anybody in another tenant, where Ana's session means nothing.
    let (status, _) = ana
        .send(Method::GET, "/t/globex/interaction/consent", None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Ana refuses: the application is told access_denied.
    let answer = asked_and_answered(&mut ana, client_id, "openid", "deny").await;
    assert_eq!(answer["error"], "access_denied");
    assert_eq!(answer["state"], "the state");
    assert!(!answer.contains_key("code"));

    // Leaving without answering is access_denied too.
    let (_, location, _) = ana
        .navigate(
            Method::GET,
            &authorize("acme", client_id, "openid", &[]),
            None,
        )
        .await;
    assert_eq!(location.as_deref(), Some("/t/acme/account/consent"));
    let (_, location, _) = ana
        .navigate(Method::GET, "/t/acme/oauth2/authorize/resume", None)
        .await;
    assert_eq!(
        sent_back(&location.expect("a redirect"))["error"],
        "access_denied"
    );
}

#[tokio::test]
async fn withdrawing_a_consent_ends_its_refresh_tokens_and_asks_again() {
    let database = TestDatabase::start().await;
    let client_id = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = signed_in(&server, "ana@example.com").await;
    let answer = asked_and_answered(&mut browser, client_id, "openid invoices:read", "allow").await;
    let id = client_id.to_string();
    let (status, tokens) = token(
        &server,
        &[
            ("grant_type", "authorization_code"),
            ("code", &answer["code"]),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("client_id", &id),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let refresh = tokens["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned();
    let access = tokens["access_token"]
        .as_str()
        .expect("an access token")
        .to_owned();
    assert_eq!(userinfo(&server, &access).await, StatusCode::OK);

    // Withdrawn by the person, with the session's CSRF token.
    browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    let (status, body) = browser
        .send(
            Method::DELETE,
            &format!("/t/acme/interaction/consents/{client_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = browser
        .send(
            Method::DELETE,
            &format!("/t/acme/interaction/consents/{client_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "oauth.consent_not_found");

    let (status, refused) = token(
        &server,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &id),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(refused["error"], "invalid_grant");
    // The access token issued under it is no longer in force either.
    assert_eq!(userinfo(&server, &access).await, StatusCode::UNAUTHORIZED);

    let (_, location, _) = browser
        .navigate(
            Method::GET,
            &authorize("acme", client_id, "openid invoices:read", &[]),
            None,
        )
        .await;
    assert_eq!(location.as_deref(), Some("/t/acme/account/consent"));

    // The history keeps what happened, and the audit log what was done.
    let actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM oauth.consent_history ORDER BY at")
            .fetch_all(database.owner())
            .await
            .expect("history");
    assert_eq!(actions, ["given", "withdrawn"]);
    let recorded: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM platform.outbox WHERE event_type LIKE 'oauth.consent_%'
         ORDER BY event_type",
    )
    .fetch_all(database.owner())
    .await
    .expect("outbox");
    assert_eq!(recorded, ["oauth.consent_given", "oauth.consent_withdrawn"]);
}
