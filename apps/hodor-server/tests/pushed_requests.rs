//! Pushed authorization requests at the real server binary, against a
//! real database: a client pushes its request, the browser brings the
//! reference once, and what must be refused is.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
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
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
    ClientId, ClientSettings, ClientType, CreateClient, GrantType, s256_challenge,
};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::header::HeaderMap;
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

fn issuer(slug: &str) -> String {
    format!("http://localhost:8080/t/{slug}")
}

struct Tenant {
    tenants: TenantService,
    applications: ApplicationService,
    context: TenantContext,
    application: ApplicationId,
}

/// A person of the tenant with `email` and the password.
async fn person(database: &TestDatabase, context: &TenantContext, email: &str) {
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(SystemClock);
    let person = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
        .create(
            context,
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
    CredentialService::new(units(), Arc::new(PgPasswordStore), Arc::new(hasher), clock)
        .set_password(
            context,
            person,
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

/// A tenant with Ana and Bea, who have a password, a signing key, and a
/// first-party application.
async fn tenant(database: &TestDatabase, slug: &str) -> Tenant {
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(SystemClock);
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        clock.clone(),
    );
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
    let context = TenantContext::assume(created.id());
    for email in ["ana@example.com", "bea@example.com"] {
        person(database, &context, email).await;
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
    Tenant {
        tenants,
        applications,
        context,
        application: application.id(),
    }
}

/// A confidential client with `client_secret_basic`, required to push its
/// requests when `strict`, and its secret.
async fn make_client(tenant: &Tenant, strict: bool) -> (ClientId, String) {
    let mut settings = ClientSettings::new(
        "Payroll",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.authentication_method = AuthenticationMethod::ClientSecretBasic;
    settings.allowed_scopes = vec!["openid".to_owned()];
    settings.require_pushed_requests = strict;
    let (client, secret) = tenant
        .applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: tenant.application,
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    (client.id(), secret.expect("a secret").expose().to_owned())
}

/// The request a client pushes, beside its credentials.
fn request(nonce: &str) -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".to_owned()),
        ("redirect_uri", REDIRECT.to_owned()),
        ("scope", "openid".to_owned()),
        ("state", "pushed".to_owned()),
        ("nonce", nonce.to_owned()),
        ("code_challenge", s256_challenge(VERIFIER, &Sha256Digest)),
        ("code_challenge_method", "S256".to_owned()),
    ]
}

fn basic(client: ClientId, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client}:{secret}")))
}

/// Posts a form to an endpoint of the tenant, with `Basic` credentials if
/// given.
async fn post(
    server: &Server,
    path: &str,
    credentials: Option<String>,
    pairs: &[(&str, String)],
) -> (StatusCode, HeaderMap, Value) {
    let mut request = reqwest::Client::new()
        .post(format!("{}{path}", server.base))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs.iter().map(|(name, value)| (*name, value.as_str())))
                .finish(),
        );
    if let Some(credentials) = credentials {
        request = request.header("authorization", credentials);
    }
    let response = request.send().await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    (
        status,
        headers,
        response.json().await.unwrap_or(Value::Null),
    )
}

async fn push(server: &Server, slug: &str, client: ClientId, secret: &str) -> (StatusCode, Value) {
    let (status, _, body) = post(
        server,
        &format!("/t/{slug}/oauth2/par"),
        Some(basic(client, secret)),
        &request("n-pushed"),
    )
    .await;
    (status, body)
}

/// Sends the browser to the authorization endpoint with `pairs`, and reads
/// where it was sent: the client's address and its query, or Hodor's own
/// page.
async fn authorize(
    browser: &mut Browser,
    slug: &str,
    pairs: &[(&str, &str)],
) -> Result<BTreeMap<String, String>, String> {
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish();
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!("/t/{slug}/oauth2/authorize?{query}"),
            None,
        )
        .await;
    if status == StatusCode::BAD_REQUEST {
        return Err(body);
    }
    assert_eq!(status, StatusCode::FOUND, "{body}");
    let location = location.expect("a redirect");
    let (address, query) = location.split_once('?').expect("a query");
    assert_eq!(address, REDIRECT, "only to the client's address");
    Ok(form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect())
}

fn payload(token: &str) -> Value {
    let part = token.split('.').nth(1).expect("claims");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("JSON")
}

async fn server(database: &TestDatabase) -> Server {
    start_server_with(database, &[("HODOR_SECRET_KEYS", ROOT_KEY)]).await
}

#[tokio::test]
async fn a_pushed_request_is_brought_once_by_its_reference_to_a_code_and_tokens() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let (client, secret) = make_client(&acme, false).await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    let (_, signed_in) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(signed_in["status"], "completed");

    let (status, headers, pushed) = post(
        &server,
        "/t/acme/oauth2/par",
        Some(basic(client, &secret)),
        &request("n-pushed"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{pushed}");
    assert_eq!(pushed["expires_in"], 60);
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let reference = pushed["request_uri"]
        .as_str()
        .expect("a reference")
        .to_owned();
    assert!(reference.starts_with("urn:ietf:params:oauth:request_uri:"));

    // Only the hash of the reference is in the database.
    let everything: String = sqlx::query_scalar(
        "SELECT string_agg(to_jsonb(t)::text, '') FROM oauth.authorization_request t",
    )
    .fetch_one(database.owner())
    .await
    .expect("dump");
    assert!(!everything.contains(&reference));

    // The browser brings the reference: the pushed request is the request,
    // whatever is outside, but for what OpenID Connect asks to repeat.
    let id = client.to_string();
    let answer = authorize(
        &mut browser,
        "acme",
        &[
            ("client_id", &id),
            ("request_uri", &reference),
            ("response_type", "code"),
            ("scope", "openid"),
            ("state", "outside"),
        ],
    )
    .await
    .expect("a redirect");
    assert_eq!(answer["state"], "pushed", "{answer:?}");
    assert_eq!(answer["iss"], issuer("acme"));
    let code = answer["code"].clone();
    let (status, _, tokens) = post(
        &server,
        "/t/acme/oauth2/token",
        Some(basic(client, &secret)),
        &[
            ("grant_type", "authorization_code".to_owned()),
            ("code", code),
            ("redirect_uri", REDIRECT.to_owned()),
            ("code_verifier", VERIFIER.to_owned()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let id_token = payload(tokens["id_token"].as_str().expect("an ID token"));
    assert_eq!(id_token["nonce"], "n-pushed", "the nonce that was pushed");

    // Used once: brought again, it is refused, at the client's address
    // when one is outside, and on Hodor's own page otherwise.
    let again = authorize(
        &mut browser,
        "acme",
        &[
            ("client_id", &id),
            ("request_uri", &reference),
            ("redirect_uri", REDIRECT),
            ("state", "again"),
        ],
    )
    .await
    .expect("a redirect");
    assert_eq!(again["error"], "invalid_request_uri", "{again:?}");
    assert_eq!(again["state"], "again");
    let page = authorize(
        &mut browser,
        "acme",
        &[("client_id", &id), ("request_uri", &reference)],
    )
    .await
    .expect_err("Hodor's own page");
    assert!(
        page.contains("oauth.authorization_request_uri_invalid"),
        "{page}"
    );

    // Discovery names the endpoint, and that the tenant does not require
    // it.
    let document: Value = reqwest::get(format!(
        "{}/t/acme/.well-known/openid-configuration",
        server.base
    ))
    .await
    .expect("discovery")
    .json()
    .await
    .expect("JSON");
    assert_eq!(
        document["pushed_authorization_request_endpoint"],
        format!("{}/oauth2/par", issuer("acme"))
    );
    assert_eq!(document["require_pushed_authorization_requests"], false);
    assert_eq!(document["request_uri_parameter_supported"], false);
}

#[tokio::test]
async fn a_pushed_request_that_must_be_refused_is_refused() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let (client, secret) = make_client(&acme, false).await;
    let (stranger, _) = make_client(&acme, false).await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    let id = client.to_string();

    // A check that fails is answered at once, as JSON, never at the
    // redirect address.
    let mut asking_too_much = request("n");
    asking_too_much.retain(|(name, _)| *name != "scope");
    asking_too_much.push(("scope", "openid payroll:write".to_owned()));
    let (status, headers, body) = post(
        &server,
        "/t/acme/oauth2/par",
        Some(basic(client, &secret)),
        &asking_too_much,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_scope");
    assert!(headers.get("location").is_none());
    let (status, headers, body) = post(
        &server,
        "/t/acme/oauth2/par",
        Some(basic(client, "not the secret")),
        &request("n"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    assert!(headers.get("www-authenticate").is_some());
    let answer = reqwest::get(format!("{}/t/acme/oauth2/par", server.base))
        .await
        .expect("answer");
    assert_eq!(answer.status(), StatusCode::METHOD_NOT_ALLOWED);

    // A reference brought by another client is unknown to it, and still
    // its own client's.
    let (_, pushed) = push(&server, "acme", client, &secret).await;
    let reference = pushed["request_uri"]
        .as_str()
        .expect("a reference")
        .to_owned();
    let other = stranger.to_string();
    let answer = authorize(
        &mut browser,
        "acme",
        &[
            ("client_id", &other),
            ("request_uri", &reference),
            ("redirect_uri", REDIRECT),
        ],
    )
    .await
    .expect("a redirect");
    assert_eq!(answer["error"], "invalid_request_uri", "{answer:?}");

    // Past its life.
    sqlx::query(
        "UPDATE oauth.authorization_request
         SET expires_at = received_at + interval '1 millisecond'
         WHERE reference_hash IS NOT NULL",
    )
    .execute(database.owner())
    .await
    .expect("aged");
    let answer = authorize(
        &mut browser,
        "acme",
        &[
            ("client_id", &id),
            ("request_uri", &reference),
            ("redirect_uri", REDIRECT),
        ],
    )
    .await
    .expect("a redirect");
    assert_eq!(answer["error"], "invalid_request_uri", "{answer:?}");

    // A reference Hodor did not make.
    let forged = format!("urn:ietf:params:oauth:request_uri:{}", "A".repeat(43));
    let answer = authorize(
        &mut browser,
        "acme",
        &[
            ("client_id", &id),
            ("request_uri", &forged),
            ("redirect_uri", REDIRECT),
        ],
    )
    .await
    .expect("a redirect");
    assert_eq!(answer["error"], "invalid_request_uri", "{answer:?}");
}

#[tokio::test]
async fn a_client_or_a_tenant_that_requires_pushed_requests_refuses_any_other() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let (strict, strict_secret) = make_client(&acme, true).await;
    let (lenient, lenient_secret) = make_client(&acme, false).await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    let direct = |client: ClientId| {
        let mut pairs: Vec<(&str, String)> = request("n");
        pairs.push(("client_id", client.to_string()));
        pairs
    };
    let as_pairs =
        |pairs: &[(&'static str, String)]| -> Vec<(&'static str, String)> { pairs.to_vec() };

    // The client that must push is refused without a pushed request, at
    // its address; the other is not.
    let pairs = as_pairs(&direct(strict));
    let borrowed: Vec<(&str, &str)> = pairs.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let answer = authorize(&mut browser, "acme", &borrowed)
        .await
        .expect("a redirect");
    assert_eq!(answer["error"], "invalid_request", "{answer:?}");
    assert_eq!(
        answer["error_description"],
        "this client must push its authorization requests"
    );
    let pairs = as_pairs(&direct(lenient));
    let borrowed: Vec<(&str, &str)> = pairs.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let answer = authorize(&mut browser, "acme", &borrowed)
        .await
        .expect("a redirect");
    assert!(answer.contains_key("code"), "{answer:?}");

    // Pushed, the strict client is answered.
    let (status, pushed) = push(&server, "acme", strict, &strict_secret).await;
    assert_eq!(status, StatusCode::CREATED, "{pushed}");
    let id = strict.to_string();
    let answer = authorize(
        &mut browser,
        "acme",
        &[
            ("client_id", &id),
            (
                "request_uri",
                pushed["request_uri"].as_str().expect("a reference"),
            ),
        ],
    )
    .await
    .expect("a redirect");
    assert!(answer.contains_key("code"), "{answer:?}");

    // The tenant requires it of every client, and gives pushed requests
    // ten seconds: discovery says so, and the lenient client is refused
    // too.
    let mut settings = acme
        .tenants
        .get(&acme.context)
        .await
        .expect("tenant")
        .snapshot()
        .settings
        .clone();
    settings.pushed_requests.required = true;
    settings.pushed_requests.lifetime_seconds = 10;
    acme.tenants
        .change_settings(&acme.context, settings, Caller::system())
        .await
        .expect("changed");
    let pairs = as_pairs(&direct(lenient));
    let borrowed: Vec<(&str, &str)> = pairs.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let answer = authorize(&mut browser, "acme", &borrowed)
        .await
        .expect("a redirect");
    assert_eq!(answer["error"], "invalid_request", "{answer:?}");
    let (status, pushed) = push(&server, "acme", lenient, &lenient_secret).await;
    assert_eq!(status, StatusCode::CREATED, "{pushed}");
    assert_eq!(pushed["expires_in"], 10);
    let document: Value = reqwest::get(format!(
        "{}/t/acme/.well-known/openid-configuration",
        server.base
    ))
    .await
    .expect("discovery")
    .json()
    .await
    .expect("JSON");
    assert_eq!(document["require_pushed_authorization_requests"], true);
}

/// The hidden fields of a page of `form_post` that posts to the client's
/// address, by name.
fn posted_fields(status: StatusCode, body: &str) -> BTreeMap<String, String> {
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains(&format!("<form method=\"post\" action=\"{REDIRECT}\">")),
        "{body}"
    );
    body.lines()
        .filter_map(|line| line.trim().strip_prefix("<input type=\"hidden\" name=\""))
        .filter_map(|rest| {
            let (name, rest) = rest.split_once("\" value=\"")?;
            let (value, _) = rest.split_once("\">")?;
            Some((name.to_owned(), value.to_owned()))
        })
        .collect()
}

#[tokio::test]
async fn a_pushed_request_keeps_its_response_mode_and_its_hint() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let (client, secret) = make_client(&acme, false).await;
    let server = server(&database).await;
    let id = client.to_string();
    let mut ana = Browser::not_following(&server);
    let (_, signed_in) = ana.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(signed_in["status"], "completed");
    let mut bea = Browser::not_following(&server);
    let (_, signed_in) = bea.sign_in("acme", "bea@example.com", PASSWORD).await;
    assert_eq!(signed_in["status"], "completed");
    let bring = |reference: &str, outside: &[(&str, &str)]| {
        let mut pairs = vec![
            ("client_id", id.clone()),
            ("request_uri", reference.to_owned()),
        ];
        pairs.extend(
            outside
                .iter()
                .map(|(name, value)| (*name, (*value).to_owned())),
        );
        format!(
            "/t/acme/oauth2/authorize?{}",
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs.iter().map(|(name, value)| (*name, value.as_str())))
                .finish()
        )
    };
    let pushed_with = |extra: &[(&'static str, String)]| {
        let mut pairs = request("n-mode");
        pairs.extend(extra.iter().cloned());
        pairs
    };
    let reference_of = |body: &Value| {
        body["request_uri"]
            .as_str()
            .expect("a reference")
            .to_owned()
    };

    // Pushed with `form_post`, the answer is posted, whatever mode the
    // browser names outside.
    let (status, _, pushed) = post(
        &server,
        "/t/acme/oauth2/par",
        Some(basic(client, &secret)),
        &pushed_with(&[("response_mode", "form_post".to_owned())]),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{pushed}");
    let (status, _, body) = ana
        .navigate(
            Method::GET,
            &bring(&reference_of(&pushed), &[("response_mode", "query")]),
            None,
        )
        .await;
    let fields = posted_fields(status, &body);
    assert_eq!(fields["state"], "pushed", "{fields:?}");
    assert!(fields.contains_key("code"), "{fields:?}");
    let code = fields["code"].clone();
    let (status, _, tokens) = post(
        &server,
        "/t/acme/oauth2/token",
        Some(basic(client, &secret)),
        &[
            ("grant_type", "authorization_code".to_owned()),
            ("code", code),
            ("redirect_uri", REDIRECT.to_owned()),
            ("code_verifier", VERIFIER.to_owned()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let hint = tokens["id_token"]
        .as_str()
        .expect("Ana's ID token")
        .to_owned();

    // A refused reference is answered in the mode named beside the
    // redirect address it goes to.
    let (status, _, body) = ana
        .navigate(
            Method::GET,
            &bring(
                &reference_of(&pushed),
                &[
                    ("redirect_uri", REDIRECT),
                    ("response_mode", "form_post"),
                    ("state", "again"),
                ],
            ),
            None,
        )
        .await;
    let fields = posted_fields(status, &body);
    assert_eq!(fields["error"], "invalid_request_uri", "{fields:?}");
    assert_eq!(fields["state"], "again");

    // A hint that is not an ID token of the tenant is refused when pushed,
    // as JSON.
    let (status, headers, refused) = post(
        &server,
        "/t/acme/oauth2/par",
        Some(basic(client, &secret)),
        &pushed_with(&[("id_token_hint", "not.an.idtoken".to_owned())]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "invalid_request");
    assert!(headers.get("location").is_none());

    // Ana's hint is kept with the pushed request: with `prompt=none`, Ana's
    // browser gets a code and Bea's is told to sign in, though nothing
    // outside names a hint.
    let hinted = pushed_with(&[
        ("id_token_hint", hint.clone()),
        ("prompt", "none".to_owned()),
    ]);
    let (status, _, for_ana) = post(
        &server,
        "/t/acme/oauth2/par",
        Some(basic(client, &secret)),
        &hinted,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{for_ana}");
    let answer = authorize(
        &mut ana,
        "acme",
        &[("client_id", &id), ("request_uri", &reference_of(&for_ana))],
    )
    .await
    .expect("a redirect");
    assert!(answer.contains_key("code"), "{answer:?}");
    let (_, _, for_bea) = post(
        &server,
        "/t/acme/oauth2/par",
        Some(basic(client, &secret)),
        &hinted,
    )
    .await;
    let answer = authorize(
        &mut bea,
        "acme",
        &[("client_id", &id), ("request_uri", &reference_of(&for_bea))],
    )
    .await
    .expect("a redirect");
    assert_eq!(answer["error"], "login_required", "{answer:?}");
}
