//! An application in the browser is answered with an ID token, at the real
//! server binary against a real database: in the fragment, alone or with a
//! code, checked with a library of its own against the published key set,
//! its hashes computed here with another implementation of SHA-256; and
//! the endpoint refuses what a client did not register. A marked client is
//! answered with an access token too, which reads UserInfo and lives five
//! minutes. Specified in `docs/architecture/contexts/oauth.md`, "Response
//! types and modes", "The ID token through the browser" and "The access
//! token through the browser".

use aws_lc_rs::digest::{SHA256, digest};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
    BrowserAccessTokens, ClientId, ClientSettings, ClientType, CreateClient, GrantType,
    ResponseType, SubjectType, s256_challenge,
};
use hodor_tenant::api::{CreateTenant, TenantService};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

mod support;
use support::{Browser, MEMORY_KIBIBYTES, PASSES, Server, start_server_with};

const PASSWORD: &str = "correct horse battery staple";
const REDIRECT: &str = "https://payroll.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const NONCE: &str = "n-0S6_WzA2Mj";
const STATE: &str = "af0ifjsldkj & more";
/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";

fn issuer(slug: &str) -> String {
    format!("http://localhost:8080/t/{slug}")
}

/// The clients of a tenant: one of every response type, one of `code`
/// alone, and one of every response type that is pairwise.
struct Clients {
    every: ClientId,
    code_only: ClientId,
    pairwise: ClientId,
}

/// A tenant with Ana, who has a password, a name and an email address, an
/// active signing key, and the public clients of a first-party
/// application.
async fn tenant(database: &TestDatabase, slug: &str) -> Clients {
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
                identifiers: vec![
                    (IdentifierKind::Email, "ana@example.com".to_owned()),
                    (IdentifierKind::Username, "ana.lima".to_owned()),
                ],
                profile: Profile {
                    display_name: Some("Ana Lima".to_owned()),
                    locale: Some("pt-BR".to_owned()),
                },
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
        .expect("application")
        .id();
    let client = |response_types: Vec<ResponseType>, subject_type: SubjectType| {
        let applications = applications.clone();
        let context = context.clone();
        async move {
            make_client(
                &applications,
                &context,
                application,
                response_types,
                subject_type,
            )
            .await
        }
    };
    Clients {
        every: client(ResponseType::ALL.to_vec(), SubjectType::Public).await,
        code_only: client(vec![ResponseType::Code], SubjectType::Public).await,
        pairwise: client(ResponseType::ALL.to_vec(), SubjectType::Pairwise).await,
    }
}

async fn make_client(
    applications: &ApplicationService,
    context: &TenantContext,
    application: ApplicationId,
    response_types: Vec<ResponseType>,
    subject_type: SubjectType,
) -> ClientId {
    let mut settings = ClientSettings::new(
        "Payroll in the browser",
        ClientType::Public,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.authentication_method = AuthenticationMethod::None;
    // The types that return an access token are for a marked client.
    if response_types
        .iter()
        .any(|kind| kind.returns_access_token())
    {
        settings.browser_access_tokens = Some(BrowserAccessTokens::asked(Vec::new()));
    }
    settings.response_types = response_types;
    settings.subject_type = subject_type;
    // `groups` is allowed, and not in the mark of the marked clients.
    settings.allowed_scopes = ["openid", "profile", "email", "groups"]
        .map(str::to_owned)
        .to_vec();
    applications
        .create_client(
            context,
            CreateClient {
                application_id: application,
                client_type: ClientType::Public,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client")
        .0
        .id()
}

async fn server(database: &TestDatabase) -> Server {
    start_server_with(database, &[("HODOR_SECRET_KEYS", ROOT_KEY)]).await
}

fn authorize_query(
    client_id: ClientId,
    response_type: &str,
    scope: &str,
    extra: &[(&str, &str)],
) -> String {
    let challenge = s256_challenge(VERIFIER, &Sha256Digest);
    let id = client_id.to_string();
    let mut pairs = vec![
        ("response_type", response_type),
        ("client_id", id.as_str()),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    pairs.extend_from_slice(extra);
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// Where an answer sent the browser: the parameters of its fragment, and
/// of its query, each as a form is read.
struct SentBack {
    fragment: BTreeMap<String, String>,
    query: BTreeMap<String, String>,
}

fn sent_back(location: &str) -> SentBack {
    assert!(location.starts_with(REDIRECT), "{location}");
    let (before, fragment) = location.split_once('#').unwrap_or((location, ""));
    let query = before.split_once('?').map_or("", |(_, query)| query);
    let read = |text: &str| -> BTreeMap<String, String> {
        form_urlencoded::parse(text.as_bytes())
            .into_owned()
            .collect()
    };
    SentBack {
        fragment: read(fragment),
        query: read(query),
    }
}

/// What the authorization endpoint answers a signed-in browser with, and
/// the headers of the answer.
async fn answered(browser: &mut Browser, slug: &str, query: &str) -> SentBack {
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!("/t/{slug}/oauth2/authorize?{query}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    sent_back(&location.expect("a redirect"))
}

/// The base64url of the left half of the SHA-256 of `value`, computed
/// here with another implementation than Hodor's.
fn left_half(value: &str) -> String {
    let hash = digest(&SHA256, value.as_bytes());
    URL_SAFE_NO_PAD.encode(&hash.as_ref()[..16])
}

/// The claims of `token`, checked with a library of its own against the
/// tenant's published key set.
async fn checked(server: &Server, slug: &str, client_id: ClientId, token: &str) -> Value {
    let key_set: JwkSet = reqwest::get(format!("{}/t/{slug}/oauth2/jwks", server.base))
        .await
        .expect("key set")
        .json()
        .await
        .expect("JSON");
    let header = decode_header(token).expect("header");
    assert_eq!(header.alg, Algorithm::ES256);
    let jwk = key_set
        .find(&header.kid.expect("kid"))
        .expect("the signing key is published");
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[client_id.to_string()]);
    validation.set_issuer(&[issuer(slug)]);
    validation.set_required_spec_claims(&["exp", "iat", "iss", "sub", "aud"]);
    decode::<Value>(
        token,
        &DecodingKey::from_jwk(jwk).expect("key"),
        &validation,
    )
    .expect("the ID token checks")
    .claims
}

async fn redeem(server: &Server, slug: &str, client_id: ClientId, code: &str) -> Value {
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
async fn an_id_token_comes_in_the_fragment_after_the_sign_in_with_the_claims_of_its_scopes() {
    let database = TestDatabase::start().await;
    let clients = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);

    // Nobody is signed in: the request waits for the sign-in, and is
    // answered as it asked when the person comes back.
    let query = authorize_query(
        clients.every,
        "id_token",
        "openid profile email",
        &[("nonce", NONCE), ("state", STATE)],
    );
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!("/t/acme/oauth2/authorize?{query}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location
            .expect("a redirect")
            .starts_with("/t/acme/account/sign-in?"),
        "to the sign-in"
    );
    let (_, signed_in) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(signed_in["continue"], "/t/acme/oauth2/authorize/resume");
    let response = browser
        .client
        .get(format!("{}/t/acme/oauth2/authorize/resume", server.base))
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
    let location = response.headers()["location"]
        .to_str()
        .expect("ascii")
        .to_owned();
    assert!(
        location.starts_with(&format!("{REDIRECT}#")),
        "in the fragment, and nothing in the query: {location}"
    );
    let answer = sent_back(&location);
    assert!(answer.query.is_empty());
    assert_eq!(answer.fragment["state"], STATE);
    assert_eq!(answer.fragment["iss"], issuer("acme"));
    assert!(!answer.fragment.contains_key("code"), "nothing to redeem");
    assert!(!answer.fragment.contains_key("access_token"));

    let claims = checked(&server, "acme", clients.every, &answer.fragment["id_token"]).await;
    assert_eq!(claims["nonce"], NONCE, "echoed exactly");
    assert_eq!(claims["s_hash"], left_half(STATE));
    assert!(claims.get("c_hash").is_none() && claims.get("at_hash").is_none());
    assert_eq!(claims["amr"], serde_json::json!(["pwd"]));
    // No access token: the claims of the scopes are in the ID token.
    assert_eq!(claims["name"], "Ana Lima");
    assert_eq!(claims["preferred_username"], "ana.lima");
    assert_eq!(claims["locale"], "pt-BR");
    assert_eq!(claims["email"], "ana@example.com");
    assert_eq!(claims["email_verified"], false);
    let (_, session) = browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(claims["sid"], session["session_id"]);
    assert_eq!(claims["sub"], session["user_id"]);
}

#[tokio::test]
async fn a_code_comes_with_an_id_token_that_names_it_and_redeems_for_the_same_person() {
    let database = TestDatabase::start().await;
    let clients = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;

    let answer = answered(
        &mut browser,
        "acme",
        &authorize_query(
            clients.every,
            "code id_token",
            "openid profile",
            &[("nonce", NONCE), ("state", STATE)],
        ),
    )
    .await;
    let code = &answer.fragment["code"];
    let front = checked(&server, "acme", clients.every, &answer.fragment["id_token"]).await;
    assert_eq!(
        front["c_hash"],
        left_half(code),
        "the code that came with it"
    );
    assert_eq!(front["s_hash"], left_half(STATE));
    assert_eq!(front["nonce"], NONCE);
    assert!(front.get("name").is_none(), "profile is read at UserInfo");

    // The code redeems with its verifier, and the ID token of the token
    // endpoint names the same person, for the same nonce, tied to its
    // access token.
    let tokens = redeem(&server, "acme", clients.every, code).await;
    let access_token = tokens["access_token"].as_str().expect("an access token");
    let back = checked(
        &server,
        "acme",
        clients.every,
        tokens["id_token"].as_str().expect("an ID token"),
    )
    .await;
    for same in ["iss", "sub", "nonce", "sid", "auth_time"] {
        assert_eq!(back[same], front[same], "{same}");
    }
    assert_eq!(back["at_hash"], left_half(access_token));

    // The `code id_token` of the words in the other order is the same type.
    let answer = answered(
        &mut browser,
        "acme",
        &authorize_query(
            clients.every,
            "id_token code",
            "openid",
            &[("nonce", NONCE)],
        ),
    )
    .await;
    assert!(answer.fragment.contains_key("code") && answer.fragment.contains_key("id_token"));
    assert!(!answer.fragment.contains_key("state"), "none was sent");
}

#[tokio::test]
async fn a_pairwise_client_is_named_the_same_through_the_browser_and_at_the_token_endpoint() {
    let database = TestDatabase::start().await;
    let clients = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    let (_, session) = browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;

    let answer = answered(
        &mut browser,
        "acme",
        &authorize_query(
            clients.pairwise,
            "code id_token",
            "openid",
            &[("nonce", NONCE)],
        ),
    )
    .await;
    let front = checked(
        &server,
        "acme",
        clients.pairwise,
        &answer.fragment["id_token"],
    )
    .await;
    assert_ne!(
        front["sub"], session["user_id"],
        "an identifier of its sector"
    );
    assert_ne!(front["sid"], session["session_id"]);
    let tokens = redeem(&server, "acme", clients.pairwise, &answer.fragment["code"]).await;
    let back = checked(
        &server,
        "acme",
        clients.pairwise,
        tokens["id_token"].as_str().expect("an ID token"),
    )
    .await;
    assert_eq!(back["sub"], front["sub"]);
    assert_eq!(back["sid"], front["sid"]);
}

#[tokio::test]
async fn the_endpoint_answers_none_with_the_state_and_refuses_what_breaks_the_rules() {
    let database = TestDatabase::start().await;
    let clients = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;

    // `none`: the state and the issuer, in the query, and nothing else.
    let answer = answered(
        &mut browser,
        "acme",
        &authorize_query(clients.every, "none", "openid", &[("state", STATE)]),
    )
    .await;
    assert!(answer.fragment.is_empty());
    assert_eq!(
        answer.query.keys().map(String::as_str).collect::<Vec<_>>(),
        ["iss", "state"]
    );
    assert_eq!(answer.query["state"], STATE);

    // Each refusal comes back where the answer would have.
    let error = |answer: &SentBack, place: &str| -> String {
        let parameters = if place == "fragment" {
            &answer.fragment
        } else {
            &answer.query
        };
        assert_eq!(
            parameters.get("state").map(String::as_str),
            Some(STATE),
            "{place}"
        );
        assert_eq!(parameters["iss"], issuer("acme"));
        parameters
            .get("error")
            .cloned()
            .unwrap_or_else(|| panic!("an error in the {place}"))
    };
    for (case, client, response_type, extra, place, expected) in [
        (
            "a type the client did not register",
            clients.code_only,
            "id_token",
            vec![("nonce", NONCE)],
            "fragment",
            "unauthorized_client",
        ),
        (
            "an ID token without a nonce",
            clients.every,
            "id_token",
            vec![],
            "fragment",
            "invalid_request",
        ),
        (
            "an ID token in the query",
            clients.every,
            "code id_token",
            vec![("nonce", NONCE), ("response_mode", "query")],
            "fragment",
            "invalid_request",
        ),
        (
            "an access token through the browser, for a client that is not marked",
            clients.code_only,
            "id_token token",
            vec![("nonce", NONCE)],
            "fragment",
            "unauthorized_client",
        ),
        (
            "an access token in the query",
            clients.every,
            "token",
            vec![("response_mode", "query")],
            "fragment",
            "invalid_request",
        ),
        (
            "an unknown type",
            clients.every,
            "code code",
            vec![],
            "query",
            "unsupported_response_type",
        ),
        (
            "a mode not offered",
            clients.every,
            "code",
            vec![("response_mode", "form_post.jwt")],
            "query",
            "invalid_request",
        ),
    ] {
        let mut extra = extra;
        extra.push(("state", STATE));
        let answer = answered(
            &mut browser,
            "acme",
            &authorize_query(client, response_type, "openid", &extra),
        )
        .await;
        assert_eq!(error(&answer, place), expected, "{case}");
        assert!(!answer.fragment.contains_key("id_token"), "{case}");
    }

    // `code` in the fragment, when asked.
    let answer = answered(
        &mut browser,
        "acme",
        &authorize_query(
            clients.code_only,
            "code",
            "openid",
            &[("response_mode", "fragment")],
        ),
    )
    .await;
    assert!(answer.query.is_empty() && answer.fragment.contains_key("code"));
}

/// The fields of a page of `form_post`, read as a browser reads them, and
/// where it posts them.
fn posted_fields(body: &str) -> (String, BTreeMap<String, String>) {
    let unescaped = |text: &str| {
        text.replace("&quot;", "\"")
            .replace("&#x27;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    };
    let action = body
        .split_once("<form method=\"post\" action=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(action, _)| unescaped(action))
        .expect("a form that posts");
    let fields = body
        .lines()
        .filter_map(|line| line.strip_prefix("<input type=\"hidden\" name=\""))
        .map(|rest| {
            let (name, rest) = rest.split_once("\" value=\"").expect("a value");
            let value = rest.strip_suffix("\">").expect("the end of the field");
            (unescaped(name), unescaped(value))
        })
        .collect();
    (action, fields)
}

#[tokio::test]
async fn a_code_and_an_id_token_come_posted_by_the_page_of_form_post() {
    let database = TestDatabase::start().await;
    let clients = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;

    let query = authorize_query(
        clients.every,
        "code id_token",
        "openid",
        &[
            ("nonce", NONCE),
            ("state", STATE),
            ("response_mode", "form_post"),
        ],
    );
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!("/t/acme/oauth2/authorize?{query}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(location.is_none(), "a page, not a redirect");
    let (action, fields) = posted_fields(&body);
    assert_eq!(action, REDIRECT);
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["code", "id_token", "iss", "state"]
    );
    assert_eq!(fields["state"], STATE);
    assert_eq!(fields["iss"], issuer("acme"));
    let claims = checked(&server, "acme", clients.every, &fields["id_token"]).await;
    assert_eq!(claims["nonce"], NONCE);
    assert_eq!(claims["c_hash"], left_half(&fields["code"]));
    assert_eq!(claims["s_hash"], left_half(STATE));

    // An error of a type of the fragment, asked as a form, is posted too.
    let query = authorize_query(
        clients.every,
        "id_token",
        "openid",
        &[("state", STATE), ("response_mode", "form_post")],
    );
    let (status, _, body) = browser
        .navigate(
            Method::GET,
            &format!("/t/acme/oauth2/authorize?{query}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, fields) = posted_fields(&body);
    assert_eq!(fields["error"], "invalid_request", "no nonce");
    assert!(!fields.contains_key("id_token"));
}

/// The claims of an access token, checked with a library of its own
/// against the tenant's published key set, for the issuer as an audience.
async fn checked_access_token(server: &Server, slug: &str, token: &str) -> Value {
    let key_set: JwkSet = reqwest::get(format!("{}/t/{slug}/oauth2/jwks", server.base))
        .await
        .expect("key set")
        .json()
        .await
        .expect("JSON");
    let header = decode_header(token).expect("header");
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    let jwk = key_set
        .find(&header.kid.expect("kid"))
        .expect("the signing key is published");
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[issuer(slug)]);
    validation.set_issuer(&[issuer(slug)]);
    decode::<Value>(
        token,
        &DecodingKey::from_jwk(jwk).expect("key"),
        &validation,
    )
    .expect("the access token checks")
    .claims
}

async fn userinfo(server: &Server, slug: &str, token: &str) -> (StatusCode, Value) {
    let response = reqwest::Client::new()
        .get(format!("{}/t/{slug}/oauth2/userinfo", server.base))
        .bearer_auth(token)
        .send()
        .await
        .expect("response");
    let status = response.status();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_marked_client_gets_an_access_token_in_the_fragment_that_lives_five_minutes() {
    let database = TestDatabase::start().await;
    let clients = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;

    let query = authorize_query(
        clients.every,
        "id_token token",
        "openid profile",
        &[("nonce", NONCE), ("state", STATE)],
    );
    let response = browser
        .client
        .get(format!("{}/t/acme/oauth2/authorize?{query}", server.base))
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
    let location = response.headers()["location"]
        .to_str()
        .expect("ascii")
        .to_owned();
    assert!(
        location.starts_with(&format!("{REDIRECT}#")),
        "in the fragment alone: {location}"
    );
    let answer = sent_back(&location);
    assert!(answer.query.is_empty());
    assert_eq!(
        answer
            .fragment
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "access_token",
            "expires_in",
            "id_token",
            "iss",
            "scope",
            "state",
            "token_type"
        ],
        "no code and no refresh token"
    );
    assert_eq!(answer.fragment["token_type"], "Bearer");
    assert_eq!(answer.fragment["expires_in"], "300");
    assert_eq!(answer.fragment["scope"], "openid profile");
    let access_token = &answer.fragment["access_token"];

    // The ID token names the access token by `at_hash`, computed here with
    // another implementation of SHA-256.
    let id_token = checked(&server, "acme", clients.every, &answer.fragment["id_token"]).await;
    assert_eq!(id_token["at_hash"], left_half(access_token));
    assert_eq!(id_token["s_hash"], left_half(STATE));
    assert_eq!(id_token["nonce"], NONCE);
    assert!(id_token.get("name").is_none(), "read at UserInfo");

    // The access token checks against the key set, lives five minutes,
    // and reads UserInfo.
    let claims = checked_access_token(&server, "acme", access_token).await;
    assert_eq!(claims["client_id"], clients.every.to_string());
    assert_eq!(claims["sub"], id_token["sub"]);
    assert_eq!(claims["scope"], "openid profile");
    assert_eq!(
        claims["exp"].as_i64().expect("exp") - claims["iat"].as_i64().expect("iat"),
        300
    );
    let (status, person) = userinfo(&server, "acme", access_token).await;
    assert_eq!(status, StatusCode::OK, "{person}");
    assert_eq!(person["sub"], id_token["sub"]);
    assert_eq!(person["name"], "Ana Lima");

    // `token` alone, the access token and nothing else of OpenID Connect.
    let answer = answered(
        &mut browser,
        "acme",
        &authorize_query(clients.every, "token", "openid", &[]),
    )
    .await;
    assert!(answer.fragment.contains_key("access_token"));
    assert!(!answer.fragment.contains_key("id_token"));
    assert!(!answer.fragment.contains_key("code"));
}

#[tokio::test]
async fn a_code_comes_with_an_access_token_and_the_code_redeems_as_any_code() {
    let database = TestDatabase::start().await;
    let clients = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;

    let answer = answered(
        &mut browser,
        "acme",
        &authorize_query(
            clients.every,
            "code id_token token",
            "openid email",
            &[("nonce", NONCE), ("state", STATE)],
        ),
    )
    .await;
    let code = &answer.fragment["code"];
    let browser_token = &answer.fragment["access_token"];
    let front = checked(&server, "acme", clients.every, &answer.fragment["id_token"]).await;
    assert_eq!(front["c_hash"], left_half(code));
    assert_eq!(front["at_hash"], left_half(browser_token));

    // The token endpoint answers the code with a token of its own, of the
    // client's lifetime, and no refresh token: the client has no such
    // grant, and none ever comes through the browser.
    let tokens = redeem(&server, "acme", clients.every, code).await;
    assert_ne!(tokens["access_token"], Value::from(browser_token.as_str()));
    assert!(tokens.get("refresh_token").is_none());
    let back = checked(
        &server,
        "acme",
        clients.every,
        tokens["id_token"].as_str().expect("an ID token"),
    )
    .await;
    assert_eq!(back["sub"], front["sub"]);

    // `code token`: the code and the access token, no ID token.
    let answer = answered(
        &mut browser,
        "acme",
        &authorize_query(clients.every, "code token", "openid", &[]),
    )
    .await;
    assert!(answer.fragment.contains_key("code") && answer.fragment.contains_key("access_token"));
    assert!(!answer.fragment.contains_key("id_token"));
}

#[tokio::test]
async fn a_request_for_a_token_asks_only_for_what_the_mark_allows_and_comes_posted_as_a_form() {
    let database = TestDatabase::start().await;
    let clients = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;

    // `groups` is the client's, and not in its mark.
    let answer = answered(
        &mut browser,
        "acme",
        &authorize_query(clients.every, "token", "openid groups", &[("state", STATE)]),
    )
    .await;
    assert_eq!(answer.fragment["error"], "invalid_scope");
    assert!(!answer.fragment.contains_key("access_token"));

    // Posted by the page of `form_post`, as any answer can be.
    let query = authorize_query(
        clients.every,
        "code id_token token",
        "openid",
        &[
            ("nonce", NONCE),
            ("state", STATE),
            ("response_mode", "form_post"),
        ],
    );
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!("/t/acme/oauth2/authorize?{query}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(location.is_none());
    let (action, fields) = posted_fields(&body);
    assert_eq!(action, REDIRECT);
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "access_token",
            "code",
            "expires_in",
            "id_token",
            "iss",
            "scope",
            "state",
            "token_type"
        ]
    );
    let claims = checked(&server, "acme", clients.every, &fields["id_token"]).await;
    assert_eq!(claims["at_hash"], left_half(&fields["access_token"]));
    assert_eq!(claims["c_hash"], left_half(&fields["code"]));
}

#[tokio::test]
async fn a_pushed_request_for_an_access_token_is_answered_in_the_fragment() {
    let database = TestDatabase::start().await;
    let clients = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;

    let id = clients.every.to_string();
    let pushed = reqwest::Client::new()
        .post(format!("{}/t/acme/oauth2/par", server.base))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("client_id", id.as_str()),
                    ("response_type", "token id_token"),
                    ("redirect_uri", REDIRECT),
                    ("scope", "openid"),
                    ("nonce", NONCE),
                    ("state", STATE),
                ])
                .finish(),
        )
        .send()
        .await
        .expect("response");
    assert_eq!(pushed.status(), StatusCode::CREATED);
    let pushed: Value = pushed.json().await.expect("JSON");
    let reference = pushed["request_uri"].as_str().expect("a reference");
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("client_id", id.as_str()), ("request_uri", reference)])
        .finish();
    let answer = answered(&mut browser, "acme", &query).await;
    assert!(answer.query.is_empty(), "the pushed request's fragment");
    assert_eq!(answer.fragment["state"], STATE);
    let claims = checked(&server, "acme", clients.every, &answer.fragment["id_token"]).await;
    assert_eq!(
        claims["at_hash"],
        left_half(&answer.fragment["access_token"])
    );
}
