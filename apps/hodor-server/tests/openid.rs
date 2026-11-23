//! An application signs a person in through Hodor as an OpenID Provider,
//! at the real server binary against a real database: it finds everything
//! in the discovery document, checks the ID token with a library of its
//! own, and reads the person's claims at UserInfo.

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
use hodor_kernel::{Caller, Digest as _, Secret, SystemClock, TenantContext};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod, ClientId,
    ClientSettings, ClientType, CreateClient, CreateResourceServer, GrantType,
    ResourceServerSettings, ScopeDefinition, s256_challenge,
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
const AUDIENCE: &str = "https://api.payroll.example.com";
const NONCE: &str = "n-0S6_WzA2Mj";
/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";

fn issuer(slug: &str) -> String {
    format!("http://localhost:8080/t/{slug}")
}

/// A tenant with Ana, who has a password and a name, an active signing key,
/// and a public client of a first-party application with a resource server.
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
        .expect("application");
    applications
        .create_resource_server(
            &context,
            CreateResourceServer {
                application_id: application.id(),
                audience: AUDIENCE.to_owned(),
                settings: ResourceServerSettings {
                    name: "Payroll interface".to_owned(),
                    scopes: vec![ScopeDefinition {
                        name: "payroll:read".to_owned(),
                        description: "reads payslips".to_owned(),
                    }],
                },
            },
            Caller::system(),
        )
        .await
        .expect("resource server");
    let mut settings = ClientSettings::new(
        "Payroll",
        ClientType::Public,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.authentication_method = AuthenticationMethod::None;
    settings.allowed_scopes = ["openid", "profile", "email", "payroll:read"]
        .map(str::to_owned)
        .to_vec();
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

fn authorize_query(client_id: ClientId, scope: &str, extra: &[(&str, &str)]) -> String {
    let challenge = s256_challenge(VERIFIER, &Sha256Digest);
    let id = client_id.to_string();
    let mut pairs = vec![
        ("response_type", "code"),
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

fn query_of(location: &str) -> BTreeMap<String, String> {
    let (_, query) = location.split_once('?').expect("a query");
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

/// A code, from a browser that is signed in already.
async fn code(browser: &mut Browser, slug: &str, query: &str) -> String {
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!("/t/{slug}/oauth2/authorize?{query}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    query_of(&location.expect("a redirect"))["code"].clone()
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

struct Answer {
    status: StatusCode,
    challenge: Option<String>,
    cache: Option<String>,
    body: Value,
}

async fn userinfo(server: &Server, slug: &str, method: Method, token: Option<&str>) -> Answer {
    let mut request =
        reqwest::Client::new().request(method, format!("{}/t/{slug}/oauth2/userinfo", server.base));
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = request.send().await.expect("response");
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    Answer {
        status: response.status(),
        challenge: header("www-authenticate"),
        cache: header("cache-control"),
        body: response.json().await.unwrap_or(Value::Null),
    }
}

#[tokio::test]
async fn the_discovery_document_names_what_answers() {
    let database = TestDatabase::start().await;
    tenant(&database, "acme").await;
    let server = server(&database).await;
    let http = reqwest::Client::new();

    let mut documents = Vec::new();
    for path in [
        "/t/acme/.well-known/openid-configuration",
        "/t/acme/.well-known/oauth-authorization-server",
    ] {
        let response = http
            .get(format!("{}{path}", server.base))
            .send()
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert_eq!(response.headers()["cache-control"], "public, max-age=300");
        documents.push(response.json::<Value>().await.expect("JSON"));
    }
    assert_eq!(documents[0], documents[1], "one document at both addresses");
    let document = &documents[0];
    assert_eq!(document["issuer"], issuer("acme"));

    // Every endpoint it names is there. The server is reached at its own
    // address, the document names the public one.
    let local = |advertised: &Value| {
        advertised
            .as_str()
            .expect("an address")
            .replacen("http://localhost:8080", &server.base, 1)
    };
    let jwks = http
        .get(local(&document["jwks_uri"]))
        .send()
        .await
        .expect("response");
    assert_eq!(jwks.status(), StatusCode::OK);
    let authorize = http
        .get(local(&document["authorization_endpoint"]))
        .send()
        .await
        .expect("response");
    assert_eq!(
        authorize.status(),
        StatusCode::BAD_REQUEST,
        "answers, with its own page"
    );
    let token = http
        .post(local(&document["token_endpoint"]))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("grant_type=authorization_code")
        .send()
        .await
        .expect("response");
    assert!(
        [StatusCode::BAD_REQUEST, StatusCode::UNAUTHORIZED].contains(&token.status()),
        "answers, as OAuth"
    );
    let refusal: Value = token.json().await.expect("JSON");
    assert!(refusal["error"].is_string());
    let info = http
        .get(local(&document["userinfo_endpoint"]))
        .send()
        .await
        .expect("response");
    assert_eq!(info.status(), StatusCode::UNAUTHORIZED, "answers, as OAuth");

    // The grants it names are answered by the token endpoint, and the ones
    // it does not name are refused as unsupported.
    let advertised: Vec<&str> = document["grant_types_supported"]
        .as_array()
        .expect("grants")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for grant in ["authorization_code", "refresh_token", "client_credentials"] {
        let response = http
            .post(local(&document["token_endpoint"]))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!("grant_type={grant}&client_id=unknown"))
            .send()
            .await
            .expect("response");
        let body: Value = response.json().await.expect("JSON");
        assert_eq!(
            body["error"] == "unsupported_grant_type",
            !advertised.contains(&grant),
            "{grant}: {body}"
        );
    }
}

#[tokio::test]
async fn an_application_learns_who_signed_in_and_reads_their_claims() {
    let database = TestDatabase::start().await;
    let client_id = tenant(&database, "acme").await;
    tenant(&database, "globex").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);

    // Nobody signed in and prompt=none: no page, login_required.
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/authorize?{}",
                authorize_query(client_id, "openid", &[("prompt", "none")])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        query_of(&location.expect("a redirect"))["error"],
        "login_required"
    );

    let (_, signed_in) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(signed_in["status"], "completed");

    // max_age=0: the session is too old, so the person signs in again, and
    // the sign-in page is told the hint and the languages.
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/authorize?{}",
                authorize_query(
                    client_id,
                    "openid",
                    &[
                        ("max_age", "0"),
                        ("login_hint", "ana@example.com"),
                        ("ui_locales", "pt-BR en"),
                    ]
                )
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let location = location.expect("a redirect");
    assert!(
        location.starts_with("/t/acme/account/sign-in?"),
        "{location}"
    );
    let told = query_of(&location);
    assert_eq!(told["continue"], "authorization");
    assert_eq!(told["login_hint"], "ana@example.com");
    assert_eq!(told["ui_locales"], "pt-BR en");

    // The whole journey, with a nonce.
    let code = code(
        &mut browser,
        "acme",
        &authorize_query(
            client_id,
            "openid profile email payroll:read",
            &[("nonce", NONCE), ("resource", AUDIENCE)],
        ),
    )
    .await;
    let tokens = redeem(&server, "acme", client_id, &code).await;
    let access_token = tokens["access_token"].as_str().expect("access token");
    let id_token = tokens["id_token"].as_str().expect("an ID token");

    // Checked with a library of its own against the published key set.
    let key_set: JwkSet = reqwest::get(format!("{}/t/acme/oauth2/jwks", server.base))
        .await
        .expect("key set")
        .json()
        .await
        .expect("JSON");
    let header = decode_header(id_token).expect("header");
    assert_eq!(header.alg, Algorithm::ES256);
    let jwk = key_set
        .find(&header.kid.expect("kid"))
        .expect("the signing key is published");
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[client_id.to_string()]);
    validation.set_issuer(&[issuer("acme")]);
    validation.set_required_spec_claims(&["exp", "iat", "iss", "sub", "aud"]);
    let claims = decode::<Value>(
        id_token,
        &DecodingKey::from_jwk(jwk).expect("key"),
        &validation,
    )
    .expect("the ID token checks")
    .claims;
    assert_eq!(claims["nonce"], NONCE, "echoed exactly");
    assert_eq!(claims["amr"], serde_json::json!(["pwd"]));
    assert_eq!(claims["acr"], "urn:hodor:acr:single-factor");
    assert!(claims["auth_time"].as_i64().is_some());
    let digest = Sha256Digest.sha256(access_token.as_bytes());
    assert_eq!(claims["at_hash"], URL_SAFE_NO_PAD.encode(&digest[..16]));
    assert!(claims.get("email").is_none(), "claims come from UserInfo");

    // UserInfo, by GET and by POST.
    for method in [Method::GET, Method::POST] {
        let answer = userinfo(&server, "acme", method, Some(access_token)).await;
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
        assert_eq!(answer.cache.as_deref(), Some("no-store"));
        assert_eq!(answer.body["sub"], claims["sub"]);
        assert_eq!(answer.body["name"], "Ana Lima");
        assert_eq!(answer.body["preferred_username"], "ana.lima");
        assert_eq!(answer.body["locale"], "pt-BR");
        assert_eq!(answer.body["email"], "ana@example.com");
        assert_eq!(
            answer.body["email_verified"], false,
            "Ana never followed a link"
        );
    }

    // Without a token, with a token for Globex, with a broken one.
    let none = userinfo(&server, "acme", Method::GET, None).await;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED);
    assert_eq!(none.challenge.as_deref(), Some("Bearer"));
    let foreign = userinfo(&server, "globex", Method::GET, Some(access_token)).await;
    assert_eq!(foreign.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        foreign.challenge.as_deref(),
        Some("Bearer error=\"invalid_token\"")
    );
    let broken = format!("{access_token}x");
    let refused = userinfo(&server, "acme", Method::GET, Some(&broken)).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);

    // A token for the resource server only does not read UserInfo, and no
    // ID token comes without openid.
    let code = self::code(
        &mut browser,
        "acme",
        &authorize_query(client_id, "payroll:read", &[("resource", AUDIENCE)]),
    )
    .await;
    let tokens = redeem(&server, "acme", client_id, &code).await;
    assert!(tokens.get("id_token").is_none());
    let resource_only = tokens["access_token"].as_str().expect("access token");
    let answer = userinfo(&server, "acme", Method::GET, Some(resource_only)).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
}
