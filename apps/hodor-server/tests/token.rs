//! An application exchanges its code for an access token at the real
//! server binary, against a real database, and checks the token with a
//! library of its own against the published key set.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
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
    ASSERTION_TYPE, ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings,
    AuthenticationMethod, ClientId, ClientSettings, ClientType, CreateClient, CreateResourceServer,
    GrantType, ResourceServerSettings, ScopeDefinition, s256_challenge,
};
use hodor_tenant::api::{CreateTenant, TenantService};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

mod support;
use support::{Browser, MEMORY_KIBIBYTES, PASSES, Server, start_server_with};

const PASSWORD: &str = "correct horse battery staple";
const REDIRECT: &str = "https://payroll.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const AUDIENCE: &str = "https://api.payroll.example.com";
/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";

fn issuer(slug: &str) -> String {
    format!("http://localhost:8080/t/{slug}")
}

struct Tenant {
    applications: ApplicationService,
    context: TenantContext,
    application: ApplicationId,
}

/// A tenant with Ana, who has a password, an active signing key, and a
/// first-party application with a resource server.
async fn tenant(database: &TestDatabase, slug: &str) -> Tenant {
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
    Tenant {
        applications,
        context,
        application: application.id(),
    }
}

/// A client of the tenant's application, with its secret if it has one.
async fn client(
    tenant: &Tenant,
    client_type: ClientType,
    method: AuthenticationMethod,
) -> (ClientId, Option<String>) {
    let mut settings = ClientSettings::new(
        "Payroll",
        client_type,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.authentication_method = method;
    settings.allowed_scopes = vec!["openid".to_owned(), "payroll:read".to_owned()];
    let (client, secret) = tenant
        .applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: tenant.application,
                client_type,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    (client.id(), secret.map(|value| value.expose().to_owned()))
}

async fn server(database: &TestDatabase) -> Server {
    start_server_with(database, &[("HODOR_SECRET_KEYS", ROOT_KEY)]).await
}

fn authorize_query(client_id: ClientId) -> String {
    let challenge = s256_challenge(VERIFIER, &Sha256Digest);
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", &client_id.to_string()),
            ("redirect_uri", REDIRECT),
            ("scope", "openid payroll:read"),
            ("resource", AUDIENCE),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ])
        .finish()
}

/// A code for `client_id`, from a browser that is signed in already.
async fn code(browser: &mut Browser, slug: &str, client_id: ClientId) -> String {
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!("/t/{slug}/oauth2/authorize?{}", authorize_query(client_id)),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    let location = location.expect("a redirect");
    let (_, query) = location.split_once('?').expect("a query");
    let answer: BTreeMap<String, String> = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    answer["code"].clone()
}

struct Answer {
    status: StatusCode,
    headers: reqwest::header::HeaderMap,
    body: Value,
}

async fn token(
    server: &Server,
    slug: &str,
    basic: Option<(&str, &str)>,
    pairs: &[(&str, &str)],
) -> Answer {
    let mut request = reqwest::Client::new()
        .post(format!("{}/t/{slug}/oauth2/token", server.base))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish(),
        );
    if let Some((id, secret)) = basic {
        request = request.header(
            "authorization",
            format!("Basic {}", STANDARD.encode(format!("{id}:{secret}"))),
        );
    }
    let response = request.send().await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.json().await.unwrap_or(Value::Null);
    Answer {
        status,
        headers,
        body,
    }
}

fn redeem<'a>(code: &'a str, extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
    ];
    pairs.extend_from_slice(extra);
    pairs
}

#[tokio::test]
async fn an_application_gets_an_access_token_anyone_can_check() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let globex = tenant(&database, "globex").await;
    let (client_id, _) = client(&acme, ClientType::Public, AuthenticationMethod::None).await;
    let (globex_client, _) = client(&globex, ClientType::Public, AuthenticationMethod::None).await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    let (_, signed_in) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(signed_in["status"], "completed");

    let code = code(&mut browser, "acme", client_id).await;
    let id = client_id.to_string();
    let answer = token(&server, "acme", None, &redeem(&code, &[("client_id", &id)])).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(answer.headers["cache-control"], "no-store");
    assert_eq!(answer.headers["pragma"], "no-cache");
    assert_eq!(answer.body["token_type"], "Bearer");
    assert_eq!(answer.body["expires_in"], 300);
    assert_eq!(answer.body["scope"], "openid payroll:read");
    assert!(answer.body.get("refresh_token").is_none());
    let access_token = answer.body["access_token"]
        .as_str()
        .expect("token")
        .to_owned();

    // Checked with a library of its own against the published key set.
    let key_set: JwkSet = reqwest::get(format!("{}/t/acme/oauth2/jwks", server.base))
        .await
        .expect("key set")
        .json()
        .await
        .expect("JSON");
    let header = decode_header(&access_token).expect("header");
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    let kid = header.kid.expect("kid");
    let jwk = key_set.find(&kid).expect("the signing key is published");
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[AUDIENCE]);
    validation.set_issuer(&[issuer("acme")]);
    validation.set_required_spec_claims(&["exp", "iat", "iss", "sub", "aud"]);
    let claims = decode::<Value>(
        &access_token,
        &DecodingKey::from_jwk(jwk).expect("key"),
        &validation,
    )
    .expect("the token checks")
    .claims;
    assert_eq!(claims["client_id"], id);
    assert_eq!(claims["scope"], "openid payroll:read");
    assert!(claims["jti"].as_str().is_some_and(|jti| jti.len() == 22));
    assert!(claims["auth_time"].as_i64().is_some());

    // The token is checked against Globex's key set: refused.
    let globex_keys: JwkSet = reqwest::get(format!("{}/t/globex/oauth2/jwks", server.base))
        .await
        .expect("key set")
        .json()
        .await
        .expect("JSON");
    assert!(
        globex_keys.find(&kid).is_none(),
        "one tenant's key, not another's"
    );

    // A code redeems once.
    let again = token(&server, "acme", None, &redeem(&code, &[("client_id", &id)])).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert_eq!(again.body["error"], "invalid_grant");

    // Acme's code and client mean nothing at Globex.
    let fresh = self::code(&mut browser, "acme", client_id).await;
    let at_globex = token(
        &server,
        "globex",
        None,
        &redeem(&fresh, &[("client_id", &id)]),
    )
    .await;
    assert_eq!(at_globex.status, StatusCode::UNAUTHORIZED);
    assert_eq!(at_globex.body["error"], "invalid_client");
    let globex_id = globex_client.to_string();
    let foreign = token(
        &server,
        "globex",
        None,
        &redeem(&fresh, &[("client_id", &globex_id)]),
    )
    .await;
    assert_eq!(foreign.body["error"], "invalid_grant");

    // A wrong verifier is refused, and the code stays unredeemed for no one
    // else.
    let wrong = token(
        &server,
        "acme",
        None,
        &[
            ("grant_type", "authorization_code"),
            ("code", &fresh),
            ("redirect_uri", REDIRECT),
            (
                "code_verifier",
                "a-wrong-verifier-that-is-long-enough-to-be-one",
            ),
            ("client_id", &id),
        ],
    )
    .await;
    assert_eq!(wrong.body["error"], "invalid_grant");

    // Neither the token nor the code is stored anywhere.
    let everything: String = sqlx::query_scalar(
        r#"SELECT concat(
               (SELECT string_agg(to_jsonb(t)::text, '') FROM oauth.authorization_code t),
               (SELECT string_agg(to_jsonb(t)::text, '') FROM platform.outbox t))"#,
    )
    .fetch_one(database.owner())
    .await
    .expect("dump");
    assert!(!everything.contains(&access_token));
    assert!(!everything.contains(&code));
    assert!(everything.contains("oauth.access_token_issued"));
}

fn seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

#[tokio::test]
async fn a_confidential_client_proves_who_it_is_its_own_way() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let (secret_client, secret) = client(
        &acme,
        ClientType::Confidential,
        AuthenticationMethod::ClientSecretBasic,
    )
    .await;
    let secret = secret.expect("a secret");
    let (signing_client, _) = client(
        &acme,
        ClientType::Confidential,
        AuthenticationMethod::PrivateKeyJwt,
    )
    .await;
    // The client's own key pair; Hodor is given only its public half.
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .expect("key");
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).expect("pair");
    let point = pair.public_key().as_ref();
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": "payroll-2026",
        "alg": "ES256",
        "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
    });
    acme.applications
        .add_client_key(
            &acme.context,
            signing_client,
            &jwk.to_string(),
            Caller::system(),
        )
        .await
        .expect("key");
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;

    // A wrong secret: 401, with the challenge of Basic.
    let id = secret_client.to_string();
    let code = code(&mut browser, "acme", secret_client).await;
    let wrong = token(
        &server,
        "acme",
        Some((
            &id,
            "hodor_cs_0000000000000000000000000000000000000000000000000000000000000000",
        )),
        &redeem(&code, &[]),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body["error"], "invalid_client");
    assert_eq!(
        wrong.headers["www-authenticate"],
        format!("Basic realm=\"{}\"", issuer("acme")).as_str()
    );
    // The secret in the form is not how this client was registered.
    let in_form = token(
        &server,
        "acme",
        None,
        &redeem(&code, &[("client_id", &id), ("client_secret", &secret)]),
    )
    .await;
    assert_eq!(in_form.status, StatusCode::UNAUTHORIZED);
    assert!(in_form.headers.get("www-authenticate").is_none());
    let right = token(&server, "acme", Some((&id, &secret)), &redeem(&code, &[])).await;
    assert_eq!(right.status, StatusCode::OK, "{}", right.body);

    // An assertion signed with the client's key, used once.
    let signing_id = signing_client.to_string();
    let encoding = EncodingKey::from_ec_der(pkcs8.as_ref());
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("payroll-2026".to_owned());
    let assertion = jsonwebtoken::encode(
        &header,
        &json!({
            "iss": signing_id,
            "sub": signing_id,
            "aud": format!("{}/oauth2/token", issuer("acme")),
            "exp": seconds_now() + 60,
            "iat": seconds_now(),
            "jti": "payroll-assertion-1",
        }),
        &encoding,
    )
    .expect("assertion");
    let with_assertion = [
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion.as_str()),
    ];
    let code = self::code(&mut browser, "acme", signing_client).await;
    let first = token(&server, "acme", None, &redeem(&code, &with_assertion)).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let code = self::code(&mut browser, "acme", signing_client).await;
    let reused = token(&server, "acme", None, &redeem(&code, &with_assertion)).await;
    assert_eq!(reused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reused.body["error"], "invalid_client");

    // Proving it two ways at once is malformed.
    let both = token(
        &server,
        "acme",
        Some((&id, &secret)),
        &redeem(&code, &with_assertion),
    )
    .await;
    assert_eq!(both.status, StatusCode::BAD_REQUEST);
    assert_eq!(both.body["error"], "invalid_request");

    // Only a form, and only POST.
    let not_a_form = reqwest::Client::new()
        .post(format!("{}/t/acme/oauth2/token", server.base))
        .json(&json!({"grant_type": "authorization_code"}))
        .send()
        .await
        .expect("response");
    assert_eq!(not_a_form.status(), StatusCode::BAD_REQUEST);
    let get = reqwest::get(format!("{}/t/acme/oauth2/token", server.base))
        .await
        .expect("response");
    assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
}
