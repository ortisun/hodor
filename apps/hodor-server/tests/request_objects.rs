//! Request objects at the real server binary, against a real database, by
//! value and at an address of the client's own web server:
//! objects signed with keys of the test's own making carry the request
//! through to its tokens, and those that must be refused are.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _, RSA_PSS_SHA256, RsaKeyPair,
};
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
    GrantType, RequestObjectAlgorithm, ResourceServerSettings, ScopeDefinition, s256_challenge,
};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

mod support;
use support::{
    Answer, Browser, ClientWebServer, MEMORY_KIBIBYTES, PASSES, Server, start_server_with,
};

const PASSWORD: &str = "correct horse battery staple";
const REDIRECT: &str = "https://payroll.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const AUDIENCE: &str = "https://api.payroll.example.com";
/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";

fn issuer(slug: &str) -> String {
    format!("http://localhost:8080/t/{slug}")
}

fn seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

struct Tenant {
    applications: ApplicationService,
    context: TenantContext,
    application: ApplicationId,
}

/// A tenant with Ana, who has a password, a signing key, and a
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

/// A confidential client proving who it is with `method`, with the
/// request object algorithm `chosen`, and its secret if it has one.
async fn make_client(
    tenant: &Tenant,
    method: AuthenticationMethod,
    chosen: Option<RequestObjectAlgorithm>,
) -> (ClientId, Option<String>) {
    let mut settings = ClientSettings::new(
        "Payroll",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.authentication_method = method;
    settings.allowed_scopes = vec!["openid".to_owned(), "payroll:read".to_owned()];
    settings.request_object_algorithm = chosen;
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
    (client.id(), secret.map(|value| value.expose().to_owned()))
}

/// The client's own keys; Hodor is given only their public halves.
struct Keys {
    ec: Vec<u8>,
    rsa: RsaKeyPair,
}

async fn give_keys(tenant: &Tenant, client: ClientId) -> Keys {
    let ec = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .expect("key")
        .as_ref()
        .to_vec();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &ec).expect("pair");
    let point = pair.public_key().as_ref();
    let rsa = RsaKeyPair::generate(KeySize::Rsa2048).expect("RSA key");
    let public = rsa.public_key();
    for jwk in [
        json!({
            "kty": "EC", "crv": "P-256", "kid": "ec", "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        }),
        json!({
            "kty": "RSA", "kid": "rsa",
            "n": URL_SAFE_NO_PAD.encode(public.modulus().big_endian_without_leading_zero()),
            "e": URL_SAFE_NO_PAD.encode(public.exponent().big_endian_without_leading_zero()),
        }),
    ] {
        tenant
            .applications
            .add_client_key(&tenant.context, client, &jwk.to_string(), Caller::system())
            .await
            .expect("key");
    }
    Keys { ec, rsa }
}

fn encode(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(value.to_string())
}

fn es256(keys: &Keys, claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        encode(&json!({"alg": "ES256", "kid": "ec"})),
        encode(claims)
    );
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &keys.ec).expect("pair");
    let signature = pair
        .sign(&SystemRandom::new(), input.as_bytes())
        .expect("signature");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
}

fn ps256(keys: &Keys, claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        encode(&json!({"alg": "PS256", "kid": "rsa"})),
        encode(claims)
    );
    let mut signature = vec![0; keys.rsa.public_modulus_len()];
    keys.rsa
        .sign(
            &RSA_PSS_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut signature,
        )
        .expect("signature");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn unsigned(claims: &Value) -> String {
    format!("{}.{}.", encode(&json!({"alg": "none"})), encode(claims))
}

/// The whole request, as a client puts it in its object.
fn claims(slug: &str, client: ClientId, nonce: &str) -> Value {
    let id = client.to_string();
    json!({
        "iss": id,
        "aud": issuer(slug),
        "exp": seconds_now() + 300,
        "nbf": seconds_now() - 5,
        "client_id": id,
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "scope": "openid payroll:read",
        "resource": [AUDIENCE],
        "state": "inside",
        "nonce": nonce,
        "code_challenge": s256_challenge(VERIFIER, &Sha256Digest),
        "code_challenge_method": "S256",
    })
}

/// Sends a signed-in browser to the authorization endpoint with `object`
/// and the parameters `outside`, and reads where it was sent back to.
async fn authorize(
    browser: &mut Browser,
    slug: &str,
    client: ClientId,
    object: &str,
    outside: &[(&str, &str)],
) -> BTreeMap<String, String> {
    let id = client.to_string();
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("client_id", id.as_str()), ("request", object)])
        .extend_pairs(outside.iter().copied())
        .finish();
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!("/t/{slug}/oauth2/authorize?{query}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    let location = location.expect("a redirect");
    let (address, query) = location.split_once('?').expect("a query");
    assert_eq!(address, REDIRECT, "only to the client's address");
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

async fn token(
    server: &Server,
    slug: &str,
    basic: Option<(&str, &str)>,
    pairs: &[(&str, &str)],
) -> (StatusCode, Value) {
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
    (status, response.json().await.unwrap_or(Value::Null))
}

/// An assertion of `client`, signed with its P-256 key.
fn assertion(slug: &str, client: ClientId, keys: &Keys, jti: &str) -> String {
    let id = client.to_string();
    es256(
        keys,
        &json!({
            "iss": id, "sub": id,
            "aud": format!("{}/oauth2/token", issuer(slug)),
            "exp": seconds_now() + 60, "iat": seconds_now(), "jti": jti,
        }),
    )
}

fn payload(token: &str) -> Value {
    let part = token.split('.').nth(1).expect("claims");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("JSON")
}

async fn server(database: &TestDatabase) -> Server {
    start_server_with(database, &[("HODOR_SECRET_KEYS", ROOT_KEY)]).await
}

#[tokio::test]
async fn a_request_object_signed_by_the_client_carries_the_request_to_its_tokens() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let (client, _) = make_client(&acme, AuthenticationMethod::PrivateKeyJwt, None).await;
    let keys = give_keys(&acme, client).await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    let (_, signed_in) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(signed_in["status"], "completed");

    // Signed with ES256; the parameters outside it are ignored but for the
    // three OpenID Connect asks to repeat, which agree, the scopes in
    // another order.
    let object = es256(&keys, &claims("acme", client, "nonce-es256"));
    let answer = authorize(
        &mut browser,
        "acme",
        client,
        &object,
        &[
            ("response_type", "code"),
            ("scope", "payroll:read openid"),
            ("state", "outside"),
            ("redirect_uri", "https://elsewhere.example.com/callback"),
        ],
    )
    .await;
    assert_eq!(answer["state"], "inside", "{answer:?}");
    assert_eq!(answer["iss"], issuer("acme"));
    let code = answer["code"].clone();
    let client_assertion = assertion("acme", client, &keys, "assertion-1");
    let (status, tokens) = token(
        &server,
        "acme",
        None,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", &client_assertion),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert_eq!(tokens["scope"], "openid payroll:read");
    let id_token = payload(tokens["id_token"].as_str().expect("an ID token"));
    assert_eq!(id_token["nonce"], "nonce-es256", "the nonce of the object");
    let access = payload(tokens["access_token"].as_str().expect("an access token"));
    assert!(
        access["aud"]
            .as_array()
            .is_some_and(|audiences| audiences.contains(&json!(AUDIENCE))),
        "the resource of the object: {access}"
    );

    // Signed with PS256 by the client's RSA key.
    let answer = authorize(
        &mut browser,
        "acme",
        client,
        &ps256(&keys, &claims("acme", client, "nonce-ps256")),
        &[],
    )
    .await;
    assert!(answer.contains_key("code"), "{answer:?}");

    // A scope outside that is not the one inside: invalid_request, at the
    // client's address.
    let answer = authorize(
        &mut browser,
        "acme",
        client,
        &object,
        &[("scope", "openid"), ("redirect_uri", REDIRECT)],
    )
    .await;
    assert_eq!(answer["error"], "invalid_request", "{answer:?}");
    assert!(!answer.contains_key("code"));

    // Discovery says so.
    let document: Value = reqwest::get(format!(
        "{}/t/acme/.well-known/openid-configuration",
        server.base
    ))
    .await
    .expect("discovery")
    .json()
    .await
    .expect("JSON");
    assert_eq!(document["request_parameter_supported"], true);
    assert_eq!(
        document["request_object_signing_alg_values_supported"],
        json!(["ES256", "RS256", "PS256", "none"])
    );
    assert_eq!(document["request_uri_parameter_supported"], true);
}

#[tokio::test]
async fn a_request_object_that_must_be_refused_is_refused() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let (client, _) = make_client(&acme, AuthenticationMethod::PrivateKeyJwt, None).await;
    let _keys = give_keys(&acme, client).await;
    let (stranger, _) = client_of_its_own(&acme).await;
    let stranger_keys = give_keys(&acme, stranger).await;
    let (strict, _) = make_client(
        &acme,
        AuthenticationMethod::PrivateKeyJwt,
        Some(RequestObjectAlgorithm::Es256),
    )
    .await;
    let (signs_nothing, secret) = make_client(
        &acme,
        AuthenticationMethod::ClientSecretBasic,
        Some(RequestObjectAlgorithm::None),
    )
    .await;
    let secret = secret.expect("a secret");
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    let outside = [("redirect_uri", REDIRECT), ("state", "outside")];

    // Signed by another client's key.
    let answer = authorize(
        &mut browser,
        "acme",
        client,
        &es256(&stranger_keys, &claims("acme", client, "n")),
        &outside,
    )
    .await;
    assert_eq!(answer["error"], "invalid_request_object", "{answer:?}");
    assert_eq!(answer["state"], "outside");

    // Not signed, for a client that names no algorithm and for one that
    // names ES256.
    for named in [client, strict] {
        let answer = authorize(
            &mut browser,
            "acme",
            named,
            &unsigned(&claims("acme", named, "n")),
            &outside,
        )
        .await;
        assert_eq!(answer["error"], "invalid_request_object", "{answer:?}");
    }

    // Not signed, for the client whose administrator chose `none`: read,
    // and the code is redeemed with its secret.
    let mut bare = claims("acme", signs_nothing, "n-unsigned");
    for name in ["iss", "aud", "exp", "nbf"] {
        bare.as_object_mut().expect("object").remove(name);
    }
    let answer = authorize(&mut browser, "acme", signs_nothing, &unsigned(&bare), &[]).await;
    let code = answer.get("code").expect("a code").clone();
    let id = signs_nothing.to_string();
    let (status, tokens) = token(
        &server,
        "acme",
        Some((&id, &secret)),
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let id_token = payload(tokens["id_token"].as_str().expect("an ID token"));
    assert_eq!(id_token["nonce"], "n-unsigned");

    // An object for nobody this tenant knows and an address of nobody's:
    // Hodor's own page.
    let mut nowhere = claims("acme", client, "n");
    nowhere["redirect_uri"] = json!("https://elsewhere.example.com/callback");
    let id = client.to_string();
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("client_id", id.as_str()), ("request", &unsigned(&nowhere))])
        .finish();
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!("/t/acme/oauth2/authorize?{query}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(location, None);
    assert!(
        body.contains("oauth.authorization_request_object_invalid"),
        "{body}"
    );
}

/// A second client with `private_key_jwt`, whose keys sign nothing of the
/// first's.
async fn client_of_its_own(tenant: &Tenant) -> (ClientId, Option<String>) {
    make_client(tenant, AuthenticationMethod::PrivateKeyJwt, None).await
}

/// A client with `private_key_jwt` whose request object addresses are
/// `request_uris`, checked as the server checks them, with the development
/// exception of `web`.
async fn client_with_addresses(
    tenant: &Tenant,
    web: &ClientWebServer,
    request_uris: &[String],
) -> Result<ClientId, hodor_kernel::DomainError> {
    let guarded =
        hodor_adapters_http::GuardedHttpClient::new(hodor_adapters_http::OutboundPolicy {
            development_hosts: vec![web.host.clone()],
            ..hodor_adapters_http::OutboundPolicy::default()
        })
        .expect("guarded client");
    let mut settings = ClientSettings::new(
        "Payroll",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.authentication_method = AuthenticationMethod::PrivateKeyJwt;
    settings.allowed_scopes = vec!["openid".to_owned(), "payroll:read".to_owned()];
    settings.request_uris = request_uris.to_vec();
    let (client, _) = tenant
        .applications
        .clone()
        .with_destinations(Arc::new(guarded))
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
        .await?;
    Ok(client.id())
}

/// Sends a browser to the authorization endpoint with `reference` as
/// `request_uri` and the parameters `outside`, and reads where it was sent
/// back to.
async fn authorize_by_reference(
    browser: &mut Browser,
    slug: &str,
    client: ClientId,
    reference: &str,
    outside: &[(&str, &str)],
) -> BTreeMap<String, String> {
    let id = client.to_string();
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("client_id", id.as_str()), ("request_uri", reference)])
        .extend_pairs(outside.iter().copied())
        .finish();
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!("/t/{slug}/oauth2/authorize?{query}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    let location = location.expect("a redirect");
    let (address, query) = location.split_once('?').expect("a query");
    assert_eq!(address, REDIRECT, "only to the client's address");
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn sha256_fragment(content: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        content,
    ))
}

#[tokio::test]
async fn a_request_object_at_the_client_s_address_carries_the_request_to_its_tokens() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let web = ClientWebServer::start();
    let client = client_with_addresses(&acme, &web, &[web.url("/requests/")])
        .await
        .expect("client");
    let keys = give_keys(&acme, client).await;
    let server = start_server_with(
        &database,
        &[
            ("HODOR_SECRET_KEYS", ROOT_KEY),
            ("HODOR_OUTBOUND_DEVELOPMENT_HOSTS", &web.host),
        ],
    )
    .await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;

    // Kept as a file is, with a line end, and named with its hash.
    let object = format!(
        "{}\n",
        es256(&keys, &claims("acme", client, "nonce-at-address"))
    );
    web.serve("/requests/one", Answer::content(object.clone()));
    let reference = format!(
        "{}#{}",
        web.url("/requests/one"),
        sha256_fragment(object.as_bytes())
    );
    let answer = authorize_by_reference(
        &mut browser,
        "acme",
        client,
        &reference,
        &[("response_type", "code"), ("scope", "openid payroll:read")],
    )
    .await;
    assert_eq!(answer["state"], "inside", "{answer:?}");
    let code = answer.get("code").expect("a code").clone();
    let client_assertion = assertion("acme", client, &keys, "assertion-at-address");
    let (status, tokens) = token(
        &server,
        "acme",
        None,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", &client_assertion),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let id_token = payload(tokens["id_token"].as_str().expect("an ID token"));
    assert_eq!(id_token["nonce"], "nonce-at-address");
    assert_eq!(
        web.asked(),
        ["/requests/one"],
        "fetched once, without its fragment"
    );

    // Discovery says that registered addresses are fetched.
    let document: Value = reqwest::get(format!(
        "{}/t/acme/.well-known/openid-configuration",
        server.base
    ))
    .await
    .expect("discovery")
    .json()
    .await
    .expect("JSON");
    assert_eq!(document["request_uri_parameter_supported"], true);
    assert_eq!(document["require_request_uri_registration"], true);
}

#[tokio::test]
async fn a_request_object_at_an_address_that_must_be_refused_is_refused() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let web = ClientWebServer::start();
    let client = client_with_addresses(&acme, &web, &[web.url("/requests/")])
        .await
        .expect("client");
    let keys = give_keys(&acme, client).await;

    // An address that leads to a private network is refused when it is
    // registered.
    let error = client_with_addresses(&acme, &web, &["https://10.255.255.1/requests/".to_owned()])
        .await
        .expect_err("a private address");
    assert_eq!(error.code(), "oauth.client_request_uri_forbidden");
    // One registered when its name led elsewhere, written here directly,
    // is refused when it is to be fetched.
    let moved = client_with_addresses(&acme, &web, &[web.url("/requests/")])
        .await
        .expect("client");
    sqlx::query("UPDATE oauth.client SET request_uris = $2 WHERE id = $1")
        .bind(moved.as_uuid())
        .bind(vec!["https://10.255.255.1/requests/".to_owned()])
        .execute(database.owner())
        .await
        .expect("written");

    let server = start_server_with(
        &database,
        &[
            ("HODOR_SECRET_KEYS", ROOT_KEY),
            ("HODOR_OUTBOUND_DEVELOPMENT_HOSTS", &web.host),
        ],
    )
    .await;
    let mut browser = Browser::not_following(&server);
    let outside = [("redirect_uri", REDIRECT), ("state", "outside")];
    let object = es256(&keys, &claims("acme", client, "n"));
    let refused = |answer: &BTreeMap<String, String>, what: &str| {
        assert_eq!(answer["error"], "invalid_request_uri", "{what}: {answer:?}");
        assert_eq!(answer["state"], "outside", "{what}");
        assert!(!answer.contains_key("code"), "{what}");
    };

    // An address the client did not register is never fetched.
    web.serve("/elsewhere/one", Answer::content(object.clone()));
    let answer = authorize_by_reference(
        &mut browser,
        "acme",
        client,
        &web.url("/elsewhere/one"),
        &outside,
    )
    .await;
    refused(&answer, "unregistered");

    // An address that resolves to a private network.
    let answer = authorize_by_reference(
        &mut browser,
        "acme",
        moved,
        "https://10.255.255.1/requests/one",
        &outside,
    )
    .await;
    refused(&answer, "private");
    assert!(
        web.asked().is_empty(),
        "nothing was fetched: {:?}",
        web.asked()
    );

    // Content whose hash differs from the fragment.
    web.serve("/requests/one", Answer::content(object.clone()));
    let answer = authorize_by_reference(
        &mut browser,
        "acme",
        client,
        &format!(
            "{}#{}",
            web.url("/requests/one"),
            sha256_fragment(b"another object")
        ),
        &outside,
    )
    .await;
    refused(&answer, "hash");

    // More than 16 kibibytes.
    web.serve(
        "/requests/large",
        Answer::content(vec![b'a'; 16 * 1024 + 1]),
    );
    let answer = authorize_by_reference(
        &mut browser,
        "acme",
        client,
        &web.url("/requests/large"),
        &outside,
    )
    .await;
    refused(&answer, "large");

    // A redirect, never followed.
    web.serve(
        "/requests/moved",
        Answer {
            status: 302,
            headers: vec![("location".to_owned(), web.url("/requests/one"))],
            body: Vec::new(),
            delay: std::time::Duration::ZERO,
        },
    );
    let before = web.asked().len();
    let answer = authorize_by_reference(
        &mut browser,
        "acme",
        client,
        &web.url("/requests/moved"),
        &outside,
    )
    .await;
    refused(&answer, "redirect");
    assert_eq!(web.asked()[before..], ["/requests/moved"], "not followed");

    // No answer within 5 seconds.
    let mut slow = Answer::content(object);
    slow.delay = std::time::Duration::from_secs(8);
    web.serve("/requests/slow", slow);
    let started = std::time::Instant::now();
    let answer = authorize_by_reference(
        &mut browser,
        "acme",
        client,
        &web.url("/requests/slow"),
        &outside,
    )
    .await;
    refused(&answer, "slow");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(7),
        "given up after 5 seconds: {:?}",
        started.elapsed()
    );
    assert!(
        !web.asked().contains(&"/elsewhere/one".to_owned()),
        "the unregistered address was never fetched"
    );
}
