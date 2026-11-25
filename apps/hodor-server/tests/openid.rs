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
    PgApplicationStore, PgClientStore, PgGroupPolicy, PgGroupRepository, PgInvitationRepository,
    PgKeyStore, PgOrganizationRepository, PgPasswordStore, PgResourceServerStore,
    PgTenantDirectory, PgTenantRepository, PgUserRepository,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_identity::api::{
    CreateUser, GroupMember, GroupService, IdentifierKind, IdentityService, OrganizationService,
    Profile, UserKind,
};
use hodor_kernel::{Caller, Digest as _, Secret, SystemClock, TenantContext};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod, ClientId,
    ClientSettings, ClientType, CreateClient, CreateResourceServer, GrantType, IdTokenAlgorithm,
    ResourceServerSettings, ScopeDefinition, s256_challenge,
};
use hodor_tenant::api::{CreateTenant, TenantService};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

mod support;
use support::{Browser, MEMORY_KIBIBYTES, PASSES, Server, base32, start_server_with};

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
    tenant_signing_with(database, slug, IdTokenAlgorithm::Es256).await
}

async fn tenant_signing_with(
    database: &TestDatabase,
    slug: &str,
    id_token_algorithm: IdTokenAlgorithm,
) -> ClientId {
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
    settings.id_token_algorithm = id_token_algorithm;
    settings.allowed_scopes = ["openid", "profile", "email", "groups", "payroll:read"]
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
    // Back-channel logout is offered, and every logout token carries `sid`.
    assert_eq!(document["backchannel_logout_supported"], true);
    assert_eq!(document["backchannel_logout_session_supported"], true);
    assert!(
        document["scopes_supported"]
            .as_array()
            .is_some_and(|scopes| scopes.contains(&Value::from("groups")))
    );
    for claim in ["org_id", "groups"] {
        assert!(
            document["claims_supported"]
                .as_array()
                .is_some_and(|claims| claims.contains(&Value::from(claim))),
            "{claim}"
        );
    }

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
    let logout = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client")
        .get(local(&document["end_session_endpoint"]))
        .send()
        .await
        .expect("response");
    assert_eq!(
        logout.status(),
        StatusCode::FOUND,
        "answers: nobody to sign out, so to the sign-in page"
    );
    for endpoint in ["revocation_endpoint", "introspection_endpoint"] {
        let response = http
            .post(local(&document[endpoint]))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("token=anything&client_id=unknown")
            .send()
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{endpoint}");
        let refusal: Value = response.json().await.expect("JSON");
        assert_eq!(
            refusal["error"], "invalid_client",
            "{endpoint} answers, as OAuth"
        );
    }

    // The grants it names are answered by the token endpoint, and the ones
    // it does not name are refused as unsupported.
    let advertised: Vec<&str> = document["grant_types_supported"]
        .as_array()
        .expect("grants")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for grant in [
        "authorization_code",
        "refresh_token",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:token-exchange",
    ] {
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
    let (_, session) = browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(
        claims["sid"], session["session_id"],
        "the session the person signed in with"
    );

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

/// Who Ana is in a tenant, by its slug.
#[tokio::test]
async fn a_token_names_the_organization_and_the_groups_of_the_person() {
    let database = TestDatabase::start().await;
    let client_id = tenant(&database, "acme").await;
    let (tenant, ana) = ana_of(&database, "acme").await;
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(SystemClock);
    let groups = GroupService::new(
        units(),
        Arc::new(PgGroupRepository),
        Arc::new(PgUserRepository),
        Arc::new(PgGroupPolicy),
        clock.clone(),
    );
    let staff = groups
        .create(&tenant, "staff", None, Caller::system())
        .await
        .expect("group")
        .id();
    let finance = groups
        .create(&tenant, "finance", None, Caller::system())
        .await
        .expect("group")
        .id();
    groups
        .add_member(
            &tenant,
            staff,
            GroupMember::Group(finance),
            Caller::system(),
        )
        .await
        .expect("nested");
    groups
        .add_member(&tenant, finance, GroupMember::User(ana), Caller::system())
        .await
        .expect("member");
    let organizations = OrganizationService::new(
        units(),
        Arc::new(PgOrganizationRepository),
        Arc::new(PgInvitationRepository),
        Arc::new(PgUserRepository),
        clock,
    );
    let initech = organizations
        .create(&tenant, "Initech", None, Caller::system())
        .await
        .expect("organization")
        .id();
    organizations
        .add_member(&tenant, initech, ana, BTreeSet::new(), Caller::system())
        .await
        .expect("member");
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;

    let named = initech.to_string();
    let code = code(
        &mut browser,
        "acme",
        &authorize_query(
            client_id,
            "openid groups",
            &[("organization", named.as_str())],
        ),
    )
    .await;
    let answer = redeem(&server, "acme", client_id, &code).await;
    let access = claims_of(answer["access_token"].as_str().expect("an access token"));
    assert_eq!(access["org_id"], named);
    let mut expected = vec![staff.to_string(), finance.to_string()];
    expected.sort();
    assert_eq!(
        access["groups"],
        serde_json::json!(expected),
        "her own group and the one that holds it"
    );
    let identity = claims_of(answer["id_token"].as_str().expect("an ID token"));
    assert_eq!(identity["org_id"], named);
    assert!(identity.get("groups").is_none());

    let info = userinfo(
        &server,
        "acme",
        Method::GET,
        answer["access_token"].as_str(),
    )
    .await;
    assert_eq!(info.status, StatusCode::OK);
    assert_eq!(info.body["groups"], serde_json::json!(expected));
}

#[tokio::test]
async fn a_client_that_asks_for_rs256_gets_id_tokens_from_the_published_rsa_key() {
    let database = TestDatabase::start().await;
    let client_id = tenant_signing_with(&database, "acme", IdTokenAlgorithm::Rs256).await;
    let server = server(&database).await;
    let key_set = || async {
        reqwest::get(format!("{}/t/acme/oauth2/jwks", server.base))
            .await
            .expect("key set")
            .json::<JwkSet>()
            .await
            .expect("JSON")
    };
    let rsa = |set: &JwkSet| {
        set.keys
            .iter()
            .filter(|key| key.common.key_algorithm == Some(jsonwebtoken::jwk::KeyAlgorithm::RS256))
            .count()
    };
    // The first read of the key set gives the tenant a key for every
    // algorithm its tokens may be signed with, before any such token.
    let before = key_set().await;
    assert_eq!(
        rsa(&before),
        1,
        "an RSA key is published before the first RS256 token"
    );

    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    let first = code(
        &mut browser,
        "acme",
        &authorize_query(client_id, "openid", &[("nonce", NONCE)]),
    )
    .await;
    let tokens = redeem(&server, "acme", client_id, &first).await;
    let id_token = tokens["id_token"].as_str().expect("an ID token");
    let header = decode_header(id_token).expect("header");
    assert_eq!(header.alg, Algorithm::RS256);
    let published = key_set().await;
    assert_eq!(rsa(&published), 1, "no other key was made for it");
    assert!(
        before.find(header.kid.as_deref().expect("kid")).is_some(),
        "a relying party that read the set before finds the key that signed"
    );
    let jwk = published
        .find(&header.kid.expect("kid"))
        .expect("the key that signed");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id.to_string()]);
    validation.set_issuer(&[issuer("acme")]);
    let claims = decode::<Value>(
        id_token,
        &DecodingKey::from_jwk(jwk).expect("key"),
        &validation,
    )
    .expect("the ID token checks")
    .claims;
    assert_eq!(claims["nonce"], NONCE);

    // The access token is still signed with the default.
    let access =
        decode_header(tokens["access_token"].as_str().expect("access token")).expect("header");
    assert_eq!(access.alg, Algorithm::ES256);

    // A second token is signed by the same key: none is made again.
    let again = code(
        &mut browser,
        "acme",
        &authorize_query(client_id, "openid", &[("nonce", NONCE)]),
    )
    .await;
    redeem(&server, "acme", client_id, &again).await;
    assert_eq!(rsa(&key_set().await), 1);

    // An ID token signed with RS256 is a hint logout accepts.
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!("/t/acme/oauth2/logout?id_token_hint={id_token}"),
            None,
        )
        .await;
    assert_ne!(status, StatusCode::BAD_REQUEST, "{location:?}");
}

async fn ana_of(database: &TestDatabase, slug: &str) -> (TenantContext, hodor_kernel::UserId) {
    let units = Arc::new(database.app().clone());
    let entry = TenantService::new(
        units.clone(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        Arc::new(SystemClock),
    )
    .find_by_slug(slug)
    .await
    .expect("lookup")
    .expect("the tenant");
    let tenant = TenantContext::assume(entry.tenant_id);
    let ana = IdentityService::new(units, Arc::new(PgUserRepository), Arc::new(SystemClock))
        .find_by_login(&tenant, "ana@example.com")
        .await
        .expect("lookup")
        .expect("Ana")
        .id();
    (tenant, ana)
}

/// Gives Ana an authenticator application, with the server's own way of
/// keeping its secret, and answers the secret's bytes.
async fn enroll_application(database: &TestDatabase, slug: &str) -> Vec<u8> {
    use hodor_adapters_crypto::AwsLcHmacSha1;
    use hodor_adapters_postgres::{PgSealingStateStore, PgTotpStore};
    use hodor_credential::api::{TotpService, totp_code_at};
    use hodor_keys::api::TenantSecretBox;

    let (tenant, ana) = ana_of(database, slug).await;
    let units = Arc::new(database.app().clone());
    let root = Arc::new(SecretKeys::parse(&Secret::from(ROOT_KEY.to_owned())).expect("root"));
    let sealing = TenantSecretBox::new(
        units.clone(),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root.clone())),
        Arc::new(PgSealingStateStore),
        Some(root),
        Arc::new(SystemClock),
    );
    let totp = TotpService::new(
        units,
        Arc::new(PgTotpStore),
        Arc::new(sealing),
        Arc::new(AwsLcHmacSha1),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    );
    let enrollment = totp
        .begin_enrollment(&tenant, ana, slug, "ana@example.com")
        .await
        .expect("begin");
    let secret = base32(enrollment.secret());
    let code = totp_code_at(
        &AwsLcHmacSha1,
        &secret,
        hodor_kernel::Clock::now(&SystemClock),
    );
    totp.confirm_enrollment(&tenant, ana, &Secret::from(code), Caller::system())
        .await
        .expect("confirm");
    secret
}

/// A code of Ana's application that has not been used: the next one,
/// which the window accepts.
fn next_code(secret: &[u8]) -> String {
    use hodor_adapters_crypto::AwsLcHmacSha1;
    use hodor_credential::api::totp_code_at;
    let later = hodor_kernel::Clock::now(&SystemClock) + time::Duration::seconds(30);
    totp_code_at(&AwsLcHmacSha1, secret, later)
}

/// Gives a tenant a phishing-resistant level, under a name of its own.
async fn add_strong_level(database: &TestDatabase, slug: &str) {
    use hodor_tenant::api::{AssuranceLevel, AssuranceLevels, AssuranceRequirement};
    let (tenant, _) = ana_of(database, slug).await;
    let tenants = TenantService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        Arc::new(SystemClock),
    );
    let mut settings = tenants
        .get(&tenant)
        .await
        .expect("tenant")
        .snapshot()
        .settings
        .clone();
    let mut levels: Vec<AssuranceLevel> = settings
        .authentication
        .assurance_levels
        .levels()
        .into_iter()
        .cloned()
        .collect();
    levels.push(AssuranceLevel {
        acr: "urn:acme:phishing-resistant".to_owned(),
        requirement: AssuranceRequirement::PhishingResistant,
    });
    settings.authentication.assurance_levels = AssuranceLevels::new(levels).expect("valid");
    tenants
        .change_settings(&tenant, settings, Caller::system())
        .await
        .expect("changed");
}

/// The claims of a token, unchecked: its signature is checked elsewhere.
fn claims_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("a payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url")).expect("JSON")
}

#[tokio::test]
async fn an_application_that_asks_for_more_gets_it_after_only_the_missing_factor() {
    let database = TestDatabase::start().await;
    let client_id = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);

    // A password session first; the application comes later.
    let (_, signed_in) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(signed_in["status"], "completed");
    let secret = enroll_application(&database, "acme").await;

    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/authorize?{}",
                authorize_query(client_id, "openid", &[("acr_values", "urn:hodor:acr:mfa")])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    let location = location.expect("a redirect");
    assert!(
        location.starts_with("/t/acme/account/sign-in?"),
        "{location}"
    );

    // The page finds the step-up and is asked only for the code.
    let (status, waiting) = browser
        .send(Method::GET, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{waiting}");
    assert_eq!(waiting["step"], "totp", "{waiting}");
    let (status, done) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/sign-in/steps/totp",
            Some(serde_json::json!({ "code": next_code(&secret) })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["status"], "completed", "{done}");
    let resume = done["continue"].as_str().expect("continue").to_owned();

    let (status, location, body) = browser.navigate(Method::GET, &resume, None).await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    let answer = query_of(&location.expect("a redirect"));
    let tokens = redeem(&server, "acme", client_id, &answer["code"]).await;
    let id_token = claims_of(tokens["id_token"].as_str().expect("ID token"));
    assert_eq!(id_token["acr"], "urn:hodor:acr:mfa");
    assert_eq!(id_token["amr"], serde_json::json!(["pwd", "otp", "mfa"]));
    let access_token = claims_of(tokens["access_token"].as_str().expect("access token"));
    assert_eq!(access_token["acr"], "urn:hodor:acr:mfa");
    assert_eq!(access_token["amr"], id_token["amr"]);

    // Now the session is enough: the next request is answered at once.
    let again = code(
        &mut browser,
        "acme",
        &authorize_query(client_id, "openid", &[("acr_values", "urn:hodor:acr:mfa")]),
    )
    .await;
    assert!(!again.is_empty());
}

#[tokio::test]
async fn a_level_out_of_reach_is_unmet_and_another_tenants_level_asks_for_nothing() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let globex = tenant(&database, "globex").await;
    add_strong_level(&database, "acme").await;
    let server = server(&database).await;

    // Acme: Ana has an application, which is not phishing-resistant.
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    enroll_application(&database, "acme").await;
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/authorize?{}",
                authorize_query(
                    acme,
                    "openid",
                    &[
                        ("acr_values", "urn:acme:phishing-resistant"),
                        ("state", "s1")
                    ]
                )
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let answer = query_of(&location.expect("a redirect"));
    assert_eq!(answer["error"], "unmet_authentication_requirements");
    assert_eq!(answer["state"], "s1");

    // Discovery names Acme's three levels, and Globex's two.
    let document: Value = reqwest::get(format!(
        "{}/t/acme/.well-known/openid-configuration",
        server.base
    ))
    .await
    .expect("document")
    .json()
    .await
    .expect("JSON");
    assert_eq!(
        document["acr_values_supported"],
        serde_json::json!([
            "urn:hodor:acr:single-factor",
            "urn:hodor:acr:mfa",
            "urn:acme:phishing-resistant"
        ])
    );

    // At Globex the same name is no level: nothing more is asked.
    let mut other = Browser::not_following(&server);
    other.sign_in("globex", "ana@example.com", PASSWORD).await;
    let code = code(
        &mut other,
        "globex",
        &authorize_query(
            globex,
            "openid",
            &[("acr_values", "urn:acme:phishing-resistant")],
        ),
    )
    .await;
    let tokens = redeem(&server, "globex", globex, &code).await;
    let id_token = claims_of(tokens["id_token"].as_str().expect("ID token"));
    assert_eq!(id_token["acr"], "urn:hodor:acr:single-factor");
}

#[tokio::test]
async fn max_age_asks_again_for_the_password_and_not_for_the_identifier() {
    let database = TestDatabase::start().await;
    let client_id = tenant(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let (status, _, _) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/authorize?{}",
                authorize_query(client_id, "openid", &[("max_age", "0")])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let (_, waiting) = browser
        .send(Method::GET, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(waiting["step"], "password", "{waiting}");
    let (_, done) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/sign-in/steps/password",
            Some(serde_json::json!({ "password": PASSWORD })),
        )
        .await;
    assert_eq!(done["status"], "completed", "{done}");
    let resume = done["continue"].as_str().expect("continue").to_owned();
    let (status, location, body) = browser.navigate(Method::GET, &resume, None).await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    let answer = query_of(&location.expect("a redirect"));
    let tokens = redeem(&server, "acme", client_id, &answer["code"]).await;
    let id_token = claims_of(tokens["id_token"].as_str().expect("ID token"));
    let auth_time = id_token["auth_time"].as_i64().expect("auth_time");
    let issued = id_token["iat"].as_i64().expect("iat");
    assert!(issued - auth_time <= 5, "the person proved it just now");
}

/// Makes a tenant require a second factor of everyone who signs in.
async fn require_second_factor(database: &TestDatabase, slug: &str) {
    let (tenant, _) = ana_of(database, slug).await;
    let tenants = TenantService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        Arc::new(SystemClock),
    );
    let mut settings = tenants
        .get(&tenant)
        .await
        .expect("tenant")
        .snapshot()
        .settings
        .clone();
    settings.authentication.second_factor = hodor_tenant::api::SecondFactorPolicy::Required;
    tenants
        .change_settings(&tenant, settings, Caller::system())
        .await
        .expect("changed");
}

/// How many rows of `table` of the tenant hold `text` anywhere.
async fn rows_holding(database: &TestDatabase, table: &str, text: &str) -> i64 {
    // The table is one of this file's own names, never input.
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM {table} AS row WHERE strpos(row_to_json(row)::text, $1) > 0"
    )))
    .bind(text)
    .fetch_one(database.owner())
    .await
    .expect("count")
}

#[tokio::test]
async fn under_the_policy_a_person_with_no_factor_sets_up_an_application_while_signing_in() {
    use hodor_adapters_crypto::AwsLcHmacSha1;
    use hodor_credential::api::totp_code_at;

    let database = TestDatabase::start().await;
    let client_id = tenant(&database, "acme").await;
    require_second_factor(&database, "acme").await;
    let (tenant_context, ana) = ana_of(&database, "acme").await;
    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);

    // An application sends Ana to sign in; she has no second factor.
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/authorize?{}",
                authorize_query(client_id, "openid", &[("nonce", NONCE)])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    assert!(
        location
            .expect("a redirect")
            .starts_with("/t/acme/account/sign-in?"),
    );
    let (status, waiting) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "{waiting}");
    assert_eq!(
        (waiting["status"].as_str(), waiting["step"].as_str()),
        (Some("pending"), Some("enrollment")),
        "{waiting}"
    );
    let (_, kinds) = browser
        .send(
            Method::GET,
            "/t/acme/interaction/sign-in/steps/enrollment/kinds",
            None,
        )
        .await;
    assert_eq!(
        kinds["kinds"],
        serde_json::json!(["authenticator_application", "security_key", "passkey"])
    );

    // She scans the QR code; the test reads the secret it holds.
    let (status, begun) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/sign-in/steps/enrollment/options",
            Some(serde_json::json!({ "kind": "authenticator_application" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{begun}");
    let shown = begun["secret"].as_str().expect("secret").to_owned();
    assert_eq!(
        begun["uri"],
        format!(
            "otpauth://totp/acme:ana%40example.com?secret={shown}&issuer=acme&algorithm=SHA1&digits=6&period=30"
        )
    );
    // The sign-in keeps which enrollment it began; no row anywhere holds
    // the secret as it was shown.
    let (kind, id): (Option<String>, Option<sqlx::types::Uuid>) = sqlx::query_as(
        "SELECT enrollment_kind, enrollment_id FROM authentication.transaction
         WHERE tenant_id = $1 AND candidate_user_id = $2",
    )
    .bind(tenant_context.tenant_id().as_uuid())
    .bind(ana.as_uuid())
    .fetch_one(database.owner())
    .await
    .expect("the transaction");
    assert_eq!(kind.as_deref(), Some("authenticator_application"));
    let id = id.expect("the enrollment");
    let pending: String =
        sqlx::query_scalar("SELECT status FROM credential.totp WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_context.tenant_id().as_uuid())
            .bind(id)
            .fetch_one(database.owner())
            .await
            .expect("the enrollment");
    assert_eq!(pending, "pending");
    for table in ["authentication.transaction", "credential.totp"] {
        assert_eq!(rows_holding(&database, table, &shown).await, 0, "{table}");
    }

    let secret = base32(&shown);
    let code = totp_code_at(
        &AwsLcHmacSha1,
        &secret,
        hodor_kernel::Clock::now(&SystemClock),
    );
    let (status, done) = browser
        .send(
            Method::POST,
            "/t/acme/interaction/sign-in/steps/enrollment",
            Some(serde_json::json!({ "code": code })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["status"], "completed", "{done}");
    let codes: Vec<String> = done["recovery_codes"]
        .as_array()
        .expect("recovery codes, once")
        .iter()
        .map(|code| code.as_str().expect("a code").to_owned())
        .collect();
    assert_eq!(codes.len(), 10);
    for code in &codes {
        assert_eq!(
            rows_holding(&database, "credential.recovery_code", code).await,
            0,
            "a recovery code is kept only as its hash"
        );
    }
    let (_, who) = browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_eq!(who["assurance"], "multi_factor", "{who}");
    assert_eq!(
        who["methods"],
        serde_json::json!(["password", "enrollment"])
    );

    // The application's tokens say multi-factor.
    let resume = done["continue"].as_str().expect("continue").to_owned();
    let (status, location, body) = browser.navigate(Method::GET, &resume, None).await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    let answer = query_of(&location.expect("a redirect"));
    let tokens = redeem(&server, "acme", client_id, &answer["code"]).await;
    let id_token = claims_of(tokens["id_token"].as_str().expect("ID token"));
    assert_eq!(id_token["acr"], "urn:hodor:acr:mfa");
    assert_eq!(id_token["amr"], serde_json::json!(["pwd", "mfa"]));
    let access_token = claims_of(tokens["access_token"].as_str().expect("access token"));
    assert_eq!(access_token["acr"], "urn:hodor:acr:mfa");

    // The audit trail has the enrollment, and the next sign-in asks for
    // the code of the application set up.
    let enrolled: Vec<Value> = sqlx::query_scalar(
        "SELECT payload FROM platform.outbox
         WHERE tenant_id = $1 AND event_type = 'authentication.second_factor_enrolled'",
    )
    .bind(tenant_context.tenant_id().as_uuid())
    .fetch_all(database.owner())
    .await
    .expect("events");
    assert_eq!(
        enrolled,
        [serde_json::json!({ "user_id": ana, "kind": "authenticator_application" })]
    );
    let mut later = Browser::not_following(&server);
    let (_, waiting) = later.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(waiting["step"], "totp", "{waiting}");
    let (_, done) = later
        .send(
            Method::POST,
            "/t/acme/interaction/sign-in/steps/totp",
            Some(serde_json::json!({ "code": next_code(&secret) })),
        )
        .await;
    assert_eq!(done["status"], "completed", "{done}");
}
