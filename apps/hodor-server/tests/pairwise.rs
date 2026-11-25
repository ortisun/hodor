//! Pairwise subject identifiers at the real server binary, against a real
//! database: one person signs in to four applications, two of one sector,
//! one of another and one public, and each is told who she is as its
//! sector knows her, in its ID token, its access token, at UserInfo, at
//! introspection, through a token exchange, at the end-session endpoint and
//! in its logout token.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hodor_adapters_crypto::{
    Argon2Parameters, Argon2idHasher, AwsLcHmacSha256, HashingLimits, LocalKeyProvider, OsRandom,
    SecretKeys, Sha256Digest,
};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    OutboxDispatcher, PgApplicationStore, PgClientStore, PgDueLogoutDeliveries, PgKeyStore,
    PgLogoutDeliveryStore, PgPairwiseSecretStore, PgPasswordStore, PgResourceServerStore,
    PgSealingStateStore, PgSessionClients, PgTenantDirectory, PgTenantRepository, PgUserRepository,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, Secret, SystemClock, TenantContext, UserId};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy, TenantSecretBox};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings,
    BackChannelLogoutFanOut, BackChannelLogoutSender, ClientSettings, ClientType, CreateClient,
    CreateResourceServer, ExchangeRule, GrantType, LogoutDeliverySettings, LogoutSenderPorts,
    PairwisePorts, PairwiseSubjects, ResourceServerSettings, ScopeDefinition, SubjectType,
    s256_challenge,
};
use hodor_oauth::testing::{FakeDestinations, RecordingClients};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

mod support;
use support::{Browser, MEMORY_KIBIBYTES, PASSES, Server, start_server_with};

const PASSWORD: &str = "correct horse battery staple";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const AUDIENCE: &str = "https://api.payroll.example.com";
/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";
const OUT: &str = "https://payroll.example.com/signed-out";
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// A client of the test: its identifier, its secret and its one redirect
/// address.
#[derive(Clone)]
struct App {
    id: String,
    secret: String,
    redirect: &'static str,
}

struct Tenant {
    context: TenantContext,
    ana: UserId,
    applications: ApplicationService,
    payroll: ApplicationId,
}

fn root() -> Arc<SecretKeys> {
    Arc::new(SecretKeys::parse(&Secret::from(ROOT_KEY.to_owned())).expect("root"))
}

/// The tenant `acme`, with Ana, who has a password, an active signing key,
/// and the application Payroll, which has a resource server.
async fn tenant(database: &TestDatabase) -> Tenant {
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
            slug: "acme".to_owned(),
            display_name: "Acme".to_owned(),
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
    KeyService::new(
        units(),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root())),
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
    })
    .with_destinations(Arc::new(FakeDestinations));
    let payroll = applications
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
    applications
        .create_resource_server(
            &context,
            CreateResourceServer {
                application_id: payroll,
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
        context,
        ana,
        applications,
        payroll,
    }
}

/// A confidential client of a first-party application named `name`.
async fn app(
    tenant: &Tenant,
    name: &str,
    subject_type: SubjectType,
    redirect: &'static str,
    logout: Option<&str>,
) -> App {
    let application = tenant
        .applications
        .create_application(
            &tenant.context,
            ApplicationSettings {
                name: name.to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application")
        .id();
    let mut settings = ClientSettings::new(
        name,
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec![redirect.to_owned()],
    );
    settings.allowed_scopes = vec![
        "openid".to_owned(),
        "email".to_owned(),
        "payroll:read".to_owned(),
    ];
    settings.subject_type = subject_type;
    settings.backchannel_logout_uri = logout.map(str::to_owned);
    settings.post_logout_redirect_uris = vec![OUT.to_owned()];
    let (client, secret) = tenant
        .applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: application,
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    App {
        id: client.id().to_string(),
        secret: secret.expect("a secret").expose().to_owned(),
        redirect,
    }
}

async fn server(database: &TestDatabase) -> Server {
    start_server_with(database, &[("HODOR_SECRET_KEYS", ROOT_KEY)]).await
}

fn form(pairs: &[(&str, &str)]) -> String {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

async fn post(server: &Server, endpoint: &str, app: &App, pairs: &[(&str, &str)]) -> Value {
    let response = reqwest::Client::new()
        .post(format!("{}/t/acme/oauth2/{endpoint}", server.base))
        .header("content-type", "application/x-www-form-urlencoded")
        .header(
            "authorization",
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", app.id, app.secret))
            ),
        )
        .body(form(pairs))
        .send()
        .await
        .expect("response");
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::OK, "{endpoint}: {body}");
    body
}

/// The tokens `app` gets from the session the browser holds.
async fn tokens(browser: &mut Browser, server: &Server, app: &App) -> Value {
    let challenge = s256_challenge(VERIFIER, &Sha256Digest);
    let (status, location, body) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/authorize?{}",
                form(&[
                    ("response_type", "code"),
                    ("client_id", &app.id),
                    ("redirect_uri", app.redirect),
                    ("scope", "openid email payroll:read"),
                    ("resource", AUDIENCE),
                    ("code_challenge", &challenge),
                    ("code_challenge_method", "S256"),
                ])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    let location = location.expect("a redirect");
    let (_, query) = location.split_once('?').expect("a query");
    let answer: BTreeMap<String, String> = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    post(
        server,
        "token",
        app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &answer["code"]),
            ("redirect_uri", app.redirect),
            ("code_verifier", VERIFIER),
        ],
    )
    .await
}

fn claims_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("claims");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url")).expect("JSON")
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap_or_else(|| panic!("no {name}"))
}

/// The issuer the server names, for the worker's use case in this test.
struct IssuerOf(String);

#[async_trait::async_trait]
impl hodor_oauth::api::TenantIssuer for IssuerOf {
    async fn issuer(&self, _tenant: &TenantContext) -> Result<String, hodor_kernel::DomainError> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn two_applications_of_one_sector_share_an_identifier_and_another_sector_does_not() {
    let database = TestDatabase::start().await;
    let tenant = tenant(&database).await;
    let payroll_logout = "https://payroll.example.com/backchannel-logout";
    let travel_logout = "https://travel.example.net/backchannel-logout";
    let payroll = app(
        &tenant,
        "Payroll web",
        SubjectType::Pairwise,
        "https://payroll.example.com/callback",
        Some(payroll_logout),
    )
    .await;
    // Of the same host, another path and port: the same sector.
    let payslips = app(
        &tenant,
        "Payslips",
        SubjectType::Pairwise,
        "https://payroll.example.com:8443/payslips",
        None,
    )
    .await;
    let travel = app(
        &tenant,
        "Travel",
        SubjectType::Pairwise,
        "https://travel.example.net/callback",
        Some(travel_logout),
    )
    .await;
    let reports = app(
        &tenant,
        "Reports",
        SubjectType::Public,
        "https://reports.example.org/callback",
        None,
    )
    .await;

    let server = server(&database).await;
    let mut browser = Browser::not_following(&server);
    let (_, answer) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(answer["status"], "completed", "{answer}");
    let mut issued = BTreeMap::new();
    for (name, app) in [
        ("payroll", &payroll),
        ("payslips", &payslips),
        ("travel", &travel),
        ("reports", &reports),
    ] {
        issued.insert(name, tokens(&mut browser, &server, app).await);
    }
    let id_token = |name: &str| claims_of(text(&issued[name], "id_token"));
    let sub = |name: &str| id_token(name)["sub"].clone();
    let sid = |name: &str| id_token(name)["sid"].clone();

    // The demonstration: compare their `sub`.
    assert_eq!(sub("payroll"), sub("payslips"), "one sector");
    assert_ne!(sub("payroll"), sub("travel"), "two sectors");
    assert_eq!(sub("reports"), tenant.ana.to_string(), "a public client");
    for name in ["payroll", "travel"] {
        assert_ne!(sub(name), tenant.ana.to_string());
        assert_ne!(sid(name), sid("reports"));
    }
    assert_eq!(sid("payroll"), sid("payslips"));
    assert_ne!(sid("payroll"), sid("travel"));

    // Each access token, UserInfo and introspection say the same as the
    // ID token.
    for (name, app) in [
        ("payroll", &payroll),
        ("payslips", &payslips),
        ("travel", &travel),
        ("reports", &reports),
    ] {
        let access = text(&issued[name], "access_token");
        assert_eq!(claims_of(access)["sub"], sub(name), "{name}");
        let userinfo: Value = reqwest::Client::new()
            .get(format!("{}/t/acme/oauth2/userinfo", server.base))
            .bearer_auth(access)
            .send()
            .await
            .expect("response")
            .json()
            .await
            .expect("JSON");
        assert_eq!(userinfo["sub"], sub(name), "{name}: {userinfo}");
        assert_eq!(userinfo["email"], "ana@example.com");
        let introspected = post(&server, "introspect", app, &[("token", access)]).await;
        assert_eq!(introspected["active"], true, "{introspected}");
        assert_eq!(introspected["sub"], sub(name), "{name}");
    }

    // An agent given Payroll's token holds one on Ana's behalf that names
    // her as Payroll knows her.
    let agent = IdentityService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgUserRepository),
        Arc::new(SystemClock),
    )
    .create(
        &tenant.context,
        CreateUser {
            kind: UserKind::Agent,
            identifiers: Vec::new(),
            profile: Profile::default(),
            confirmed: true,
        },
        Caller::system(),
    )
    .await
    .expect("an agent")
    .id();
    let mut settings = ClientSettings::new(
        "Assistant",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials, GrantType::TokenExchange],
        Vec::new(),
    );
    settings.allowed_scopes = vec!["payroll:read".to_owned()];
    settings.principal = Some(agent);
    settings.exchange_rules = vec![ExchangeRule {
        subject_audience: AUDIENCE.to_owned(),
        audience: AUDIENCE.to_owned(),
    }];
    let (assistant, secret) = tenant
        .applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: tenant.payroll,
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    let assistant = App {
        id: assistant.id().to_string(),
        secret: secret.expect("a secret").expose().to_owned(),
        redirect: "",
    };
    let own = post(
        &server,
        "token",
        &assistant,
        &[("grant_type", "client_credentials")],
    )
    .await;
    let exchanged = post(
        &server,
        "token",
        &assistant,
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", text(&issued["payroll"], "access_token")),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("actor_token", text(&own, "access_token")),
            ("actor_token_type", ACCESS_TOKEN_TYPE),
            ("audience", AUDIENCE),
        ],
    )
    .await;
    let held = text(&exchanged, "access_token");
    assert_eq!(claims_of(held)["sub"], sub("payroll"));
    assert_eq!(claims_of(held)["act"]["sub"], agent.to_string());
    let introspected = post(&server, "introspect", &assistant, &[("token", held)]).await;
    assert_eq!(introspected["sub"], sub("payroll"));
    // The record of what happened names Ana by her user identifier.
    let (payload,): (Value,) = sqlx::query_as(
        "SELECT payload FROM platform.outbox WHERE event_type = 'oauth.token_exchanged'",
    )
    .fetch_one(database.owner())
    .await
    .expect("the event");
    assert_eq!(payload["subject_id"], tenant.ana.to_string());

    // The tenant's one pairwise secret is stored sealed.
    let stored: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT sealed_secret FROM oauth.pairwise_secret")
            .fetch_all(database.owner())
            .await
            .expect("secrets");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0][0], hodor_keys::api::SEALED_FORMAT);

    // Payroll signs Ana out with its own ID token: its pairwise `sub` and
    // `sid` name her session, so it ends without asking.
    let response = browser
        .client
        .get(format!(
            "{}/t/acme/oauth2/logout?{}",
            server.base,
            form(&[
                ("id_token_hint", text(&issued["payroll"], "id_token")),
                ("post_logout_redirect_uri", OUT),
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
    assert_eq!(response.headers()["location"], OUT, "ended without asking");
    let (status, _) = browser
        .send(Method::GET, "/t/acme/interaction/session", None)
        .await;
    assert_ne!(status, StatusCode::OK, "the session ended");

    // The worker's part: each application with an address is told, as it
    // knows Ana and her session.
    let dispatcher = OutboxDispatcher::new(
        database.platform().clone(),
        database.app().clone(),
        vec![Arc::new(BackChannelLogoutFanOut::new(
            Arc::new(PgSessionClients),
            Arc::new(PgClientStore),
            Arc::new(PgApplicationStore),
            Arc::new(PgLogoutDeliveryStore),
            Arc::new(SystemClock),
        ))],
    );
    while dispatcher
        .dispatch_batch(100)
        .await
        .expect("dispatch")
        .delivered
        > 0
    {}
    let clients = RecordingClients::default();
    let issuer = text(&id_token("payroll"), "iss").to_owned();
    let sender = BackChannelLogoutSender::new(
        LogoutSenderPorts {
            units_of_work: Arc::new(database.app().clone()),
            clients: Arc::new(PgClientStore),
            deliveries: Arc::new(PgLogoutDeliveryStore),
            due: Arc::new(PgDueLogoutDeliveries::new(database.platform().clone())),
            issuers: Arc::new(IssuerOf(issuer.clone())),
            keys: KeyService::new(
                Arc::new(database.app().clone()),
                Arc::new(PgKeyStore),
                Arc::new(LocalKeyProvider::new(root())),
                Arc::new(SystemClock),
            ),
            http: Arc::new(clients.clone()),
            random: Arc::new(OsRandom),
            clock: Arc::new(SystemClock),
        },
        LogoutDeliverySettings::default(),
    )
    .with_pairwise_subjects(PairwiseSubjects::new(PairwisePorts {
        units_of_work: Arc::new(database.app().clone()),
        secrets: Arc::new(PgPairwiseSecretStore),
        secret_box: Arc::new(TenantSecretBox::new(
            Arc::new(database.app().clone()),
            Arc::new(PgKeyStore),
            Arc::new(LocalKeyProvider::new(root())),
            Arc::new(PgSealingStateStore),
            Some(root()),
            Arc::new(SystemClock),
        )),
        mac: Arc::new(AwsLcHmacSha256),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    }));
    let leases = sender.lease_due(10).await.expect("leased");
    assert_eq!(leases.len(), 2, "Payroll and Travel have an address");
    for lease in leases {
        sender.send(lease).await.expect("sent");
    }
    let set: jsonwebtoken::jwk::JwkSet =
        reqwest::get(format!("{}/t/acme/oauth2/jwks", server.base))
            .await
            .expect("key set")
            .json()
            .await
            .expect("JSON");
    for (name, app, address) in [
        ("payroll", &payroll, payroll_logout),
        ("travel", &travel, travel_logout),
    ] {
        let told = clients.tokens_to(address);
        assert_eq!(told.len(), 1, "{name} is told once");
        let header = jsonwebtoken::decode_header(&told[0]).expect("header");
        let jwk = set.find(&header.kid.expect("kid")).expect("published");
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.set_audience(&[app.id.as_str()]);
        validation.set_issuer(&[issuer.as_str()]);
        let claims = jsonwebtoken::decode::<Value>(
            &told[0],
            &jsonwebtoken::DecodingKey::from_jwk(jwk).expect("key"),
            &validation,
        )
        .expect("the signature checks")
        .claims;
        assert_eq!(claims["sub"], sub(name), "{name}");
        assert_eq!(claims["sid"], sid(name), "{name}");
    }

    // Discovery says both subject types.
    let discovery: Value = reqwest::get(format!(
        "{}/t/acme/.well-known/openid-configuration",
        server.base
    ))
    .await
    .expect("discovery")
    .json()
    .await
    .expect("JSON");
    assert_eq!(
        discovery["subject_types_supported"],
        json!(["public", "pairwise"])
    );
}
