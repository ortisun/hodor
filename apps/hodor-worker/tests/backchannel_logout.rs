//! Back-channel logout sent by the worker binary, run as a real process
//! against a real database, to clients the test runs on this machine.
//!
//! This machine's addresses are what the guarded client refuses, so the
//! clients are reached through the development exception, and a client
//! named `localhost` without it shows the refusal.

use axum::Extension;
use axum::body::Body;
use hodor_adapters_crypto::{LocalKeyProvider, OsRandom, SecretKeys, Sha256Digest};
use hodor_adapters_http::{GuardedHttpClient, OutboundPolicy};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgApplicationStore, PgClientStore, PgGrantStore, PgKeyStore, PgResourceServerStore,
    PgTenantDirectory, PgTenantRepository,
};
use hodor_kernel::{
    Actor, Caller, Clock as _, CorrelationId, DestinationCheck, DomainError, EventEnvelope,
    EventMetadata, Secret, SystemClock, TenantContext, UnitOfWorkFactory, UserId,
};
use hodor_keys::api::KeyService;
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, Client, ClientSettings, ClientType,
    CreateClient, Grant, GrantId, GrantStatus, GrantStore as _, GrantType, IdTokenAlgorithm,
};
use hodor_session::api::SessionId;
use hodor_tenant::api::{CreateTenant, TenantService};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tower::ServiceExt as _;

const PUBLIC_URL: &str = "https://login.example.com";

/// One request a client received.
#[derive(Debug, Clone)]
struct Received {
    at: Instant,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Received {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map_or("", |(_, value)| value.as_str())
    }

    fn logout_token(&self) -> String {
        String::from_utf8(self.body.clone())
            .expect("text")
            .strip_prefix("logout_token=")
            .expect("a form with the logout token alone")
            .to_owned()
    }
}

/// A client's back-channel logout address on this machine: keeps every
/// request and answers each with the status it is told.
#[derive(Clone)]
struct Address {
    port: u16,
    received: Arc<Mutex<Vec<Received>>>,
    status: Arc<AtomicU16>,
}

impl Address {
    async fn start(status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = Self {
            port: listener.local_addr().expect("address").port(),
            received: Arc::default(),
            status: Arc::new(AtomicU16::new(status)),
        };
        let serving = address.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let serving = serving.clone();
                tokio::spawn(async move {
                    let Some(request) = read_request(&mut stream).await else {
                        return;
                    };
                    serving
                        .received
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(request);
                    let status = serving.status.load(Ordering::SeqCst);
                    let answer = format!(
                        "HTTP/1.1 {status} Answer\r\ncontent-length: 0\r\ncache-control: no-store\r\nconnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(answer.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        address
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/backchannel-logout", self.port)
    }

    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    fn received(&self) -> Vec<Received> {
        self.received
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Reads one request: its head, then as many bytes of body as it says.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Received> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
    };
    let head = String::from_utf8_lossy(&bytes[..head_end]).to_string();
    let headers: Vec<(String, String)> = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = bytes[head_end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Some(Received {
        at: Instant::now(),
        headers,
        body,
    })
}

/// Says every address may be called, as a name that resolved to a public
/// address when it was set would.
struct EverywhereThen;

#[async_trait::async_trait]
impl DestinationCheck for EverywhereThen {
    async fn check(&self, _url: &str) -> Result<(), DomainError> {
        Ok(())
    }
}

/// The guarded client, with the development exception for these hosts.
fn guarded(hosts: &[String]) -> Arc<dyn DestinationCheck> {
    Arc::new(
        GuardedHttpClient::new(OutboundPolicy {
            development_hosts: hosts.to_vec(),
            ..OutboundPolicy::default()
        })
        .expect("client"),
    )
}

fn root_setting() -> String {
    format!("root:{}", SecretKeys::generate(&OsRandom).expose())
}

fn keys(database: &TestDatabase, root: &str) -> KeyService {
    let root = Arc::new(SecretKeys::parse(&Secret::new(root.to_owned())).expect("root keys"));
    KeyService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root)),
        Arc::new(SystemClock),
    )
}

/// A tenant with this slug, as an operator makes one.
async fn tenant(database: &TestDatabase, slug: &str) -> TenantContext {
    let tenants = TenantService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        Arc::new(SystemClock),
    );
    let made = tenants
        .create(
            CreateTenant {
                slug: slug.to_owned(),
                display_name: "Acme".to_owned(),
                open_registration: false,
                system: false,
            },
            Caller::system(),
        )
        .await
        .expect("tenant");
    TenantContext::assume(made.id())
}

/// An application of the tenant, and a way to make its clients, whose
/// addresses are checked by `destinations`.
struct Applications {
    service: ApplicationService,
    application: hodor_oauth::api::ApplicationId,
}

impl Applications {
    async fn of(
        database: &TestDatabase,
        tenant: &TenantContext,
        destinations: Arc<dyn DestinationCheck>,
    ) -> Self {
        let service = ApplicationService::new(ApplicationPorts {
            units_of_work: Arc::new(database.app().clone()),
            applications: Arc::new(PgApplicationStore),
            clients: Arc::new(PgClientStore),
            resource_servers: Arc::new(PgResourceServerStore),
            digest: Arc::new(Sha256Digest),
            random: Arc::new(OsRandom),
            clock: Arc::new(SystemClock),
        })
        .with_destinations(destinations);
        let application = service
            .create_application(
                tenant,
                ApplicationSettings {
                    name: "Payroll".to_owned(),
                    first_party: true,
                },
                Caller::system(),
            )
            .await
            .expect("application")
            .id();
        Self {
            service,
            application,
        }
    }

    async fn client(
        &self,
        tenant: &TenantContext,
        address: Option<String>,
        algorithm: IdTokenAlgorithm,
    ) -> Client {
        let mut settings = ClientSettings::new(
            "Payroll web",
            ClientType::Confidential,
            vec![GrantType::AuthorizationCode],
            vec!["https://payroll.example.com/callback".to_owned()],
        );
        settings.backchannel_logout_uri = address;
        settings.id_token_algorithm = algorithm;
        self.service
            .create_client(
                tenant,
                CreateClient {
                    application_id: self.application,
                    client_type: ClientType::Confidential,
                    settings,
                    secret_lifetime: None,
                },
                Caller::system(),
            )
            .await
            .expect("client")
            .0
    }
}

/// A code was issued to `client` in `session` with `openid`.
async fn signed_in(
    database: &TestDatabase,
    tenant: &TenantContext,
    client: &Client,
    user: UserId,
    session: SessionId,
) {
    let mut uow = UnitOfWorkFactory::begin(database.app(), tenant)
        .await
        .expect("begin");
    PgGrantStore
        .insert(
            uow.as_mut(),
            &Grant {
                id: GrantId::generate(),
                client_id: client.id(),
                user_id: user,
                session_id: session,
                scopes: vec!["openid".to_owned(), "email".to_owned()],
                audiences: Vec::new(),
                organization: None,
                claims: hodor_oauth::api::GrantClaims::default(),
                status: GrantStatus::Active,
                created_at: SystemClock.now(),
                revoked_at: None,
                revocation_reason: None,
            },
        )
        .await
        .expect("grant");
    uow.commit().await.expect("commit");
}

/// The person signed out: `session.revoked` is in the outbox, as the
/// session context records it.
async fn signed_out(
    database: &TestDatabase,
    tenant: &TenantContext,
    user: UserId,
    session: SessionId,
) {
    let mut uow = UnitOfWorkFactory::begin(database.app(), tenant)
        .await
        .expect("begin");
    uow.record_event(EventEnvelope {
        metadata: EventMetadata::new(
            tenant.tenant_id(),
            Actor::User(user),
            CorrelationId::generate(),
            &SystemClock,
        ),
        event_type: "session.revoked".to_owned(),
        payload: serde_json::json!({
            "session_id": session.to_string(),
            "user_id": user.to_string(),
            "reason": "sign_out",
        }),
    });
    uow.commit().await.expect("commit");
}

fn start_worker(database: &TestDatabase, root: &str, settings: &[(&str, String)]) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hodor-worker"));
    command
        .env_remove("HODOR_SMTP_URL")
        .env_remove("HODOR_MAIL_FROM")
        .env_remove("HODOR_OUTBOUND_DEVELOPMENT_HOSTS")
        .env("HODOR_SECRET_KEYS", root)
        .env("HODOR_PUBLIC_URL", PUBLIC_URL)
        .env("HODOR_DATABASE_URL", database.app_url())
        .env("HODOR_PLATFORM_DATABASE_URL", database.platform_url())
        .env("HODOR_OPS_ADDR", "127.0.0.1:0")
        .env("HODOR_OUTBOX_POLL_INTERVAL_MS", "50")
        .env("HODOR_BACKCHANNEL_LOGOUT_POLL_INTERVAL_MS", "50")
        .env("HODOR_LOG_FORMAT", "pretty")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (name, value) in settings {
        command.env(name, value);
    }
    command.spawn().expect("worker should start")
}

async fn stop(mut worker: Child) {
    let status = Command::new("kill")
        .args(["-TERM", &worker.id().to_string()])
        .status()
        .expect("kill should run");
    assert!(status.success(), "sending SIGTERM failed");
    let status = tokio::task::spawn_blocking(move || worker.wait())
        .await
        .expect("wait task")
        .expect("worker exit status");
    assert!(
        status.success(),
        "the worker should exit with code 0: {status}"
    );
}

/// Waits up to `seconds` for `condition` to hold.
async fn eventually<F, Fut>(seconds: u64, mut condition: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let until = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < until {
        if condition().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// The status, attempts, last answer and last error of the one delivery to
/// `client`.
async fn delivery_to(
    database: &TestDatabase,
    client: &Client,
) -> Option<(String, i32, Option<i32>, Option<String>)> {
    sqlx::query_as(
        "SELECT status, attempts, last_response_status, last_error
         FROM oauth.logout_delivery WHERE client_id = $1",
    )
    .bind(client.id().as_uuid())
    .fetch_optional(database.owner())
    .await
    .expect("delivery")
}

/// The tenant's published key set, as `/t/{slug}/oauth2/jwks` answers it.
async fn key_set(keys: KeyService, tenant: &TenantContext) -> JwkSet {
    let answer = hodor_protocol_http::key_set_routes(keys)
        .layer(Extension(tenant.clone()))
        .oneshot(
            http::Request::get("/oauth2/jwks")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("answer");
    assert_eq!(answer.status(), http::StatusCode::OK);
    let body = axum::body::to_bytes(answer.into_body(), 1 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&body).expect("a key set")
}

/// The claims of a logout token, once its signature has been checked
/// against the key set with a library that is not Hodor's.
fn verified(token: &str, set: &JwkSet, client: &Client) -> serde_json::Value {
    let header = decode_header(token).expect("header");
    assert_eq!(header.typ.as_deref(), Some("logout+jwt"));
    let kid = header.kid.expect("kid");
    let jwk = set.find(&kid).expect("the key is published");
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[client.id().to_string()]);
    validation.set_issuer(&[format!("{PUBLIC_URL}/t/acme")]);
    validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
    decode::<serde_json::Value>(
        token,
        &DecodingKey::from_jwk(jwk).expect("decoding key"),
        &validation,
    )
    .expect("the signature checks against the tenant's key set")
    .claims
}

#[tokio::test]
async fn every_client_of_the_session_gets_one_logout_token_the_key_set_verifies() {
    let database = TestDatabase::start().await;
    let root = root_setting();
    let acme = tenant(&database, "acme").await;
    let (payroll_address, billing_address) = (Address::start(200).await, Address::start(204).await);
    let hosts = vec![payroll_address.host(), billing_address.host()];
    let applications = Applications::of(&database, &acme, guarded(&hosts)).await;
    let payroll = applications
        .client(&acme, Some(payroll_address.url()), IdTokenAlgorithm::Es256)
        .await;
    let billing = applications
        .client(&acme, Some(billing_address.url()), IdTokenAlgorithm::Rs256)
        .await;
    let reports = applications
        .client(&acme, None, IdTokenAlgorithm::Es256)
        .await;
    let (ana, session) = (UserId::generate(), SessionId::generate());
    for client in [&payroll, &billing, &reports] {
        signed_in(&database, &acme, client, ana, session).await;
    }
    // Another session of the same person, which does not end.
    signed_in(&database, &acme, &payroll, ana, SessionId::generate()).await;
    signed_out(&database, &acme, ana, session).await;

    let worker = start_worker(
        &database,
        &root,
        &[("HODOR_OUTBOUND_DEVELOPMENT_HOSTS", hosts.join(","))],
    );
    assert!(
        eventually(30, || async {
            !payroll_address.received().is_empty() && !billing_address.received().is_empty()
        })
        .await,
        "both clients with an address should be told"
    );
    let set = key_set(keys(&database, &root), &acme).await;
    for (client, address, algorithm) in [
        (&payroll, &payroll_address, Algorithm::ES256),
        (&billing, &billing_address, Algorithm::RS256),
    ] {
        let request = address.received()[0].clone();
        assert_eq!(
            request.header("content-type"),
            "application/x-www-form-urlencoded"
        );
        let token = request.logout_token();
        assert_eq!(decode_header(&token).expect("header").alg, algorithm);
        let claims = verified(&token, &set, client);
        assert_eq!(claims["sub"], ana.to_string());
        assert_eq!(claims["sid"], session.to_string());
        assert_eq!(
            claims["events"],
            serde_json::json!({ "http://schemas.openid.net/event/backchannel-logout": {} })
        );
        assert!(claims["jti"].is_string());
        assert!(claims.get("nonce").is_none());
        assert!(
            eventually(10, || async {
                delivery_to(&database, client)
                    .await
                    .is_some_and(|delivery| delivery.0 == "delivered" && delivery.1 == 1)
            })
            .await
        );
    }
    assert!(delivery_to(&database, &reports).await.is_none());
    stop(worker).await;
    assert_eq!(payroll_address.received().len(), 1, "told once");
    assert_eq!(billing_address.received().len(), 1, "told once");
}

#[tokio::test]
async fn a_client_that_refuses_is_tried_with_growing_waits_then_set_aside_while_another_is_told() {
    let database = TestDatabase::start().await;
    let root = root_setting();
    let acme = tenant(&database, "acme").await;
    let (down, up) = (Address::start(400).await, Address::start(200).await);
    let hosts = vec![down.host(), up.host()];
    let applications = Applications::of(&database, &acme, guarded(&hosts)).await;
    let refusing = applications
        .client(&acme, Some(down.url()), IdTokenAlgorithm::Es256)
        .await;
    let taking = applications
        .client(&acme, Some(up.url()), IdTokenAlgorithm::Es256)
        .await;
    let (ana, session) = (UserId::generate(), SessionId::generate());
    signed_in(&database, &acme, &refusing, ana, session).await;
    signed_in(&database, &acme, &taking, ana, session).await;
    signed_out(&database, &acme, ana, session).await;

    let worker = start_worker(
        &database,
        &root,
        &[
            ("HODOR_OUTBOUND_DEVELOPMENT_HOSTS", hosts.join(",")),
            ("HODOR_BACKCHANNEL_LOGOUT_MAX_ATTEMPTS", "3".to_owned()),
            ("HODOR_BACKCHANNEL_LOGOUT_FIRST_RETRY_MS", "400".to_owned()),
        ],
    );
    assert!(
        eventually(30, || async {
            delivery_to(&database, &taking)
                .await
                .is_some_and(|delivery| delivery.0 == "delivered")
        })
        .await,
        "the client that takes it is told whatever the other does"
    );
    assert!(
        eventually(30, || async {
            delivery_to(&database, &refusing)
                .await
                .is_some_and(|delivery| delivery.0 == "set_aside")
        })
        .await,
        "the refused delivery should be set aside"
    );
    let attempts = down.received();
    assert_eq!(attempts.len(), 3);
    let first_wait = attempts[1].at - attempts[0].at;
    let second_wait = attempts[2].at - attempts[1].at;
    assert!(first_wait >= Duration::from_millis(400), "{first_wait:?}");
    assert!(second_wait >= Duration::from_millis(800), "{second_wait:?}");
    assert!(second_wait > first_wait);
    let tokens: Vec<String> = attempts.iter().map(Received::logout_token).collect();
    assert_ne!(tokens[0], tokens[1], "each attempt is signed anew");
    let set_aside = delivery_to(&database, &refusing).await.expect("delivery");
    assert_eq!(set_aside.1, 3);
    assert_eq!(set_aside.2, Some(400));
    assert_eq!(set_aside.3.as_deref(), Some("the client answered 400"));
    let recorded: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM platform.outbox WHERE event_type = 'oauth.backchannel_logout_set_aside'",
    )
    .fetch_one(database.owner())
    .await
    .expect("outbox");
    assert_eq!(recorded, 1);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(down.received().len(), 3, "nothing more is tried");
    stop(worker).await;
    assert_eq!(up.received().len(), 1);
}

#[tokio::test]
async fn an_address_that_leads_to_this_machine_is_refused_when_set_and_when_called() {
    let database = TestDatabase::start().await;
    let root = root_setting();
    let acme = tenant(&database, "acme").await;
    let address = Address::start(200).await;

    // Set through the guarded client, a private address is refused.
    let checked = Applications::of(&database, &acme, guarded(&[])).await;
    for url in [
        format!("https://127.0.0.1:{}/logout", address.port),
        format!("https://localhost:{}/logout", address.port),
        "https://169.254.169.254/latest/meta-data".to_owned(),
    ] {
        let mut settings = ClientSettings::new(
            "Payroll web",
            ClientType::Confidential,
            vec![GrantType::AuthorizationCode],
            vec!["https://payroll.example.com/callback".to_owned()],
        );
        settings.backchannel_logout_uri = Some(url.clone());
        let error = checked
            .service
            .create_client(
                &acme,
                CreateClient {
                    application_id: checked.application,
                    client_type: ClientType::Confidential,
                    settings,
                    secret_lifetime: None,
                },
                Caller::system(),
            )
            .await
            .expect_err(&url);
        assert_eq!(
            error.code(),
            "oauth.client_backchannel_logout_uri_forbidden",
            "{url}"
        );
    }

    // A name that resolved to a public address when it was set and leads
    // to this machine now is refused when it is called.
    let moved = Applications::of(&database, &acme, Arc::new(EverywhereThen)).await;
    let client = moved
        .client(
            &acme,
            Some(format!("https://localhost:{}/logout", address.port)),
            IdTokenAlgorithm::Es256,
        )
        .await;
    let (ana, session) = (UserId::generate(), SessionId::generate());
    signed_in(&database, &acme, &client, ana, session).await;
    signed_out(&database, &acme, ana, session).await;
    let worker = start_worker(
        &database,
        &root,
        &[("HODOR_BACKCHANNEL_LOGOUT_MAX_ATTEMPTS", "1".to_owned())],
    );
    assert!(
        eventually(30, || async {
            delivery_to(&database, &client)
                .await
                .is_some_and(|delivery| delivery.0 == "set_aside")
        })
        .await,
        "the delivery should be set aside"
    );
    let refused = delivery_to(&database, &client).await.expect("delivery");
    assert_eq!(refused.2, None, "nothing answered");
    assert!(
        refused
            .3
            .as_deref()
            .is_some_and(|reason| reason.starts_with("http.destination_forbidden")),
        "{:?}",
        refused.3
    );
    stop(worker).await;
    assert!(address.received().is_empty(), "nothing was connected to");
}
