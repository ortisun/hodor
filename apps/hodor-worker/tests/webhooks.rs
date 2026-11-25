//! Webhooks sent by the worker binary, run as a real process against a
//! real database, to endpoints the test runs on this machine.
//!
//! This machine's addresses are exactly what the guarded client refuses,
//! so the endpoints are reached through the development exception, and an
//! endpoint named `localhost` without it shows the refusal.

use hodor_adapters_crypto::{LocalKeyProvider, OsRandom, SecretKeys};
use hodor_adapters_http::{GuardedHttpClient, OutboundPolicy};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgDeliveryStore, PgEndpointStore, PgKeyStore, PgSealingStateStore};
use hodor_kernel::{
    Actor, Caller, CorrelationId, DestinationCheck, DomainError, EventEnvelope, EventMetadata,
    Secret, SystemClock, TenantContext, TenantId, UnitOfWorkFactory,
};
use hodor_keys::api::TenantSecretBox;
use hodor_webhooks::api::{DeliveryId, RegisterEndpoint, WebhookService};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::Notify;

/// One request an endpoint received.
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
}

/// An endpoint on this machine: keeps every request, answers each with the
/// status it is told, and, when told to hold, answers only once released.
#[derive(Clone)]
struct Endpoint {
    port: u16,
    received: Arc<Mutex<Vec<Received>>>,
    status: Arc<AtomicU16>,
    hold: Arc<Mutex<bool>>,
    released: Arc<Notify>,
}

impl Endpoint {
    async fn start(status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let endpoint = Self {
            port: listener.local_addr().expect("address").port(),
            received: Arc::default(),
            status: Arc::new(AtomicU16::new(status)),
            hold: Arc::default(),
            released: Arc::new(Notify::new()),
        };
        let serving = endpoint.clone();
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
                    let holding = *serving.hold.lock().unwrap_or_else(|e| e.into_inner());
                    if holding {
                        serving.released.notified().await;
                    }
                    let status = serving.status.load(Ordering::SeqCst);
                    let answer = format!(
                        "HTTP/1.1 {status} Answer\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(answer.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        endpoint
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/hook", self.port)
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

    fn answer(&self, status: u16) {
        self.status.store(status, Ordering::SeqCst);
    }

    fn holding(&self, hold: bool) {
        *self.hold.lock().unwrap_or_else(|e| e.into_inner()) = hold;
        if !hold {
            self.released.notify_waiters();
        }
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
/// address when it was registered would.
struct EverywhereThen;

#[async_trait::async_trait]
impl DestinationCheck for EverywhereThen {
    async fn check(&self, _url: &str) -> Result<(), DomainError> {
        Ok(())
    }
}

fn root_setting() -> String {
    format!("root:{}", SecretKeys::generate(&OsRandom).expose())
}

fn service(
    database: &TestDatabase,
    root: &str,
    destinations: Arc<dyn DestinationCheck>,
) -> WebhookService {
    let root = Arc::new(SecretKeys::parse(&Secret::new(root.to_owned())).expect("root keys"));
    let secrets = TenantSecretBox::new(
        Arc::new(database.app().clone()),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root.clone())),
        Arc::new(PgSealingStateStore),
        Some(root),
        Arc::new(SystemClock),
    );
    WebhookService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgEndpointStore),
        Arc::new(PgDeliveryStore),
        Arc::new(secrets),
        destinations,
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    )
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

async fn register(service: &WebhookService, tenant: &TenantContext, url: &str) -> String {
    let (_, secret) = service
        .register(
            tenant,
            RegisterEndpoint {
                url: url.to_owned(),
                description: None,
                event_types: vec!["session.started".to_owned()],
            },
            Caller::system(),
        )
        .await
        .expect("registered");
    secret.expose().clone()
}

/// A session starts in `tenant`: its event is in the outbox.
async fn session_started(database: &TestDatabase, tenant: &TenantContext) {
    let mut uow = UnitOfWorkFactory::begin(database.app(), tenant)
        .await
        .expect("begin");
    uow.record_event(EventEnvelope {
        metadata: EventMetadata::new(
            tenant.tenant_id(),
            Actor::System,
            CorrelationId::generate(),
            &SystemClock,
        ),
        event_type: "session.started".to_owned(),
        payload: serde_json::json!({ "session_id": "s", "methods": ["password"] }),
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
        .env("HODOR_DATABASE_URL", database.app_url())
        .env("HODOR_PLATFORM_DATABASE_URL", database.platform_url())
        .env("HODOR_OPS_ADDR", "127.0.0.1:0")
        .env("HODOR_OUTBOX_POLL_INTERVAL_MS", "50")
        .env("HODOR_WEBHOOK_POLL_INTERVAL_MS", "50")
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
/// the endpoint at `url`.
async fn delivery_to(
    database: &TestDatabase,
    url: &str,
) -> Option<(String, i32, Option<i32>, Option<String>, sqlx::types::Uuid)> {
    sqlx::query_as(
        "SELECT d.status, d.attempts, d.last_response_status, d.last_error, d.id
         FROM webhooks.delivery d JOIN webhooks.endpoint e
           ON e.tenant_id = d.tenant_id AND e.id = d.endpoint_id
         WHERE e.url = $1",
    )
    .bind(url)
    .fetch_optional(database.owner())
    .await
    .expect("delivery")
}

fn header_map(received: &Received) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in &received.headers {
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("name"),
            http::HeaderValue::from_str(value).expect("value"),
        );
    }
    headers
}

#[tokio::test]
async fn a_running_worker_sends_a_signed_webhook_that_another_library_checks() {
    let database = TestDatabase::start().await;
    let root = root_setting();
    let tenant = TenantContext::assume(TenantId::generate());
    let endpoint = Endpoint::start(204).await;
    let hosts = vec![endpoint.host()];
    let secret = register(
        &service(&database, &root, guarded(&hosts)),
        &tenant,
        &endpoint.url(),
    )
    .await;
    session_started(&database, &tenant).await;

    let worker = start_worker(
        &database,
        &root,
        &[("HODOR_OUTBOUND_DEVELOPMENT_HOSTS", hosts.join(","))],
    );
    assert!(
        eventually(20, || async { !endpoint.received().is_empty() }).await,
        "the endpoint should receive the event"
    );
    let request = endpoint.received()[0].clone();
    assert_eq!(request.header("content-type"), "application/json");
    // Checked by the `standardwebhooks` crate, which shares no code with
    // Hodor, with the secret the administrator was shown.
    standardwebhooks::Webhook::new(&secret)
        .expect("secret")
        .verify(&request.body, &header_map(&request))
        .expect("the signature checks with another implementation");
    let body: serde_json::Value = serde_json::from_slice(&request.body).expect("JSON");
    assert_eq!(body["type"], "session.started");
    assert_eq!(body["tenant_id"], tenant.tenant_id().to_string());
    assert_eq!(body["id"], request.header("webhook-id"));
    assert_eq!(body["data"]["methods"], serde_json::json!(["password"]));

    assert!(
        eventually(10, || async {
            delivery_to(&database, &endpoint.url())
                .await
                .is_some_and(|delivery| delivery.0 == "delivered" && delivery.1 == 1)
        })
        .await
    );
    stop(worker).await;
    assert_eq!(endpoint.received().len(), 1, "sent once");
}

#[tokio::test]
async fn a_failing_delivery_waits_longer_each_time_is_set_aside_and_sent_again_while_others_flow() {
    let database = TestDatabase::start().await;
    let root = root_setting();
    let tenant = TenantContext::assume(TenantId::generate());
    let (down, up, slow) = (
        Endpoint::start(503).await,
        Endpoint::start(204).await,
        Endpoint::start(204).await,
    );
    slow.holding(true);
    let hosts = vec![down.host(), up.host(), slow.host()];
    let service = service(&database, &root, guarded(&hosts));
    for endpoint in [&down, &up, &slow] {
        register(&service, &tenant, &endpoint.url()).await;
    }
    session_started(&database, &tenant).await;

    let worker = start_worker(
        &database,
        &root,
        &[
            ("HODOR_OUTBOUND_DEVELOPMENT_HOSTS", hosts.join(",")),
            ("HODOR_WEBHOOK_MAX_ATTEMPTS", "3".to_owned()),
            ("HODOR_WEBHOOK_FIRST_RETRY_MS", "400".to_owned()),
        ],
    );

    // One endpoint never answers and another refuses: the third gets its
    // event all the same.
    assert!(
        eventually(20, || async {
            !up.received().is_empty() && !slow.received().is_empty()
        })
        .await
    );
    assert!(
        eventually(10, || async {
            delivery_to(&database, &up.url())
                .await
                .is_some_and(|delivery| delivery.0 == "delivered")
        })
        .await
    );
    let held = delivery_to(&database, &slow.url()).await.expect("delivery");
    assert_eq!((held.0.as_str(), held.1), ("pending", 0), "still in flight");

    // The refused one is tried three times, each wait longer than the one
    // before, and then set aside.
    assert!(
        eventually(20, || async {
            delivery_to(&database, &down.url())
                .await
                .is_some_and(|delivery| delivery.0 == "set_aside")
        })
        .await,
        "the failing delivery should be set aside"
    );
    let attempts = down.received();
    assert_eq!(attempts.len(), 3);
    let first_wait = attempts[1].at - attempts[0].at;
    let second_wait = attempts[2].at - attempts[1].at;
    assert!(first_wait >= Duration::from_millis(400), "{first_wait:?}");
    assert!(second_wait >= Duration::from_millis(800), "{second_wait:?}");
    assert!(second_wait > first_wait);
    let set_aside = delivery_to(&database, &down.url()).await.expect("delivery");
    assert_eq!(set_aside.1, 3);
    assert_eq!(set_aside.2, Some(503));
    assert_eq!(set_aside.3.as_deref(), Some("the endpoint answered 503"));
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(down.received().len(), 3, "nothing more is tried");

    // Asked for again, it is sent again, with the same identifier.
    down.answer(200);
    service
        .redeliver(
            &tenant,
            DeliveryId::from_uuid(set_aside.4),
            Caller::system(),
        )
        .await
        .expect("delivered again");
    assert!(
        eventually(10, || async {
            delivery_to(&database, &down.url())
                .await
                .is_some_and(|delivery| delivery.0 == "delivered")
        })
        .await
    );
    let attempts = down.received();
    assert_eq!(attempts.len(), 4);
    assert_eq!(
        attempts[3].header("webhook-id"),
        attempts[0].header("webhook-id")
    );

    slow.holding(false);
    assert!(
        eventually(10, || async {
            delivery_to(&database, &slow.url())
                .await
                .is_some_and(|delivery| delivery.0 == "delivered")
        })
        .await
    );
    stop(worker).await;
}

#[tokio::test]
async fn an_endpoint_at_a_private_address_is_refused_when_registered_and_when_delivered_to() {
    let database = TestDatabase::start().await;
    let root = root_setting();
    let tenant = TenantContext::assume(TenantId::generate());
    let endpoint = Endpoint::start(204).await;

    // Registered through the guarded client, a private address is refused.
    for url in [
        format!("https://127.0.0.1:{}/hook", endpoint.port),
        format!("https://localhost:{}/hook", endpoint.port),
        "https://169.254.169.254/latest/meta-data".to_owned(),
    ] {
        let error = service(&database, &root, guarded(&[]))
            .register(
                &tenant,
                RegisterEndpoint {
                    url: url.clone(),
                    description: None,
                    event_types: vec!["session.started".to_owned()],
                },
                Caller::system(),
            )
            .await
            .expect_err(&url);
        assert_eq!(error.code(), "webhooks.endpoint_address_forbidden", "{url}");
    }

    // A name that resolved to a public address when it was registered and
    // leads to this machine now is refused when it is delivered to.
    let moved = format!("https://localhost:{}/hook", endpoint.port);
    register(
        &service(&database, &root, Arc::new(EverywhereThen)),
        &tenant,
        &moved,
    )
    .await;
    session_started(&database, &tenant).await;
    let worker = start_worker(
        &database,
        &root,
        &[("HODOR_WEBHOOK_MAX_ATTEMPTS", "1".to_owned())],
    );
    assert!(
        eventually(20, || async {
            delivery_to(&database, &moved)
                .await
                .is_some_and(|delivery| delivery.0 == "set_aside")
        })
        .await,
        "the delivery should be set aside"
    );
    let refused = delivery_to(&database, &moved).await.expect("delivery");
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
    assert!(endpoint.received().is_empty(), "nothing was connected to");
}
