//! Trust bundles fetched again by the worker binary, run as a real process
//! against a real database, from a bundle endpoint the test runs on this
//! machine.
//!
//! This machine's addresses are exactly what the guarded client refuses,
//! so the endpoint is reached through the development exception, and a
//! bundle endpoint named `localhost` without it shows the refusal.

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::routing::get;
use hodor_adapters_crypto::Sha256Digest;
use hodor_adapters_http::{GuardedHttpClient, OutboundPolicy};
use hodor_adapters_postgres::PgTrustDomainStore;
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_kernel::{Caller, SystemClock, TenantContext, TenantId};
use hodor_keys::api::{TrustDomainId, TrustDomainPorts, TrustDomainService, TrustSourceRequest};
use hodor_keys::testing::{FakeBundleEndpoints, sample_bundle};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

/// A bundle endpoint on this machine: answers what it is told, and keeps
/// the paths it was asked for.
#[derive(Clone, Default)]
struct Endpoint {
    answer: Arc<Mutex<(StatusCode, String)>>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Endpoint {
    async fn start(&self) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let port = listener.local_addr().expect("address").port();
        let app = Router::new()
            .fallback(get(|State(endpoint): State<Self>, uri: Uri| async move {
                endpoint
                    .asked
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(uri.path().to_owned());
                endpoint
                    .answer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
            }))
            .with_state(self.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        port
    }

    fn serve(&self, status: StatusCode, body: String) {
        *self.answer.lock().unwrap_or_else(|e| e.into_inner()) = (status, body);
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

fn service(database: &TestDatabase, hosts: &[String]) -> TrustDomainService {
    let guarded = || {
        Arc::new(
            GuardedHttpClient::new(OutboundPolicy {
                development_hosts: hosts.to_vec(),
                ..OutboundPolicy::default()
            })
            .expect("client"),
        )
    };
    TrustDomainService::new(TrustDomainPorts {
        units_of_work: Arc::new(database.app().clone()),
        store: Arc::new(PgTrustDomainStore),
        destinations: guarded(),
        http: guarded(),
        digest: Arc::new(Sha256Digest),
        clock: Arc::new(SystemClock),
    })
}

fn start_worker(database: &TestDatabase, hosts: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_hodor-worker"))
        .env_remove("HODOR_SMTP_URL")
        .env_remove("HODOR_MAIL_FROM")
        .env_remove("HODOR_SECRET_KEYS")
        .env("HODOR_OUTBOUND_DEVELOPMENT_HOSTS", hosts)
        .env("HODOR_DATABASE_URL", database.app_url())
        .env("HODOR_PLATFORM_DATABASE_URL", database.platform_url())
        .env("HODOR_OPS_ADDR", "127.0.0.1:0")
        .env("HODOR_TRUST_BUNDLE_POLL_INTERVAL_MS", "50")
        .env("HODOR_LOG_FORMAT", "pretty")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("worker should start")
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

/// What is stored of a trust domain's bundle and refresh: the sequence of
/// the bundle in force, the code of the last failure, and whether a lease
/// is held.
async fn stored(database: &TestDatabase, id: TrustDomainId) -> (Option<i64>, Option<String>, bool) {
    sqlx::query_as(
        "SELECT bundle_sequence, last_error, leased_until IS NOT NULL
         FROM keys.trust_domain WHERE id = $1",
    )
    .bind(id.as_uuid())
    .fetch_one(database.owner())
    .await
    .expect("trust domain")
}

/// Makes the trust domain's bundle due now, as five minutes passing would.
async fn due_now(database: &TestDatabase, id: TrustDomainId) {
    sqlx::query("UPDATE keys.trust_domain SET next_refresh_at = now() WHERE id = $1")
        .bind(id.as_uuid())
        .execute(database.owner())
        .await
        .expect("due");
}

async fn events(database: &TestDatabase, tenant: &TenantContext) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT event_type FROM platform.outbox
         WHERE tenant_id = $1 AND event_type LIKE 'keys.trust%'
         ORDER BY created_at, id",
    )
    .bind(tenant.tenant_id().as_uuid())
    .fetch_all(database.owner())
    .await
    .expect("events")
}

#[tokio::test]
async fn the_worker_refreshes_a_bundle_and_keeps_it_when_the_next_does_not_read() {
    let database = TestDatabase::start().await;
    let endpoint = Endpoint::default();
    let port = endpoint.start().await;
    let host = format!("127.0.0.1:{port}");
    let url = format!("http://{host}/bundle");
    endpoint.serve(StatusCode::OK, sample_bundle(Some(1), &["one"]).to_string());
    let tenant = TenantContext::assume(TenantId::generate());
    let added = service(&database, std::slice::from_ref(&host))
        .add(
            &tenant,
            "spire.example",
            TrustSourceRequest::BundleEndpoint { url: url.clone() },
            Caller::system(),
        )
        .await
        .expect("added");
    assert_eq!(stored(&database, added.id()).await.0, Some(1));

    // A bundle endpoint named `localhost`, which the development exception
    // does not cover: it was accepted when it was saved, as a name that
    // resolved to a public address would have been, and is refused at
    // every fetch without any connection.
    let named = format!("https://localhost:{port}/named");
    let anywhere = FakeBundleEndpoints::default();
    anywhere.serve(&named, &sample_bundle(Some(1), &["named"]));
    let refused = TrustDomainService::new(TrustDomainPorts {
        units_of_work: Arc::new(database.app().clone()),
        store: Arc::new(PgTrustDomainStore),
        destinations: Arc::new(anywhere.clone()),
        http: Arc::new(anywhere),
        digest: Arc::new(Sha256Digest),
        clock: Arc::new(SystemClock),
    })
    .add(
        &tenant,
        "named.example",
        TrustSourceRequest::BundleEndpoint { url: named },
        Caller::system(),
    )
    .await
    .expect("added");

    let worker = start_worker(&database, &host);

    // A newer bundle is put in force.
    endpoint.serve(StatusCode::OK, sample_bundle(Some(2), &["two"]).to_string());
    due_now(&database, added.id()).await;
    due_now(&database, refused.id()).await;
    assert!(
        eventually(20, || async {
            stored(&database, added.id()).await == (Some(2), None, false)
        })
        .await,
        "the newer bundle is in force: {:?}",
        stored(&database, added.id()).await
    );
    assert!(
        eventually(20, || async {
            stored(&database, refused.id()).await.1.as_deref()
                == Some("keys.bundle_endpoint_forbidden")
        })
        .await,
        "the name leading to this machine is refused: {:?}",
        stored(&database, refused.id()).await
    );
    assert!(
        !endpoint.asked().iter().any(|path| path == "/named"),
        "nothing was asked of the refused name"
    );

    // A bundle that does not read keeps the one in force.
    endpoint.serve(StatusCode::OK, "{\"keys\": \"none\"}".to_owned());
    due_now(&database, added.id()).await;
    assert!(
        eventually(20, || async {
            stored(&database, added.id()).await
                == (Some(2), Some("keys.trust_bundle_invalid".to_owned()), false)
        })
        .await,
        "the bundle in force is kept: {:?}",
        stored(&database, added.id()).await
    );

    // So does an older one, and a failing endpoint.
    endpoint.serve(StatusCode::OK, sample_bundle(Some(1), &["one"]).to_string());
    due_now(&database, added.id()).await;
    assert!(
        eventually(20, || async {
            stored(&database, added.id()).await
                == (
                    Some(2),
                    Some("keys.trust_bundle_sequence_invalid".to_owned()),
                    false,
                )
        })
        .await,
        "an older bundle never replaces a newer one: {:?}",
        stored(&database, added.id()).await
    );
    endpoint.serve(StatusCode::SERVICE_UNAVAILABLE, String::new());
    due_now(&database, added.id()).await;
    assert!(
        eventually(20, || async {
            stored(&database, added.id()).await
                == (
                    Some(2),
                    Some("keys.bundle_endpoint_unreachable".to_owned()),
                    false,
                )
        })
        .await,
        "a failing endpoint keeps the bundle: {:?}",
        stored(&database, added.id()).await
    );
    stop(worker).await;

    let kept: String = sqlx::query_scalar("SELECT bundle FROM keys.trust_domain WHERE id = $1")
        .bind(added.id().as_uuid())
        .fetch_one(database.owner())
        .await
        .expect("bundle");
    assert!(kept.contains("\"kid\":\"two\""));
    // Every change audited; one failure for the run of failures of each
    // trust domain.
    let mut recorded = events(&database, &tenant).await;
    recorded.sort();
    assert_eq!(
        recorded,
        [
            "keys.trust_bundle_refresh_failed",
            "keys.trust_bundle_refresh_failed",
            "keys.trust_bundle_refreshed",
            "keys.trust_domain_added",
            "keys.trust_domain_added",
        ]
    );
}
