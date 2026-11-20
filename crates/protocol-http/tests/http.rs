//! Behavior of the HTTP base layer, exercised through the router.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Router};
use hodor_kernel::{DomainError, ErrorKind, TenantContext, TenantId};
use hodor_protocol_http::{
    Health, Limits, Problem, ReadinessCheck, ResolvedTenant, TenantResolver, TenantStatus,
    ops_router, public_router, serve,
};
use http_body_util::BodyExt as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tower::ServiceExt as _;

/// Knows two tenants and counts lookups.
struct Tenants {
    acme: TenantId,
    lookups: AtomicUsize,
}

#[async_trait::async_trait]
impl TenantResolver for Tenants {
    async fn resolve(&self, slug: &str) -> Result<Option<ResolvedTenant>, DomainError> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        match slug {
            "acme" => Ok(Some(ResolvedTenant {
                context: TenantContext::assume(self.acme),
                status: TenantStatus::Active,
            })),
            "frozen" => Ok(Some(ResolvedTenant {
                context: TenantContext::assume(TenantId::generate()),
                status: TenantStatus::Suspended,
            })),
            "broken" => Err(DomainError::new(
                ErrorKind::Unavailable,
                "tenant.lookup_unavailable",
                "try again later",
            )),
            _ => Ok(None),
        }
    }
}

async fn whoami(Extension(tenant): Extension<TenantContext>) -> String {
    tenant.tenant_id().to_string()
}

async fn fail() -> impl IntoResponse {
    Problem::from(
        DomainError::internal("database.error", "the operation could not be completed")
            .with_detail("password authentication failed for user hodor_app_login"),
    )
}

async fn conflict() -> impl IntoResponse {
    Problem::from(DomainError::conflict(
        "user.identifier_taken",
        "identifier already in use",
    ))
}

async fn slow() -> &'static str {
    tokio::time::sleep(Duration::from_millis(300)).await;
    "done"
}

struct App {
    router: Router,
    tenants: Arc<Tenants>,
}

fn app_with(limits: Limits) -> App {
    let tenants = Arc::new(Tenants {
        acme: TenantId::generate(),
        lookups: AtomicUsize::new(0),
    });
    let routes = Router::new()
        .route("/whoami", get(whoami))
        .route("/fail", get(fail))
        .route("/conflict", get(conflict))
        .route("/slow", get(slow))
        .route("/echo", post(|body: String| async move { body }));
    App {
        router: public_router(tenants.clone(), routes, limits),
        tenants,
    }
}

fn app() -> App {
    app_with(Limits::default())
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).expect("JSON body")
    }
}

async fn send(router: &Router, request: Request<Body>) -> Reply {
    let response = router.clone().oneshot(request).await.expect("response");
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.expect("body").to_bytes();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8(bytes.to_vec()).expect("UTF-8 body"),
    }
}

async fn get_path(router: &Router, path: &str) -> Reply {
    send(
        router,
        Request::get(path).body(Body::empty()).expect("request"),
    )
    .await
}

#[tokio::test]
async fn handlers_receive_the_tenant_from_the_path() {
    let app = app();
    let reply = get_path(&app.router, "/t/acme/whoami").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, app.tenants.acme.to_string());
}

#[tokio::test]
async fn unknown_and_malformed_tenants_get_the_same_answer() {
    let app = app();
    let unknown = get_path(&app.router, "/t/nobody/whoami").await;
    let malformed = get_path(&app.router, "/t/No_Such.Tenant/whoami").await;
    let traversal = get_path(&app.router, "/t/../whoami").await;

    for reply in [&unknown, &malformed, &traversal] {
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_eq!(
            reply.headers[header::CONTENT_TYPE],
            "application/problem+json"
        );
        let mut body = reply.json();
        // The request id differs per request by design; everything else
        // must be identical.
        body.as_object_mut().expect("object").remove("request_id");
        assert_eq!(
            body,
            serde_json::json!({
                "type": "urn:hodor:error:tenant.not_found",
                "title": "Not Found",
                "status": 404,
                "detail": "the requested resource does not exist",
                "code": "tenant.not_found",
            })
        );
    }
    // Malformed slugs never reach the directory.
    assert_eq!(app.tenants.lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_tenant_is_never_taken_from_headers_or_query() {
    let app = app();
    let reply = send(
        &app.router,
        Request::get("/t/nobody/whoami?tenant=acme&tenant_id=acme")
            .header("x-tenant", "acme")
            .header("x-tenant-id", app.tenants.acme.to_string())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_suspended_tenant_is_refused_with_a_distinct_error() {
    let reply = get_path(&app().router, "/t/frozen/whoami").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.json()["code"], "tenant.suspended");
}

#[tokio::test]
async fn a_failing_tenant_lookup_is_reported_as_unavailable() {
    let reply = get_path(&app().router, "/t/broken/whoami").await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reply.json()["code"], "tenant.lookup_unavailable");
}

#[tokio::test]
async fn unknown_routes_are_problem_documents() {
    let app = app();
    for path in ["/", "/nothing", "/t/acme/nothing"] {
        let reply = get_path(&app.router, path).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(reply.json()["code"], "route.not_found", "{path}");
    }
}

#[tokio::test]
async fn domain_errors_map_to_status_and_code() {
    let reply = get_path(&app().router, "/t/acme/conflict").await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    let body = reply.json();
    assert_eq!(body["code"], "user.identifier_taken");
    assert_eq!(body["detail"], "identifier already in use");
    assert_eq!(body["status"], 409);
}

#[tokio::test]
async fn internal_errors_do_not_leak_details() {
    let reply = get_path(&app().router, "/t/acme/fail").await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(reply.json()["detail"], "the request could not be completed");
    assert!(!reply.body.contains("password authentication"));
    assert!(!reply.body.contains("hodor_app_login"));
}

#[tokio::test]
async fn every_response_carries_a_request_id_and_security_headers() {
    let app = app();
    let ok = get_path(&app.router, "/t/acme/whoami").await;
    let missing = get_path(&app.router, "/nothing").await;

    for reply in [&ok, &missing] {
        assert_eq!(reply.headers["x-content-type-options"], "nosniff");
        assert_eq!(reply.headers["x-frame-options"], "DENY");
        assert_eq!(reply.headers["referrer-policy"], "no-referrer");
        assert_eq!(reply.headers["cache-control"], "no-store");
        assert_eq!(
            reply.headers["content-security-policy"],
            "default-src 'none'; frame-ancestors 'none'"
        );
        assert!(reply.headers.contains_key("strict-transport-security"));
        assert!(reply.headers.contains_key("x-request-id"));
    }
    assert_ne!(ok.headers["x-request-id"], missing.headers["x-request-id"]);
    // The id in an error body matches the header.
    assert_eq!(
        missing.json()["request_id"],
        missing.headers["x-request-id"].to_str().expect("ascii")
    );
}

#[tokio::test]
async fn a_request_id_sent_by_the_client_is_not_adopted() {
    let reply = send(
        &app().router,
        Request::get("/t/acme/whoami")
            .header("x-request-id", "attacker-chosen")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_ne!(reply.headers["x-request-id"], "attacker-chosen");
}

#[tokio::test]
async fn oversized_bodies_are_rejected() {
    let app = app_with(Limits {
        max_body_bytes: 16,
        ..Limits::default()
    });
    let post = |body: &'static str| {
        Request::post("/t/acme/echo")
            .body(Body::from(body))
            .expect("request")
    };
    assert_eq!(
        send(&app.router, post("small")).await.status,
        StatusCode::OK
    );
    assert_eq!(
        send(&app.router, post("this body is longer than sixteen bytes"))
            .await
            .status,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn slow_requests_time_out() {
    let app = app_with(Limits {
        request_timeout: Duration::from_millis(50),
        ..Limits::default()
    });
    let reply = get_path(&app.router, "/t/acme/slow").await;
    assert_eq!(reply.status, StatusCode::REQUEST_TIMEOUT);
    assert!(reply.headers.contains_key("x-request-id"));
}

struct Database(AtomicBool);

#[async_trait::async_trait]
impl ReadinessCheck for Database {
    fn name(&self) -> &'static str {
        "database"
    }

    async fn check(&self) -> Result<(), String> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err("connection refused to 10.0.0.5:5432".to_owned())
        }
    }
}

#[tokio::test]
async fn health_endpoints_reflect_dependencies_and_draining() {
    let database = Arc::new(Database(AtomicBool::new(true)));
    let health = Health::new(vec![database.clone()]);
    let router = ops_router(health.clone());

    for path in ["/livez", "/readyz", "/startupz"] {
        assert_eq!(
            get_path(&router, path).await.status,
            StatusCode::OK,
            "{path}"
        );
    }

    // A failing dependency makes the process unready, but it is still alive.
    database.0.store(false, Ordering::SeqCst);
    let unready = get_path(&router, "/readyz").await;
    assert_eq!(unready.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unready.json()["failed"], serde_json::json!(["database"]));
    assert!(
        !unready.body.contains("10.0.0.5"),
        "no internals in the body"
    );
    assert_eq!(get_path(&router, "/livez").await.status, StatusCode::OK);

    // Draining fails readiness even with healthy dependencies.
    database.0.store(true, Ordering::SeqCst);
    health.begin_draining();
    assert_eq!(
        get_path(&router, "/readyz").await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(get_path(&router, "/startupz").await.status, StatusCode::OK);
    assert_eq!(get_path(&router, "/livez").await.status, StatusCode::OK);
}

struct Unresponsive;

#[async_trait::async_trait]
impl ReadinessCheck for Unresponsive {
    fn name(&self) -> &'static str {
        "database"
    }

    async fn check(&self) -> Result<(), String> {
        std::future::pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn a_dependency_that_does_not_answer_counts_as_failed() {
    let router = ops_router(Health::new(vec![Arc::new(Unresponsive)]));
    let started = tokio::time::Instant::now();

    let reply = get_path(&router, "/readyz").await;

    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reply.json()["failed"], serde_json::json!(["database"]));
    assert!(started.elapsed() <= Duration::from_secs(3));
}

#[tokio::test]
async fn shutdown_lets_in_flight_requests_finish() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let app = app();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(listener, app.router, async {
        let _ = stopped.await;
    }));

    // Start a request that takes 300 ms, then ask the server to stop while
    // it is still running.
    let mut connection = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    connection
        .write_all(b"GET /t/acme/slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    tokio::time::sleep(Duration::from_millis(100)).await;
    stop.send(()).expect("server is running");

    let mut response = String::new();
    connection
        .read_to_string(&mut response)
        .await
        .expect("read");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("done"), "{response}");

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server stops after draining")
        .expect("server task")
        .expect("server result");

    // New connections are refused once the server has stopped.
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}
