//! Assembly of the public router and the serving loop.

use crate::problem::Problem;
use crate::request::request_context;
use crate::tenant::{TenantResolver, resolve_tenant};
use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::timeout::TimeoutLayer;

/// Limits applied to every request on the public listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest accepted request body, in bytes.
    pub max_body_bytes: usize,
    /// Largest accepted body of the one request that carries a SAML
    /// response, which a SAML identity provider posts to an assertion
    /// consumer address. Form encoding writes some characters of base64
    /// and its line breaks three times longer, so the body may be larger
    /// than the response it holds.
    pub max_saml_response_bytes: usize,
    /// Longest time a request may take before it is answered with 408.
    pub request_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 * 1024,
            max_saml_response_bytes: 2 * hodor_federation::api::MAX_SAML_POSTED_BYTES,
            request_timeout: Duration::from_secs(30),
        }
    }
}

async fn route_not_found() -> impl IntoResponse {
    Problem::new(
        StatusCode::NOT_FOUND,
        "route.not_found",
        "the requested resource does not exist",
    )
}

/// Builds the router for the public listener.
///
/// `tenant_routes` are mounted under `/t/{slug}` and run with the resolved
/// tenant's `TenantContext` as a request extension. `site_routes` are
/// mounted at the root and belong to no tenant: they must serve nothing
/// that differs from one tenant to another.
pub fn public_router(
    resolver: Arc<dyn TenantResolver>,
    tenant_routes: Router,
    site_routes: Router,
    limits: Limits,
) -> Router {
    let tenant_routes = tenant_routes
        .fallback(route_not_found)
        .layer(middleware::from_fn_with_state(resolver, resolve_tenant));

    Router::new()
        .nest("/t/{tenant}", tenant_routes)
        .merge(site_routes)
        .fallback(route_not_found)
        .layer(DefaultBodyLimit::max(
            limits.max_body_bytes.max(limits.max_saml_response_bytes),
        ))
        .layer(middleware::from_fn_with_state(limits, limit_bodies))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            limits.request_timeout,
        ))
        // Outermost, so that every response, including those produced by
        // the layers above, carries the request identifier and security headers.
        .layer(middleware::from_fn(request_context))
}

/// Whether a request posts a SAML response to an assertion consumer
/// address: `POST /t/{slug}/interaction/sign-in/providers/{alias}/saml`.
fn posts_a_saml_response(request: &Request) -> bool {
    let path = request.uri().path();
    request.method() == Method::POST
        && path.starts_with("/t/")
        && path.ends_with("/saml")
        && path.contains("/interaction/sign-in/providers/")
}

/// Refuses a body larger than the limit of its request, whether it says
/// its length or not: `max_body_bytes` for every request, the larger
/// `max_saml_response_bytes` for a posted SAML response only.
async fn limit_bodies(State(limits): State<Limits>, request: Request, next: Next) -> Response {
    let largest = if posts_a_saml_response(&request) {
        limits.max_saml_response_bytes
    } else {
        limits.max_body_bytes
    };
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|length| length > largest) {
        return Problem::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request.body_too_large",
            "the request body is larger than this server accepts",
        )
        .into_response();
    }
    let (parts, body) = request.into_parts();
    let body = Body::new(http_body_util::Limited::new(body, largest));
    next.run(Request::from_parts(parts, body)).await
}

/// Serves `router` until `shutdown` resolves, then stops accepting
/// connections and waits for in-flight requests to finish.
///
/// # Errors
///
/// Returns an error if the listener fails.
pub async fn serve<F>(listener: TcpListener, router: Router, shutdown: F) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    // The connection's address is made available to handlers, which use it
    // to record where a sign-in comes from and to limit attempts.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}
