//! Assembly of the public router and the serving loop.

use crate::problem::Problem;
use crate::request::request_context;
use crate::tenant::{TenantResolver, resolve_tenant};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// Limits applied to every request on the public listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest accepted request body, in bytes.
    pub max_body_bytes: usize,
    /// Longest time a request may take before it is answered with 408.
    pub request_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 * 1024,
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
        .layer(DefaultBodyLimit::max(limits.max_body_bytes))
        .layer(RequestBodyLimitLayer::new(limits.max_body_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            limits.request_timeout,
        ))
        // Outermost, so that every response, including those produced by
        // the layers above, carries the request identifier and security headers.
        .layer(middleware::from_fn(request_context))
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
