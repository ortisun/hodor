//! `hodor-ext-authz`: Envoy's external authorization over gRPC, each check
//! answered by one call of Hodor's Authorization API.
//!
//! It holds no decision of its own and keeps none: a check becomes an
//! `evaluate` asked as the client of the destination's application, and
//! every failure is a denial. It depends on no crate of the workspace but
//! `hodor-observability`. Specified in
//! `docs/operations/hodor-ext-authz.md` and Decision 0058.

pub mod check;
pub mod config;
pub mod hodor;
pub mod pattern;
pub mod service;

pub use config::{ConfigError, Settings, TokenSource};
pub use service::{ExtAuthz, Outcome};

use axum::Router;
use axum::routing::get;
use std::future::Future;
use tokio::net::TcpListener;
use tonic::transport::Server;
use tonic::transport::server::TcpIncoming;

/// Serves the adapter's gRPC service on `listener` until `stop` resolves.
///
/// # Errors
///
/// Returns the transport's error if serving fails.
pub async fn serve(
    listener: TcpListener,
    adapter: ExtAuthz,
    stop: impl Future<Output = ()> + Send,
) -> Result<(), tonic::transport::Error> {
    Server::builder()
        .add_service(adapter.service())
        .serve_with_incoming_shutdown(TcpIncoming::from(listener), stop)
        .await
}

/// The operations port: `/startupz`, `/readyz` and `/livez`. The adapter is
/// ready as soon as it listens: Hodor being unreachable is a denial, not a
/// reason to stop sending checks to it.
pub fn operations() -> Router {
    Router::new()
        .route("/startupz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ok" }))
        .route("/livez", get(|| async { "ok" }))
}
