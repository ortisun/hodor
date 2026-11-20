//! Liveness, readiness and startup endpoints for the operations listener.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Longest a single check may take. A dependency that does not answer in
/// time counts as failed, so a probe gets its answer instead of hanging
/// until the prober gives up.
const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Something the process needs in order to serve requests.
///
/// Only hard dependencies belong here (the database). Optional ones, such as
/// Redis, OPA or external identity providers, must not make the process
/// unready.
#[async_trait::async_trait]
pub trait ReadinessCheck: Send + Sync {
    /// Short name reported when the check fails.
    fn name(&self) -> &'static str;

    /// Checks the dependency.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure, for the log.
    async fn check(&self) -> Result<(), String>;
}

/// Health state shared between the operations endpoints and the shutdown
/// sequence.
#[derive(Clone)]
pub struct Health {
    draining: Arc<AtomicBool>,
    checks: Arc<[Arc<dyn ReadinessCheck>]>,
}

impl std::fmt::Debug for Health {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let checks: Vec<&str> = self.checks.iter().map(|c| c.name()).collect();
        f.debug_struct("Health")
            .field("draining", &self.is_draining())
            .field("checks", &checks)
            .finish()
    }
}

impl Health {
    /// Creates the health state with the checks readiness depends on.
    #[must_use]
    pub fn new(checks: Vec<Arc<dyn ReadinessCheck>>) -> Self {
        Self {
            draining: Arc::new(AtomicBool::new(false)),
            checks: checks.into(),
        }
    }

    /// Marks the process as shutting down. Readiness fails from now on, so
    /// the load balancer stops sending new requests while in-flight ones
    /// finish.
    pub fn begin_draining(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    /// Whether shutdown has begun.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    async fn failed_checks(&self) -> Vec<&'static str> {
        let mut failed = Vec::new();
        for check in self.checks.iter() {
            let outcome = tokio::time::timeout(CHECK_TIMEOUT, check.check())
                .await
                .unwrap_or_else(|_| Err("timed out".to_owned()));
            if let Err(reason) = outcome {
                tracing::warn!(check = check.name(), %reason, "readiness check failed");
                failed.push(check.name());
            }
        }
        failed
    }
}

fn report(failed: &[&'static str]) -> Response {
    if failed.is_empty() {
        (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "unavailable", "failed": failed })),
        )
            .into_response()
    }
}

async fn livez() -> Response {
    report(&[])
}

async fn readyz(State(health): State<Health>) -> Response {
    if health.is_draining() {
        return report(&["draining"]);
    }
    report(&health.failed_checks().await)
}

async fn startupz(State(health): State<Health>) -> Response {
    report(&health.failed_checks().await)
}

/// Routes for the operations listener, which is not exposed to the internet.
///
/// * `/livez`: the process responds.
/// * `/readyz`: dependencies are reachable and the process is not draining.
/// * `/startupz`: dependencies are reachable.
pub fn ops_router(health: Health) -> Router {
    Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route("/startupz", get(startupz))
        .with_state(health)
}
