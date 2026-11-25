//! `hodor-cert-manager-issuer`: cert-manager's outside issuer, which signs
//! the approved requests for an authority addressed to its kinds through
//! the tenant's certificate authority in Hodor.
//!
//! It holds no decision of its own: Hodor checks every request it sends.
//! It depends on no crate of the workspace but `hodor-observability`, and
//! reaches Hodor through the token endpoint and the signing operation
//! alone. Specified in `docs/operations/hodor-cert-manager-issuer.md` and
//! Decision 0074.

pub mod assertion;
pub mod config;
pub mod hodor;
pub mod kubernetes;
pub mod reconcile;
pub mod request;

pub use assertion::ClientKey;
pub use config::{Authentication, ConfigError, Settings};
pub use hodor::{Failure, Hodor, Signed, Signer};
pub use reconcile::{Cluster, ClusterError, Next, Reconciler, Request};

use axum::Router;
use axum::routing::get;

/// The operations port: `/startupz`, `/readyz` and `/livez`. The issuer is
/// ready as soon as it runs: Hodor being unreachable leaves requests
/// pending, not a reason to restart it.
pub fn operations() -> Router {
    Router::new()
        .route("/startupz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ok" }))
        .route("/livez", get(|| async { "ok" }))
}
