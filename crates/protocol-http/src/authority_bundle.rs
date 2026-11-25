//! The bundle of a tenant's certificate authority, published as a SPIFFE
//! bundle endpoint of the `https_web` profile under the tenant's issuer.
//! Mounted only when the installation turns the authority on.
//!
//! Specified in `docs/architecture/contexts/keys.md`, "Its bundle".

use crate::problem::Problem;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{self, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use hodor_kernel::TenantContext;
use hodor_keys::api::{AuthorityService, BUNDLE_REFRESH_HINT_SECONDS};

/// The route of the bundle, relative to the tenant: `GET
/// /certificate-authority/bundle`.
pub fn authority_bundle_routes(authority: AuthorityService) -> Router {
    Router::new()
        .route("/certificate-authority/bundle", get(bundle))
        .with_state(authority)
}

async fn bundle(
    State(authority): State<AuthorityService>,
    Extension(tenant): Extension<TenantContext>,
) -> Response {
    let found = match authority.bundle(&tenant).await {
        Ok(Some(bundle)) => bundle,
        Ok(None) => {
            return Problem::new(
                StatusCode::NOT_FOUND,
                "keys.authority_not_found",
                "the tenant has no active certificate authority",
            )
            .into_response();
        }
        Err(error) => return Problem::from(error).into_response(),
    };
    let mut response = (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        found.document().to_owned(),
    )
        .into_response();
    if let Ok(value) =
        HeaderValue::from_str(&format!("public, max-age={BUNDLE_REFRESH_HINT_SECONDS}"))
    {
        response.headers_mut().insert(header::CACHE_CONTROL, value);
    }
    response
}
