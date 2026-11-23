//! The service interface Open Policy Agent instances call: bundles,
//! status and decision logs.
//!
//! Specified in `docs/architecture/contexts/authorization.md`, "The
//! service interface". The routes belong to no tenant, since a shared
//! instance serves several; each request is the instance's, by its
//! credential, and what it may reach is decided by the bundles' rules.

use crate::problem::Problem;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use hodor_authorization_opa::api::{BundleService, Instance, Pull};
use hodor_kernel::DomainError;

/// The routes of the service interface, to be mounted at the root: they
/// answer under `/opa/`.
pub fn policy_agent_routes(bundles: BundleService) -> Router {
    Router::new()
        .route("/opa/bundles/{name}", get(bundle))
        .route("/opa/status", post(status))
        .route("/opa/logs", post(logs))
        .with_state(bundles)
}

/// The bearer token of a request, if it has one.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// Whether the body is gzip-compressed, as its encoding says.
fn compressed(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("gzip"))
}

fn refused(error: DomainError) -> Response {
    let mut response = Problem::from(error).into_response();
    if response.status() == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}

async fn instance(bundles: &BundleService, headers: &HeaderMap) -> Result<Instance, DomainError> {
    bundles.authenticate(bearer(headers)).await
}

fn not_found() -> Response {
    Problem::new(
        StatusCode::NOT_FOUND,
        "authorization.bundle_not_found",
        "there is no bundle of this name for this instance",
    )
    .into_response()
}

fn entity_tag(value: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(value).ok()
}

async fn bundle(
    State(bundles): State<BundleService>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let instance = match instance(&bundles, &headers).await {
        Ok(instance) => instance,
        Err(error) => return refused(error),
    };
    let held = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok());
    match bundles.pull(&instance, &name, held).await {
        Ok(Pull::NotFound) => not_found(),
        Ok(Pull::NotModified { entity_tag: tag }) => {
            let mut response = StatusCode::NOT_MODIFIED.into_response();
            if let Some(tag) = entity_tag(&tag) {
                response.headers_mut().insert(header::ETAG, tag);
            }
            response
        }
        Ok(Pull::Bundle {
            entity_tag: tag,
            archive,
        }) => {
            let mut response = archive.into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/gzip"),
            );
            // An instance asks again with the tag; nothing in between may
            // keep a copy.
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            if let Some(tag) = entity_tag(&tag) {
                headers.insert(header::ETAG, tag);
            }
            response
        }
        Err(error) => refused(error),
    }
}

async fn status(State(bundles): State<BundleService>, headers: HeaderMap, body: Bytes) -> Response {
    let instance = match instance(&bundles, &headers).await {
        Ok(instance) => instance,
        Err(error) => return refused(error),
    };
    match bundles
        .report_status(&instance, &body, compressed(&headers))
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => refused(error),
    }
}

async fn logs(State(bundles): State<BundleService>, headers: HeaderMap, body: Bytes) -> Response {
    let instance = match instance(&bundles, &headers).await {
        Ok(instance) => instance,
        Err(error) => return refused(error),
    };
    match bundles
        .upload_decisions(&instance, &body, compressed(&headers))
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => refused(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_bearer_token_is_read() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer(&headers), None);
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer(&headers), None);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer  hodor_pa_x "),
        );
        assert_eq!(bearer(&headers), Some("hodor_pa_x"));
    }
}
