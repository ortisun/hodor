//! The OpenID Provider's own addresses: UserInfo and the discovery
//! document.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "OpenID Provider".
//! These handlers translate between HTTP and the OAuth context; the rules
//! are the context's.

use crate::tenant::TenantSlug;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use hodor_kernel::TenantContext;
use hodor_oauth::api::{BearerRefusal, UserInfoService, discovery_document};

/// What UserInfo needs.
#[derive(Clone)]
pub struct UserInfoState {
    /// The use case.
    pub userinfo: UserInfoService,
    /// The address people reach this installation at, without a path.
    pub public_url: String,
}

impl std::fmt::Debug for UserInfoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserInfoState").finish_non_exhaustive()
    }
}

fn issuer(public_url: &str, slug: &str) -> String {
    format!("{}/t/{slug}", public_url.trim_end_matches('/'))
}

/// UserInfo, to be mounted under a tenant at `/oauth2`.
pub fn userinfo_routes(state: UserInfoState) -> Router {
    Router::new()
        .route("/userinfo", get(userinfo).post(userinfo))
        .with_state(state)
}

/// The discovery document, to be mounted under a tenant.
pub fn discovery_routes(public_url: String) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/oauth-authorization-server", get(discovery))
        .with_state(public_url)
}

async fn discovery(
    State(public_url): State<String>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
) -> Response {
    let mut response = Json(discovery_document(&issuer(&public_url, &slug))).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

/// The token of `Authorization: Bearer`, or nothing. A header with another
/// scheme carries no bearer token.
fn bearer(headers: &HeaderMap) -> Result<Option<&str>, ()> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ())?;
    let (scheme, token) = value.trim().split_once(' ').ok_or(())?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(());
    }
    let token = token.trim();
    if token.is_empty() {
        return Err(());
    }
    Ok(Some(token))
}

fn not_cached(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn refused(refusal: BearerRefusal) -> Response {
    let (status, challenge) = match refusal {
        BearerRefusal::Missing => (StatusCode::UNAUTHORIZED, "Bearer".to_owned()),
        BearerRefusal::InvalidToken(reason) => {
            tracing::info!(reason, "UserInfo refused a token");
            (
                StatusCode::UNAUTHORIZED,
                "Bearer error=\"invalid_token\"".to_owned(),
            )
        }
        BearerRefusal::InsufficientScope => (
            StatusCode::FORBIDDEN,
            "Bearer error=\"insufficient_scope\", scope=\"openid\"".to_owned(),
        ),
    };
    let mut response = status.into_response();
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    not_cached(response)
}

async fn userinfo(
    State(state): State<UserInfoState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
) -> Response {
    let Ok(token) = bearer(&headers) else {
        return refused(BearerRefusal::InvalidToken(
            "the Authorization header is not a bearer token",
        ));
    };
    match state
        .userinfo
        .claims(&tenant, &issuer(&state.public_url, &slug), token)
        .await
    {
        Ok(Ok(claims)) => not_cached(Json(claims).into_response()),
        Ok(Err(refusal)) => refused(refusal),
        Err(error) => {
            tracing::error!(%error, "UserInfo could not answer");
            not_cached(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(value).expect("header"),
        );
        headers
    }

    #[test]
    fn a_bearer_token_is_read_from_its_header_only() {
        assert_eq!(bearer(&HeaderMap::new()), Ok(None));
        assert_eq!(bearer(&with("Bearer abc.def.ghi")), Ok(Some("abc.def.ghi")));
        assert_eq!(bearer(&with("bearer abc")), Ok(Some("abc")));
        assert_eq!(bearer(&with("Basic abc")), Err(()));
        assert_eq!(bearer(&with("Bearer ")), Err(()));
        assert_eq!(bearer(&with("Bearer")), Err(()));
    }
}
