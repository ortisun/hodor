//! The OpenID Provider's own addresses: UserInfo and the discovery
//! document.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "OpenID Provider".
//! These handlers translate between HTTP and the OAuth context; the rules
//! are the context's.

use crate::bearer::{bearer, not_cached, refused};
use crate::forwarded_identity::IdentityHeader;
use crate::tenant::TenantSlug;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use hodor_kernel::TenantContext;
use hodor_oauth::api::{
    BearerRefusal, ForwardedIdentity, OPENID_SCOPE, UserInfoAnswer, UserInfoService,
    advertise_certificate_bound_tokens, advertise_forwarded_methods, discovery_document,
    with_registration,
};
use hodor_tenant::api::{RegistrationPolicy, TenantService};

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

/// What the discovery document needs.
#[derive(Clone)]
pub struct DiscoveryState {
    /// The address people reach this installation at, without a path.
    pub public_url: String,
    /// The tenant's assurance levels, which the document names.
    pub tenants: TenantService,
    /// The header of the caller's identity trusted proxies write, if the
    /// operator named one: the document then names the methods it makes
    /// usable.
    pub identity_header: Option<IdentityHeader>,
}

impl std::fmt::Debug for DiscoveryState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryState").finish_non_exhaustive()
    }
}

/// The discovery document, to be mounted under a tenant.
pub fn discovery_routes(state: DiscoveryState) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/oauth-authorization-server", get(discovery))
        .with_state(state)
}

async fn discovery(
    State(state): State<DiscoveryState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
) -> Response {
    let (levels, registration_open, pushed_required) = match state.tenants.get(&tenant).await {
        Ok(found) => {
            let settings = &found.snapshot().settings;
            (
                settings.authentication.assurance_levels.clone(),
                settings.registration == RegistrationPolicy::Open,
                settings.pushed_requests.required,
            )
        }
        Err(error) => return crate::problem::Problem::from(error).into_response(),
    };
    let names: Vec<&str> = levels
        .levels()
        .iter()
        .map(|level| level.acr.as_str())
        .collect();
    let mut document = with_registration(
        discovery_document(&issuer(&state.public_url, &slug), &names, pushed_required),
        registration_open,
    );
    if let Some(header) = state.identity_header {
        advertise_forwarded_methods(&mut document, header.methods());
        if header.forwards_certificates() {
            advertise_certificate_bound_tokens(&mut document);
        }
    }
    let mut response = Json(document).into_response();
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

/// Why the token's place in a request cannot be read.
#[derive(Debug, PartialEq, Eq)]
enum TokenPlace {
    /// `access_token` is given more than once in the form.
    Repeated,
}

/// The `access_token` of a form body (RFC 6750, section 2.2): read only
/// from a `POST` whose content is `application/x-www-form-urlencoded`.
/// Other parameters are ignored.
fn form_token(
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Option<String>, TokenPlace> {
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|kind| {
            kind.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if method != Method::POST || !is_form {
        return Ok(None);
    }
    let mut tokens = form_urlencoded::parse(body)
        .filter(|(name, _)| name == "access_token")
        .map(|(_, value)| value.into_owned());
    match (tokens.next(), tokens.next()) {
        (_, Some(_)) => Err(TokenPlace::Repeated),
        (token, None) => Ok(token.filter(|token| !token.is_empty())),
    }
}

/// `400` with the challenge `invalid_request`, for a request that sends
/// its token more than one way (RFC 6750, sections 2 and 3.1).
fn invalid_request(reason: &'static str) -> Response {
    tracing::info!(reason, surface = "UserInfo", "a bearer request was refused");
    let mut response = StatusCode::BAD_REQUEST.into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"invalid_request\""),
    );
    not_cached(response)
}

async fn userinfo(
    State(state): State<UserInfoState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    forwarded: Option<Extension<ForwardedIdentity>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(in_header) = bearer(&headers) else {
        return refused(
            BearerRefusal::InvalidToken("the Authorization header is not a bearer token"),
            OPENID_SCOPE,
            "UserInfo",
        );
    };
    let forwarded = forwarded.map(|Extension(found)| found);
    let in_form = match form_token(&method, &headers, &body) {
        Ok(token) => token,
        Err(TokenPlace::Repeated) => {
            return invalid_request("access_token is given more than once");
        }
    };
    let token = match (in_header, in_form.as_deref()) {
        (Some(_), Some(_)) => {
            return invalid_request("the token is sent both in the header and in the form");
        }
        (Some(token), None) | (None, Some(token)) => Some(token),
        (None, None) => None,
    };
    match state
        .userinfo
        .answer(
            &tenant,
            &issuer(&state.public_url, &slug),
            token,
            forwarded.as_ref(),
        )
        .await
    {
        Ok(Ok(UserInfoAnswer::Json(claims))) => not_cached(Json(claims).into_response()),
        // A signed answer (OpenID Connect Core, section 5.3.2).
        Ok(Ok(UserInfoAnswer::Signed(jwt))) => not_cached(
            (
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/jwt"),
                )],
                jwt,
            )
                .into_response(),
        ),
        Ok(Err(refusal)) => refused(refusal, OPENID_SCOPE, "UserInfo"),
        Err(error) => {
            tracing::error!(%error, "UserInfo could not answer");
            not_cached(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=utf-8"),
        );
        headers
    }

    #[test]
    fn a_token_is_read_from_a_form_posted_only() {
        assert_eq!(
            form_token(&Method::POST, &form(), b"access_token=abc.def&x=1"),
            Ok(Some("abc.def".to_owned()))
        );
        assert_eq!(form_token(&Method::POST, &form(), b"x=1"), Ok(None));
        assert_eq!(
            form_token(&Method::POST, &form(), b"access_token="),
            Ok(None)
        );
        // Not a form, or not posted: the body is not read.
        assert_eq!(
            form_token(&Method::POST, &HeaderMap::new(), b"access_token=abc"),
            Ok(None)
        );
        let mut json = HeaderMap::new();
        json.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert_eq!(
            form_token(&Method::POST, &json, b"access_token=abc"),
            Ok(None)
        );
        assert_eq!(
            form_token(&Method::GET, &form(), b"access_token=abc"),
            Ok(None)
        );
        // Twice is refused, even with one value empty.
        assert_eq!(
            form_token(&Method::POST, &form(), b"access_token=a&access_token=b"),
            Err(TokenPlace::Repeated)
        );
        assert_eq!(
            form_token(&Method::POST, &form(), b"access_token=a&access_token="),
            Err(TokenPlace::Repeated)
        );
    }

    #[test]
    fn a_token_sent_two_ways_is_an_invalid_request() {
        let response = invalid_request("test");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Bearer error=\"invalid_request\""
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}
