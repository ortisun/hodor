//! The OpenID Provider's own addresses: UserInfo and the discovery
//! document.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "OpenID Provider".
//! These handlers translate between HTTP and the OAuth context; the rules
//! are the context's.

use crate::bearer::{bearer, not_cached, refused};
use crate::forwarded_identity::IdentityHeader;
use crate::tenant::TenantSlug;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use hodor_kernel::TenantContext;
use hodor_oauth::api::{
    BearerRefusal, ForwardedIdentity, OPENID_SCOPE, UserInfoService,
    advertise_certificate_bound_tokens, advertise_forwarded_methods, discovery_document,
};
use hodor_tenant::api::TenantService;

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
    let levels = match state.tenants.get(&tenant).await {
        Ok(found) => found
            .snapshot()
            .settings
            .authentication
            .assurance_levels
            .clone(),
        Err(error) => return crate::problem::Problem::from(error).into_response(),
    };
    let names: Vec<&str> = levels
        .levels()
        .iter()
        .map(|level| level.acr.as_str())
        .collect();
    let mut document = discovery_document(&issuer(&state.public_url, &slug), &names);
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

async fn userinfo(
    State(state): State<UserInfoState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    forwarded: Option<Extension<ForwardedIdentity>>,
    headers: HeaderMap,
) -> Response {
    let Ok(token) = bearer(&headers) else {
        return refused(
            BearerRefusal::InvalidToken("the Authorization header is not a bearer token"),
            OPENID_SCOPE,
            "UserInfo",
        );
    };
    let forwarded = forwarded.map(|Extension(found)| found);
    match state
        .userinfo
        .claims(
            &tenant,
            &issuer(&state.public_url, &slug),
            token,
            forwarded.as_ref(),
        )
        .await
    {
        Ok(Ok(claims)) => not_cached(Json(claims).into_response()),
        Ok(Err(refusal)) => refused(refusal, OPENID_SCOPE, "UserInfo"),
        Err(error) => {
            tracing::error!(%error, "UserInfo could not answer");
            not_cached(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}
