//! Front-channel logout over HTTP: the frames made when a session ends in
//! its own browser, the cookie that names them, the signed-out page's
//! policy, and the route the page reads its frames from.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Front-channel
//! logout", and `docs/api/interaction-api.md`, "The frames of a sign-out".
//! The rules are the OAuth context's.

use crate::interaction::{cookie, set_cookie};
use crate::pages::PAGES_CONTENT_SECURITY_POLICY;
use axum::Json;
use axum::extract::State;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::{Extension, http::StatusCode};
use hodor_kernel::TenantContext;
use hodor_oauth::api::{
    FRAMES_LIFETIME, FrontChannelLogoutService, SignedOutHandle, frame_sources,
};
use hodor_session::api::SessionId;
use serde::Serialize;
use std::sync::Arc;

/// The cookie that names the frames kept for the signed-out page.
pub(crate) const SIGNED_OUT_COOKIE: &str = "__Secure-hodor_signed_out";

/// The signed-out page, under `/t/{slug}`.
pub const SIGNED_OUT_PAGE: &str = "/account/signed-out";

/// What front-channel logout needs at the HTTP layer: its use cases, and
/// the address the tenants' issuers start with.
#[derive(Clone)]
pub struct FrontChannel {
    /// The use cases of front-channel logout.
    pub service: FrontChannelLogoutService,
    /// The address people reach this installation at, without a path.
    pub public_url: String,
}

impl std::fmt::Debug for FrontChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrontChannel").finish_non_exhaustive()
    }
}

fn signed_out_cookie(slug: &str, value: &str, max_age: i64) -> String {
    format!(
        "{SIGNED_OUT_COOKIE}={value}; Path=/t/{slug}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax"
    )
}

/// Makes and keeps the frames of `session`, which just ended in its own
/// browser, and answers the handle that browser gets for them; `None` when
/// there is no frame. A failure is logged and counts as no frame: the
/// session has ended all the same.
pub(crate) async fn sign_out_frames(
    front_channel: Option<&FrontChannel>,
    tenant: &TenantContext,
    slug: &str,
    session: SessionId,
) -> Option<SignedOutHandle> {
    let front_channel = front_channel?;
    let issuer = format!(
        "{}/t/{slug}",
        front_channel.public_url.trim_end_matches('/')
    );
    match front_channel
        .service
        .sign_out(tenant, &issuer, session)
        .await
    {
        Ok(handle) => handle,
        Err(error) => {
            tracing::warn!(
                code = error.code(),
                "the frames of front-channel logout could not be made"
            );
            None
        }
    }
}

/// The cookie that names the frames of `handle`, or that tells the browser
/// to forget an older one when there is none.
pub(crate) fn frames_cookie(slug: &str, handle: Option<&SignedOutHandle>) -> String {
    match handle {
        Some(handle) => signed_out_cookie(slug, handle.expose(), FRAMES_LIFETIME.whole_seconds()),
        None => signed_out_cookie(slug, "", 0),
    }
}

/// Makes the frames of `session`, which just ended in the browser of
/// `response`, and gives that browser their cookie. Without front-channel
/// logout no cookie is set at all.
pub(crate) async fn keep_frames(
    front_channel: Option<&FrontChannel>,
    tenant: &TenantContext,
    slug: &str,
    session: SessionId,
    response: &mut Response,
) {
    if front_channel.is_none() {
        return;
    }
    let handle = sign_out_frames(front_channel, tenant, slug, session).await;
    set_cookie(response, &frames_cookie(slug, handle.as_ref()));
}

/// The frames kept under the handle the browser's cookie holds; none
/// without one, or when they cannot be read.
pub(crate) async fn kept_frames(
    front_channel: Option<&FrontChannel>,
    tenant: &TenantContext,
    headers: &HeaderMap,
) -> Vec<String> {
    let (Some(front_channel), Some(handle)) = (front_channel, cookie(headers, SIGNED_OUT_COOKIE))
    else {
        return Vec::new();
    };
    match front_channel.service.frames(tenant, handle).await {
        Ok(frames) => frames,
        Err(error) => {
            tracing::warn!(
                code = error.code(),
                "the frames of front-channel logout could not be read"
            );
            Vec::new()
        }
    }
}

/// The policy of the signed-out page: the hosted pages' own, and
/// `frame-src` naming the sites of `frames` when there are any.
pub(crate) fn signed_out_policy(frames: &[String]) -> String {
    let sources = frame_sources(frames);
    if sources.is_empty() {
        PAGES_CONTENT_SECURITY_POLICY.to_owned()
    } else {
        format!(
            "{PAGES_CONTENT_SECURITY_POLICY}; frame-src {}",
            sources.join(" ")
        )
    }
}

/// What the signed-out page's own route needs.
#[derive(Clone)]
pub(crate) struct SignedOutPage {
    pub(crate) index: Arc<str>,
    pub(crate) front_channel: Option<FrontChannel>,
}

/// The signed-out page: the application's `index.html`, sent with the
/// policy that allows the frames kept for this browser's sign-out.
pub(crate) async fn signed_out_page(
    State(page): State<SignedOutPage>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    let frames = kept_frames(page.front_channel.as_ref(), &tenant, &headers).await;
    let mut response = (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // Made for this browser's sign-out: never kept by a cache.
            (header::CACHE_CONTROL, "no-store"),
        ],
        page.index.to_string(),
    )
        .into_response();
    if let Ok(policy) = HeaderValue::from_str(&signed_out_policy(&frames)) {
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, policy);
    } else {
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(PAGES_CONTENT_SECURITY_POLICY),
        );
    }
    response
}

#[derive(Serialize)]
struct FramesBody {
    frames: Vec<String>,
}

/// `GET /interaction/signed-out`: the addresses the signed-out page loads.
pub(crate) async fn signed_out_frames(
    front_channel: Option<&FrontChannel>,
    tenant: &TenantContext,
    headers: &HeaderMap,
) -> Response {
    let frames = kept_frames(front_channel, tenant, headers).await;
    let mut response = (StatusCode::OK, Json(FramesBody { frames })).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_adds_the_sites_of_the_frames_only_when_there_are_some() {
        assert_eq!(signed_out_policy(&[]), PAGES_CONTENT_SECURITY_POLICY);
        let policy = signed_out_policy(&[
            "https://payroll.example.com/fc?iss=a&sid=b".to_owned(),
            "https://payroll.example.com/other?iss=a&sid=c".to_owned(),
            "https://reports.example.com:8443/fc?iss=a&sid=d".to_owned(),
        ]);
        assert!(
            policy.starts_with(PAGES_CONTENT_SECURITY_POLICY),
            "{policy}"
        );
        assert!(
            policy.ends_with(
                "; frame-src https://payroll.example.com https://reports.example.com:8443"
            ),
            "{policy}"
        );
        assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
    }

    #[test]
    fn the_cookie_lives_as_long_as_the_frames_and_is_sent_by_a_redirect_from_another_site() {
        let cookie = signed_out_cookie("acme", "handle", 120);
        assert_eq!(
            cookie,
            "__Secure-hodor_signed_out=handle; Path=/t/acme; Max-Age=120; HttpOnly; Secure; \
             SameSite=Lax"
        );
    }
}
