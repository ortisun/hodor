//! The end-session endpoint: where an application sends a person's browser
//! to sign out of Hodor too, and where a logout that asked the person
//! finishes.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Logout initiated by
//! the relying party". These handlers translate between HTTP and the OAuth
//! and session contexts; the rules are the OAuth context's.

use crate::authorize::{error_page, redirect_to};
use crate::interaction::{SESSION_COOKIE, cookie, set_cookie};
use crate::problem::Problem;
use crate::signed_out::{FrontChannel, SIGNED_OUT_PAGE, frames_cookie, sign_out_frames};
use crate::tenant::TenantSlug;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use hodor_kernel::{Actor, Caller, CorrelationId, TenantContext};
use hodor_oauth::api::{
    ClientId, CurrentSession, LogoutDecision, LogoutParameters, LogoutService, ReturnAddress,
};
use hodor_session::api::{Session, SessionService};

/// The cookie that keeps a logout request while the person is asked.
pub(crate) const LOGOUT_COOKIE: &str = "__Secure-hodor_logout";
/// How long a logout request is kept while the person is asked.
const ASKING_SECONDS: i64 = 600;
/// Why a session ended through this endpoint, in its event.
const REASON: &str = "relying_party_logout";

/// What the end-session endpoint needs.
#[derive(Clone)]
pub struct LogoutState {
    /// The use cases of the endpoint.
    pub logout: LogoutService,
    /// The session use cases, to find and end the browser's session.
    pub sessions: SessionService,
    /// The address people reach this installation at, without a path.
    pub public_url: String,
    /// Front-channel logout: the frames made when a session ends here at
    /// once. `None` tells no client through the browser.
    pub front_channel: Option<FrontChannel>,
}

impl std::fmt::Debug for LogoutState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogoutState").finish_non_exhaustive()
    }
}

/// The routes of the end-session endpoint, to be mounted under a tenant at
/// `/oauth2`.
pub fn logout_routes(state: LogoutState) -> Router {
    Router::new()
        .route("/logout", get(logout_by_query).post(logout_by_form))
        .route("/logout/finish", get(finish))
        .with_state(state)
}

fn issuer(state: &LogoutState, slug: &str) -> String {
    format!("{}/t/{slug}", state.public_url.trim_end_matches('/'))
}

fn not_cached(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn redirect_to_path(path: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(location) = HeaderValue::from_str(path) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

/// The cookie value of a kept return address: its three parts, form
/// encoded, so that it holds only characters a cookie may.
fn kept_value(kept: &ReturnAddress) -> String {
    let mut value = form_urlencoded::Serializer::new(String::new());
    value.append_pair("client", &kept.client_id.to_string());
    value.append_pair("uri", &kept.uri);
    if let Some(state) = &kept.state {
        value.append_pair("state", state);
    }
    value.finish()
}

fn kept_from(value: &str) -> Option<ReturnAddress> {
    let mut client = None;
    let mut uri = None;
    let mut state = None;
    for (name, part) in form_urlencoded::parse(value.as_bytes()) {
        match name.as_ref() {
            "client" => client = part.parse::<ClientId>().ok(),
            "uri" => uri = Some(part.into_owned()),
            "state" => state = Some(part.into_owned()),
            _ => {}
        }
    }
    Some(ReturnAddress {
        client_id: client?,
        uri: uri?,
        state,
    })
}

fn logout_cookie(slug: &str, value: &str, max_age: i64) -> String {
    format!(
        "{LOGOUT_COOKIE}={value}; Path=/t/{slug}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict"
    )
}

/// The cookie that keeps `kept` until the finish. A request without a
/// return address replaces one kept before.
fn kept_cookie(slug: &str, kept: Option<&ReturnAddress>) -> String {
    match kept {
        Some(kept) => logout_cookie(slug, &kept_value(kept), ASKING_SECONDS),
        None => logout_cookie(slug, "", 0),
    }
}

/// A page of the tenant's, with the languages the request asked for.
fn with_locales(page: &str, locales: Option<&str>) -> String {
    let Some(locales) = locales else {
        return page.to_owned();
    };
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("ui_locales", locales)
        .finish();
    let separator = if page.contains('?') { '&' } else { '?' };
    format!("{page}{separator}{query}")
}

fn forget_session(response: &mut Response, slug: &str) {
    set_cookie(
        response,
        &format!("{SESSION_COOKIE}=; Path=/t/{slug}; Max-Age=0; HttpOnly; Secure; SameSite=Lax"),
    );
}

/// The browser's session, by its cookie.
async fn current(
    state: &LogoutState,
    tenant: &TenantContext,
    headers: &HeaderMap,
) -> Result<Option<Session>, Box<Response>> {
    let Some(token) = cookie(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    state
        .sessions
        .find_by_token(tenant, token)
        .await
        .map_err(|error| Box::new(Problem::from(error).into_response()))
}

/// Where the browser goes once nothing more is to be done: back to the
/// application, or Hodor's sign-in page, which says the person is signed
/// out.
fn back(slug: &str, kept: Option<&ReturnAddress>) -> Response {
    match kept {
        // Exactly the registered address, with `state` added only when the
        // request had one.
        Some(kept) => match &kept.state {
            Some(value) => redirect_to(&kept.uri, &[("state", value.as_str())]),
            None => redirect_to_path(&kept.uri),
        },
        None => redirect_to_path(&format!("/t/{slug}/account/sign-in?notice=signed-out")),
    }
}

async fn logout(
    state: &LogoutState,
    tenant: &TenantContext,
    slug: &str,
    headers: &HeaderMap,
    parameters: &LogoutParameters,
    by_form: bool,
) -> Response {
    let request = match state
        .logout
        .check(tenant, &issuer(state, slug), parameters)
        .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(refusal)) => {
            if let Some(reason) = refusal.reason {
                tracing::info!(reason, code = refusal.code, "a logout request was refused");
            }
            return error_page(refusal.code);
        }
        Err(error) => return Problem::from(error).into_response(),
    };
    let session = if by_form {
        None
    } else {
        match current(state, tenant, headers).await {
            Ok(session) => session,
            Err(response) => return *response,
        }
    };
    let now = session.as_ref().map(|session| CurrentSession {
        user_id: session.user_id(),
        session_id: session.id(),
    });
    let decision = match state.logout.decide(tenant, &request, now, by_form).await {
        Ok(decision) => decision,
        Err(error) => return Problem::from(error).into_response(),
    };
    match (decision, session) {
        (LogoutDecision::EndSession, Some(session)) => {
            let caller = Caller {
                actor: Actor::User(session.user_id()),
                correlation_id: CorrelationId::generate(),
            };
            if let Err(error) = state
                .sessions
                .revoke(tenant, session.id(), REASON, caller)
                .await
            {
                return Problem::from(error).into_response();
            }
            let handle =
                sign_out_frames(state.front_channel.as_ref(), tenant, slug, session.id()).await;
            let mut response = if handle.is_some() {
                // The clients are told through the signed-out page first,
                // which then comes back to the finish; the return address
                // waits in the logout cookie, as when the person is asked.
                let mut response = redirect_to_path(&with_locales(
                    &format!("/t/{slug}{SIGNED_OUT_PAGE}?continue=logout"),
                    request.ui_locales.as_deref(),
                ));
                set_cookie(
                    &mut response,
                    &kept_cookie(slug, request.return_to.as_ref()),
                );
                response
            } else {
                back(slug, request.return_to.as_ref())
            };
            if state.front_channel.is_some() {
                set_cookie(&mut response, &frames_cookie(slug, handle.as_ref()));
            }
            forget_session(&mut response, slug);
            response
        }
        (LogoutDecision::Finish | LogoutDecision::EndSession, _) => {
            back(slug, request.return_to.as_ref())
        }
        (LogoutDecision::Ask, _) => {
            let mut response = redirect_to_path(&with_locales(
                &format!("/t/{slug}/account/sign-out"),
                request.ui_locales.as_deref(),
            ));
            set_cookie(
                &mut response,
                &kept_cookie(slug, request.return_to.as_ref()),
            );
            response
        }
    }
}

async fn logout_by_query(
    State(state): State<LogoutState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let parameters = LogoutParameters::from_pairs(
        form_urlencoded::parse(query.unwrap_or_default().as_bytes()).into_owned(),
    );
    not_cached(logout(&state, &tenant, &slug, &headers, &parameters, false).await)
}

async fn logout_by_form(
    State(state): State<LogoutState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|kind| {
            kind.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !is_form {
        return not_cached(error_page("oauth.logout_request_invalid"));
    }
    let parameters = LogoutParameters::from_pairs(form_urlencoded::parse(&body).into_owned());
    not_cached(logout(&state, &tenant, &slug, &headers, &parameters, true).await)
}

async fn finish(
    State(state): State<LogoutState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
) -> Response {
    let kept = cookie(&headers, LOGOUT_COOKIE).and_then(kept_from);
    let session = match current(&state, &tenant, &headers).await {
        Ok(session) => session,
        Err(response) => return not_cached(*response),
    };
    let mut response = if session.is_some() {
        // The person chose to stay signed in, or came here some other way.
        redirect_to_path(&format!("/t/{slug}/account"))
    } else {
        let kept = match kept {
            Some(kept) => match state.logout.still_returns(&tenant, &kept).await {
                Ok(true) => Some(kept),
                Ok(false) => None,
                Err(error) => return not_cached(Problem::from(error).into_response()),
            },
            None => None,
        };
        back(&slug, kept.as_ref())
    };
    set_cookie(&mut response, &logout_cookie(&slug, "", 0));
    not_cached(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kept_return_address_survives_the_cookie() {
        let kept = ReturnAddress {
            client_id: ClientId::generate(),
            uri: "https://app.example.com/out?from=hodor&x=1".to_owned(),
            state: Some("a b;c=\"d\"".to_owned()),
        };
        let value = kept_value(&kept);
        assert!(
            value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"*-._+%&=".contains(&b)),
            "only characters a cookie may hold: {value}"
        );
        assert_eq!(kept_from(&value), Some(kept));
        assert_eq!(kept_from("uri=https%3A%2F%2Fa.example"), None);
        assert_eq!(kept_from(""), None);
    }
}
