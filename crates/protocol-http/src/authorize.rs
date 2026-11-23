//! The authorization endpoint of OAuth 2.x: where a client sends a
//! person's browser to ask for an authorization code.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Authorization
//! endpoint". These handlers translate between HTTP and the OAuth and
//! session contexts; the rules are the OAuth context's.

use crate::interaction::{SESSION_COOKIE, cookie, set_cookie};
use crate::problem::Problem;
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
    AuthorizationCodeService, AuthorizationError, AuthorizationParameters, AuthorizationRefusal,
    AuthorizationRequest, PENDING_LIFETIME, PendingAuthorizationId, SessionDecision,
    SignedInPerson,
};
use hodor_session::api::SessionService;

/// The cookie that holds a pending authorization request's identifier and
/// the secret that binds it to the browser.
pub(crate) const AUTHORIZATION_COOKIE: &str = "__Secure-hodor_authorization";

/// What the authorization endpoint needs.
#[derive(Clone)]
pub struct AuthorizationState {
    /// The use cases of the endpoint.
    pub authorization: AuthorizationCodeService,
    /// The session use cases, to find who the browser is signed in as.
    pub sessions: SessionService,
    /// The address people reach this installation at, without a path. The
    /// issuer of a tenant is this address followed by `/t/{slug}`.
    pub public_url: String,
}

impl std::fmt::Debug for AuthorizationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationState").finish_non_exhaustive()
    }
}

/// The routes of the authorization endpoint, to be mounted under a tenant
/// at `/oauth2`.
pub fn authorization_routes(state: AuthorizationState) -> Router {
    Router::new()
        .route(
            "/authorize",
            get(authorize_by_query).post(authorize_by_form),
        )
        .route("/authorize/resume", get(resume))
        .with_state(state)
}

/// The address the pages go to after a completed sign-in, when this
/// browser holds a pending authorization request of the tenant.
pub(crate) fn waiting(headers: &HeaderMap, slug: &str) -> Option<String> {
    cookie(headers, AUTHORIZATION_COOKIE)
        .filter(|value| !value.is_empty())
        .map(|_| format!("/t/{slug}/oauth2/authorize/resume"))
}

fn issuer(state: &AuthorizationState, slug: &str) -> String {
    format!("{}/t/{slug}", state.public_url.trim_end_matches('/'))
}

/// Hodor's own page, for a request that cannot be answered at its
/// redirect address. It names the reason by its code and holds no script.
pub(crate) fn error_page(code: &'static str) -> Response {
    let body = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>This request cannot be answered</title>\n</head>\n<body>\n\
         <h1>This request cannot be answered</h1>\n\
         <p>The application that sent you here made a request that Hodor cannot answer. \
         Go back to the application and try again; if this happens again, tell whoever \
         runs it.</p>\n<p>Reason: <code>{code}</code></p>\n</body>\n</html>\n"
    );
    let mut response = (StatusCode::BAD_REQUEST, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

/// Sends the browser to `uri` with `parameters` added to its query.
pub(crate) fn redirect_to(uri: &str, parameters: &[(&str, &str)]) -> Response {
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (name, value) in parameters {
        query.append_pair(name, value);
    }
    let separator = if uri.contains('?') { '&' } else { '?' };
    let location = format!("{uri}{separator}{}", query.finish());
    match HeaderValue::from_str(&location) {
        Ok(location) => {
            let mut response = StatusCode::FOUND.into_response();
            response.headers_mut().insert(header::LOCATION, location);
            response
        }
        // A registered address is printable ASCII; this cannot happen.
        Err(_) => error_page("oauth.authorization_redirect_uri_unregistered"),
    }
}

fn redirect_error(error: &AuthorizationError, issuer: &str) -> Response {
    let mut parameters = vec![
        ("error", error.error),
        ("error_description", error.description),
    ];
    if let Some(state) = &error.state {
        parameters.push(("state", state));
    }
    parameters.push(("iss", issuer));
    redirect_to(&error.redirect_uri, &parameters)
}

fn error_for(
    request: &AuthorizationRequest,
    error: &'static str,
    description: &'static str,
) -> AuthorizationError {
    AuthorizationError {
        redirect_uri: request.redirect_uri.clone(),
        error,
        description,
        state: request.state.clone(),
    }
}

/// Who the browser is signed in as, by its session cookie.
async fn signed_in(
    state: &AuthorizationState,
    tenant: &TenantContext,
    headers: &HeaderMap,
) -> Result<Option<SignedInPerson>, Box<Response>> {
    let Some(token) = cookie(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    match state.sessions.find_by_token(tenant, token).await {
        Ok(Some(session)) => {
            let snapshot = session.snapshot();
            Ok(Some(SignedInPerson {
                user_id: snapshot.user_id,
                session_id: snapshot.id,
                signed_in_at: snapshot.signed_in_at,
                methods: snapshot.methods.clone(),
            }))
        }
        Ok(None) => Ok(None),
        Err(error) => Err(Box::new(Problem::from(error).into_response())),
    }
}

async fn issue(
    state: &AuthorizationState,
    tenant: &TenantContext,
    slug: &str,
    request: &AuthorizationRequest,
    person: &SignedInPerson,
) -> Response {
    let caller = Caller {
        actor: Actor::User(person.user_id),
        correlation_id: CorrelationId::generate(),
    };
    match state
        .authorization
        .issue_code(tenant, request, person, caller)
        .await
    {
        Ok(code) => {
            let issuer = issuer(state, slug);
            let mut parameters = vec![("code", code.expose())];
            if let Some(value) = &request.state {
                parameters.push(("state", value));
            }
            parameters.push(("iss", &issuer));
            redirect_to(&request.redirect_uri, &parameters)
        }
        Err(error) => Problem::from(error).into_response(),
    }
}

fn authorization_cookie(slug: &str, value: &str, max_age: i64) -> String {
    format!(
        "{AUTHORIZATION_COOKIE}={value}; Path=/t/{slug}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict"
    )
}

async fn authorize(
    state: &AuthorizationState,
    tenant: &TenantContext,
    slug: &str,
    headers: &HeaderMap,
    parameters: &AuthorizationParameters,
) -> Response {
    let request = match state.authorization.check(tenant, parameters).await {
        Ok(Ok(request)) => request,
        Ok(Err(AuthorizationRefusal::NotRedirectable(code))) => return error_page(code),
        Ok(Err(AuthorizationRefusal::Redirect(error))) => {
            return redirect_error(&error, &issuer(state, slug));
        }
        Err(error) => return Problem::from(error).into_response(),
    };
    let person = match signed_in(state, tenant, headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    match (
        request.decide(person.as_ref(), state.authorization.now()),
        person,
    ) {
        (SessionDecision::Issue, Some(person)) => {
            issue(state, tenant, slug, &request, &person).await
        }
        (SessionDecision::LoginRequired | SessionDecision::Issue, _) => redirect_error(
            &error_for(&request, "login_required", "the person is not signed in"),
            &issuer(state, slug),
        ),
        (SessionDecision::SignIn, _) => {
            let location = sign_in_address(slug, &request);
            match state.authorization.hold(tenant, request).await {
                Ok((id, secret)) => {
                    let mut response = redirect_to_path(&location);
                    set_cookie(
                        &mut response,
                        &authorization_cookie(
                            slug,
                            &format!("{id}.{}", secret.expose()),
                            PENDING_LIFETIME.whole_seconds(),
                        ),
                    );
                    response
                }
                Err(error) => Problem::from(error).into_response(),
            }
        }
    }
}

/// The sign-in page, told that an application's request waits for it and
/// given the request's `login_hint` and `ui_locales`.
fn sign_in_address(slug: &str, request: &AuthorizationRequest) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    query.append_pair("continue", "authorization");
    if let Some(hint) = &request.login_hint {
        query.append_pair("login_hint", hint);
    }
    if let Some(locales) = &request.ui_locales {
        query.append_pair("ui_locales", locales);
    }
    format!("/t/{slug}/account/sign-in?{}", query.finish())
}

fn redirect_to_path(path: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(location) = HeaderValue::from_str(path) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

async fn authorize_by_query(
    State(state): State<AuthorizationState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let parameters = AuthorizationParameters::from_pairs(
        form_urlencoded::parse(query.unwrap_or_default().as_bytes()).into_owned(),
    );
    authorize(&state, &tenant, &slug, &headers, &parameters).await
}

async fn authorize_by_form(
    State(state): State<AuthorizationState>,
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
        return error_page("oauth.authorization_form_expected");
    }
    let parameters =
        AuthorizationParameters::from_pairs(form_urlencoded::parse(&body).into_owned());
    authorize(&state, &tenant, &slug, &headers, &parameters).await
}

fn forget_authorization(response: &mut Response, slug: &str) {
    set_cookie(response, &authorization_cookie(slug, "", 0));
}

async fn resume(
    State(state): State<AuthorizationState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
) -> Response {
    let handle = cookie(&headers, AUTHORIZATION_COOKIE)
        .and_then(|value| value.split_once('.'))
        .and_then(|(id, secret)| Some((id.parse::<PendingAuthorizationId>().ok()?, secret)));
    let resumed = match handle {
        Some((id, secret)) => match state.authorization.resume(&tenant, id, secret).await {
            Ok(resumed) => resumed,
            Err(error) => return Problem::from(error).into_response(),
        },
        None => None,
    };
    let Some(resumed) = resumed else {
        let mut response = error_page("oauth.authorization_request_not_found");
        forget_authorization(&mut response, &slug);
        return response;
    };
    let person = match signed_in(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    let now = state.authorization.now();
    let mut response = match person {
        Some(person)
            if resumed
                .request
                .satisfied_after_sign_in(Some(&person), resumed.received_at, now) =>
        {
            issue(&state, &tenant, &slug, &resumed.request, &person).await
        }
        _ => redirect_error(
            &error_for(
                &resumed.request,
                "access_denied",
                "the person did not sign in",
            ),
            &issuer(&state, &slug),
        ),
    };
    forget_authorization(&mut response, &slug);
    response
}
