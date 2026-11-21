//! The interaction interface: how a browser signs in, and how a person
//! registers or recovers a password.
//!
//! Specified in `docs/api/interaction-api.md`. These handlers translate
//! between HTTP and the authentication context; they decide nothing about
//! a sign-in themselves.

use crate::problem::Problem;
use crate::request::ClientAddress;
use crate::tenant::TenantSlug;
use axum::extract::{Request, State};
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use hodor_authentication::api::{
    AccountRequest, AccountService, AuthenticationService, SignIn, StepInput, TransactionId,
};
use hodor_kernel::{
    Actor, Caller, Clock, CorrelationId, Digest, DomainError, Secret, TenantContext,
};
use hodor_session::api::{ClientInfo, Session, SessionService, SessionToken};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

const SIGN_IN_COOKIE: &str = "__Secure-hodor_signin";
const SESSION_COOKIE: &str = "__Secure-hodor_session";
const CSRF_HEADER: HeaderName = HeaderName::from_static("x-csrf-token");
/// A sign-in lasts ten minutes; so does its cookie.
const SIGN_IN_COOKIE_SECONDS: i64 = 600;

/// What the interaction handlers need.
#[derive(Clone)]
pub struct InteractionState {
    /// The sign-in use cases.
    pub authentication: AuthenticationService,
    /// Registration and password recovery.
    pub accounts: AccountService,
    /// The session use cases.
    pub sessions: SessionService,
    /// For deriving the CSRF token from a sign-in's secret.
    pub digest: Arc<dyn Digest>,
    /// For telling the browser how long the session cookie may live.
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for InteractionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InteractionState").finish_non_exhaustive()
    }
}

/// The routes of the interaction interface, to be mounted under a tenant
/// at `/interaction`.
pub fn interaction_routes(state: InteractionState) -> Router {
    Router::new()
        .route(
            "/sign-in",
            post(start_sign_in)
                .get(describe_sign_in)
                .delete(cancel_sign_in),
        )
        .route("/sign-in/steps/identifier", post(submit_identifier))
        .route("/sign-in/steps/password", post(submit_password))
        .route("/session", get(current_session))
        .route("/registration", post(request_registration))
        .route("/registration/complete", post(complete_registration))
        .route("/recovery", post(request_recovery))
        .route("/recovery/complete", post(reset_password))
        .layer(middleware::from_fn(refuse_other_origins))
        .with_state(state)
}

/// The one shape of every response about a sign-in.
#[derive(Debug, Serialize)]
struct SignInBody {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempts_left: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    csrf_token: Option<String>,
}

#[derive(Deserialize)]
struct IdentifierBody {
    identifier: String,
}

/// No `Debug`: this holds a password until it is wrapped.
#[derive(Deserialize)]
struct PasswordBody {
    password: String,
}

/// What a person gives when asking to register or to recover a password.
#[derive(Deserialize)]
struct AskBody {
    email: String,
    locale: Option<String>,
}

/// No `Debug`: this holds a token and a password until they are used.
#[derive(Deserialize)]
struct CompleteRegistrationBody {
    token: String,
    password: String,
    display_name: Option<String>,
}

/// No `Debug`: this holds a token and a password until they are used.
#[derive(Deserialize)]
struct ResetPasswordBody {
    token: String,
    password: String,
}

/// The one answer to asking, whoever the address belongs to.
#[derive(Debug, Serialize)]
struct AcceptedBody {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct SessionBody {
    user_id: String,
    session_id: String,
    signed_in_at: String,
    assurance: &'static str,
    methods: Vec<String>,
    expires_at: String,
}

/// The sign-in a browser is in the middle of, as its cookie names it.
struct Handle {
    id: TransactionId,
    secret: Secret<String>,
}

fn problem(status: StatusCode, code: &'static str, detail: &'static str) -> Response {
    Problem::new(status, code, detail).into_response()
}

fn no_sign_in() -> Response {
    // The same answer as the authentication context gives for a sign-in
    // that does not exist, so that a missing cookie, a malformed one and a
    // wrong secret cannot be told apart.
    Problem::from(DomainError::not_found(
        "authentication.transaction_not_found",
        "this sign-in does not exist; start again",
    ))
    .into_response()
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

fn handle(headers: &HeaderMap) -> Option<Handle> {
    let (id, secret) = cookie(headers, SIGN_IN_COOKIE)?.split_once('.')?;
    Some(Handle {
        id: id.parse().ok()?,
        secret: Secret::from(secret.to_owned()),
    })
}

fn csrf_token(digest: &dyn Digest, secret: &str) -> String {
    let mut input = b"csrf:".to_vec();
    input.extend_from_slice(secret.as_bytes());
    digest
        .sha256(&input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Compares without stopping at the first difference, so that the time
/// taken does not reveal how much of a guess was right.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0_u8, |diff, (x, y)| diff | (x ^ y))
            == 0
}

fn csrf_is_valid(headers: &HeaderMap, digest: &dyn Digest, handle: &Handle) -> bool {
    headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|presented| same(presented, &csrf_token(digest, handle.secret.expose())))
}

fn set_cookie(response: &mut Response, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn sign_in_cookie(slug: &str, value: &str, max_age: i64) -> String {
    format!(
        "{SIGN_IN_COOKIE}={value}; Path=/t/{slug}/interaction; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict"
    )
}

fn session_cookie(slug: &str, token: &SessionToken, max_age: i64) -> String {
    format!(
        "{SESSION_COOKIE}={}; Path=/t/{slug}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax",
        token.expose()
    )
}

/// Turns the outcome of a sign-in operation into its response, including
/// the cookies that go with it.
fn respond(
    state: &InteractionState,
    slug: &str,
    secret: &str,
    status: StatusCode,
    outcome: SignIn,
) -> Response {
    let token = || Some(csrf_token(state.digest.as_ref(), secret));
    match outcome {
        SignIn::Pending { step, .. } => (
            status,
            Json(SignInBody {
                status: "pending",
                step: Some(step),
                attempts_left: None,
                csrf_token: token(),
            }),
        )
            .into_response(),
        SignIn::Rejected {
            step,
            attempts_left,
            ..
        } => (
            status,
            Json(SignInBody {
                status: "rejected",
                step: Some(step),
                attempts_left: Some(attempts_left),
                csrf_token: token(),
            }),
        )
            .into_response(),
        SignIn::Failed => {
            let mut response = (
                status,
                Json(SignInBody {
                    status: "failed",
                    step: None,
                    attempts_left: None,
                    csrf_token: None,
                }),
            )
                .into_response();
            set_cookie(&mut response, &sign_in_cookie(slug, "", 0));
            response
        }
        SignIn::Completed { session, token } => {
            let lifetime = (session.snapshot().absolute_expires_at - state.clock.now())
                .whole_seconds()
                .max(0);
            let mut response = (
                status,
                Json(SignInBody {
                    status: "completed",
                    step: None,
                    attempts_left: None,
                    csrf_token: None,
                }),
            )
                .into_response();
            set_cookie(&mut response, &sign_in_cookie(slug, "", 0));
            set_cookie(&mut response, &session_cookie(slug, &token, lifetime));
            response
        }
    }
}

/// Refuses requests that change something and name another origin.
///
/// Browsers send `Origin` on such requests. When it is present it must be
/// this server's own; when it is absent the request did not come from a
/// page of another site, and the other protections apply.
async fn refuse_other_origins(request: Request, next: Next) -> Response {
    let changes_something = !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    if changes_something && let Some(origin) = request.headers().get(header::ORIGIN) {
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok());
        let origin_host = origin
            .to_str()
            .ok()
            .and_then(|origin| origin.split_once("://"))
            .map(|(_, host)| host);
        if host.is_none() || origin_host != host {
            return problem(
                StatusCode::FORBIDDEN,
                "request.cross_origin",
                "this request comes from another site",
            );
        }
    }
    next.run(request).await
}

async fn start_sign_in(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    Extension(ClientAddress(address)): Extension<ClientAddress>,
    headers: HeaderMap,
) -> Response {
    let client = ClientInfo {
        address: address.map(|a| a.to_string()),
        description: headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    };
    let started = match state.authentication.start(&tenant, client).await {
        Ok(started) => started,
        Err(error) => return Problem::from(error).into_response(),
    };
    let secret = started.secret.expose();
    let mut response = (
        StatusCode::CREATED,
        Json(SignInBody {
            status: "pending",
            step: Some(started.step),
            attempts_left: None,
            csrf_token: Some(csrf_token(state.digest.as_ref(), secret)),
        }),
    )
        .into_response();
    let value = format!("{}.{secret}", started.transaction_id);
    set_cookie(
        &mut response,
        &sign_in_cookie(&slug, &value, SIGN_IN_COOKIE_SECONDS),
    );
    response
}

async fn describe_sign_in(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
) -> Response {
    let Some(handle) = handle(&headers) else {
        return no_sign_in();
    };
    match state
        .authentication
        .describe(&tenant, handle.id, handle.secret.expose())
        .await
    {
        Ok(outcome) => respond(
            &state,
            &slug,
            handle.secret.expose(),
            StatusCode::OK,
            outcome,
        ),
        Err(error) => Problem::from(error).into_response(),
    }
}

async fn submit(
    state: &InteractionState,
    tenant: &TenantContext,
    slug: &str,
    headers: &HeaderMap,
    input: StepInput,
) -> Response {
    let Some(handle) = handle(headers) else {
        return no_sign_in();
    };
    if !csrf_is_valid(headers, state.digest.as_ref(), &handle) {
        return problem(
            StatusCode::FORBIDDEN,
            "request.csrf_token_invalid",
            "the request is missing its CSRF token, or the token is wrong",
        );
    }
    match state
        .authentication
        .submit(tenant, handle.id, handle.secret.expose(), input)
        .await
    {
        Ok(outcome) => respond(state, slug, handle.secret.expose(), StatusCode::OK, outcome),
        Err(error) => Problem::from(error).into_response(),
    }
}

async fn submit_identifier(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
    Json(body): Json<IdentifierBody>,
) -> Response {
    submit(
        &state,
        &tenant,
        &slug,
        &headers,
        StepInput::Identifier(body.identifier),
    )
    .await
}

async fn submit_password(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
    Json(body): Json<PasswordBody>,
) -> Response {
    let input = StepInput::Password(Secret::from(body.password));
    submit(&state, &tenant, &slug, &headers, input).await
}

async fn cancel_sign_in(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
) -> Response {
    let Some(handle) = handle(&headers) else {
        return no_sign_in();
    };
    if !csrf_is_valid(&headers, state.digest.as_ref(), &handle) {
        return problem(
            StatusCode::FORBIDDEN,
            "request.csrf_token_invalid",
            "the request is missing its CSRF token, or the token is wrong",
        );
    }
    match state
        .authentication
        .cancel(&tenant, handle.id, handle.secret.expose())
        .await
    {
        Ok(()) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            set_cookie(&mut response, &sign_in_cookie(&slug, "", 0));
            response
        }
        Err(error) => Problem::from(error).into_response(),
    }
}

fn session_body(session: &Session) -> SessionBody {
    let state = session.snapshot();
    let text = |moment: time::OffsetDateTime| moment.format(&Rfc3339).unwrap_or_default();
    SessionBody {
        user_id: state.user_id.to_string(),
        session_id: state.id.to_string(),
        signed_in_at: text(state.signed_in_at),
        assurance: state.assurance.as_str(),
        methods: state.methods.clone(),
        expires_at: text(session.expires_at()),
    }
}

async fn current_session(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    let not_authenticated = || {
        // One answer whatever the reason: no cookie, an unknown token, an
        // expired or a revoked session.
        problem(
            StatusCode::UNAUTHORIZED,
            "session.not_authenticated",
            "there is no valid session",
        )
    };
    let Some(token) = cookie(&headers, SESSION_COOKIE) else {
        return not_authenticated();
    };
    match state.sessions.find_by_token(&tenant, token).await {
        Ok(Some(session)) => (StatusCode::OK, Json(session_body(&session))).into_response(),
        Ok(None) => not_authenticated(),
        Err(error) => Problem::from(error).into_response(),
    }
}

/// Someone who is not signed in.
fn anonymous() -> Caller {
    Caller {
        actor: Actor::Anonymous,
        correlation_id: CorrelationId::generate(),
    }
}

/// "If there is something to send, it was sent": the same whether the
/// address has an account, has none or is not an address at all.
fn accepted(result: Result<(), DomainError>) -> Response {
    match result {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(AcceptedBody { status: "accepted" }),
        )
            .into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}

fn done<T>(result: Result<T, DomainError>) -> Response {
    match result {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}

async fn request_registration(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(ClientAddress(address)): Extension<ClientAddress>,
    Json(body): Json<AskBody>,
) -> Response {
    let address = address.map(|a| a.to_string());
    let request = AccountRequest {
        email: &body.email,
        locale: body.locale.as_deref(),
        address: address.as_deref(),
    };
    accepted(
        state
            .accounts
            .request_registration(&tenant, request, anonymous())
            .await,
    )
}

async fn complete_registration(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Json(body): Json<CompleteRegistrationBody>,
) -> Response {
    done(
        state
            .accounts
            .complete_registration(
                &tenant,
                &body.token,
                &Secret::from(body.password),
                body.display_name,
                anonymous(),
            )
            .await,
    )
}

async fn request_recovery(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(ClientAddress(address)): Extension<ClientAddress>,
    Json(body): Json<AskBody>,
) -> Response {
    let address = address.map(|a| a.to_string());
    let request = AccountRequest {
        email: &body.email,
        locale: body.locale.as_deref(),
        address: address.as_deref(),
    };
    accepted(
        state
            .accounts
            .request_recovery(&tenant, request, anonymous())
            .await,
    )
}

async fn reset_password(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Json(body): Json<ResetPasswordBody>,
) -> Response {
    done(
        state
            .accounts
            .reset_password(
                &tenant,
                &body.token,
                &Secret::from(body.password),
                anonymous(),
            )
            .await,
    )
}
