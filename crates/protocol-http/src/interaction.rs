//! The interaction interface: how a browser signs in, and how a person
//! registers or recovers a password.
//!
//! Specified in `docs/api/interaction-api.md`. These handlers translate
//! between HTTP and the authentication context; they decide nothing about
//! a sign-in themselves.

use crate::problem::Problem;
use crate::request::ClientAddress;
use crate::tenant::TenantSlug;
use axum::extract::{RawPathParams, Request, State};
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use hodor_authentication::api::{
    AccountRequest, AccountService, AuthenticationService, ExternalInput, SignIn, StepInput,
    TransactionId,
};
use hodor_federation::api::{Alias, EXTERNAL_STEP, ExternalSignIn};
use hodor_kernel::{
    Actor, Caller, Clock, CorrelationId, Digest, DomainError, Secret, TenantContext,
};
use hodor_session::api::{ClientInfo, Session, SessionId, SessionService, SessionToken};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

const SIGN_IN_COOKIE: &str = "__Secure-hodor_signin";
pub(crate) const SESSION_COOKIE: &str = "__Secure-hodor_session";
pub(crate) const CSRF_HEADER: HeaderName = HeaderName::from_static("x-csrf-token");
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
    /// Signing in through an identity provider. `None` when this
    /// installation is not set up for it: no provider is offered then.
    pub external: Option<ExternalSignIn>,
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
        .route("/sign-in/providers", get(offered_providers))
        .route("/sign-in/providers/{alias}", post(choose_provider))
        .route(
            "/sign-in/providers/{alias}/callback",
            post(finish_with_provider),
        )
        .route(
            "/sign-in/providers/{alias}/password",
            post(sign_in_with_directory),
        )
        .route("/session", get(current_session).delete(sign_out))
        .route("/sessions", get(list_sessions).delete(end_other_sessions))
        .route("/sessions/{session_id}", delete(end_session))
        .route("/registration", post(request_registration))
        .route("/registration/complete", post(complete_registration))
        .route("/recovery", post(request_recovery))
        .route("/recovery/complete", post(reset_password))
        .layer(middleware::from_fn(refuse_other_origins))
        // Another site posts to the assertion consumer: it is outside the
        // origin check, and can only keep the answer to a response for a
        // sign-in that this origin's page finishes.
        .route(
            "/sign-in/providers/{alias}/saml",
            post(receive_saml_response),
        )
        .route(
            "/sign-in/providers/{alias}/saml/metadata",
            get(saml_metadata),
        )
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

/// A provider as the sign-in page shows it.
#[derive(Debug, Serialize)]
struct OfferedBody {
    alias: String,
    display_name: String,
    kind: &'static str,
}

#[derive(Debug, Serialize)]
struct ProvidersBody {
    providers: Vec<OfferedBody>,
}

/// Where to send the browser.
#[derive(Debug, Serialize)]
struct RedirectBody {
    redirect: String,
}

/// No `Debug`: this holds a password until it is wrapped.
#[derive(Deserialize)]
struct DirectoryBody {
    identifier: String,
    password: String,
}

/// No `Debug`: this holds what a provider sent back until it is used.
#[derive(Deserialize)]
struct CallbackBody {
    /// What an OpenID Connect provider or GitHub sent back. A SAML
    /// provider sends no code: its response was kept when it was posted.
    #[serde(default)]
    code: Option<String>,
    state: String,
    /// What the assertion consumer gave the browser that posted a SAML
    /// response.
    #[serde(default)]
    receipt: Option<String>,
}

/// What a SAML identity provider posts. No `Debug`: the response says who
/// a person is until it is checked.
#[derive(Deserialize)]
struct SamlPost {
    #[serde(rename = "SAMLResponse")]
    response: String,
    #[serde(rename = "RelayState", default)]
    relay_state: String,
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
    csrf_token: String,
}

/// One of a person's sessions, as they see it in their own list.
#[derive(Debug, Serialize)]
struct ListedSession {
    session_id: String,
    current: bool,
    started_at: String,
    last_activity_at: String,
    expires_at: String,
    address: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionsBody {
    sessions: Vec<ListedSession>,
}

#[derive(Debug, Serialize)]
struct EndedBody {
    ended: usize,
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

pub(crate) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
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

pub(crate) fn csrf_token(digest: &dyn Digest, secret: &str) -> String {
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
pub(crate) fn same(a: &str, b: &str) -> bool {
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
pub(crate) async fn refuse_other_origins(request: Request, next: Next) -> Response {
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

fn provider_not_found() -> Response {
    problem(
        StatusCode::NOT_FOUND,
        "federation.provider_not_found",
        "there is no such identity provider",
    )
}

/// The alias in the path, if it is there.
fn alias_of(parameters: &RawPathParams) -> Option<String> {
    parameters
        .iter()
        .find(|(name, _)| *name == "alias")
        .map(|(_, value)| value.to_owned())
}

async fn offered_providers(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
) -> Response {
    let Some(external) = &state.external else {
        return Json(ProvidersBody {
            providers: Vec::new(),
        })
        .into_response();
    };
    match external.offered(&tenant).await {
        Ok(offered) => Json(ProvidersBody {
            providers: offered
                .into_iter()
                .map(|provider| OfferedBody {
                    alias: provider.alias,
                    display_name: provider.display_name,
                    kind: provider.kind.as_str(),
                })
                .collect(),
        })
        .into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}

async fn choose_provider(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    parameters: RawPathParams,
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
    let (Some(external), Some(alias)) = (&state.external, alias_of(&parameters)) else {
        return provider_not_found();
    };
    // A pending authorization is made only for a sign-in that is this browser's and is
    // still in progress.
    match state
        .authentication
        .describe(&tenant, handle.id, handle.secret.expose())
        .await
    {
        Ok(SignIn::Pending { .. } | SignIn::Rejected { .. }) => {}
        Ok(_) => {
            return Problem::from(DomainError::conflict(
                "authentication.transaction_not_active",
                "this sign-in is no longer in progress; start again",
            ))
            .into_response();
        }
        Err(error) => return Problem::from(error).into_response(),
    }
    match external.begin(&tenant, &slug, handle.id, &alias).await {
        Ok(redirect) => Json(RedirectBody { redirect }).into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}

async fn finish_with_provider(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    parameters: RawPathParams,
    headers: HeaderMap,
    Json(body): Json<CallbackBody>,
) -> Response {
    let (Some(_), Some(alias)) = (&state.external, alias_of(&parameters)) else {
        return provider_not_found();
    };
    let mut fields = vec![
        ("provider".to_owned(), Secret::from(alias)),
        ("state".to_owned(), Secret::from(body.state)),
    ];
    if let Some(code) = body.code {
        fields.push(("code".to_owned(), Secret::from(code)));
    }
    if let Some(receipt) = body.receipt {
        fields.push(("receipt".to_owned(), Secret::from(receipt)));
    }
    let input = StepInput::External(ExternalInput {
        step: EXTERNAL_STEP.to_owned(),
        fields,
    });
    submit(&state, &tenant, &slug, &headers, input).await
}

/// A relay state that may be written into an address: a plain token, as
/// Hodor makes them, of at most 80 characters.
fn is_plain_token(relay_state: &str) -> bool {
    (1..=80).contains(&relay_state.len())
        && relay_state
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Where a SAML identity provider posts its response. The response is checked
/// against the request of the pending authorization its relay state names,
/// only its answer is kept there, and the browser is sent to the page that
/// finishes. What the browser is told is the same whatever was found.
async fn receive_saml_response(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    parameters: RawPathParams,
    posted: Result<axum::Form<SamlPost>, axum::extract::rejection::FormRejection>,
) -> Response {
    // The alias goes into the address the browser is sent to: only one
    // that is an alias at all.
    let (Some(external), Some(alias)) = (
        &state.external,
        alias_of(&parameters).filter(|alias| Alias::parse(alias).is_ok()),
    ) else {
        return provider_not_found();
    };
    let mut location = format!("/t/{slug}/account/providers/{alias}/callback?binding=saml");
    if let Ok(axum::Form(post)) = posted
        && is_plain_token(&post.relay_state)
    {
        // The receipt goes to this browser only, in the address it is sent
        // to: finishing needs it, so the browser that finishes is the one
        // that carried the response.
        let receipt = match external
            .keep_saml_response(&tenant, &alias, &post.relay_state, &post.response)
            .await
        {
            Ok(receipt) => receipt,
            Err(error) => return Problem::from(error).into_response(),
        };
        location.push_str("&state=");
        location.push_str(&post.relay_state);
        location.push_str("&receipt=");
        location.push_str(&receipt);
    }
    match HeaderValue::from_str(&location) {
        Ok(location) => (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response(),
        Err(_) => provider_not_found(),
    }
}

/// Hodor's metadata for one SAML provider of the tenant.
async fn saml_metadata(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    parameters: RawPathParams,
) -> Response {
    let (Some(external), Some(alias)) = (&state.external, alias_of(&parameters)) else {
        return provider_not_found();
    };
    match external.saml_metadata(&tenant, &slug, &alias).await {
        Ok(metadata) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/samlmetadata+xml"),
            )],
            metadata,
        )
            .into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}

async fn sign_in_with_directory(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    parameters: RawPathParams,
    headers: HeaderMap,
    Json(body): Json<DirectoryBody>,
) -> Response {
    let (Some(_), Some(alias)) = (&state.external, alias_of(&parameters)) else {
        return provider_not_found();
    };
    let input = StepInput::External(ExternalInput {
        step: EXTERNAL_STEP.to_owned(),
        fields: vec![
            ("provider".to_owned(), Secret::from(alias)),
            ("identifier".to_owned(), Secret::from(body.identifier)),
            ("password".to_owned(), Secret::from(body.password)),
        ],
    });
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

fn written(moment: time::OffsetDateTime) -> String {
    moment.format(&Rfc3339).unwrap_or_default()
}

fn session_body(session: &Session, csrf_token: String) -> SessionBody {
    let state = session.snapshot();
    SessionBody {
        user_id: state.user_id.to_string(),
        session_id: state.id.to_string(),
        signed_in_at: written(state.signed_in_at),
        assurance: state.assurance.as_str(),
        methods: state.methods.clone(),
        expires_at: written(session.expires_at()),
        csrf_token,
    }
}

/// One answer whatever the reason: no cookie, an unknown token, an expired
/// or a revoked session.
fn not_authenticated() -> Response {
    problem(
        StatusCode::UNAUTHORIZED,
        "session.not_authenticated",
        "there is no valid session",
    )
}

/// The person a request comes from, by their session cookie.
struct SignedIn {
    session: Session,
    /// The CSRF token that belongs to the session, derived from its token.
    csrf_token: String,
}

impl SignedIn {
    fn caller(&self) -> Caller {
        Caller {
            actor: Actor::User(self.session.user_id()),
            correlation_id: CorrelationId::generate(),
        }
    }
}

async fn signed_in(
    state: &InteractionState,
    tenant: &TenantContext,
    headers: &HeaderMap,
) -> Result<SignedIn, Box<Response>> {
    let token = cookie(headers, SESSION_COOKIE).ok_or_else(|| Box::new(not_authenticated()))?;
    match state.sessions.find_by_token(tenant, token).await {
        Ok(Some(session)) => Ok(SignedIn {
            session,
            csrf_token: csrf_token(state.digest.as_ref(), token),
        }),
        Ok(None) => Err(Box::new(not_authenticated())),
        Err(error) => Err(Box::new(Problem::from(error).into_response())),
    }
}

/// The signed-in person, for a request that changes something: it must
/// also carry the session's CSRF token.
async fn signed_in_to_change(
    state: &InteractionState,
    tenant: &TenantContext,
    headers: &HeaderMap,
) -> Result<SignedIn, Box<Response>> {
    let person = signed_in(state, tenant, headers).await?;
    let presented = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if presented.is_some_and(|presented| same(presented, &person.csrf_token)) {
        Ok(person)
    } else {
        Err(Box::new(problem(
            StatusCode::FORBIDDEN,
            "request.csrf_token_invalid",
            "the request is missing its CSRF token, or the token is wrong",
        )))
    }
}

/// Tells the browser to forget the session cookie.
fn forget_session(response: &mut Response, slug: &str) {
    set_cookie(
        response,
        &format!("{SESSION_COOKIE}=; Path=/t/{slug}; Max-Age=0; HttpOnly; Secure; SameSite=Lax"),
    );
}

async fn current_session(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    match signed_in(&state, &tenant, &headers).await {
        Ok(person) => (
            StatusCode::OK,
            Json(session_body(&person.session, person.csrf_token)),
        )
            .into_response(),
        Err(response) => *response,
    }
}

async fn sign_out(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
) -> Response {
    let person = match signed_in_to_change(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    let ended = state
        .sessions
        .revoke(&tenant, person.session.id(), "sign_out", person.caller())
        .await;
    match ended {
        Ok(()) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            forget_session(&mut response, &slug);
            response
        }
        Err(error) => Problem::from(error).into_response(),
    }
}

async fn list_sessions(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    let person = match signed_in(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    let listed = state
        .sessions
        .list_for_user(&tenant, person.session.user_id())
        .await;
    match listed {
        Ok(sessions) => {
            let sessions = sessions
                .iter()
                .map(|session| {
                    let stored = session.snapshot();
                    ListedSession {
                        session_id: stored.id.to_string(),
                        current: stored.id == person.session.id(),
                        started_at: written(stored.started_at),
                        last_activity_at: written(stored.last_activity_at),
                        expires_at: written(session.expires_at()),
                        address: stored.client.address.clone(),
                        description: stored.client.description.clone(),
                    }
                })
                .collect();
            (StatusCode::OK, Json(SessionsBody { sessions })).into_response()
        }
        Err(error) => Problem::from(error).into_response(),
    }
}

async fn end_session(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    let person = match signed_in_to_change(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    let not_found = || {
        Problem::from(DomainError::not_found(
            "session.not_found",
            "the session does not exist",
        ))
        .into_response()
    };
    // Something that is not an identifier names no session.
    let Some(id) = parameters
        .iter()
        .find(|(name, _)| *name == "session_id")
        .and_then(|(_, value)| value.parse::<SessionId>().ok())
    else {
        return not_found();
    };
    let ended = state
        .sessions
        .revoke_for_user(
            &tenant,
            person.session.user_id(),
            id,
            "ended_by_user",
            person.caller(),
        )
        .await;
    match ended {
        Ok(()) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            if id == person.session.id() {
                forget_session(&mut response, &slug);
            }
            response
        }
        Err(error) => Problem::from(error).into_response(),
    }
}

async fn end_other_sessions(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    let person = match signed_in_to_change(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    let ended = state
        .sessions
        .revoke_all_for_user(
            &tenant,
            person.session.user_id(),
            Some(person.session.id()),
            "ended_by_user",
            person.caller(),
        )
        .await;
    match ended {
        Ok(ended) => (StatusCode::OK, Json(EndedBody { ended })).into_response(),
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
