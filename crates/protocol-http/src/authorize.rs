//! The authorization endpoint of OAuth 2.x: where a client sends a
//! person's browser to ask for an authorization code.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Authorization
//! endpoint". These handlers translate between HTTP and the OAuth and
//! session contexts; the rules are the OAuth context's.

use crate::interaction::{
    SESSION_COOKIE, SIGN_IN_COOKIE_SECONDS, cookie, set_cookie, sign_in_cookie,
};
use crate::problem::Problem;
use crate::request::ClientAddress;
use crate::tenant::TenantSlug;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use hodor_authentication::api::{AuthenticationService, StepUp, StepUpRequest};
use hodor_kernel::{Actor, Caller, CorrelationId, TenantContext, Timestamp};
use hodor_oauth::api::{
    AuthorizationCodeService, AuthorizationError, AuthorizationParameters, AuthorizationRefusal,
    AuthorizationRequest, ConsentAnswer, ConsentService, PENDING_LIFETIME, PendingAuthorizationId,
    Proof, SessionDecision, SignedInPerson,
};
use hodor_session::api::{Assurance, ClientInfo, Session, SessionService};
use hodor_tenant::api::{AssuranceLevels, AssuranceRequirement, TenantService};

/// The cookie that holds a pending authorization request's identifier and
/// the secret that binds it to the browser.
pub(crate) const AUTHORIZATION_COOKIE: &str = "__Secure-hodor_authorization";

/// What the authorization endpoint needs.
#[derive(Clone)]
pub struct AuthorizationState {
    /// The use cases of the endpoint.
    pub authorization: AuthorizationCodeService,
    /// The use cases of consent, to decide whether the person is asked.
    pub consents: ConsentService,
    /// The session use cases, to find who the browser is signed in as.
    pub sessions: SessionService,
    /// Says what a session's methods amount to, and starts step-ups.
    pub authentication: AuthenticationService,
    /// The tenant's assurance levels.
    pub tenants: TenantService,
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

/// The requirement of a tenant's level, as the session context names it.
const fn assurance_for(requirement: AssuranceRequirement) -> Assurance {
    match requirement {
        AssuranceRequirement::SingleFactor => Assurance::SingleFactor,
        AssuranceRequirement::MultiFactor => Assurance::MultiFactor,
        AssuranceRequirement::PhishingResistant => Assurance::PhishingResistant,
    }
}

/// An assurance, as a tenant's levels name it.
const fn requirement_for(assurance: Assurance) -> AssuranceRequirement {
    match assurance {
        Assurance::SingleFactor => AssuranceRequirement::SingleFactor,
        Assurance::MultiFactor => AssuranceRequirement::MultiFactor,
        Assurance::PhishingResistant => AssuranceRequirement::PhishingResistant,
    }
}

/// What a session is worth to a request: the person with the methods that
/// count, the assurance the request asks for, and whether the methods
/// reach it.
struct Standing {
    person: SignedInPerson,
    asked: Option<Assurance>,
    enough: bool,
}

async fn standing(
    state: &AuthorizationState,
    tenant: &TenantContext,
    request: &AuthorizationRequest,
    session: &Session,
    now: Timestamp,
    received_at: Option<Timestamp>,
) -> Result<Standing, Box<Response>> {
    let levels: AssuranceLevels = state
        .tenants
        .get(tenant)
        .await
        .map_err(|error| Box::new(Problem::from(error).into_response()))?
        .snapshot()
        .settings
        .authentication
        .assurance_levels
        .clone();
    let proofs: Vec<Proof> = session
        .proofs()
        .into_iter()
        .map(|(method, proven_at)| Proof {
            method: method.to_owned(),
            proven_at,
        })
        .collect();
    let counting = request.counting(&proofs, now, received_at);
    let methods: Vec<String> = counting.iter().map(|proof| proof.method.clone()).collect();
    let signed_in_at = counting
        .iter()
        .map(|proof| proof.proven_at)
        .max()
        .unwrap_or(session.snapshot().signed_in_at);
    let reached = state.authentication.assurance_of(&methods);
    let asked = request
        .acr_values
        .as_deref()
        .and_then(|values| levels.asked(values))
        .map(assurance_for);
    let enough = asked.is_none_or(|asked| reached >= Some(asked));
    let acr = reached
        .and_then(|reached| levels.reached(requirement_for(reached)))
        .map(str::to_owned);
    Ok(Standing {
        person: SignedInPerson {
            user_id: session.user_id(),
            session_id: session.id(),
            signed_in_at,
            methods,
            acr,
        },
        asked,
        enough,
    })
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

/// Issues a code for a person whose session is enough, or, when they must
/// be asked first, keeps the request and sends the browser to the consent
/// page. Returns the answer and whether it set the cookie of a request it
/// keeps.
async fn proceed(
    state: &AuthorizationState,
    tenant: &TenantContext,
    slug: &str,
    request: AuthorizationRequest,
    person: &SignedInPerson,
) -> (Response, bool) {
    let ask = match state.consents.must_ask(tenant, &request, person).await {
        Ok(ask) => ask,
        Err(error) => return (Problem::from(error).into_response(), false),
    };
    if !ask {
        return (issue(state, tenant, slug, &request, person).await, false);
    }
    if request.prompts("none") {
        let error = error_for(
            &request,
            "consent_required",
            "the person must be asked for consent",
        );
        return (redirect_error(&error, &issuer(state, slug)), false);
    }
    let location = consent_address(slug, &request);
    match state.consents.hold(tenant, request, person).await {
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
            (response, true)
        }
        Err(error) => (Problem::from(error).into_response(), false),
    }
}

/// The consent page, given the request's `ui_locales`.
fn consent_address(slug: &str, request: &AuthorizationRequest) -> String {
    match &request.ui_locales {
        Some(locales) => {
            let mut query = form_urlencoded::Serializer::new(String::new());
            query.append_pair("ui_locales", locales);
            format!("/t/{slug}/account/consent?{}", query.finish())
        }
        None => format!("/t/{slug}/account/consent"),
    }
}

fn authorization_cookie(slug: &str, value: &str, max_age: i64) -> String {
    format!(
        "{AUTHORIZATION_COOKIE}={value}; Path=/t/{slug}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict"
    )
}

fn client_of(headers: &HeaderMap, address: Option<std::net::IpAddr>) -> ClientInfo {
    ClientInfo {
        address: address.map(|a| a.to_string()),
        description: headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    }
}

/// Keeps the request while the person signs in or steps up, and sends the
/// browser to the sign-in page with the authorization cookie, and the
/// sign-in cookie of a step-up when one was started.
async fn hold(
    state: &AuthorizationState,
    tenant: &TenantContext,
    slug: &str,
    request: AuthorizationRequest,
    step_up: Option<String>,
) -> Response {
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
            if let Some(handle) = step_up {
                set_cookie(
                    &mut response,
                    &sign_in_cookie(slug, &handle, SIGN_IN_COOKIE_SECONDS),
                );
            }
            response
        }
        Err(error) => Problem::from(error).into_response(),
    }
}

/// Starts a step-up of `session`, carrying `carried`, to what the request
/// asks for; answers `unmet_authentication_requirements` when the person
/// cannot reach it.
#[allow(clippy::too_many_arguments)]
async fn step_up(
    state: &AuthorizationState,
    tenant: &TenantContext,
    slug: &str,
    client: ClientInfo,
    request: AuthorizationRequest,
    session: &Session,
    standing: Standing,
    carried: Vec<String>,
) -> Response {
    let asked = StepUpRequest {
        session_id: session.id(),
        user_id: session.user_id(),
        carried,
        demanded: standing.asked,
    };
    match state
        .authentication
        .start_step_up(tenant, client, asked)
        .await
    {
        Ok(StepUp::Started(started)) => {
            let handle = format!("{}.{}", started.transaction_id, started.secret.expose());
            hold(state, tenant, slug, request, Some(handle)).await
        }
        Ok(StepUp::Unreachable) => {
            let mut response = redirect_error(
                &error_for(
                    &request,
                    "unmet_authentication_requirements",
                    "the person cannot reach the assurance asked for",
                ),
                &issuer(state, slug),
            );
            forget_authorization(&mut response, slug);
            response
        }
        // The session reaches what the step-up would demand: nothing to ask.
        Ok(StepUp::NotNeeded) => {
            let (mut response, kept) =
                proceed(state, tenant, slug, request, &standing.person).await;
            if !kept {
                forget_authorization(&mut response, slug);
            }
            response
        }
        Err(error) => Problem::from(error).into_response(),
    }
}

async fn authorize(
    state: &AuthorizationState,
    tenant: &TenantContext,
    slug: &str,
    headers: &HeaderMap,
    client: ClientInfo,
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
    let session = match signed_in(state, tenant, headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let now = state.authorization.now();
    let standing = match &session {
        Some(session) => match standing(state, tenant, &request, session, now, None).await {
            Ok(standing) => Some(standing),
            Err(response) => return *response,
        },
        None => None,
    };
    let decision = request.decide(
        session.is_some(),
        standing
            .as_ref()
            .map_or(&[][..], |standing| standing.person.methods.as_slice()),
        standing.as_ref().is_some_and(|standing| standing.enough),
    );
    match (decision, session, standing) {
        (SessionDecision::Issue, Some(_), Some(standing)) => {
            proceed(state, tenant, slug, request, &standing.person)
                .await
                .0
        }
        (SessionDecision::StepUp { carried }, Some(session), Some(standing)) => {
            step_up(
                state, tenant, slug, client, request, &session, standing, carried,
            )
            .await
        }
        (SessionDecision::SignIn, _, _) => hold(state, tenant, slug, request, None).await,
        (
            SessionDecision::LoginRequired
            | SessionDecision::Issue
            | SessionDecision::StepUp { .. },
            _,
            _,
        ) => redirect_error(
            &error_for(&request, "login_required", "the person is not signed in"),
            &issuer(state, slug),
        ),
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
    address: Option<Extension<ClientAddress>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let parameters = AuthorizationParameters::from_pairs(
        form_urlencoded::parse(query.unwrap_or_default().as_bytes()).into_owned(),
    );
    let client = client_of(&headers, address.and_then(|Extension(ClientAddress(a))| a));
    authorize(&state, &tenant, &slug, &headers, client, &parameters).await
}

async fn authorize_by_form(
    State(state): State<AuthorizationState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    address: Option<Extension<ClientAddress>>,
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
    let client = client_of(&headers, address.and_then(|Extension(ClientAddress(a))| a));
    authorize(&state, &tenant, &slug, &headers, client, &parameters).await
}

fn forget_authorization(response: &mut Response, slug: &str) {
    set_cookie(response, &authorization_cookie(slug, "", 0));
}

async fn resume(
    State(state): State<AuthorizationState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    address: Option<Extension<ClientAddress>>,
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
    let session = match signed_in(&state, &tenant, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let now = state.authorization.now();
    let request = resumed.request;
    let denied = |state: &AuthorizationState, description: &'static str| {
        redirect_error(
            &error_for(&request, "access_denied", description),
            &issuer(state, &slug),
        )
    };
    let (mut response, kept) = match (resumed.consent, session) {
        // A request that waited for consent is answered by the answer, for
        // the session it was asked in.
        (Some(wait), Some(session)) if wait.session_id == session.id() => match wait.answer {
            Some(ConsentAnswer::Agreed) => {
                match standing(&state, &tenant, &request, &session, now, None).await {
                    Ok(standing) => (
                        issue(&state, &tenant, &slug, &request, &standing.person).await,
                        false,
                    ),
                    Err(response) => (*response, false),
                }
            }
            Some(ConsentAnswer::Refused) => (denied(&state, "the person refused"), false),
            None => (denied(&state, "the person did not answer"), false),
        },
        (Some(_), _) => (
            denied(&state, "the person is not signed in as they were asked"),
            false,
        ),
        (None, Some(session))
            if request.signed_in_as_asked(session.snapshot().signed_in_at, resumed.received_at) =>
        {
            match standing(
                &state,
                &tenant,
                &request,
                &session,
                now,
                Some(resumed.received_at),
            )
            .await
            {
                Err(response) => (*response, false),
                Ok(standing) if !standing.person.methods.is_empty() && standing.enough => {
                    proceed(&state, &tenant, &slug, request.clone(), &standing.person).await
                }
                // A new sign-in that did not reach what was asked: the
                // session is stepped up, and the request kept again. A
                // step-up demands the level, so its completion is enough.
                Ok(standing) => {
                    let carried = standing.person.methods.clone();
                    let client =
                        client_of(&headers, address.and_then(|Extension(ClientAddress(a))| a));
                    return step_up(
                        &state,
                        &tenant,
                        &slug,
                        client,
                        request.clone(),
                        &session,
                        standing,
                        carried,
                    )
                    .await;
                }
            }
        }
        (None, _) => (denied(&state, "the person did not sign in"), false),
    };
    if !kept {
        forget_authorization(&mut response, &slug);
    }
    response
}
