//! The consent routes of the interaction interface: what a waiting
//! authorization request asks for, the person's answer, and the person's
//! consents.
//!
//! Specified in `docs/api/interaction-api.md`, "Consent". These handlers
//! translate between HTTP and the OAuth context; the rules are its own.

use crate::authorize::AUTHORIZATION_COOKIE;
use crate::interaction::{
    CSRF_HEADER, SESSION_COOKIE, cookie, csrf_token, refuse_other_origins, same,
};
use crate::problem::Problem;
use crate::tenant::TenantSlug;
use axum::body::Bytes;
use axum::extract::{RawPathParams, State};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Extension, Json, Router};
use hodor_kernel::{Actor, Caller, CorrelationId, Digest, DomainError, TenantContext};
use hodor_oauth::api::{
    AskedScope, ClientId, ConsentActor, ConsentAnswer, ConsentService, PendingAuthorizationId,
    SignedInPerson,
};
use hodor_session::api::{Session, SessionService};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

/// What the consent routes need.
#[derive(Clone)]
pub struct ConsentState {
    /// The use cases of consent.
    pub consents: ConsentService,
    /// The session use cases, to find who the browser is signed in as.
    pub sessions: SessionService,
    /// For the CSRF token derived from the session token.
    pub digest: Arc<dyn Digest>,
}

impl std::fmt::Debug for ConsentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentState").finish_non_exhaustive()
    }
}

/// The consent routes, to be mounted under a tenant at `/interaction`
/// beside the other routes of the interaction interface.
pub fn consent_routes(state: ConsentState) -> Router {
    Router::new()
        .route("/consent", get(describe).post(answer))
        .route("/consents", get(list))
        .route("/consents/{client_id}", delete(withdraw))
        .layer(middleware::from_fn(refuse_other_origins))
        .with_state(state)
}

/// The person a request comes from, by their session cookie, with the
/// CSRF token of the session.
struct SignedIn {
    session: Session,
    csrf_token: String,
}

impl SignedIn {
    fn person(&self) -> SignedInPerson {
        let state = self.session.snapshot();
        SignedInPerson {
            user_id: state.user_id,
            session_id: state.id,
            signed_in_at: state.signed_in_at,
            methods: state.methods.clone(),
            acr: None,
        }
    }

    fn caller(&self) -> Caller {
        Caller {
            actor: Actor::User(self.session.user_id()),
            correlation_id: CorrelationId::generate(),
        }
    }
}

fn not_authenticated() -> Response {
    Problem::new(
        StatusCode::UNAUTHORIZED,
        "session.not_authenticated",
        "there is no valid session",
    )
    .into_response()
}

fn request_not_found() -> Response {
    Problem::from(DomainError::not_found(
        "oauth.consent_request_not_found",
        "no request waits for this person's consent in this browser",
    ))
    .into_response()
}

async fn signed_in(
    state: &ConsentState,
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
    state: &ConsentState,
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
        Err(Box::new(
            Problem::new(
                StatusCode::FORBIDDEN,
                "request.csrf_token_invalid",
                "the request is missing its CSRF token, or the token is wrong",
            )
            .into_response(),
        ))
    }
}

/// The waiting request this browser's cookie names.
fn waiting(headers: &HeaderMap) -> Option<(PendingAuthorizationId, &str)> {
    let (id, secret) = cookie(headers, AUTHORIZATION_COOKIE)?.split_once('.')?;
    Some((id.parse().ok()?, secret))
}

#[derive(Debug, Serialize)]
struct ScopeBody {
    scope: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_server: Option<String>,
}

#[derive(Debug, Serialize)]
struct QuestionBody {
    application: String,
    scopes: Vec<ScopeBody>,
    offline_access: bool,
    csrf_token: String,
}

async fn describe(
    State(state): State<ConsentState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    let person = match signed_in(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    let Some((id, secret)) = waiting(&headers) else {
        return request_not_found();
    };
    let asked = person.person();
    match state
        .consents
        .describe(&tenant, id, secret, asked.user_id, asked.session_id)
        .await
    {
        Ok(Some(question)) => {
            let scopes = question
                .scopes
                .into_iter()
                .map(|scope| match scope {
                    AskedScope::OpenId { scope } => ScopeBody {
                        scope,
                        kind: "openid",
                        description: None,
                        resource_server: None,
                    },
                    AskedScope::Resource {
                        scope,
                        description,
                        resource_server,
                    } => ScopeBody {
                        scope,
                        kind: "resource",
                        description: Some(description),
                        resource_server: Some(resource_server),
                    },
                })
                .collect();
            Json(QuestionBody {
                application: question.application,
                scopes,
                offline_access: question.offline_access,
                csrf_token: person.csrf_token,
            })
            .into_response()
        }
        Ok(None) => request_not_found(),
        Err(error) => Problem::from(error).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerBody {
    decision: Decision,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Serialize)]
struct ContinueBody {
    #[serde(rename = "continue")]
    next: String,
}

async fn answer(
    State(state): State<ConsentState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let person = match signed_in_to_change(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    let Ok(AnswerBody { decision }) = serde_json::from_slice(&body) else {
        return Problem::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.body_invalid",
            "the body must be { \"decision\": \"allow\" } or { \"decision\": \"deny\" }",
        )
        .into_response();
    };
    let Some((id, secret)) = waiting(&headers) else {
        return request_not_found();
    };
    let given = match decision {
        Decision::Allow => ConsentAnswer::Agreed,
        Decision::Deny => ConsentAnswer::Refused,
    };
    match state
        .consents
        .answer(
            &tenant,
            id,
            secret,
            &person.person(),
            given,
            person.caller(),
        )
        .await
    {
        Ok(true) => Json(ContinueBody {
            next: format!("/t/{slug}/oauth2/authorize/resume"),
        })
        .into_response(),
        Ok(false) => request_not_found(),
        Err(error) => Problem::from(error).into_response(),
    }
}

fn written(moment: time::OffsetDateTime) -> String {
    moment.format(&Rfc3339).unwrap_or_default()
}

#[derive(Debug, Serialize)]
struct ListedBody {
    client_id: String,
    application: String,
    scopes: Vec<String>,
    given_at: String,
    expires_at: String,
}

#[derive(Debug, Serialize)]
struct ConsentsBody {
    consents: Vec<ListedBody>,
}

async fn list(
    State(state): State<ConsentState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    let person = match signed_in(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    match state.consents.list(&tenant, person.session.user_id()).await {
        Ok(listed) => Json(ConsentsBody {
            consents: listed
                .into_iter()
                .map(|listed| ListedBody {
                    client_id: listed.consent.client_id.to_string(),
                    application: listed.application,
                    scopes: listed.consent.scopes,
                    given_at: written(listed.consent.given_at),
                    expires_at: written(listed.consent.expires_at),
                })
                .collect(),
        })
        .into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}

async fn withdraw(
    State(state): State<ConsentState>,
    Extension(tenant): Extension<TenantContext>,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    let person = match signed_in_to_change(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    // Something that is not an identifier names no consent.
    let Some(client) = parameters
        .iter()
        .find(|(name, _)| *name == "client_id")
        .and_then(|(_, value)| value.parse::<ClientId>().ok())
    else {
        return Problem::from(DomainError::not_found(
            "oauth.consent_not_found",
            "there is no such consent",
        ))
        .into_response();
    };
    match state
        .consents
        .withdraw(
            &tenant,
            person.session.user_id(),
            client,
            ConsentActor::Person,
            person.caller(),
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}
