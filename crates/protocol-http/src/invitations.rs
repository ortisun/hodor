//! Accepting an invitation to an organization, on the interaction
//! interface.
//!
//! See `docs/api/interaction-api.md`, "Accepting an invitation".

use crate::interaction::{
    CSRF_HEADER, SESSION_COOKIE, cookie, csrf_token, refuse_other_origins, same,
};
use crate::problem::Problem;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use hodor_authentication::api::InvitationService;
use hodor_kernel::{Actor, Caller, CorrelationId, Digest, Secret, TenantContext};
use hodor_session::api::SessionService;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

/// What the routes of invitations need.
#[derive(Clone)]
pub struct InvitationState {
    /// The use cases of invitations.
    pub invitations: InvitationService,
    /// The session use cases, to find who the browser is signed in as.
    pub sessions: SessionService,
    /// For deriving the session's CSRF token.
    pub digest: Arc<dyn Digest>,
}

impl std::fmt::Debug for InvitationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitationState").finish_non_exhaustive()
    }
}

/// The routes of invitations, to be mounted under a tenant at
/// `/interaction`, next to the other interaction routes.
pub fn invitation_routes(state: InvitationState) -> Router {
    Router::new()
        .route("/invitations/describe", post(describe))
        .route("/invitations/accept", post(accept))
        .layer(middleware::from_fn(refuse_other_origins))
        .with_state(state)
}

/// No `Debug`: this holds a token.
#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

/// No `Debug`: this holds a token and a password.
#[derive(Deserialize)]
struct AcceptBody {
    token: String,
    password: Option<String>,
    display_name: Option<String>,
}

#[derive(Serialize)]
struct DescriptionBody {
    organization_name: String,
    email: String,
    has_account: bool,
    expires_at: String,
}

fn anonymous() -> Caller {
    Caller {
        actor: Actor::Anonymous,
        correlation_id: CorrelationId::generate(),
    }
}

async fn describe(
    State(state): State<InvitationState>,
    Extension(tenant): Extension<TenantContext>,
    Json(body): Json<TokenBody>,
) -> Response {
    match state.invitations.describe(&tenant, &body.token).await {
        Ok(found) => (
            StatusCode::OK,
            Json(DescriptionBody {
                organization_name: found.organization_name,
                email: found.email,
                has_account: found.has_account,
                expires_at: found.expires_at.format(&Rfc3339).unwrap_or_default(),
            }),
        )
            .into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}

async fn accept(
    State(state): State<InvitationState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    Json(body): Json<AcceptBody>,
) -> Response {
    let accepted = match cookie(&headers, SESSION_COOKIE) {
        // Signed in: the session's user accepts, with the session's CSRF
        // token, and no password.
        Some(token) => {
            let session = match state.sessions.find_by_token(&tenant, token).await {
                Ok(Some(session)) => session,
                Ok(None) => return not_authenticated(),
                Err(error) => return Problem::from(error).into_response(),
            };
            let expected = csrf_token(state.digest.as_ref(), token);
            let presented = headers
                .get(CSRF_HEADER)
                .and_then(|value| value.to_str().ok());
            if !presented.is_some_and(|presented| same(presented, &expected)) {
                return Problem::new(
                    StatusCode::FORBIDDEN,
                    "request.csrf_token_invalid",
                    "the request is missing its CSRF token, or the token is wrong",
                )
                .into_response();
            }
            let caller = Caller {
                actor: Actor::User(session.user_id()),
                correlation_id: CorrelationId::generate(),
            };
            state
                .invitations
                .accept_signed_in(&tenant, &body.token, session.user_id(), caller)
                .await
        }
        // Not signed in: an account is made for an address that has none.
        None => {
            let Some(password) = body.password else {
                return Problem::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "request.invalid_body",
                    "a password is needed to create the account",
                )
                .into_response();
            };
            state
                .invitations
                .accept_as_new(
                    &tenant,
                    &body.token,
                    &Secret::from(password),
                    body.display_name,
                    anonymous(),
                )
                .await
                .map(|_| ())
        }
    };
    match accepted {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => Problem::from(error).into_response(),
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
