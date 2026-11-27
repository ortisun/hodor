//! A signed-in person's own profile: their display name and standard
//! claims, read and replaced from the account page.
//!
//! Specified in `docs/api/interaction-api.md`, "The person's profile". The
//! rules are the identity context's; the person cannot vouch for their
//! telephone number.

use super::{InteractionState, problem, signed_in, signed_in_to_change};
use crate::claims::ClaimsBody;
use crate::problem::Problem;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use hodor_identity::api::{User, UserKind};
use hodor_kernel::TenantContext;
use serde::{Deserialize, Serialize};

/// What the account page shows and changes of the person.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProfileBody {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    claims: ClaimsBody,
}

impl From<&User> for ProfileBody {
    fn from(user: &User) -> Self {
        let state = user.snapshot();
        Self {
            display_name: state.profile.display_name.clone(),
            claims: ClaimsBody::of(&state.claims, state.kind == UserKind::Human),
        }
    }
}

/// `GET /interaction/profile`.
pub(super) async fn read_profile(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    let person = match signed_in(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    match state
        .accounts
        .own_profile(&tenant, person.session.user_id())
        .await
    {
        Ok(user) => Json(ProfileBody::from(&user)).into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}

/// `PUT /interaction/profile`.
pub(super) async fn replace_profile(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let person = match signed_in_to_change(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    // Read once the person is known, so that everyone else is refused in
    // one way whatever they send.
    let Ok(body) = serde_json::from_slice::<ProfileBody>(&body) else {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.invalid_body",
            "the body is { \"display_name\": …, \"claims\": { … } }",
        );
    };
    match state
        .accounts
        .change_own_profile(
            &tenant,
            person.session.user_id(),
            body.display_name,
            body.claims.into_claims(),
            person.caller(),
        )
        .await
    {
        Ok(user) => Json(ProfileBody::from(&user)).into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}
