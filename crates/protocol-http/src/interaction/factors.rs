//! A signed-in person's own factors: listing them, the authenticator
//! application, renaming and removing keys, and recovery codes.
//!
//! Specified in `docs/api/interaction-api.md`, "Managing one's factors".
//! Every change needs a recent sign-in, checked here before anything else
//! is read; the rules themselves are the authentication context's.

use super::{InteractionState, SignedIn, signed_in, signed_in_to_change, written};
use crate::problem::Problem;
use axum::extract::{RawPathParams, State};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use hodor_authentication::api::{
    Factors, Remover, recent_sign_in_required, recent_sign_in_until, signed_in_recently,
};
use hodor_credential::api::{RecoveryCodes, WebAuthnCredential, WebAuthnCredentialId};
use hodor_kernel::{DomainError, Secret, TenantContext};
use serde::{Deserialize, Serialize};

/// Whether an authenticator application is in use.
#[derive(Debug, Serialize)]
pub(crate) struct ApplicationBody {
    pub(crate) in_use: bool,
}

/// A security key or a passkey, as its owner and an administrator see it.
#[derive(Debug, Serialize)]
pub(crate) struct KeyBody {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) passkey: bool,
    pub(crate) created_at: String,
    pub(crate) last_used_at: Option<String>,
}

impl From<&WebAuthnCredential> for KeyBody {
    fn from(key: &WebAuthnCredential) -> Self {
        let state = key.snapshot();
        Self {
            id: state.id.to_string(),
            name: state.name.clone(),
            passkey: state.discoverable == Some(true),
            created_at: written(state.created_at),
            last_used_at: state.last_used_at.map(written),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct RemainingBody {
    pub(crate) remaining: u32,
}

/// A person's factors. `recent_sign_in_until` is for the person only.
#[derive(Debug, Serialize)]
pub(crate) struct FactorsBody {
    pub(crate) authenticator_application: Option<ApplicationBody>,
    pub(crate) keys: Vec<KeyBody>,
    pub(crate) recovery_codes: RemainingBody,
    pub(crate) second_factor_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recent_sign_in_until: Option<Option<String>>,
}

impl From<&Factors> for FactorsBody {
    fn from(factors: &Factors) -> Self {
        Self {
            authenticator_application: factors
                .authenticator_application
                .map(|in_use| ApplicationBody { in_use }),
            keys: factors.keys.iter().map(KeyBody::from).collect(),
            recovery_codes: RemainingBody {
                remaining: factors.recovery_codes_remaining,
            },
            second_factor_required: factors.second_factor_required,
            recent_sign_in_until: None,
        }
    }
}

/// New recovery codes, shown once.
#[derive(Debug, Serialize)]
pub(crate) struct CodesBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_codes: Option<Vec<String>>,
}

pub(crate) fn codes_of(codes: Option<&RecoveryCodes>) -> Option<Vec<String>> {
    codes.map(|codes| codes.codes().map(str::to_owned).collect())
}

/// The secret of an application being enrolled. No `Debug`: it is the
/// secret.
#[derive(Serialize)]
struct EnrollmentBody {
    secret: String,
    uri: String,
}

/// No `Debug`: this holds a code until it is wrapped.
#[derive(Deserialize)]
pub(super) struct ConfirmBody {
    code: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct RenameBody {
    name: String,
}

/// The signed-in person, for a request that changes their factors: it
/// carries the CSRF token and comes soon after a sign-in.
pub(super) async fn recently_signed_in(
    state: &InteractionState,
    tenant: &TenantContext,
    headers: &HeaderMap,
) -> Result<SignedIn, Box<Response>> {
    let person = signed_in_to_change(state, tenant, headers).await?;
    if signed_in_recently(person.session.snapshot().signed_in_at, state.clock.now()) {
        Ok(person)
    } else {
        Err(Box::new(
            Problem::from(recent_sign_in_required()).into_response(),
        ))
    }
}

fn key_of(parameters: &RawPathParams) -> Option<WebAuthnCredentialId> {
    parameters
        .iter()
        .find(|(name, _)| *name == "key_id")
        .and_then(|(_, value)| value.parse().ok())
}

fn key_not_found() -> Response {
    Problem::from(DomainError::not_found(
        "credential.webauthn_credential_not_found",
        "there is no such security key or passkey",
    ))
    .into_response()
}

pub(super) async fn list_factors(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    let person = match signed_in(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    match state
        .factors
        .factors(&tenant, person.session.user_id())
        .await
    {
        Ok(factors) => {
            let mut body = FactorsBody::from(&factors);
            body.recent_sign_in_until = Some(
                recent_sign_in_until(person.session.snapshot().signed_in_at, state.clock.now())
                    .map(written),
            );
            Json(body).into_response()
        }
        Err(error) => Problem::from(error).into_response(),
    }
}

pub(super) async fn begin_authenticator_application(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    let person = match recently_signed_in(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    match state
        .factors
        .begin_authenticator_application(&tenant, person.session.user_id())
        .await
    {
        Ok(enrollment) => (
            StatusCode::CREATED,
            Json(EnrollmentBody {
                secret: enrollment.secret().to_owned(),
                uri: enrollment.address().to_owned(),
            }),
        )
            .into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}

pub(super) async fn confirm_authenticator_application(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    Json(body): Json<ConfirmBody>,
) -> Response {
    // Confirming finishes what was begun with a recent sign-in.
    let person = match signed_in_to_change(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    let code = Secret::from(body.code);
    match state
        .factors
        .confirm_authenticator_application(
            &tenant,
            person.session.user_id(),
            &code,
            person.caller(),
        )
        .await
    {
        Ok(codes) => Json(CodesBody {
            recovery_codes: codes_of(codes.as_ref()),
        })
        .into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}

pub(super) async fn remove_authenticator_application(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    let person = match recently_signed_in(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    match state
        .factors
        .remove_authenticator_application(
            &tenant,
            person.session.user_id(),
            Remover::Person,
            person.caller(),
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}

pub(super) async fn rename_key(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    parameters: RawPathParams,
    headers: HeaderMap,
    Json(body): Json<RenameBody>,
) -> Response {
    let person = match recently_signed_in(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    let Some(id) = key_of(&parameters) else {
        return key_not_found();
    };
    match state
        .factors
        .rename_key(
            &tenant,
            person.session.user_id(),
            id,
            &body.name,
            person.caller(),
        )
        .await
    {
        Ok(key) => Json(KeyBody::from(&key)).into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}

pub(super) async fn remove_key(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    let person = match recently_signed_in(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    let Some(id) = key_of(&parameters) else {
        return key_not_found();
    };
    match state
        .factors
        .remove_key(
            &tenant,
            person.session.user_id(),
            id,
            Remover::Person,
            person.caller(),
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}

pub(super) async fn generate_recovery_codes(
    State(state): State<InteractionState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    let person = match recently_signed_in(&state, &tenant, &headers).await {
        Ok(person) => person,
        Err(response) => return *response,
    };
    match state
        .factors
        .generate_recovery_codes(&tenant, person.session.user_id(), person.caller())
        .await
    {
        Ok(codes) => (
            StatusCode::CREATED,
            Json(CodesBody {
                recovery_codes: codes_of(Some(&codes)),
            }),
        )
            .into_response(),
        Err(error) => Problem::from(error).into_response(),
    }
}
