//! A user's second factors, as the administration and console interfaces
//! show and remove them.
//!
//! Specified in `docs/api/admin-api.md`, "A user's factors". An
//! administrator sees which factors a person has and removes them, never a
//! secret, a key or a code; the tenant's policy does not hold an
//! administrator back, and no session is ended.

use super::{Shared, authorize, failed, parameter, respond, user_not_found};
use crate::interaction::factors::FactorsBody;
use axum::Router;
use axum::extract::{RawPathParams, State};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Extension, Json};
use hodor_authentication::api::Remover;
use hodor_credential::api::WebAuthnCredentialId;
use hodor_kernel::{DomainError, TenantContext, UserId};

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/users/{user}/factors", get(list_factors))
        .route(
            "/users/{user}/factors/authenticator-application",
            delete(remove_authenticator_application),
        )
        .route("/users/{user}/factors/keys/{key}", delete(remove_key))
        .route(
            "/users/{user}/factors/recovery-codes",
            delete(remove_recovery_codes),
        )
}

fn user_of(parameters: &RawPathParams) -> Result<UserId, Box<Response>> {
    parameter(parameters, "user").ok_or_else(user_not_found)
}

async fn list_factors(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/users/{user_id}/factors").await?;
            let user = user_of(&parameters)?;
            let factors = state.factors.factors(&tenant, user).await.map_err(failed)?;
            Ok(Json(FactorsBody::from(&factors)).into_response())
        }
        .await,
    )
}

async fn remove_authenticator_application(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let caller = authorize(
                &state,
                &tenant,
                &headers,
                "DELETE",
                "/users/{user_id}/factors/authenticator-application",
            )
            .await?;
            let user = user_of(&parameters)?;
            state
                .factors
                .remove_authenticator_application(&tenant, user, Remover::Administrator, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

async fn remove_key(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let caller = authorize(
                &state,
                &tenant,
                &headers,
                "DELETE",
                "/users/{user_id}/factors/keys/{key_id}",
            )
            .await?;
            let user = user_of(&parameters)?;
            let key: WebAuthnCredentialId = parameter(&parameters, "key").ok_or_else(|| {
                failed(DomainError::not_found(
                    "credential.webauthn_credential_not_found",
                    "there is no such security key or passkey",
                ))
            })?;
            state
                .factors
                .remove_key(&tenant, user, key, Remover::Administrator, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

async fn remove_recovery_codes(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let caller = authorize(
                &state,
                &tenant,
                &headers,
                "DELETE",
                "/users/{user_id}/factors/recovery-codes",
            )
            .await?;
            let user = user_of(&parameters)?;
            state
                .factors
                .remove_recovery_codes(&tenant, user, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}
