//! Client registration, as the administration and console interfaces
//! manage it: the tenant's settings and policy, and its initial access
//! tokens.
//!
//! Specified in `docs/api/admin-api.md`, "Client registration". The rules
//! are the OAuth context's; these handlers translate them.

use super::{Shared, authorize, body, failed, parameter, respond, written};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawPathParams, State};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json};
use hodor_kernel::{DomainError, TenantContext, Timestamp};
use hodor_oauth::api::{
    ApplicationId, DEFAULT_INITIAL_ACCESS_TOKEN_LIFETIME, DEFAULT_MOST_REGISTERED_CLIENTS,
    InitialAccessToken, InitialAccessTokenId, NewInitialAccessToken, RegistrationInForce,
    RegistrationPolicy, RegistrationSettings, RegistrationWay,
};
use serde::{Deserialize, Serialize};
use time::Duration;

const SETTINGS: &str = "/client-registration";
const TOKENS: &str = "/client-registration/initial-access-tokens";
const TOKEN: &str = "/client-registration/initial-access-tokens/{token_id}";

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route(SETTINGS, get(read_settings).put(replace_settings))
        .route(TOKENS, get(list_tokens).post(create_token))
        .route(
            "/client-registration/initial-access-tokens/{token}",
            get(get_token).delete(revoke_token),
        )
}

fn token_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "oauth.initial_access_token_not_found",
        "there is no such initial access token",
    ))
}

#[derive(Debug, Serialize)]
struct SettingsBody {
    enabled: bool,
    application_id: Option<String>,
    ways: Vec<&'static str>,
    max_clients: u32,
    policy: serde_json::Value,
    updated_at: Option<String>,
}

impl From<&RegistrationInForce> for SettingsBody {
    fn from(in_force: &RegistrationInForce) -> Self {
        let settings = &in_force.settings;
        Self {
            enabled: settings.enabled,
            application_id: settings.application_id.map(|id| id.to_string()),
            ways: settings.way_names(),
            max_clients: settings.max_clients,
            policy: settings.policy.to_json(),
            updated_at: in_force.updated_at.map(written),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewSettingsBody {
    enabled: bool,
    #[serde(default)]
    application_id: Option<String>,
    #[serde(default)]
    ways: Option<Vec<String>>,
    #[serde(default)]
    max_clients: Option<u32>,
    #[serde(default)]
    policy: Option<serde_json::Value>,
}

impl NewSettingsBody {
    /// The settings the body gives, each member left out at its default.
    fn settings(self) -> Result<RegistrationSettings, DomainError> {
        let defaults = RegistrationSettings::default();
        let application_id = self
            .application_id
            .map(|given| {
                given.parse::<ApplicationId>().map_err(|_| {
                    DomainError::invalid(
                        "oauth.client_registration_application_invalid",
                        "registered clients belong to one application of the tenant",
                    )
                })
            })
            .transpose()?;
        let ways = match self.ways {
            None => defaults.ways,
            Some(names) => names
                .iter()
                .map(|name| RegistrationWay::parse(name))
                .collect::<Result<_, _>>()?,
        };
        let policy = match self.policy {
            None => RegistrationPolicy::default(),
            Some(given) => RegistrationPolicy::from_json(&given)?,
        };
        Ok(RegistrationSettings {
            enabled: self.enabled,
            application_id,
            ways,
            max_clients: self.max_clients.unwrap_or(DEFAULT_MOST_REGISTERED_CLIENTS),
            policy,
        })
    }
}

#[derive(Debug, Serialize)]
struct TokenBody {
    id: String,
    name: String,
    hint: String,
    status: &'static str,
    max_registrations: u32,
    registrations: u32,
    created_at: String,
    expires_at: String,
    last_used_at: Option<String>,
    revoked_at: Option<String>,
}

impl TokenBody {
    fn of(token: &InitialAccessToken, now: Timestamp) -> Self {
        let state = token.snapshot();
        Self {
            id: state.id.to_string(),
            name: state.name.clone(),
            hint: format!("…{}", state.hint),
            status: token.status(now).as_str(),
            max_registrations: state.max_registrations,
            registrations: state.registrations,
            created_at: written(state.created_at),
            expires_at: written(state.expires_at),
            last_used_at: state.last_used_at.map(written),
            revoked_at: state.revoked_at.map(written),
        }
    }
}

#[derive(Debug, Serialize)]
struct MadeTokenBody {
    #[serde(flatten)]
    token: TokenBody,
    initial_access_token: String,
}

#[derive(Debug, Serialize)]
struct Items {
    items: Vec<TokenBody>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewTokenBody {
    name: String,
    #[serde(default)]
    lifetime_hours: Option<i64>,
    #[serde(default)]
    max_registrations: Option<u32>,
}

async fn read_settings(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", SETTINGS).await?;
            let in_force = state
                .client_registration
                .settings(&tenant)
                .await
                .map_err(failed)?;
            Ok(Json(SettingsBody::from(&in_force)).into_response())
        }
        .await,
    )
}

async fn replace_settings(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "PUT", SETTINGS).await?;
            let given: NewSettingsBody = body(&bytes)?;
            let settings = given.settings().map_err(failed)?;
            let in_force = state
                .client_registration
                .replace(&tenant, settings, caller)
                .await
                .map_err(failed)?;
            Ok(Json(SettingsBody::from(&in_force)).into_response())
        }
        .await,
    )
}

async fn list_tokens(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", TOKENS).await?;
            let tokens = state
                .client_registration
                .tokens(&tenant)
                .await
                .map_err(failed)?;
            let now = state.client_registration.now();
            let items = tokens
                .iter()
                .map(|token| TokenBody::of(token, now))
                .collect();
            Ok(Json(Items { items }).into_response())
        }
        .await,
    )
}

async fn create_token(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "POST", TOKENS).await?;
            let given: NewTokenBody = body(&bytes)?;
            let lifetime =
                given
                    .lifetime_hours
                    .map_or(DEFAULT_INITIAL_ACCESS_TOKEN_LIFETIME, |hours| {
                        // Held far from overflow; the rule of a lifetime refuses
                        // anything past 90 days.
                        Duration::hours(hours.clamp(-1_000_000, 1_000_000))
                    });
            let (token, value) = state
                .client_registration
                .issue_token(
                    &tenant,
                    NewInitialAccessToken {
                        name: given.name,
                        lifetime,
                        max_registrations: given.max_registrations.unwrap_or(1),
                    },
                    caller,
                )
                .await
                .map_err(failed)?;
            let made = MadeTokenBody {
                token: TokenBody::of(&token, state.client_registration.now()),
                initial_access_token: value.expose().to_owned(),
            };
            Ok((StatusCode::CREATED, Json(made)).into_response())
        }
        .await,
    )
}

async fn get_token(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", TOKEN).await?;
            let id: InitialAccessTokenId =
                parameter(&parameters, "token").ok_or_else(token_not_found)?;
            let token = state
                .client_registration
                .token(&tenant, id)
                .await
                .map_err(failed)?;
            Ok(Json(TokenBody::of(&token, state.client_registration.now())).into_response())
        }
        .await,
    )
}

async fn revoke_token(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "DELETE", TOKEN).await?;
            let id: InitialAccessTokenId =
                parameter(&parameters, "token").ok_or_else(token_not_found)?;
            state
                .client_registration
                .revoke_token(&tenant, id, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}
