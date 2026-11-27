//! The registration endpoint, where a client registers itself (RFC 7591,
//! OpenID Connect Dynamic Client Registration), and its registration client
//! address, where it reads, changes and removes its registration (RFC 7592).
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "The registration
//! endpoint" and "Managing a registration". These handlers translate
//! between HTTP and the OAuth context; the rules are the context's.

use crate::bearer::bearer;
use crate::problem::Problem;
use crate::request::ClientAddress;
use crate::tenant::TenantSlug;
use axum::body::Bytes;
use axum::extract::{RawPathParams, State};
use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use hodor_kernel::{Actor, Caller, CorrelationId, Digest, DomainError, ErrorKind, TenantContext};
use hodor_oauth::api::{
    ApplicationService, ChangeRegistration, Client, ClientId, ClientRegistrationService,
    ManageRegistration, Management, RegisterClient, registration_answer,
};
use serde::Serialize;
use std::sync::Arc;

/// What the registration endpoint needs.
#[derive(Clone)]
pub struct RegistrationState {
    /// The use case that registers a client.
    pub applications: ApplicationService,
    /// The tenant's registration settings and initial access tokens.
    pub registration: ClientRegistrationService,
    /// The address people reach this installation at, without a path. The
    /// issuer of a tenant is this address followed by `/t/{slug}`.
    pub public_url: String,
    /// SHA-256, for the hash of the client address.
    pub digest: Arc<dyn Digest>,
}

impl std::fmt::Debug for RegistrationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationState").finish_non_exhaustive()
    }
}

/// The registration endpoint and the registration client addresses, to be
/// mounted under a tenant at `/oauth2`.
pub fn registration_routes(state: RegistrationState) -> Router {
    Router::new()
        .route("/register", post(register))
        .route(
            "/register/{client_id}",
            get(read).put(change).delete(remove),
        )
        .with_state(state)
}

#[derive(Serialize)]
struct ErrorAnswer {
    error: &'static str,
    error_description: String,
}

/// No answer of the registration endpoint may be kept by a cache: the
/// first one holds a secret.
fn not_cached(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// The `error` of RFC 7591, section 3.2.2, that an `Invalid` refusal is
/// answered with.
fn metadata_error(code: &str) -> &'static str {
    match code {
        "oauth.software_statement_unapproved" => "unapproved_software_statement",
        "oauth.client_redirect_uri_invalid"
        | "oauth.client_application_type_invalid"
        | "oauth.registration_redirect_host_not_allowed" => "invalid_redirect_uri",
        _ => "invalid_client_metadata",
    }
}

fn description(error: &DomainError) -> String {
    match error.detail() {
        Some(detail) => format!("{}: {detail}", error.message()),
        None => error.message().to_owned(),
    }
}

/// The answer to a refused registration, as `docs/architecture/contexts/
/// oauth.md`, "Refusals", says.
fn refused(error: &DomainError, issuer: &str) -> Response {
    tracing::info!(code = error.code(), "a registration was refused");
    let answer = |status: StatusCode, error_code: &'static str| {
        (
            status,
            Json(ErrorAnswer {
                error: error_code,
                error_description: description(error),
            }),
        )
            .into_response()
    };
    match error.kind() {
        // As an address that does not exist.
        ErrorKind::NotFound if error.code() == "oauth.client_registration_off" => Problem::new(
            StatusCode::NOT_FOUND,
            "route.not_found",
            "the requested resource does not exist",
        )
        .into_response(),
        ErrorKind::Unauthenticated => {
            let mut response = answer(StatusCode::UNAUTHORIZED, "invalid_token");
            let challenge = if matches!(
                error.code(),
                "oauth.initial_access_token_required" | "oauth.registration_access_token_required"
            ) {
                format!("Bearer realm=\"{issuer}\"")
            } else {
                format!("Bearer realm=\"{issuer}\", error=\"invalid_token\"")
            };
            if let Ok(value) = HeaderValue::from_str(&challenge) {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, value);
            }
            response
        }
        ErrorKind::RateLimited => {
            let mut response = answer(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable");
            let seconds = error.retry_after_seconds().unwrap_or(60).to_string();
            if let Ok(value) = HeaderValue::from_str(&seconds) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        ErrorKind::Forbidden => answer(StatusCode::FORBIDDEN, "access_denied"),
        ErrorKind::Conflict
            if matches!(
                error.code(),
                "oauth.client_registration_modified_concurrently"
                    | "oauth.client_modified_concurrently"
            ) =>
        {
            answer(StatusCode::CONFLICT, "temporarily_unavailable")
        }
        // A key taken twice or one too many is the registration's own.
        ErrorKind::Invalid | ErrorKind::Conflict => {
            answer(StatusCode::BAD_REQUEST, metadata_error(error.code()))
        }
        _ => Problem::from(error.clone()).into_response(),
    }
}

/// Whether the request says its body is JSON.
fn says_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
}

async fn register(
    State(state): State<RegistrationState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    address: Option<Extension<ClientAddress>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let issuer = issuer_of(&state, &slug);
    // An `Authorization` header that is not a bearer token is presented as
    // nothing a token could be, so that it is refused as one, after the
    // tenant's registration is known to be on.
    let initial_access_token = match bearer(&headers) {
        Ok(token) => token.map(str::to_owned),
        Err(()) => Some(String::new()),
    };
    let body = json_body(&headers, &bytes);
    let address_hash = address
        .and_then(|Extension(ClientAddress(address))| address)
        .map(|address| state.digest.sha256(address.to_string().as_bytes()));
    // Whoever registers is not known to Hodor; how the registration was
    // allowed is in its event.
    let caller = anonymous();
    let registered = state
        .applications
        .register_client(
            &state.registration,
            &tenant,
            RegisterClient {
                body,
                initial_access_token,
                address_hash,
            },
            caller,
        )
        .await;
    not_cached(match registered {
        Ok(registered) => {
            let uri = client_uri(&issuer, &registered.client);
            (
                StatusCode::CREATED,
                Json(registration_answer(
                    &registered.client,
                    registered.secret.as_ref(),
                    Some(Management {
                        access_token: registered.access_token.expose(),
                        client_uri: &uri,
                    }),
                )),
            )
                .into_response()
        }
        Err(error) => refused(&error, &issuer),
    })
}

/// The issuer of the tenant of `slug`.
fn issuer_of(state: &RegistrationState, slug: &str) -> String {
    format!("{}/t/{slug}", state.public_url.trim_end_matches('/'))
}

/// The registration client address of `client`, where it manages its
/// registration.
fn client_uri(issuer: &str, client: &Client) -> String {
    format!("{issuer}/oauth2/register/{}", client.id())
}

/// The body of a request, read as JSON when it says it is; anything else
/// is read as nothing, which is refused as metadata once the request is
/// admitted.
fn json_body(headers: &HeaderMap, bytes: &Bytes) -> serde_json::Value {
    if says_json(headers) {
        serde_json::from_slice(bytes).unwrap_or(serde_json::Value::Null)
    } else {
        serde_json::Value::Null
    }
}

/// Which registration a request at a registration client address names,
/// and the token it presents. An `Authorization` header that is not a
/// bearer token is presented as nothing a token could be, so that it is
/// refused as one; an address that names nothing that could be a client
/// names no registration, and is refused in the same way.
fn managed(parameters: &RawPathParams, headers: &HeaderMap) -> ManageRegistration {
    let access_token = match bearer(headers) {
        Ok(token) => token.map(str::to_owned),
        Err(()) => Some(String::new()),
    };
    let client_id = parameters
        .iter()
        .find(|(name, _)| *name == "client_id")
        .and_then(|(_, value)| value.parse::<ClientId>().ok());
    ManageRegistration {
        client_id,
        access_token,
    }
}

/// Whoever manages a registration is known to Hodor only by its token;
/// what was done is in the event.
fn anonymous() -> Caller {
    Caller {
        actor: Actor::Anonymous,
        correlation_id: CorrelationId::generate(),
    }
}

async fn read(
    State(state): State<RegistrationState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    let issuer = issuer_of(&state, &slug);
    let request = managed(&parameters, &headers);
    let read = state
        .applications
        .read_registration(&state.registration, &tenant, &request)
        .await;
    not_cached(match read {
        // The token it was sent is its current one, and the answer gives
        // it back, as RFC 7592 asks.
        Ok(client) => {
            let uri = client_uri(&issuer, &client);
            Json(registration_answer(
                &client,
                None,
                Some(Management {
                    access_token: request.access_token.as_deref().unwrap_or_default(),
                    client_uri: &uri,
                }),
            ))
            .into_response()
        }
        Err(error) => refused(&error, &issuer),
    })
}

async fn change(
    State(state): State<RegistrationState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    parameters: RawPathParams,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let issuer = issuer_of(&state, &slug);
    let changed = state
        .applications
        .change_registration(
            &state.registration,
            &tenant,
            ChangeRegistration {
                registration: managed(&parameters, &headers),
                body: json_body(&headers, &bytes),
            },
            anonymous(),
        )
        .await;
    not_cached(match changed {
        Ok(changed) => {
            let uri = client_uri(&issuer, &changed.client);
            Json(registration_answer(
                &changed.client,
                changed.secret.as_ref(),
                Some(Management {
                    access_token: changed.access_token.expose(),
                    client_uri: &uri,
                }),
            ))
            .into_response()
        }
        Err(error) => refused(&error, &issuer),
    })
}

async fn remove(
    State(state): State<RegistrationState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    let issuer = issuer_of(&state, &slug);
    let removed = state
        .applications
        .remove_registration(
            &state.registration,
            &tenant,
            &managed(&parameters, &headers),
            anonymous(),
        )
        .await;
    not_cached(match removed {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => refused(&error, &issuer),
    })
}
