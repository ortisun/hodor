//! Webhook endpoints and their deliveries, as the administration and
//! console interfaces manage them.
//!
//! Specified in `docs/api/admin-api.md`, "Webhooks".

use super::{
    PageBody, Shared, authorize, body, failed, page_request, parameter, problem, respond, written,
};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawPathParams, RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Json};
use hodor_kernel::{DomainError, Page, Secret, TenantContext};
use hodor_webhooks::api::{
    CATALOG, Delivery, DeliveryId, DeliveryQuery, DeliveryStatus, EndpointDetails, EndpointId,
    RegisterEndpoint, WebhookService,
};
use serde::{Deserialize, Serialize};

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/webhook-event-types", get(event_types))
        .route(
            "/webhook-endpoints",
            get(list_endpoints).post(register_endpoint),
        )
        // `POST /webhook-endpoints/{endpoint_id}:rotate-secret` arrives here
        // as well: the action is part of the last segment.
        .route(
            "/webhook-endpoints/{endpoint}",
            get(get_endpoint)
                .delete(remove_endpoint)
                .post(endpoint_action),
        )
        .route(
            "/webhook-endpoints/{endpoint}/subscriptions",
            put(replace_subscriptions),
        )
        .route("/webhook-deliveries", get(list_deliveries))
        // `POST /webhook-deliveries/{delivery_id}:redeliver`, likewise.
        .route("/webhook-deliveries/{delivery}", post(delivery_action))
}

#[derive(Serialize)]
struct SecretBody {
    created_at: String,
    expires_at: Option<String>,
}

#[derive(Serialize)]
struct EndpointBody {
    id: EndpointId,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    event_types: Vec<&'static str>,
    secrets: Vec<SecretBody>,
    created_at: String,
    updated_at: String,
}

impl From<&EndpointDetails> for EndpointBody {
    fn from(details: &EndpointDetails) -> Self {
        let state = details.endpoint.snapshot();
        Self {
            id: state.id,
            url: state.url.clone(),
            description: state.description.clone(),
            event_types: state
                .event_types
                .iter()
                .map(|known| known.as_str())
                .collect(),
            secrets: details
                .secrets
                .iter()
                .map(|secret| SecretBody {
                    created_at: written(secret.created_at),
                    expires_at: secret.expires_at.map(written),
                })
                .collect(),
            created_at: written(state.created_at),
            updated_at: written(state.updated_at),
        }
    }
}

/// The one shape in which a secret is ever shown.
#[derive(Serialize)]
struct WithSecretBody {
    endpoint: EndpointBody,
    secret: String,
}

#[derive(Serialize)]
struct DeliveryBody {
    id: DeliveryId,
    endpoint_id: EndpointId,
    event_id: String,
    event_type: String,
    status: &'static str,
    attempts: u32,
    next_attempt_at: Option<String>,
    last_response_status: Option<u16>,
    last_error: Option<String>,
    created_at: String,
    finished_at: Option<String>,
}

impl From<&Delivery> for DeliveryBody {
    fn from(delivery: &Delivery) -> Self {
        let state = delivery.snapshot();
        let pending = state.status == DeliveryStatus::Pending;
        Self {
            id: state.id,
            endpoint_id: state.endpoint_id,
            event_id: state.event_id.to_string(),
            event_type: state.event_type.clone(),
            status: state.status.as_str(),
            attempts: state.attempts,
            next_attempt_at: pending.then(|| written(state.next_attempt_at)),
            last_response_status: state.last_response_status,
            last_error: state.last_error.clone(),
            created_at: written(state.created_at),
            finished_at: state.finished_at.map(written),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    url: String,
    description: Option<String>,
    #[serde(default)]
    event_types: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscriptionsBody {
    event_types: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateBody {
    overlap_hours: Option<u32>,
}

#[derive(Serialize)]
struct Items {
    items: &'static [&'static str],
}

/// The webhooks use cases, or the answer of an installation that has no
/// keys to seal secrets with.
fn webhooks(state: &Shared) -> Result<&WebhookService, Box<Response>> {
    state.webhooks.as_ref().ok_or_else(|| {
        problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "webhooks.not_configured",
            "this installation is not set up to keep the secrets of webhooks",
        )
    })
}

fn endpoint_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "webhooks.endpoint_not_found",
        "there is no such webhook endpoint",
    ))
}

fn delivery_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "webhooks.delivery_not_found",
        "there is no such webhook delivery",
    ))
}

fn endpoint_of(parameters: &RawPathParams) -> Result<EndpointId, Box<Response>> {
    parameter(parameters, "endpoint").ok_or_else(endpoint_not_found)
}

/// An answer that shows a secret, once. Nothing on the way keeps it.
fn showing_secret(
    status: StatusCode,
    details: &EndpointDetails,
    secret: &Secret<String>,
) -> Response {
    let mut response = (
        status,
        Json(WithSecretBody {
            endpoint: EndpointBody::from(details),
            secret: secret.expose().clone(),
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn event_types(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/webhook-event-types").await?;
            Ok(Json(Items { items: CATALOG }).into_response())
        }
        .await,
    )
}

async fn list_endpoints(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/webhook-endpoints").await?;
            let page = page_request(query.as_deref())?;
            let found = webhooks(&state)?
                .list(&tenant, &page)
                .await
                .map_err(failed)?;
            let page = Page {
                items: found.items.iter().map(EndpointBody::from).collect(),
                next_cursor: found.next_cursor,
            };
            Ok(Json(PageBody::from(page)).into_response())
        }
        .await,
    )
}

async fn register_endpoint(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "POST", "/webhook-endpoints").await?;
            let service = webhooks(&state)?;
            let asked: RegisterBody = body(&bytes)?;
            let (details, secret) = service
                .register(
                    &tenant,
                    RegisterEndpoint {
                        url: asked.url,
                        description: asked.description,
                        event_types: asked.event_types,
                    },
                    caller,
                )
                .await
                .map_err(failed)?;
            Ok(showing_secret(StatusCode::CREATED, &details, &secret))
        }
        .await,
    )
}

async fn get_endpoint(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            authorize(
                &state,
                &tenant,
                &headers,
                "GET",
                "/webhook-endpoints/{endpoint_id}",
            )
            .await?;
            let details = webhooks(&state)?
                .get(&tenant, endpoint_of(&parameters)?)
                .await
                .map_err(failed)?;
            Ok(Json(EndpointBody::from(&details)).into_response())
        }
        .await,
    )
}

async fn remove_endpoint(
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
                "/webhook-endpoints/{endpoint_id}",
            )
            .await?;
            webhooks(&state)?
                .remove(&tenant, endpoint_of(&parameters)?, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

async fn replace_subscriptions(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(
                &state,
                &tenant,
                &headers,
                "PUT",
                "/webhook-endpoints/{endpoint_id}/subscriptions",
            )
            .await?;
            let service = webhooks(&state)?;
            let endpoint = endpoint_of(&parameters)?;
            let asked: SubscriptionsBody = body(&bytes)?;
            let details = service
                .replace_subscriptions(&tenant, endpoint, &asked.event_types, caller)
                .await
                .map_err(failed)?;
            Ok(Json(EndpointBody::from(&details)).into_response())
        }
        .await,
    )
}

/// `POST /webhook-endpoints/{endpoint_id}:rotate-secret`. The action is
/// part of the last segment of the path.
async fn endpoint_action(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            // Checked before the action is read, so that a caller without a
            // token learns nothing about paths.
            let caller = authorize(
                &state,
                &tenant,
                &headers,
                "POST",
                "/webhook-endpoints/{endpoint_id}:rotate-secret",
            )
            .await?;
            let segment: String =
                parameter(&parameters, "endpoint").ok_or_else(endpoint_not_found)?;
            let Some(id) = segment.strip_suffix(":rotate-secret") else {
                return Err(problem(
                    StatusCode::NOT_FOUND,
                    "route.not_found",
                    "there is no such action on a webhook endpoint",
                ));
            };
            let id: EndpointId = id.parse().map_err(|_| endpoint_not_found())?;
            let service = webhooks(&state)?;
            let asked: RotateBody = if bytes.is_empty() {
                RotateBody::default()
            } else {
                body(&bytes)?
            };
            let (details, secret) = service
                .rotate_secret(&tenant, id, asked.overlap_hours, caller)
                .await
                .map_err(failed)?;
            Ok(showing_secret(StatusCode::OK, &details, &secret))
        }
        .await,
    )
}

/// Reads `endpoint_id` and `status` from the query; `limit` and `cursor`
/// are read by [`page_request`].
fn delivery_query(query: Option<&str>) -> Result<DeliveryQuery, Box<Response>> {
    let invalid = || {
        problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.query_invalid",
            "endpoint_id is an identifier, and status is pending, delivered or set_aside",
        )
    };
    let mut asked = DeliveryQuery::default();
    for (name, value) in query
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
    {
        match name {
            "endpoint_id" => asked.endpoint = Some(value.parse().map_err(|_| invalid())?),
            "status" => asked.status = Some(DeliveryStatus::from_name(value).ok_or_else(invalid)?),
            _ => {}
        }
    }
    Ok(asked)
}

async fn list_deliveries(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/webhook-deliveries").await?;
            let page = page_request(query.as_deref())?;
            let asked = delivery_query(query.as_deref())?;
            let found = webhooks(&state)?
                .deliveries(&tenant, asked, &page)
                .await
                .map_err(failed)?;
            let page = Page {
                items: found.items.iter().map(DeliveryBody::from).collect(),
                next_cursor: found.next_cursor,
            };
            Ok(Json(PageBody::from(page)).into_response())
        }
        .await,
    )
}

/// `POST /webhook-deliveries/{delivery_id}:redeliver`. The action is part
/// of the last segment of the path.
async fn delivery_action(
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
                "POST",
                "/webhook-deliveries/{delivery_id}:redeliver",
            )
            .await?;
            let segment: String =
                parameter(&parameters, "delivery").ok_or_else(delivery_not_found)?;
            let Some(id) = segment.strip_suffix(":redeliver") else {
                return Err(problem(
                    StatusCode::NOT_FOUND,
                    "route.not_found",
                    "there is no such action on a webhook delivery",
                ));
            };
            let id: DeliveryId = id.parse().map_err(|_| delivery_not_found())?;
            let delivery = webhooks(&state)?
                .redeliver(&tenant, id, caller)
                .await
                .map_err(failed)?;
            Ok(Json(DeliveryBody::from(&delivery)).into_response())
        }
        .await,
    )
}
