//! The SPIFFE trust domains of a tenant, as the administration and console
//! interfaces manage them.
//!
//! Specified in `docs/api/admin-api.md`, "Trust domains".

use super::{PageBody, Shared, authorize, body, failed, page_request, parameter, respond, written};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawPathParams, RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json};
use hodor_kernel::{DomainError, Page, TenantContext};
use hodor_keys::api::{TrustDomain, TrustDomainId, TrustSourceRequest};
use serde::{Deserialize, Serialize};

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/trust-domains",
            get(list_trust_domains).post(add_trust_domain),
        )
        .route(
            "/trust-domains/{trust_domain}",
            get(get_trust_domain)
                .put(replace_trust_domain)
                .delete(remove_trust_domain),
        )
}

#[derive(Serialize)]
struct RefreshBody {
    fetched_at: Option<String>,
    next_at: Option<String>,
    failing_since: Option<String>,
    last_error: Option<String>,
}

#[derive(Serialize)]
struct TrustDomainBody {
    id: TrustDomainId,
    name: String,
    source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_endpoint_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_changed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh: Option<RefreshBody>,
    created_at: String,
    updated_at: String,
}

impl From<&TrustDomain> for TrustDomainBody {
    fn from(domain: &TrustDomain) -> Self {
        let state = domain.snapshot();
        Self {
            id: state.id,
            name: state.name.to_string(),
            source: state.source.as_str(),
            bundle_endpoint_url: state.bundle_endpoint_url.clone(),
            // The bundle is kept as JSON Hodor wrote: it is answered as it
            // is kept.
            bundle: state
                .bundle
                .as_ref()
                .and_then(|bundle| serde_json::from_str(bundle.document()).ok()),
            bundle_changed_at: state.bundle_changed_at.map(written),
            refresh: state.bundle_endpoint_url.as_ref().map(|_| RefreshBody {
                fetched_at: state.fetched_at.map(written),
                next_at: state.next_refresh_at.map(written),
                failing_since: state.failing_since.map(written),
                last_error: state.last_error.clone(),
            }),
            created_at: written(state.created_at),
            updated_at: written(state.updated_at),
        }
    }
}

/// A source as the interface takes it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceBody {
    source: String,
    bundle: Option<serde_json::Value>,
    bundle_endpoint_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewBody {
    name: String,
    source: String,
    bundle: Option<serde_json::Value>,
    bundle_endpoint_url: Option<String>,
}

fn request(
    source: &str,
    bundle: Option<serde_json::Value>,
    url: Option<String>,
) -> Result<TrustSourceRequest, Box<Response>> {
    TrustSourceRequest::from_parts(
        source,
        bundle.map(|bundle| bundle.to_string().into_bytes()),
        url,
    )
    .map_err(failed)
}

fn not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "keys.trust_domain_not_found",
        "there is no such trust domain",
    ))
}

fn trust_domain_of(parameters: &RawPathParams) -> Result<TrustDomainId, Box<Response>> {
    parameter(parameters, "trust_domain").ok_or_else(not_found)
}

async fn list_trust_domains(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/trust-domains").await?;
            let page = page_request(query.as_deref())?;
            let found = state
                .trust_domains
                .list(&tenant, &page)
                .await
                .map_err(failed)?;
            let page = Page {
                items: found.items.iter().map(TrustDomainBody::from).collect(),
                next_cursor: found.next_cursor,
            };
            Ok(Json(PageBody::from(page)).into_response())
        }
        .await,
    )
}

async fn add_trust_domain(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "POST", "/trust-domains").await?;
            let asked: NewBody = body(&bytes)?;
            let source = request(&asked.source, asked.bundle, asked.bundle_endpoint_url)?;
            let added = state
                .trust_domains
                .add(&tenant, &asked.name, source, caller)
                .await
                .map_err(failed)?;
            Ok((StatusCode::CREATED, Json(TrustDomainBody::from(&added))).into_response())
        }
        .await,
    )
}

async fn get_trust_domain(
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
                "/trust-domains/{trust_domain_id}",
            )
            .await?;
            let found = state
                .trust_domains
                .get(&tenant, trust_domain_of(&parameters)?)
                .await
                .map_err(failed)?;
            Ok(Json(TrustDomainBody::from(&found)).into_response())
        }
        .await,
    )
}

async fn replace_trust_domain(
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
                "/trust-domains/{trust_domain_id}",
            )
            .await?;
            let id = trust_domain_of(&parameters)?;
            let asked: SourceBody = body(&bytes)?;
            let source = request(&asked.source, asked.bundle, asked.bundle_endpoint_url)?;
            let replaced = state
                .trust_domains
                .replace(&tenant, id, source, caller)
                .await
                .map_err(failed)?;
            Ok(Json(TrustDomainBody::from(&replaced)).into_response())
        }
        .await,
    )
}

async fn remove_trust_domain(
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
                "/trust-domains/{trust_domain_id}",
            )
            .await?;
            state
                .trust_domains
                .remove(&tenant, trust_domain_of(&parameters)?, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}
