//! The claim mappers of a client, as the administration and console
//! interfaces manage them.
//!
//! Specified in `docs/api/admin-api.md`, "Claim mappers". The rules are
//! the OAuth context's; these handlers translate them, and ask the
//! identity context that a group a mapper names is one of the tenant's.

use super::{Shared, authorize, body, failed, parameter, respond, written};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawPathParams, State};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json};
use hodor_kernel::{DomainError, ErrorKind, TenantContext};
use hodor_oauth::api::{
    ClaimMapper, ClaimMapperId, ClaimMapperSettings, ClaimSource, ClaimTarget, ClientId,
};
use serde::{Deserialize, Serialize};

const LIST: &str = "/clients/{client_id}/claim-mappers";
const ONE: &str = "/clients/{client_id}/claim-mappers/{claim_mapper_id}";

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/clients/{client}/claim-mappers",
            get(list_mappers).post(create_mapper),
        )
        .route(
            "/clients/{client}/claim-mappers/{mapper}",
            get(get_mapper).put(replace_mapper).delete(delete_mapper),
        )
}

fn client_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "oauth.client_not_found",
        "there is no such client",
    ))
}

fn mapper_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "oauth.claim_mapper_not_found",
        "the client has no such claim mapper",
    ))
}

#[derive(Debug, Serialize)]
struct MapperBody {
    id: String,
    client_id: String,
    claim: String,
    targets: Vec<&'static str>,
    scope: Option<String>,
    source: serde_json::Value,
    created_at: String,
    updated_at: String,
}

impl From<&ClaimMapper> for MapperBody {
    fn from(mapper: &ClaimMapper) -> Self {
        let state = mapper.snapshot();
        Self {
            id: state.id.to_string(),
            client_id: state.client_id.to_string(),
            claim: state.settings.claim.clone(),
            targets: state
                .settings
                .targets
                .iter()
                .map(|target| target.as_str())
                .collect(),
            scope: state.settings.scope.clone(),
            source: state.settings.source.to_json(),
            created_at: written(state.created_at),
            updated_at: written(state.updated_at),
        }
    }
}

#[derive(Debug, Serialize)]
struct Items {
    items: Vec<MapperBody>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewMapperBody {
    claim: String,
    targets: Vec<String>,
    #[serde(default)]
    scope: Option<String>,
    source: serde_json::Value,
}

/// The settings a body gives, the group a mapper names checked to be one
/// of the tenant's.
async fn settings_of(
    state: &Shared,
    tenant: &TenantContext,
    given: NewMapperBody,
) -> Result<ClaimMapperSettings, Box<Response>> {
    let targets = given
        .targets
        .iter()
        .map(|target| ClaimTarget::parse(target))
        .collect::<Result<Vec<_>, _>>()
        .map_err(failed)?;
    let source = ClaimSource::from_json(&given.source).map_err(failed)?;
    if let ClaimSource::GroupMember(group) = &source {
        match state.groups.get(tenant, *group).await {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(failed(DomainError::invalid(
                    "oauth.claim_mapper_group_unknown",
                    "a mapper names a group of the tenant",
                )));
            }
            Err(error) => return Err(failed(error)),
        }
    }
    Ok(ClaimMapperSettings {
        claim: given.claim,
        targets,
        scope: given.scope,
        source,
    })
}

async fn list_mappers(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", LIST).await?;
            let client: ClientId = parameter(&parameters, "client").ok_or_else(client_not_found)?;
            let mappers = state
                .claim_mappers
                .mappers(&tenant, client)
                .await
                .map_err(failed)?;
            let items = mappers.iter().map(MapperBody::from).collect();
            Ok(Json(Items { items }).into_response())
        }
        .await,
    )
}

async fn create_mapper(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "POST", LIST).await?;
            let client: ClientId = parameter(&parameters, "client").ok_or_else(client_not_found)?;
            let given: NewMapperBody = body(&bytes)?;
            let settings = settings_of(&state, &tenant, given).await?;
            let mapper = state
                .claim_mappers
                .create(&tenant, client, settings, caller)
                .await
                .map_err(failed)?;
            Ok((StatusCode::CREATED, Json(MapperBody::from(&mapper))).into_response())
        }
        .await,
    )
}

async fn get_mapper(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", ONE).await?;
            let client: ClientId = parameter(&parameters, "client").ok_or_else(client_not_found)?;
            let id: ClaimMapperId =
                parameter(&parameters, "mapper").ok_or_else(mapper_not_found)?;
            let mapper = state
                .claim_mappers
                .mapper(&tenant, client, id)
                .await
                .map_err(failed)?;
            Ok(Json(MapperBody::from(&mapper)).into_response())
        }
        .await,
    )
}

async fn replace_mapper(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "PUT", ONE).await?;
            let client: ClientId = parameter(&parameters, "client").ok_or_else(client_not_found)?;
            let id: ClaimMapperId =
                parameter(&parameters, "mapper").ok_or_else(mapper_not_found)?;
            let given: NewMapperBody = body(&bytes)?;
            let settings = settings_of(&state, &tenant, given).await?;
            let mapper = state
                .claim_mappers
                .replace(&tenant, client, id, settings, caller)
                .await
                .map_err(failed)?;
            Ok(Json(MapperBody::from(&mapper)).into_response())
        }
        .await,
    )
}

async fn delete_mapper(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "DELETE", ONE).await?;
            let client: ClientId = parameter(&parameters, "client").ok_or_else(client_not_found)?;
            let id: ClaimMapperId =
                parameter(&parameters, "mapper").ok_or_else(mapper_not_found)?;
            state
                .claim_mappers
                .delete(&tenant, client, id, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}
