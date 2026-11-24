//! Service accounts and agents, as the administration and console
//! interfaces manage them.
//!
//! Specified in `docs/api/admin-api.md`, "Service accounts and agents".
//! Both are served alike, each under a path of its own; what tells them
//! apart is the kind the path names.

use super::{
    PageBody, Shared, authorize, body, failed, page_request, parameter, problem, respond, written,
};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawPathParams, RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json};
use hodor_identity::api::{ChangeWorkload, CreateWorkload, UserKind, Workload};
use hodor_kernel::{DomainError, TenantContext, UserId};
use serde::{Deserialize, Serialize};

/// One of the two collections: its kind and the paths its operations are
/// written under in the table of permissions.
#[derive(Debug)]
struct Collection {
    kind: UserKind,
    list: &'static str,
    item: &'static str,
    disable: &'static str,
    enable: &'static str,
}

const SERVICE_ACCOUNTS: Collection = Collection {
    kind: UserKind::ServiceAccount,
    list: "/service-accounts",
    item: "/service-accounts/{service_account_id}",
    disable: "/service-accounts/{service_account_id}:disable",
    enable: "/service-accounts/{service_account_id}:enable",
};

const AGENTS: Collection = Collection {
    kind: UserKind::Agent,
    list: "/agents",
    item: "/agents/{agent_id}",
    disable: "/agents/{agent_id}:disable",
    enable: "/agents/{agent_id}:enable",
};

pub(super) fn routes() -> Router<Shared> {
    collection(&SERVICE_ACCOUNTS, "/service-accounts/{workload}")
        .merge(collection(&AGENTS, "/agents/{workload}"))
}

/// The routes of one collection. `:disable` and `:enable` arrive at the
/// item's route, as part of the last segment.
fn collection(of: &'static Collection, item_route: &str) -> Router<Shared> {
    Router::new()
        .route(
            of.list,
            get(
                move |State(state): State<Shared>,
                      Extension(tenant): Extension<TenantContext>,
                      headers: HeaderMap,
                      RawQuery(query): RawQuery| async move {
                    respond(list(&state, &tenant, &headers, query.as_deref(), of).await)
                },
            )
            .post(
                move |State(state): State<Shared>,
                      Extension(tenant): Extension<TenantContext>,
                      headers: HeaderMap,
                      bytes: Bytes| async move {
                    respond(create(&state, &tenant, &headers, &bytes, of).await)
                },
            ),
        )
        .route(
            item_route,
            get(
                move |State(state): State<Shared>,
                      Extension(tenant): Extension<TenantContext>,
                      headers: HeaderMap,
                      parameters: RawPathParams| async move {
                    respond(read(&state, &tenant, &headers, &parameters, of).await)
                },
            )
            .patch(
                move |State(state): State<Shared>,
                      Extension(tenant): Extension<TenantContext>,
                      headers: HeaderMap,
                      parameters: RawPathParams,
                      bytes: Bytes| async move {
                    respond(change(&state, &tenant, &headers, &parameters, &bytes, of).await)
                },
            )
            .delete(
                move |State(state): State<Shared>,
                      Extension(tenant): Extension<TenantContext>,
                      headers: HeaderMap,
                      parameters: RawPathParams| async move {
                    respond(remove(&state, &tenant, &headers, &parameters, of).await)
                },
            )
            .post(
                move |State(state): State<Shared>,
                      Extension(tenant): Extension<TenantContext>,
                      headers: HeaderMap,
                      parameters: RawPathParams| async move {
                    respond(act(&state, &tenant, &headers, &parameters, of).await)
                },
            ),
        )
}

#[derive(Serialize)]
struct WorkloadBody {
    id: String,
    kind: &'static str,
    name: String,
    status: &'static str,
    owners: Vec<String>,
    created_at: String,
    updated_at: String,
}

impl From<&Workload> for WorkloadBody {
    fn from(workload: &Workload) -> Self {
        let state = workload.user().snapshot();
        Self {
            id: workload.id().to_string(),
            kind: workload.kind().as_str(),
            name: workload.name().to_owned(),
            status: workload.status().as_str(),
            owners: workload.owners().iter().map(ToString::to_string).collect(),
            created_at: written(state.created_at),
            updated_at: written(state.updated_at),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewWorkloadBody {
    name: String,
    owners: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadChangesBody {
    name: Option<String>,
    owners: Option<Vec<String>>,
}

fn workload_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "identity.workload_not_found",
        "the service account or agent does not exist",
    ))
}

/// The owners named by their identifiers. One that is not an identifier is
/// no user of the tenant.
fn owners(given: &[String]) -> Result<Vec<UserId>, Box<Response>> {
    given
        .iter()
        .map(|owner| {
            owner.parse().map_err(|_| {
                failed(DomainError::not_found(
                    "identity.user_not_found",
                    "the user does not exist",
                ))
            })
        })
        .collect()
}

fn workload_of(parameters: &RawPathParams) -> Result<UserId, Box<Response>> {
    parameter(parameters, "workload").ok_or_else(workload_not_found)
}

async fn list(
    state: &Shared,
    tenant: &TenantContext,
    headers: &HeaderMap,
    query: Option<&str>,
    of: &Collection,
) -> Result<Response, Box<Response>> {
    authorize(state, tenant, headers, "GET", of.list).await?;
    let page = page_request(query)?;
    let found = state
        .workloads
        .list(tenant, of.kind, &page)
        .await
        .map_err(failed)?;
    let page = hodor_kernel::Page {
        items: found.items.iter().map(WorkloadBody::from).collect(),
        next_cursor: found.next_cursor,
    };
    Ok(Json(PageBody::from(page)).into_response())
}

async fn create(
    state: &Shared,
    tenant: &TenantContext,
    headers: &HeaderMap,
    bytes: &Bytes,
    of: &Collection,
) -> Result<Response, Box<Response>> {
    let caller = authorize(state, tenant, headers, "POST", of.list).await?;
    let new: NewWorkloadBody = body(bytes)?;
    let workload = state
        .workloads
        .create(
            tenant,
            CreateWorkload {
                kind: of.kind,
                name: new.name,
                owners: owners(&new.owners)?,
            },
            caller,
        )
        .await
        .map_err(failed)?;
    Ok((StatusCode::CREATED, Json(WorkloadBody::from(&workload))).into_response())
}

async fn read(
    state: &Shared,
    tenant: &TenantContext,
    headers: &HeaderMap,
    parameters: &RawPathParams,
    of: &Collection,
) -> Result<Response, Box<Response>> {
    authorize(state, tenant, headers, "GET", of.item).await?;
    let workload = state
        .workloads
        .get(tenant, of.kind, workload_of(parameters)?)
        .await
        .map_err(failed)?;
    Ok(Json(WorkloadBody::from(&workload)).into_response())
}

async fn change(
    state: &Shared,
    tenant: &TenantContext,
    headers: &HeaderMap,
    parameters: &RawPathParams,
    bytes: &Bytes,
    of: &Collection,
) -> Result<Response, Box<Response>> {
    let caller = authorize(state, tenant, headers, "PATCH", of.item).await?;
    let id = workload_of(parameters)?;
    let asked: WorkloadChangesBody = body(bytes)?;
    let workload = state
        .workloads
        .change(
            tenant,
            of.kind,
            id,
            ChangeWorkload {
                name: asked.name,
                owners: asked.owners.as_deref().map(owners).transpose()?,
            },
            caller,
        )
        .await
        .map_err(failed)?;
    Ok(Json(WorkloadBody::from(&workload)).into_response())
}

async fn remove(
    state: &Shared,
    tenant: &TenantContext,
    headers: &HeaderMap,
    parameters: &RawPathParams,
    of: &Collection,
) -> Result<Response, Box<Response>> {
    let caller = authorize(state, tenant, headers, "DELETE", of.item).await?;
    state
        .workloads
        .delete(tenant, of.kind, workload_of(parameters)?, caller)
        .await
        .map_err(failed)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST …:disable` and `:enable`. Any other action is checked like these
/// before it is answered, so that a caller without a token learns nothing
/// about paths.
async fn act(
    state: &Shared,
    tenant: &TenantContext,
    headers: &HeaderMap,
    parameters: &RawPathParams,
    of: &Collection,
) -> Result<Response, Box<Response>> {
    let segment: String = parameter(parameters, "workload").ok_or_else(workload_not_found)?;
    let (id, disable) = if let Some(id) = segment.strip_suffix(":disable") {
        (id, true)
    } else if let Some(id) = segment.strip_suffix(":enable") {
        (id, false)
    } else {
        authorize(state, tenant, headers, "POST", of.disable).await?;
        return Err(problem(
            StatusCode::NOT_FOUND,
            "route.not_found",
            "there is no such action",
        ));
    };
    let operation = if disable { of.disable } else { of.enable };
    let caller = authorize(state, tenant, headers, "POST", operation).await?;
    let id: UserId = id.parse().map_err(|_| workload_not_found())?;
    let workload = if disable {
        state.workloads.disable(tenant, of.kind, id, caller).await
    } else {
        state.workloads.enable(tenant, of.kind, id, caller).await
    }
    .map_err(failed)?;
    Ok(Json(WorkloadBody::from(&workload)).into_response())
}
