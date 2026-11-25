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
use axum::routing::{delete, get};
use axum::{Extension, Json};
use hodor_authorization::api::check_key_scopes;
use hodor_credential::api::{
    ApiKey, ApiKeyId, ApiKeySettings, DEFAULT_API_KEY_LIFETIME, DEFAULT_API_KEY_OVERLAP,
    KeyApplicationId, REVOKED_BY_ADMINISTRATOR,
};
use hodor_identity::api::{ChangeWorkload, CreateWorkload, UserKind, Workload};
use hodor_kernel::{DomainError, ErrorKind, TenantContext, UserId};
use hodor_oauth::api::ApplicationId;
use serde::{Deserialize, Serialize};
use time::Duration;

/// One of the two collections: its kind and the paths its operations are
/// written under in the table of permissions.
#[derive(Debug)]
struct Collection {
    kind: UserKind,
    list: &'static str,
    item: &'static str,
    disable: &'static str,
    enable: &'static str,
    keys: &'static str,
    key: &'static str,
    rotate: &'static str,
}

const SERVICE_ACCOUNTS: Collection = Collection {
    kind: UserKind::ServiceAccount,
    list: "/service-accounts",
    item: "/service-accounts/{service_account_id}",
    disable: "/service-accounts/{service_account_id}:disable",
    enable: "/service-accounts/{service_account_id}:enable",
    keys: "/service-accounts/{service_account_id}/api-keys",
    key: "/service-accounts/{service_account_id}/api-keys/{api_key_id}",
    rotate: "/service-accounts/{service_account_id}/api-keys/{api_key_id}:rotate",
};

const AGENTS: Collection = Collection {
    kind: UserKind::Agent,
    list: "/agents",
    item: "/agents/{agent_id}",
    disable: "/agents/{agent_id}:disable",
    enable: "/agents/{agent_id}:enable",
    keys: "/agents/{agent_id}/api-keys",
    key: "/agents/{agent_id}/api-keys/{api_key_id}",
    rotate: "/agents/{agent_id}/api-keys/{api_key_id}:rotate",
};

pub(super) fn routes() -> Router<Shared> {
    collection(&SERVICE_ACCOUNTS, "/service-accounts/{workload}")
        .merge(collection(&AGENTS, "/agents/{workload}"))
}

/// The routes of one collection. `:disable` and `:enable` arrive at the
/// item's route, as part of the last segment, and `:rotate` at a key's.
fn collection(of: &'static Collection, item_route: &str) -> Router<Shared> {
    Router::new()
        .route(
            &format!("{item_route}/api-keys"),
            get(
                move |State(state): State<Shared>,
                      Extension(tenant): Extension<TenantContext>,
                      headers: HeaderMap,
                      parameters: RawPathParams| async move {
                    respond(list_keys(&state, &tenant, &headers, &parameters, of).await)
                },
            )
            .post(
                move |State(state): State<Shared>,
                      Extension(tenant): Extension<TenantContext>,
                      headers: HeaderMap,
                      parameters: RawPathParams,
                      bytes: Bytes| async move {
                    respond(create_key(&state, &tenant, &headers, &parameters, &bytes, of).await)
                },
            ),
        )
        .route(
            &format!("{item_route}/api-keys/{{key}}"),
            delete(
                move |State(state): State<Shared>,
                      Extension(tenant): Extension<TenantContext>,
                      headers: HeaderMap,
                      parameters: RawPathParams| async move {
                    respond(revoke_key(&state, &tenant, &headers, &parameters, of).await)
                },
            )
            .post(
                move |State(state): State<Shared>,
                      Extension(tenant): Extension<TenantContext>,
                      headers: HeaderMap,
                      parameters: RawPathParams,
                      bytes: Bytes| async move {
                    respond(rotate_key(&state, &tenant, &headers, &parameters, &bytes, of).await)
                },
            ),
        )
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

/// More days than any lifetime the credential context accepts, so that a
/// large number given is refused by its rule instead of overflowing.
const MOST_DAYS: u32 = 100_000;

fn days(given: Option<u32>, default: Duration) -> Duration {
    given.map_or(default, |days| {
        Duration::days(i64::from(days.min(MOST_DAYS)))
    })
}

/// A key, as every answer writes it: never the key, never its hash.
#[derive(Serialize)]
struct KeyBody {
    id: String,
    name: String,
    hint: String,
    scopes: Vec<String>,
    application_id: Option<String>,
    status: &'static str,
    created_at: String,
    expires_at: String,
    last_used_at: Option<String>,
    revoked_at: Option<String>,
    replaced_by: Option<String>,
}

impl KeyBody {
    fn of(key: &ApiKey, now: hodor_kernel::Timestamp) -> Self {
        let state = key.snapshot();
        Self {
            id: key.id().to_string(),
            name: state.settings.name.clone(),
            hint: format!("…{}", state.hint),
            scopes: state.settings.scopes.clone(),
            application_id: state.settings.application.map(|id| id.to_string()),
            status: key.status_at(now).as_str(),
            created_at: written(state.created_at),
            expires_at: written(state.expires_at),
            last_used_at: state.last_used_at.map(written),
            revoked_at: state.revoked_at.map(written),
            replaced_by: state.replaced_by.map(|id| id.to_string()),
        }
    }
}

/// A key just made, with the key itself, once. No `Debug`: this holds the
/// key on its way out.
#[derive(Serialize)]
struct MadeKeyBody {
    #[serde(flatten)]
    key: KeyBody,
    api_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewKeyBody {
    name: String,
    scopes: Vec<String>,
    application_id: Option<String>,
    lifetime_days: Option<u32>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RotationBody {
    lifetime_days: Option<u32>,
    keep_previous_days: Option<u32>,
}

fn key_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "credential.api_key_not_found",
        "the API key does not exist",
    ))
}

/// The workload of the path, which must exist under this collection's kind.
async fn holder(
    state: &Shared,
    tenant: &TenantContext,
    parameters: &RawPathParams,
    of: &Collection,
) -> Result<Workload, Box<Response>> {
    state
        .workloads
        .get(tenant, of.kind, workload_of(parameters)?)
        .await
        .map_err(failed)
}

/// The application a new key names, if it is one of the tenant: the
/// credential context does not know applications, so the interface asks
/// the OAuth context.
async fn application_of(
    state: &Shared,
    tenant: &TenantContext,
    given: &str,
) -> Result<KeyApplicationId, Box<Response>> {
    let refused = || {
        failed(DomainError::invalid(
            "credential.api_key_application_invalid",
            "the application is not one of the tenant",
        ))
    };
    let id: ApplicationId = given.parse().map_err(|_| refused())?;
    match state.applications.application(tenant, id).await {
        Ok(_) => Ok(KeyApplicationId::from_uuid(id.as_uuid())),
        Err(error) if error.kind() == ErrorKind::NotFound => Err(refused()),
        Err(error) => Err(failed(error)),
    }
}

async fn list_keys(
    state: &Shared,
    tenant: &TenantContext,
    headers: &HeaderMap,
    parameters: &RawPathParams,
    of: &Collection,
) -> Result<Response, Box<Response>> {
    authorize(state, tenant, headers, "GET", of.keys).await?;
    let workload = holder(state, tenant, parameters, of).await?;
    let now = state.api_keys.now();
    let keys = state
        .api_keys
        .list(tenant, workload.id())
        .await
        .map_err(failed)?;
    let items: Vec<KeyBody> = keys.iter().map(|key| KeyBody::of(key, now)).collect();
    Ok(Json(serde_json::json!({ "items": items })).into_response())
}

async fn create_key(
    state: &Shared,
    tenant: &TenantContext,
    headers: &HeaderMap,
    parameters: &RawPathParams,
    bytes: &Bytes,
    of: &Collection,
) -> Result<Response, Box<Response>> {
    let caller = authorize(state, tenant, headers, "POST", of.keys).await?;
    let workload = holder(state, tenant, parameters, of).await?;
    let asked: NewKeyBody = body(bytes)?;
    check_key_scopes(&asked.scopes, asked.application_id.is_some()).map_err(failed)?;
    let application = match &asked.application_id {
        Some(given) => Some(application_of(state, tenant, given).await?),
        None => None,
    };
    let (key, secret) = state
        .api_keys
        .create(
            tenant,
            workload.id(),
            ApiKeySettings {
                name: asked.name,
                scopes: asked.scopes,
                application,
            },
            days(asked.lifetime_days, DEFAULT_API_KEY_LIFETIME),
            caller,
        )
        .await
        .map_err(failed)?;
    let made = MadeKeyBody {
        key: KeyBody::of(&key, state.api_keys.now()),
        api_key: secret.expose().to_owned(),
    };
    Ok((StatusCode::CREATED, Json(made)).into_response())
}

async fn revoke_key(
    state: &Shared,
    tenant: &TenantContext,
    headers: &HeaderMap,
    parameters: &RawPathParams,
    of: &Collection,
) -> Result<Response, Box<Response>> {
    let caller = authorize(state, tenant, headers, "DELETE", of.key).await?;
    let workload = holder(state, tenant, parameters, of).await?;
    let id: ApiKeyId = parameter(parameters, "key").ok_or_else(key_not_found)?;
    state
        .api_keys
        .revoke(tenant, workload.id(), id, REVOKED_BY_ADMINISTRATOR, caller)
        .await
        .map_err(failed)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST …/api-keys/{api_key_id}:rotate`. Any other action is checked like
/// it before it is answered, so that a caller without a token learns
/// nothing about paths.
async fn rotate_key(
    state: &Shared,
    tenant: &TenantContext,
    headers: &HeaderMap,
    parameters: &RawPathParams,
    bytes: &Bytes,
    of: &Collection,
) -> Result<Response, Box<Response>> {
    let caller = authorize(state, tenant, headers, "POST", of.rotate).await?;
    let segment: String = parameter(parameters, "key").ok_or_else(key_not_found)?;
    let Some(id) = segment.strip_suffix(":rotate") else {
        return Err(problem(
            StatusCode::NOT_FOUND,
            "route.not_found",
            "there is no such action",
        ));
    };
    let id: ApiKeyId = id.parse().map_err(|_| key_not_found())?;
    let workload = holder(state, tenant, parameters, of).await?;
    let asked: RotationBody = if bytes.is_empty() {
        RotationBody::default()
    } else {
        body(bytes)?
    };
    let (key, secret) = state
        .api_keys
        .rotate(
            tenant,
            workload.id(),
            id,
            days(asked.lifetime_days, DEFAULT_API_KEY_LIFETIME),
            days(asked.keep_previous_days, DEFAULT_API_KEY_OVERLAP),
            caller,
        )
        .await
        .map_err(failed)?;
    let made = MadeKeyBody {
        key: KeyBody::of(&key, state.api_keys.now()),
        api_key: secret.expose().to_owned(),
    };
    Ok((StatusCode::CREATED, Json(made)).into_response())
}
