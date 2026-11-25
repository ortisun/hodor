//! The entries of access control lists, as the administration and console
//! interfaces manage them.
//!
//! Specified in `docs/api/admin-api.md`, "Access control lists". The rules
//! are the authorization context's; these handlers translate them. A
//! resource server is named by its identifier and stands for its audience,
//! the namespace of its entries.

use super::authorization::{PrincipalBody, namespace_of, principal};
use super::{PageBody, Shared, authorize, body, failed, parameter, problem, respond, written};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawPathParams, RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json};
use hodor_authorization::api::{
    AccessEntry, AccessEntryFilter, AccessEntryId, PermissionName, Subject, SubjectKind,
};
use hodor_kernel::{Cursor, DomainError, PageRequest, TenantContext};
use serde::{Deserialize, Serialize};

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/resource-servers/{resource_server}/access-entries",
            get(list_entries).post(grant),
        )
        .route(
            "/access-entries/{entry}",
            get(get_entry).delete(remove_entry),
        )
}

#[derive(Debug, Serialize)]
struct EntryBody {
    id: String,
    namespace: String,
    permission: String,
    resource_kind: String,
    resource_id: String,
    principal: PrincipalBody,
    granted_at: String,
}

impl From<&AccessEntry> for EntryBody {
    fn from(entry: &AccessEntry) -> Self {
        Self {
            id: entry.id().to_string(),
            namespace: entry.namespace().as_str().to_owned(),
            permission: entry.permission().as_str().to_owned(),
            resource_kind: entry.resource_kind().to_owned(),
            resource_id: entry.resource_id().to_owned(),
            principal: PrincipalBody {
                kind: entry.principal().kind().as_str().to_owned(),
                id: entry.principal().id().to_owned(),
            },
            granted_at: written(entry.granted_at()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantBody {
    permission: String,
    resource_id: String,
    principal: PrincipalBody,
}

fn entry_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "authorization.access_entry_not_found",
        "there is no such entry",
    ))
}

fn entry_of(parameters: &RawPathParams) -> Result<AccessEntryId, Box<Response>> {
    parameter(parameters, "entry").ok_or_else(entry_not_found)
}

/// Reads the filters, the limit and the cursor of a listing. Values are
/// percent-decoded: a resource's identifier may hold any character.
fn listing(
    query: Option<&str>,
    filter: &mut AccessEntryFilter,
) -> Result<PageRequest, Box<Response>> {
    let invalid = |detail: &'static str| {
        problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.query_invalid",
            detail,
        )
    };
    let (mut limit, mut cursor) = (None, None);
    let (mut principal_kind, mut principal_id) = (None, None);
    for (name, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match name.as_ref() {
            "resource_kind" => filter.resource_kind = Some(value.into_owned()),
            "resource_id" => filter.resource_id = Some(value.into_owned()),
            "principal_kind" => {
                principal_kind = Some(
                    SubjectKind::parse_principal(&value)
                        .map_err(|_| invalid("principal_kind is user, client or group"))?,
                );
            }
            "principal_id" => principal_id = Some(value.into_owned()),
            "limit" => {
                let asked: u32 = value
                    .parse()
                    .map_err(|_| invalid("limit must be a number from 1 to 200"))?;
                if !(1..=PageRequest::MAX_LIMIT).contains(&asked) {
                    return Err(invalid("limit must be a number from 1 to 200"));
                }
                limit = Some(asked);
            }
            "cursor" => cursor = Some(Cursor::new(value.into_owned())),
            _ => {}
        }
    }
    filter.principal = match (principal_kind, principal_id) {
        (Some(kind), Some(id)) => Some(
            Subject::new(kind, &id).map_err(|_| invalid("principal_id has 1 to 255 characters"))?,
        ),
        (None, None) => None,
        _ => {
            return Err(invalid(
                "principal_kind and principal_id are given together",
            ));
        }
    };
    Ok(PageRequest::new(limit, cursor))
}

async fn list_entries(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    RawQuery(query): RawQuery,
) -> Response {
    respond(
        async {
            let operation = "/resource-servers/{resource_server_id}/access-entries";
            authorize(&state, &tenant, &headers, "GET", operation).await?;
            let namespace = namespace_of(&state, &tenant, &parameters).await?;
            let mut filter = AccessEntryFilter::of(namespace);
            let page = listing(query.as_deref(), &mut filter)?;
            let found = state
                .access_lists
                .entries(&tenant, &filter, &page)
                .await
                .map_err(failed)?;
            let body: PageBody<EntryBody> = found.map(|entry| EntryBody::from(&entry)).into();
            Ok(Json(body).into_response())
        }
        .await,
    )
}

async fn grant(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/resource-servers/{resource_server_id}/access-entries";
            let caller = authorize(&state, &tenant, &headers, "POST", operation).await?;
            let namespace = namespace_of(&state, &tenant, &parameters).await?;
            let asked: GrantBody = body(&bytes)?;
            let permission = PermissionName::parse(&asked.permission).map_err(failed)?;
            let subject = principal(&state, &tenant, &asked.principal).await?;
            let granted = state
                .access_lists
                .grant(
                    &tenant,
                    namespace,
                    permission,
                    &asked.resource_id,
                    subject,
                    caller,
                )
                .await
                .map_err(failed)?;
            let status = if granted.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            Ok((status, Json(EntryBody::from(&granted.entry))).into_response())
        }
        .await,
    )
}

async fn get_entry(
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
                "/access-entries/{entry_id}",
            )
            .await?;
            let entry = state
                .access_lists
                .entry(&tenant, entry_of(&parameters)?)
                .await
                .map_err(failed)?
                .ok_or_else(entry_not_found)?;
            Ok(Json(EntryBody::from(&entry)).into_response())
        }
        .await,
    )
}

async fn remove_entry(
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
                "/access-entries/{entry_id}",
            )
            .await?;
            let removed = state
                .access_lists
                .remove(&tenant, entry_of(&parameters)?, caller)
                .await
                .map_err(failed)?;
            if !removed {
                return Err(entry_not_found());
            }
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}
