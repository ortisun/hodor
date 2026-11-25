//! Groups, as the administration and console interfaces manage them.
//!
//! Specified in `docs/api/admin-api.md`, "Groups".

use super::{
    PageBody, Shared, authorize, body, failed, page_request, parameter, respond, user_not_found,
    written,
};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawPathParams, RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json};
use hodor_identity::api::{Group, GroupMember};
use hodor_kernel::{DomainError, GroupId, TenantContext, UserId};
use serde::{Deserialize, Serialize};

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/groups", get(list_groups).post(create_group))
        .route(
            "/groups/{group}",
            get(get_group).patch(change_group).delete(delete_group),
        )
        .route(
            "/groups/{group}/members",
            get(list_members).post(add_member),
        )
        .route("/groups/{group}/members:remove", post(remove_member))
        .route("/users/{user}/groups", get(groups_of_user))
}

#[derive(Serialize)]
pub(super) struct GroupBody {
    id: GroupId,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<&Group> for GroupBody {
    fn from(group: &Group) -> Self {
        let state = group.snapshot();
        Self {
            id: group.id(),
            name: state.name.as_str().to_owned(),
            description: state.description.clone(),
            created_at: written(state.created_at),
            updated_at: written(state.updated_at),
        }
    }
}

#[derive(Deserialize)]
struct GroupSettingsBody {
    name: String,
    description: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct MemberBody {
    kind: String,
    id: String,
}

impl From<GroupMember> for MemberBody {
    fn from(member: GroupMember) -> Self {
        Self {
            kind: member.kind().to_owned(),
            id: member.id_text(),
        }
    }
}

impl MemberBody {
    fn member(&self) -> Result<GroupMember, Box<Response>> {
        let invalid = || {
            failed(DomainError::invalid(
                "request.invalid_body",
                "a member is { \"kind\": \"user\" or \"group\", \"id\": its identifier }",
            ))
        };
        match self.kind.as_str() {
            "user" => self
                .id
                .parse()
                .map(GroupMember::User)
                .map_err(|_| invalid()),
            "group" => self
                .id
                .parse()
                .map(GroupMember::Group)
                .map_err(|_| invalid()),
            _ => Err(invalid()),
        }
    }
}

#[derive(Serialize)]
struct EffectiveGroupBody {
    id: GroupId,
    direct: bool,
}

#[derive(Serialize)]
struct Items<T> {
    items: Vec<T>,
}

fn group_of(parameters: &RawPathParams) -> Result<GroupId, Box<Response>> {
    parameter(parameters, "group").ok_or_else(|| {
        failed(DomainError::not_found(
            "identity.group_not_found",
            "the group does not exist",
        ))
    })
}

async fn list_groups(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/groups").await?;
            let page = page_request(query.as_deref())?;
            let groups = state.groups.list(&tenant, &page).await.map_err(failed)?;
            let page = hodor_kernel::Page {
                items: groups.items.iter().map(GroupBody::from).collect(),
                next_cursor: groups.next_cursor,
            };
            Ok(Json(PageBody::from(page)).into_response())
        }
        .await,
    )
}

async fn create_group(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "POST", "/groups").await?;
            let new: GroupSettingsBody = body(&bytes)?;
            let group = state
                .groups
                .create(&tenant, &new.name, new.description, caller)
                .await
                .map_err(failed)?;
            Ok((StatusCode::CREATED, Json(GroupBody::from(&group))).into_response())
        }
        .await,
    )
}

async fn get_group(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/groups/{group_id}").await?;
            let group = state
                .groups
                .get(&tenant, group_of(&parameters)?)
                .await
                .map_err(failed)?;
            Ok(Json(GroupBody::from(&group)).into_response())
        }
        .await,
    )
}

async fn change_group(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller =
                authorize(&state, &tenant, &headers, "PATCH", "/groups/{group_id}").await?;
            let group = group_of(&parameters)?;
            let change: GroupSettingsBody = body(&bytes)?;
            let group = state
                .groups
                .change(&tenant, group, &change.name, change.description, caller)
                .await
                .map_err(failed)?;
            Ok(Json(GroupBody::from(&group)).into_response())
        }
        .await,
    )
}

async fn delete_group(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let caller =
                authorize(&state, &tenant, &headers, "DELETE", "/groups/{group_id}").await?;
            let group = group_of(&parameters)?;
            state
                .groups
                .delete(&tenant, group, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

async fn list_members(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    RawQuery(query): RawQuery,
) -> Response {
    respond(
        async {
            authorize(
                &state,
                &tenant,
                &headers,
                "GET",
                "/groups/{group_id}/members",
            )
            .await?;
            let group = group_of(&parameters)?;
            let page = page_request(query.as_deref())?;
            let members = state
                .groups
                .members(&tenant, group, &page)
                .await
                .map_err(failed)?;
            let page = hodor_kernel::Page {
                items: members.items.into_iter().map(MemberBody::from).collect(),
                next_cursor: members.next_cursor,
            };
            Ok(Json(PageBody::from(page)).into_response())
        }
        .await,
    )
}

async fn add_member(
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
                "POST",
                "/groups/{group_id}/members",
            )
            .await?;
            let group = group_of(&parameters)?;
            let member: MemberBody = body(&bytes)?;
            state
                .groups
                .add_member(&tenant, group, member.member()?, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

async fn remove_member(
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
                "POST",
                "/groups/{group_id}/members:remove",
            )
            .await?;
            let group = group_of(&parameters)?;
            let member: MemberBody = body(&bytes)?;
            state
                .groups
                .remove_member(&tenant, group, member.member()?, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

async fn groups_of_user(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/users/{user_id}/groups").await?;
            let user: UserId = parameter(&parameters, "user").ok_or_else(user_not_found)?;
            // A user the tenant does not have is answered as one.
            state.identity.get(&tenant, user).await.map_err(failed)?;
            let effective = state
                .groups
                .effective_groups(&tenant, user)
                .await
                .map_err(failed)?;
            let direct = state
                .groups
                .direct_groups(&tenant, user)
                .await
                .map_err(failed)?;
            let items = effective
                .into_iter()
                .map(|id| EffectiveGroupBody {
                    id,
                    direct: direct.contains(&id),
                })
                .collect();
            Ok(Json(Items { items }).into_response())
        }
        .await,
    )
}
