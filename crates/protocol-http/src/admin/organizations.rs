//! Organizations, their units, members and invitations, as the
//! administration and console interfaces manage them.
//!
//! Specified in `docs/api/admin-api.md`, "Organizations".

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
use axum::routing::{delete, get, put};
use axum::{Extension, Json};
use hodor_identity::api::{
    Invitation, InvitationId, Membership, Organization, Unit, UnitChange, UnitId, UnitKind,
};
use hodor_kernel::{DomainError, OrganizationId, TenantContext, UserId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/organizations",
            get(list_organizations).post(create_organization),
        )
        .route(
            "/organizations/{organization}",
            get(get_organization)
                .patch(change_organization)
                .delete(delete_organization),
        )
        .route(
            "/organizations/{organization}/units",
            get(list_units).post(create_unit),
        )
        .route(
            "/organizations/{organization}/units/{unit}",
            put(change_unit).delete(delete_unit),
        )
        .route("/organizations/{organization}/members", get(list_members))
        .route(
            "/organizations/{organization}/members/{user}",
            put(put_member).delete(remove_member),
        )
        .route(
            "/organizations/{organization}/invitations",
            get(list_invitations).post(invite),
        )
        .route(
            "/organizations/{organization}/invitations/{invitation}",
            delete(withdraw_invitation),
        )
        .route("/users/{user}/organizations", get(organizations_of_user))
}

#[derive(Serialize)]
struct OrganizationBody {
    id: OrganizationId,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<&Organization> for OrganizationBody {
    fn from(organization: &Organization) -> Self {
        let state = organization.snapshot();
        Self {
            id: organization.id(),
            name: state.name.as_str().to_owned(),
            description: state.description.clone(),
            created_at: written(state.created_at),
            updated_at: written(state.updated_at),
        }
    }
}

#[derive(Deserialize)]
struct SettingsBody {
    name: String,
    description: Option<String>,
}

#[derive(Serialize)]
struct UnitBody {
    id: UnitId,
    parent_id: Option<UnitId>,
    name: String,
    kind: &'static str,
    created_at: String,
    updated_at: String,
}

impl From<&Unit> for UnitBody {
    fn from(unit: &Unit) -> Self {
        Self {
            id: unit.id,
            parent_id: unit.parent,
            name: unit.name.as_str().to_owned(),
            kind: unit.kind.as_str(),
            created_at: written(unit.created_at),
            updated_at: written(unit.updated_at),
        }
    }
}

#[derive(Deserialize)]
struct UnitSettingsBody {
    parent_id: Option<UnitId>,
    name: String,
    kind: String,
}

#[derive(Serialize)]
struct MembershipBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_id: Option<OrganizationId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<UserId>,
    unit_ids: Vec<UnitId>,
    added_at: String,
}

impl MembershipBody {
    fn of_organization(membership: &Membership) -> Self {
        Self {
            organization_id: None,
            user_id: Some(membership.user),
            unit_ids: membership.units.iter().copied().collect(),
            added_at: written(membership.added_at),
        }
    }

    fn of_user(membership: &Membership) -> Self {
        Self {
            organization_id: Some(membership.organization),
            user_id: None,
            unit_ids: membership.units.iter().copied().collect(),
            added_at: written(membership.added_at),
        }
    }
}

#[derive(Deserialize)]
struct UnitsBody {
    #[serde(default)]
    unit_ids: BTreeSet<UnitId>,
}

#[derive(Serialize)]
struct InvitationBody {
    id: InvitationId,
    email: String,
    unit_ids: Vec<UnitId>,
    created_at: String,
    expires_at: String,
}

impl From<&Invitation> for InvitationBody {
    fn from(invitation: &Invitation) -> Self {
        Self {
            id: invitation.id,
            email: invitation.email.clone(),
            unit_ids: invitation.units.iter().copied().collect(),
            created_at: written(invitation.created_at),
            expires_at: written(invitation.expires_at),
        }
    }
}

#[derive(Deserialize)]
struct InviteBody {
    email: String,
    #[serde(default)]
    unit_ids: BTreeSet<UnitId>,
    locale: Option<String>,
}

#[derive(Serialize)]
struct Items<T> {
    items: Vec<T>,
}

fn not_found(code: &'static str, what: &'static str) -> Box<Response> {
    failed(DomainError::not_found(code, what))
}

fn organization_of(parameters: &RawPathParams) -> Result<OrganizationId, Box<Response>> {
    parameter(parameters, "organization").ok_or_else(|| {
        not_found(
            "identity.organization_not_found",
            "the organization does not exist",
        )
    })
}

fn unit_of(parameters: &RawPathParams) -> Result<UnitId, Box<Response>> {
    parameter(parameters, "unit").ok_or_else(|| {
        not_found(
            "identity.unit_not_found",
            "the unit does not exist in this organization",
        )
    })
}

fn kind_of(kind: &str) -> Result<UnitKind, Box<Response>> {
    UnitKind::parse(kind).map_err(failed)
}

async fn list_organizations(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/organizations").await?;
            let page = page_request(query.as_deref())?;
            let found = state
                .organizations
                .list(&tenant, &page)
                .await
                .map_err(failed)?;
            let page = hodor_kernel::Page {
                items: found.items.iter().map(OrganizationBody::from).collect(),
                next_cursor: found.next_cursor,
            };
            Ok(Json(PageBody::from(page)).into_response())
        }
        .await,
    )
}

async fn create_organization(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "POST", "/organizations").await?;
            let new: SettingsBody = body(&bytes)?;
            let organization = state
                .organizations
                .create(&tenant, &new.name, new.description, caller)
                .await
                .map_err(failed)?;
            Ok((
                StatusCode::CREATED,
                Json(OrganizationBody::from(&organization)),
            )
                .into_response())
        }
        .await,
    )
}

async fn get_organization(
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
                "/organizations/{organization_id}",
            )
            .await?;
            let organization = state
                .organizations
                .get(&tenant, organization_of(&parameters)?)
                .await
                .map_err(failed)?;
            Ok(Json(OrganizationBody::from(&organization)).into_response())
        }
        .await,
    )
}

async fn change_organization(
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
                "PATCH",
                "/organizations/{organization_id}",
            )
            .await?;
            let organization = organization_of(&parameters)?;
            let change: SettingsBody = body(&bytes)?;
            let organization = state
                .organizations
                .change(
                    &tenant,
                    organization,
                    &change.name,
                    change.description,
                    caller,
                )
                .await
                .map_err(failed)?;
            Ok(Json(OrganizationBody::from(&organization)).into_response())
        }
        .await,
    )
}

async fn delete_organization(
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
                "/organizations/{organization_id}",
            )
            .await?;
            let organization = organization_of(&parameters)?;
            state
                .organizations
                .delete(&tenant, organization, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

async fn list_units(
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
                "/organizations/{organization_id}/units",
            )
            .await?;
            let organization = organization_of(&parameters)?;
            let units = state
                .organizations
                .units(&tenant, organization)
                .await
                .map_err(failed)?;
            let items = units.iter().map(UnitBody::from).collect();
            Ok(Json(Items { items }).into_response())
        }
        .await,
    )
}

async fn create_unit(
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
                "/organizations/{organization_id}/units",
            )
            .await?;
            let organization = organization_of(&parameters)?;
            let new: UnitSettingsBody = body(&bytes)?;
            let unit = state
                .organizations
                .create_unit(
                    &tenant,
                    organization,
                    new.parent_id,
                    &new.name,
                    kind_of(&new.kind)?,
                    caller,
                )
                .await
                .map_err(failed)?;
            Ok((StatusCode::CREATED, Json(UnitBody::from(&unit))).into_response())
        }
        .await,
    )
}

async fn change_unit(
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
                "/organizations/{organization_id}/units/{unit_id}",
            )
            .await?;
            let organization = organization_of(&parameters)?;
            let unit = unit_of(&parameters)?;
            let change: UnitSettingsBody = body(&bytes)?;
            let change = UnitChange {
                parent: change.parent_id,
                kind: kind_of(&change.kind)?,
                name: change.name,
            };
            let unit = state
                .organizations
                .change_unit(&tenant, organization, unit, change, caller)
                .await
                .map_err(failed)?;
            Ok(Json(UnitBody::from(&unit)).into_response())
        }
        .await,
    )
}

async fn delete_unit(
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
                "/organizations/{organization_id}/units/{unit_id}",
            )
            .await?;
            let organization = organization_of(&parameters)?;
            let unit = unit_of(&parameters)?;
            state
                .organizations
                .delete_unit(&tenant, organization, unit, caller)
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
                "/organizations/{organization_id}/members",
            )
            .await?;
            let organization = organization_of(&parameters)?;
            let page = page_request(query.as_deref())?;
            let members = state
                .organizations
                .members(&tenant, organization, &page)
                .await
                .map_err(failed)?;
            let page = hodor_kernel::Page {
                items: members
                    .items
                    .iter()
                    .map(MembershipBody::of_organization)
                    .collect(),
                next_cursor: members.next_cursor,
            };
            Ok(Json(PageBody::from(page)).into_response())
        }
        .await,
    )
}

async fn put_member(
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
                "/organizations/{organization_id}/members/{user_id}",
            )
            .await?;
            let organization = organization_of(&parameters)?;
            let user: UserId = parameter(&parameters, "user").ok_or_else(user_not_found)?;
            let wanted: UnitsBody = body(&bytes)?;
            // A member already has their units replaced; anyone else joins.
            let existing = state
                .organizations
                .organizations_of(&tenant, user)
                .await
                .map_err(failed)?
                .into_iter()
                .any(|membership| membership.organization == organization);
            let membership = if existing {
                state
                    .organizations
                    .change_member_units(&tenant, organization, user, wanted.unit_ids, caller)
                    .await
            } else {
                state
                    .organizations
                    .add_member(&tenant, organization, user, wanted.unit_ids, caller)
                    .await
            }
            .map_err(failed)?;
            Ok(Json(MembershipBody::of_organization(&membership)).into_response())
        }
        .await,
    )
}

async fn remove_member(
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
                "/organizations/{organization_id}/members/{user_id}",
            )
            .await?;
            let organization = organization_of(&parameters)?;
            let user: UserId = parameter(&parameters, "user").ok_or_else(user_not_found)?;
            state
                .organizations
                .remove_member(&tenant, organization, user, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

async fn list_invitations(
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
                "/organizations/{organization_id}/invitations",
            )
            .await?;
            let organization = organization_of(&parameters)?;
            let pending = state
                .organizations
                .pending_invitations(&tenant, organization)
                .await
                .map_err(failed)?;
            let items = pending.iter().map(InvitationBody::from).collect();
            Ok(Json(Items { items }).into_response())
        }
        .await,
    )
}

async fn invite(
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
                "/organizations/{organization_id}/invitations",
            )
            .await?;
            let organization = organization_of(&parameters)?;
            let new: InviteBody = body(&bytes)?;
            state
                .invitations
                .invite(
                    &tenant,
                    organization,
                    &new.email,
                    new.unit_ids,
                    new.locale.as_deref(),
                    caller,
                )
                .await
                .map_err(failed)?;
            Ok(StatusCode::ACCEPTED.into_response())
        }
        .await,
    )
}

async fn withdraw_invitation(
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
                "/organizations/{organization_id}/invitations/{invitation_id}",
            )
            .await?;
            let organization = organization_of(&parameters)?;
            let invitation: InvitationId =
                parameter(&parameters, "invitation").ok_or_else(|| {
                    not_found(
                        "identity.invitation_invalid",
                        "the invitation is unknown, accepted, withdrawn or expired",
                    )
                })?;
            state
                .organizations
                .withdraw_invitation(&tenant, organization, invitation, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

async fn organizations_of_user(
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
                "/users/{user_id}/organizations",
            )
            .await?;
            let user: UserId = parameter(&parameters, "user").ok_or_else(user_not_found)?;
            state.identity.get(&tenant, user).await.map_err(failed)?;
            let memberships = state
                .organizations
                .organizations_of(&tenant, user)
                .await
                .map_err(failed)?;
            let items = memberships.iter().map(MembershipBody::of_user).collect();
            Ok(Json(Items { items }).into_response())
        }
        .await,
    )
}
