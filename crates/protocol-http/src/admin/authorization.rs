//! Permissions, roles, assignments, bindings and policy versions, as the
//! administration and console interfaces manage them.
//!
//! Specified in `docs/api/admin-api.md`, "Roles and their permissions",
//! "Bindings" and "Policies for Open Policy Agent". The rules are the
//! authorization context's; these handlers translate them. A resource
//! server is named by its identifier and stands for its audience, the
//! namespace of its permissions and roles. Publishing a policy is not
//! here: only the command line holds the key a bundle is signed with.

use super::{Shared, authorize, body, failed, parameter, problem, respond, written};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawPathParams, State};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json};
use hodor_authorization::api::{
    Action, ApplicationReference, AssignmentScope, BindingSettings, Condition, EngineBinding,
    EngineId, Namespace, PermissionDefinition, PermissionName, RoleAssignment, RoleContents,
    RoleDefinition, RoleKey, RoleName, Subject, SubjectKind, Validity,
};
use hodor_authorization_opa::api::{
    Author, BundleFile, PolicyService, PolicyStatus, PolicyVersion, Simulation, SimulationId,
};
use hodor_kernel::UserId;
use hodor_kernel::{DomainError, TenantContext};
use hodor_oauth::api::{ApplicationId, ClientId, ResourceServerId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// How many versions a listing answers.
const VERSIONS_LISTED: u32 = 50;

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/resource-servers/{resource_server}/permissions",
            get(list_permissions),
        )
        .route(
            "/resource-servers/{resource_server}/permissions/{permission}",
            axum::routing::put(declare_permission).delete(remove_permission),
        )
        .route("/roles", get(list_roles))
        .route(
            "/resource-servers/{resource_server}/roles/{role}",
            get(get_role).put(define_role).delete(remove_role),
        )
        .route("/users/{user}/role-assignments", get(user_assignments))
        .route(
            "/clients/{client}/role-assignments",
            get(client_assignments),
        )
        .route("/groups/{group}/role-assignments", get(group_assignments))
        .route("/role-assignments", post(assign))
        .route("/role-assignments:revoke", post(revoke))
        .route("/bindings", get(list_bindings))
        .route(
            "/resource-servers/{resource_server}/binding",
            get(get_binding).put(bind).delete(unbind),
        )
        .route("/policy-versions", get(list_versions).post(draft_version))
        // `:validate` and `:test` arrive here as part of the last segment.
        .route(
            "/policy-versions/{number}",
            get(get_version).post(version_action),
        )
        .route("/policy-versions/{number}/simulations", post(simulate))
        .route("/policy-simulations/{simulation}", get(get_simulation))
        .route("/policy-status", get(policy_status))
}

fn route_not_found() -> Box<Response> {
    problem(
        StatusCode::NOT_FOUND,
        "route.not_found",
        "there is no such route",
    )
}

fn not_found(code: &'static str, detail: &'static str) -> Box<Response> {
    failed(DomainError::not_found(code, detail))
}

/// The namespace of the resource server the path names.
pub(super) async fn namespace_of(
    state: &Shared,
    tenant: &TenantContext,
    parameters: &RawPathParams,
) -> Result<Namespace, Box<Response>> {
    let resource_server_not_found = || {
        not_found(
            "oauth.resource_server_not_found",
            "there is no such resource server",
        )
    };
    let id: ResourceServerId =
        parameter(parameters, "resource_server").ok_or_else(resource_server_not_found)?;
    let server = state
        .applications
        .resource_server(tenant, id)
        .await
        .map_err(failed)?;
    Namespace::parse(server.audience().as_str()).map_err(failed)
}

fn path_text(parameters: &RawPathParams, name: &str) -> String {
    parameters
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct PermissionBody {
    namespace: String,
    name: String,
    description: String,
}

impl From<&PermissionDefinition> for PermissionBody {
    fn from(permission: &PermissionDefinition) -> Self {
        Self {
            namespace: permission.namespace().as_str().to_owned(),
            name: permission.name().as_str().to_owned(),
            description: permission.description().to_owned(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DescriptionBody {
    #[serde(default)]
    description: String,
}

#[derive(Debug, Serialize)]
struct ItemsBody<T> {
    items: Vec<T>,
}

async fn list_permissions(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/resource-servers/{resource_server_id}/permissions";
            authorize(&state, &tenant, &headers, "GET", operation).await?;
            let namespace = namespace_of(&state, &tenant, &parameters).await?;
            let permissions = state
                .roles
                .permissions(&tenant, &namespace)
                .await
                .map_err(failed)?;
            let items = permissions.iter().map(PermissionBody::from).collect();
            Ok(Json(ItemsBody { items }).into_response())
        }
        .await,
    )
}

async fn declare_permission(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/resource-servers/{resource_server_id}/permissions/{permission}";
            let caller = authorize(&state, &tenant, &headers, "PUT", operation).await?;
            let namespace = namespace_of(&state, &tenant, &parameters).await?;
            let name =
                PermissionName::parse(&path_text(&parameters, "permission")).map_err(failed)?;
            let asked: DescriptionBody = body(&bytes)?;
            let permission = state
                .roles
                .declare_permission(&tenant, namespace, name, &asked.description, caller)
                .await
                .map_err(failed)?;
            Ok(Json(PermissionBody::from(&permission)).into_response())
        }
        .await,
    )
}

async fn remove_permission(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/resource-servers/{resource_server_id}/permissions/{permission}";
            let caller = authorize(&state, &tenant, &headers, "DELETE", operation).await?;
            let namespace = namespace_of(&state, &tenant, &parameters).await?;
            let name =
                PermissionName::parse(&path_text(&parameters, "permission")).map_err(failed)?;
            let removed = state
                .roles
                .remove_permission(&tenant, &namespace, &name, caller)
                .await
                .map_err(failed)?;
            if !removed {
                return Err(not_found(
                    "authorization.permission_not_found",
                    "the resource server declares no such permission",
                ));
            }
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct RoleReferenceBody {
    namespace: String,
    name: String,
}

impl From<&RoleKey> for RoleReferenceBody {
    fn from(key: &RoleKey) -> Self {
        Self {
            namespace: key.namespace.as_str().to_owned(),
            name: key.name.as_str().to_owned(),
        }
    }
}

impl RoleReferenceBody {
    fn key(&self) -> Result<RoleKey, Box<Response>> {
        Ok(RoleKey::new(
            Namespace::parse(&self.namespace).map_err(failed)?,
            RoleName::parse(&self.name).map_err(failed)?,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeldPermissionBody {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    condition: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleContentsBody {
    #[serde(default)]
    description: String,
    #[serde(default)]
    permissions: Vec<HeldPermissionBody>,
    #[serde(default)]
    includes: Vec<RoleReferenceBody>,
}

impl RoleContentsBody {
    fn contents(self) -> Result<RoleContents, Box<Response>> {
        let mut permissions = BTreeSet::new();
        let mut conditions = BTreeMap::new();
        for held in self.permissions {
            let name = PermissionName::parse(&held.name).map_err(failed)?;
            if let Some(text) = held.condition {
                conditions.insert(name.clone(), Condition::parse(&text).map_err(failed)?);
            }
            permissions.insert(name);
        }
        let includes = self
            .includes
            .iter()
            .map(RoleReferenceBody::key)
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(RoleContents {
            description: self.description,
            permissions,
            includes,
            conditions,
        })
    }
}

#[derive(Debug, Serialize)]
struct RoleBody {
    namespace: String,
    name: String,
    description: String,
    permissions: Vec<HeldPermissionBody>,
    includes: Vec<RoleReferenceBody>,
    created_at: String,
    updated_at: String,
}

impl From<&RoleDefinition> for RoleBody {
    fn from(role: &RoleDefinition) -> Self {
        let contents = role.contents();
        Self {
            namespace: role.key().namespace.as_str().to_owned(),
            name: role.key().name.as_str().to_owned(),
            description: contents.description.clone(),
            permissions: contents
                .permissions
                .iter()
                .map(|name| HeldPermissionBody {
                    name: name.as_str().to_owned(),
                    condition: contents
                        .conditions
                        .get(name)
                        .map(|condition| condition.as_str().to_owned()),
                })
                .collect(),
            includes: contents
                .includes
                .iter()
                .map(RoleReferenceBody::from)
                .collect(),
            created_at: written(role.created_at()),
            updated_at: written(role.updated_at()),
        }
    }
}

async fn role_key(
    state: &Shared,
    tenant: &TenantContext,
    parameters: &RawPathParams,
) -> Result<RoleKey, Box<Response>> {
    let namespace = namespace_of(state, tenant, parameters).await?;
    let name = RoleName::parse(&path_text(parameters, "role")).map_err(failed)?;
    Ok(RoleKey::new(namespace, name))
}

fn role_not_found() -> Box<Response> {
    not_found(
        "authorization.role_not_found",
        "the tenant has no such role",
    )
}

async fn list_roles(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/roles").await?;
            let roles = state.roles.roles(&tenant).await.map_err(failed)?;
            let items = roles.iter().map(RoleBody::from).collect();
            Ok(Json(ItemsBody { items }).into_response())
        }
        .await,
    )
}

async fn get_role(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/resource-servers/{resource_server_id}/roles/{role}";
            authorize(&state, &tenant, &headers, "GET", operation).await?;
            let key = role_key(&state, &tenant, &parameters).await?;
            let role = state
                .roles
                .role(&tenant, &key)
                .await
                .map_err(failed)?
                .ok_or_else(role_not_found)?;
            Ok(Json(RoleBody::from(&role)).into_response())
        }
        .await,
    )
}

async fn define_role(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/resource-servers/{resource_server_id}/roles/{role}";
            let caller = authorize(&state, &tenant, &headers, "PUT", operation).await?;
            let key = role_key(&state, &tenant, &parameters).await?;
            let asked: RoleContentsBody = body(&bytes)?;
            let contents = asked.contents()?;
            let role = state
                .roles
                .define_role(&tenant, key, contents, caller)
                .await
                .map_err(failed)?;
            Ok(Json(RoleBody::from(&role)).into_response())
        }
        .await,
    )
}

async fn remove_role(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/resource-servers/{resource_server_id}/roles/{role}";
            let caller = authorize(&state, &tenant, &headers, "DELETE", operation).await?;
            let key = role_key(&state, &tenant, &parameters).await?;
            if !state
                .roles
                .remove_role(&tenant, &key, caller)
                .await
                .map_err(failed)?
            {
                return Err(role_not_found());
            }
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

// ---------------------------------------------------------------------------
// Assignments
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrincipalBody {
    pub(super) kind: String,
    pub(super) id: String,
}

#[derive(Debug, Serialize)]
struct AssignmentBody {
    principal: PrincipalBody,
    role: RoleReferenceBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    application_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid_until: Option<String>,
    assigned_at: String,
}

impl From<&RoleAssignment> for AssignmentBody {
    fn from(assignment: &RoleAssignment) -> Self {
        Self {
            principal: PrincipalBody {
                kind: assignment.principal().kind().as_str().to_owned(),
                id: assignment.principal().id().to_owned(),
            },
            role: RoleReferenceBody::from(assignment.role()),
            application_id: assignment
                .scope()
                .application()
                .map(|application| application.as_str().to_owned()),
            organization_id: assignment
                .scope()
                .organization()
                .map(|organization| organization.as_str().to_owned()),
            valid_from: assignment.valid_from().map(written),
            valid_until: assignment.valid_until().map(written),
            assigned_at: written(assignment.assigned_at()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignBody {
    principal: PrincipalBody,
    role: RoleReferenceBody,
    #[serde(default)]
    application_id: Option<String>,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    valid_from: Option<String>,
    #[serde(default)]
    valid_until: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    principal: PrincipalBody,
    role: RoleReferenceBody,
    #[serde(default)]
    application_id: Option<String>,
    #[serde(default)]
    organization_id: Option<String>,
}

fn moment(value: Option<&str>) -> Result<Option<OffsetDateTime>, Box<Response>> {
    value
        .map(|text| {
            OffsetDateTime::parse(text, &Rfc3339).map_err(|_| {
                problem(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "request.body_invalid",
                    "valid_from and valid_until are RFC 3339 times",
                )
            })
        })
        .transpose()
}

/// The principal, checked to be a user, a client or a group of the tenant.
pub(super) async fn principal(
    state: &Shared,
    tenant: &TenantContext,
    given: &PrincipalBody,
) -> Result<Subject, Box<Response>> {
    let kind = SubjectKind::parse_principal(&given.kind).map_err(failed)?;
    match kind {
        SubjectKind::Group => {
            let group: hodor_kernel::GroupId = given
                .id
                .parse()
                .map_err(|_| not_found("identity.group_not_found", "the group does not exist"))?;
            state.groups.get(tenant, group).await.map_err(failed)?;
        }
        SubjectKind::User => {
            let user: UserId = given.id.parse().map_err(|_| super::user_not_found())?;
            state.identity.get(tenant, user).await.map_err(failed)?;
        }
        SubjectKind::Client => {
            let client: ClientId = given
                .id
                .parse()
                .map_err(|_| not_found("oauth.client_not_found", "there is no such client"))?;
            state
                .applications
                .client(tenant, client)
                .await
                .map_err(failed)?;
        }
    }
    Subject::new(kind, &given.id).map_err(failed)
}

/// The scope: the tenant, an application or an organization of the
/// tenant, never both of the last two.
async fn scope(
    state: &Shared,
    tenant: &TenantContext,
    application: Option<&str>,
    organization: Option<&str>,
) -> Result<AssignmentScope, Box<Response>> {
    if let Some(organization) = organization {
        if application.is_some() {
            return Err(problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                "authorization.scope_invalid",
                "an assignment is scoped to an application or to an organization, not both",
            ));
        }
        let id: hodor_kernel::OrganizationId = organization.parse().map_err(|_| {
            not_found(
                "identity.organization_not_found",
                "the organization does not exist",
            )
        })?;
        state.organizations.get(tenant, id).await.map_err(failed)?;
        return Ok(AssignmentScope::Organization(
            hodor_authorization::api::OrganizationReference::parse(&id.to_string())
                .map_err(failed)?,
        ));
    }
    let Some(text) = application else {
        return Ok(AssignmentScope::Tenant);
    };
    let id: ApplicationId = text.parse().map_err(|_| {
        not_found(
            "oauth.application_not_found",
            "there is no such application",
        )
    })?;
    state
        .applications
        .application(tenant, id)
        .await
        .map_err(failed)?;
    Ok(AssignmentScope::Application(
        ApplicationReference::parse(&id.to_string()).map_err(failed)?,
    ))
}

async fn assignments_of(
    state: &Shared,
    tenant: &TenantContext,
    principal: &Subject,
) -> Result<Response, Box<Response>> {
    let held = state
        .roles
        .assignments_of(tenant, principal)
        .await
        .map_err(failed)?;
    let items = held.iter().map(AssignmentBody::from).collect();
    Ok(Json(ItemsBody { items }).into_response())
}

async fn user_assignments(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/users/{user_id}/role-assignments";
            authorize(&state, &tenant, &headers, "GET", operation).await?;
            let given = PrincipalBody {
                kind: "user".to_owned(),
                id: path_text(&parameters, "user"),
            };
            let subject = principal(&state, &tenant, &given).await?;
            assignments_of(&state, &tenant, &subject).await
        }
        .await,
    )
}

async fn group_assignments(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/groups/{group_id}/role-assignments";
            authorize(&state, &tenant, &headers, "GET", operation).await?;
            let given = PrincipalBody {
                kind: "group".to_owned(),
                id: path_text(&parameters, "group"),
            };
            let subject = principal(&state, &tenant, &given).await?;
            assignments_of(&state, &tenant, &subject).await
        }
        .await,
    )
}

async fn client_assignments(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/clients/{client_id}/role-assignments";
            authorize(&state, &tenant, &headers, "GET", operation).await?;
            let given = PrincipalBody {
                kind: "client".to_owned(),
                id: path_text(&parameters, "client"),
            };
            let subject = principal(&state, &tenant, &given).await?;
            assignments_of(&state, &tenant, &subject).await
        }
        .await,
    )
}

async fn assign(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "POST", "/role-assignments").await?;
            let asked: AssignBody = body(&bytes)?;
            let subject = principal(&state, &tenant, &asked.principal).await?;
            let role = asked.role.key()?;
            let scope = scope(
                &state,
                &tenant,
                asked.application_id.as_deref(),
                asked.organization_id.as_deref(),
            )
            .await?;
            let validity = Validity {
                from: moment(asked.valid_from.as_deref())?,
                until: moment(asked.valid_until.as_deref())?,
            };
            let assignment = state
                .roles
                .assign(&tenant, subject, role, scope, validity, caller)
                .await
                .map_err(failed)?;
            Ok((StatusCode::CREATED, Json(AssignmentBody::from(&assignment))).into_response())
        }
        .await,
    )
}

async fn revoke(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/role-assignments:revoke";
            let caller = authorize(&state, &tenant, &headers, "POST", operation).await?;
            let asked: RevokeBody = body(&bytes)?;
            let subject = principal(&state, &tenant, &asked.principal).await?;
            let role = asked.role.key()?;
            let scope = scope(
                &state,
                &tenant,
                asked.application_id.as_deref(),
                asked.organization_id.as_deref(),
            )
            .await?;
            if !state
                .roles
                .revoke(&tenant, &subject, &role, &scope, caller)
                .await
                .map_err(failed)?
            {
                return Err(not_found(
                    "authorization.assignment_not_found",
                    "the principal does not hold that role there",
                ));
            }
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct BindingBody {
    namespace: String,
    engine: String,
    time_limit_milliseconds: u64,
    sensitive: bool,
    fail_open_actions: Vec<String>,
    trust_asserted: bool,
    created_at: String,
    updated_at: String,
}

impl From<&EngineBinding> for BindingBody {
    fn from(binding: &EngineBinding) -> Self {
        let settings = binding.settings();
        Self {
            namespace: binding.namespace().as_str().to_owned(),
            engine: binding.engine().as_str().to_owned(),
            time_limit_milliseconds: u64::try_from(settings.time_limit.as_millis())
                .unwrap_or(u64::MAX),
            sensitive: settings.sensitive,
            fail_open_actions: settings
                .fail_open_actions
                .iter()
                .map(|action| action.as_str().to_owned())
                .collect(),
            trust_asserted: settings.trust_asserted,
            created_at: written(binding.created_at()),
            updated_at: written(binding.updated_at()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindBody {
    engine: String,
    #[serde(default)]
    time_limit_milliseconds: Option<u32>,
    #[serde(default)]
    sensitive: bool,
    #[serde(default)]
    fail_open_actions: Vec<String>,
    #[serde(default)]
    trust_asserted: bool,
}

fn binding_not_found() -> Box<Response> {
    not_found(
        "authorization.binding_not_found",
        "no engine is bound to this resource server",
    )
}

async fn list_bindings(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/bindings").await?;
            let bindings = state.evaluation.bindings(&tenant).await.map_err(failed)?;
            let items = bindings.iter().map(BindingBody::from).collect();
            Ok(Json(ItemsBody { items }).into_response())
        }
        .await,
    )
}

async fn get_binding(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/resource-servers/{resource_server_id}/binding";
            authorize(&state, &tenant, &headers, "GET", operation).await?;
            let namespace = namespace_of(&state, &tenant, &parameters).await?;
            let binding = state
                .evaluation
                .binding(&tenant, &namespace)
                .await
                .map_err(failed)?
                .ok_or_else(binding_not_found)?;
            Ok(Json(BindingBody::from(&binding)).into_response())
        }
        .await,
    )
}

async fn bind(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/resource-servers/{resource_server_id}/binding";
            let caller = authorize(&state, &tenant, &headers, "PUT", operation).await?;
            let namespace = namespace_of(&state, &tenant, &parameters).await?;
            let asked: BindBody = body(&bytes)?;
            let mut settings =
                BindingSettings::new(namespace, EngineId::parse(&asked.engine).map_err(failed)?);
            if let Some(milliseconds) = asked.time_limit_milliseconds {
                settings.time_limit = std::time::Duration::from_millis(u64::from(milliseconds));
            }
            settings.sensitive = asked.sensitive;
            settings.trust_asserted = asked.trust_asserted;
            settings.fail_open_actions = asked
                .fail_open_actions
                .iter()
                .map(|action| Action::parse(action))
                .collect::<Result<_, _>>()
                .map_err(failed)?;
            let binding = state
                .evaluation
                .bind(&tenant, settings, caller)
                .await
                .map_err(failed)?;
            Ok(Json(BindingBody::from(&binding)).into_response())
        }
        .await,
    )
}

async fn unbind(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/resource-servers/{resource_server_id}/binding";
            let caller = authorize(&state, &tenant, &headers, "DELETE", operation).await?;
            let namespace = namespace_of(&state, &tenant, &parameters).await?;
            if !state
                .evaluation
                .unbind(&tenant, &namespace, caller)
                .await
                .map_err(failed)?
            {
                return Err(binding_not_found());
            }
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

fn policies(state: &Shared) -> Result<&PolicyService, Box<Response>> {
    state.policies.as_ref().ok_or_else(|| {
        not_found(
            "authorization.policies_unavailable",
            "this installation does not run Open Policy Agent",
        )
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileBody {
    path: String,
    contents: String,
}

#[derive(Debug, Serialize)]
struct VersionBody {
    number: u64,
    written_by: &'static str,
    digest: String,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<hodor_authorization_opa::api::Report>,
    drafted_at: String,
    changed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    files: Option<Vec<FileBody>>,
}

impl VersionBody {
    fn of(version: &PolicyVersion, with_files: bool) -> Self {
        Self {
            number: version.number,
            written_by: version.author.as_str(),
            digest: version.digest_hex(),
            state: version.state.as_str(),
            report: version.report.clone(),
            drafted_at: written(version.drafted_at),
            changed_at: written(version.changed_at),
            files: with_files.then(|| {
                version
                    .files
                    .iter()
                    .map(|file| FileBody {
                        path: file.path.clone(),
                        contents: String::from_utf8_lossy(&file.contents).into_owned(),
                    })
                    .collect()
            }),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftBody {
    files: Vec<FileBody>,
}

fn version_number(parameters: &RawPathParams) -> Result<(u64, Option<String>), Box<Response>> {
    let segment = path_text(parameters, "number");
    let (number, action) = match segment.split_once(':') {
        Some((number, action)) => (number.to_owned(), Some(action.to_owned())),
        None => (segment, None),
    };
    let number = number.parse().map_err(|_| {
        not_found(
            "authorization.policy_version_not_found",
            "the tenant has no version of this number",
        )
    })?;
    Ok((number, action))
}

async fn list_versions(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/policy-versions").await?;
            let versions = policies(&state)?
                .versions(&tenant, VERSIONS_LISTED)
                .await
                .map_err(failed)?;
            let items = versions.iter().map(|v| VersionBody::of(v, false)).collect();
            Ok(Json(ItemsBody { items }).into_response())
        }
        .await,
    )
}

async fn draft_version(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "POST", "/policy-versions").await?;
            let asked: DraftBody = body(&bytes)?;
            let files: Vec<BundleFile> = asked
                .files
                .into_iter()
                .map(|file| BundleFile {
                    path: file.path,
                    contents: file.contents.into_bytes(),
                })
                .collect();
            // What a tenant writes through the interface is its own: it is
            // served only to an instance of the tenant's own.
            let version = policies(&state)?
                .draft(&tenant, Author::Tenant, &files, caller)
                .await
                .map_err(failed)?;
            Ok((StatusCode::CREATED, Json(VersionBody::of(&version, true))).into_response())
        }
        .await,
    )
}

async fn get_version(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/policy-versions/{number}";
            authorize(&state, &tenant, &headers, "GET", operation).await?;
            let (number, action) = version_number(&parameters)?;
            if action.is_some() {
                return Err(route_not_found());
            }
            let version = policies(&state)?
                .version(&tenant, number)
                .await
                .map_err(failed)?;
            Ok(Json(VersionBody::of(&version, true)).into_response())
        }
        .await,
    )
}

async fn version_action(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            // The action is read before anything else, so that the caller is
            // recognized before the number is.
            let segment = path_text(&parameters, "number");
            let action = segment.split_once(':').map(|(_, action)| action.to_owned());
            let operation = match action.as_deref() {
                Some("validate") => "/policy-versions/{number}:validate",
                Some("test") => "/policy-versions/{number}:test",
                _ => return Err(route_not_found()),
            };
            authorize(&state, &tenant, &headers, "POST", operation).await?;
            let (number, _) = version_number(&parameters)?;
            let service = policies(&state)?;
            let version = if action.as_deref() == Some("validate") {
                service.validate(&tenant, number).await
            } else {
                service.test(&tenant, number).await
            }
            .map_err(failed)?;
            Ok((StatusCode::ACCEPTED, Json(VersionBody::of(&version, false))).into_response())
        }
        .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimulateBody {
    resource_server_id: String,
    inputs: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct SimulationBody {
    simulation_id: String,
    version: u64,
    namespace: String,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    compared_with: Option<u64>,
    results: Vec<hodor_authorization_opa::api::SimulatedAnswer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<hodor_authorization_opa::api::Report>,
    asked_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    done_at: Option<String>,
}

impl From<&Simulation> for SimulationBody {
    fn from(simulation: &Simulation) -> Self {
        Self {
            simulation_id: simulation.id.to_string(),
            version: simulation.version,
            namespace: simulation.namespace.clone(),
            state: simulation.state.as_str(),
            compared_with: simulation.compared_with,
            results: simulation.results.clone(),
            report: simulation.report.clone(),
            asked_at: written(simulation.asked_at),
            done_at: simulation.done_at.map(written),
        }
    }
}

async fn simulate(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/policy-versions/{number}/simulations";
            authorize(&state, &tenant, &headers, "POST", operation).await?;
            let (number, _) = version_number(&parameters)?;
            let asked: SimulateBody = body(&bytes)?;
            let id: ResourceServerId = asked.resource_server_id.parse().map_err(|_| {
                not_found(
                    "oauth.resource_server_not_found",
                    "there is no such resource server",
                )
            })?;
            let server = state
                .applications
                .resource_server(&tenant, id)
                .await
                .map_err(failed)?;
            let namespace = Namespace::parse(server.audience().as_str()).map_err(failed)?;
            let simulation = policies(&state)?
                .simulate(&tenant, number, &namespace, asked.inputs)
                .await
                .map_err(failed)?;
            Ok((
                StatusCode::ACCEPTED,
                Json(SimulationBody::from(&simulation)),
            )
                .into_response())
        }
        .await,
    )
}

async fn get_simulation(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/policy-simulations/{simulation_id}";
            authorize(&state, &tenant, &headers, "GET", operation).await?;
            let id: SimulationId = parameter(&parameters, "simulation").ok_or_else(|| {
                not_found(
                    "authorization.policy_simulation_not_found",
                    "the tenant has no simulation of this identifier",
                )
            })?;
            let simulation = policies(&state)?
                .simulation(&tenant, id)
                .await
                .map_err(failed)?;
            Ok(Json(SimulationBody::from(&simulation)).into_response())
        }
        .await,
    )
}

#[derive(Debug, Serialize)]
struct LatestBody {
    revision: u64,
    written_by: &'static str,
    published_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u64>,
}

#[derive(Debug, Serialize)]
struct PublicationBody {
    revision: u64,
    version: u64,
}

#[derive(Debug, Serialize)]
struct ActivationBody {
    instance: String,
    own: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reported_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    current: bool,
}

#[derive(Debug, Serialize)]
struct StatusBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    latest: Option<LatestBody>,
    publications: Vec<PublicationBody>,
    instances: Vec<ActivationBody>,
    pending_activation: bool,
}

impl From<PolicyStatus> for StatusBody {
    fn from(status: PolicyStatus) -> Self {
        Self {
            latest: status
                .latest
                .map(|(revision, author, published_at, version)| LatestBody {
                    revision,
                    written_by: author.as_str(),
                    published_at: written(published_at),
                    version,
                }),
            publications: status
                .publications
                .into_iter()
                .map(|(revision, version)| PublicationBody { revision, version })
                .collect(),
            instances: status
                .instances
                .into_iter()
                .map(|activation| ActivationBody {
                    instance: activation.instance,
                    own: activation.own,
                    active_revision: activation.active_revision,
                    reported_at: activation.reported_at.map(written),
                    error: activation.error,
                    current: activation.current,
                })
                .collect(),
            pending_activation: status.pending_activation,
        }
    }
}

async fn policy_status(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/policy-status").await?;
            let status = policies(&state)?.status(&tenant).await.map_err(failed)?;
            Ok(Json(StatusBody::from(status)).into_response())
        }
        .await,
    )
}
