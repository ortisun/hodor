//! The SCIM 2.0 server: other systems provision a tenant's users and
//! groups.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "Who may
//! call", "The surface" and "Errors", and `docs/api/api-spec.md`, "SCIM
//! 2.0". These handlers check the caller's token, read the request and
//! write the answer in the media type and the error schema of RFC 7644;
//! what happens to users and groups is the provisioning context's.

use crate::bearer::{bearer, challenge, not_cached};
use crate::request::current_request_id;
use crate::tenant::TenantSlug;
use axum::body::Bytes;
use axum::extract::{RawPathParams, RawQuery, State};
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Extension, Router};
use hodor_kernel::{
    Actor, Caller, ClientActorId, CorrelationId, DomainError, ErrorKind, GroupId, TenantContext,
    UserId,
};
use hodor_oauth::api::{BearerRefusal, ResourceAccessService};
use hodor_provisioning::api::{
    Attribute, ERROR_SCHEMA, GroupAttribute, INVALID_FILTER, INVALID_SYNTAX, ListParameters,
    ListQuery, MUTABILITY, ProvisioningService, UserAttribute, list_response, read_group,
    read_user, resource_type, resource_types, schema_named, schemas, service_provider_config,
};
use serde_json::{Value, json};

/// The audience an access token must name to be taken by the SCIM server.
pub const SCIM_AUDIENCE: &str = "urn:hodor:scim";
/// The scope that opens every route of the SCIM server.
pub const SCIM_SCOPE: &str = "scim";
/// The media type of SCIM.
pub const SCIM_MEDIA_TYPE: &str = "application/scim+json";

const SURFACE: &str = "the SCIM server";

/// What the SCIM server needs.
#[derive(Clone)]
pub struct ScimState {
    /// Checks the caller's access token.
    pub access: ResourceAccessService,
    /// Provisions users and groups.
    pub provisioning: ProvisioningService,
    /// The address people reach this installation at, without a path.
    pub public_url: String,
}

impl std::fmt::Debug for ScimState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScimState").finish_non_exhaustive()
    }
}

/// The SCIM server, to be mounted under a tenant at `/scim/v2`.
pub fn scim_routes(state: ScimState) -> Router {
    Router::new()
        .route("/ServiceProviderConfig", get(service_provider))
        .route("/ResourceTypes", get(list_resource_types))
        .route("/ResourceTypes/{name}", get(one_resource_type))
        .route("/Schemas", get(list_schemas))
        .route("/Schemas/{uri}", get(one_schema))
        .route("/Users", get(list_users).post(create_user))
        .route("/Users/.search", post(not_supported))
        .route(
            "/Users/{id}",
            get(get_user)
                .put(replace_user)
                .patch(not_supported)
                .delete(not_supported),
        )
        .route("/Groups", get(list_groups).post(create_group))
        .route("/Groups/.search", post(not_supported))
        .route(
            "/Groups/{id}",
            get(get_group)
                .put(replace_group)
                .patch(not_supported)
                .delete(delete_group),
        )
        .route("/Bulk", any(not_supported))
        .route("/.search", any(not_supported))
        .fallback(no_such_route)
        .with_state(state)
}

/// An answer in SCIM's media type, never to be kept by a cache.
fn scim(status: StatusCode, body: &Value) -> Response {
    let mut response = (status, body.to_string()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(SCIM_MEDIA_TYPE),
    );
    not_cached(response)
}

/// An error in the schema of RFC 7644, section 3.12.
fn scim_error(status: StatusCode, scim_type: Option<&str>, detail: &str) -> Response {
    let mut body = json!({
        "schemas": [ERROR_SCHEMA],
        "status": status.as_u16().to_string(),
        "detail": detail,
    });
    if let Some(scim_type) = scim_type {
        body["scimType"] = json!(scim_type);
    }
    scim(status, &body)
}

fn not_found() -> Response {
    scim_error(StatusCode::NOT_FOUND, None, "the resource does not exist")
}

/// The answer to an error of a use case.
fn refusal(error: &DomainError) -> Response {
    match error.kind() {
        ErrorKind::Invalid => {
            let scim_type = match error.code() {
                INVALID_FILTER => "invalidFilter",
                INVALID_SYNTAX => "invalidSyntax",
                MUTABILITY => "mutability",
                _ => "invalidValue",
            };
            scim_error(StatusCode::BAD_REQUEST, Some(scim_type), error.message())
        }
        ErrorKind::NotFound => not_found(),
        ErrorKind::Conflict => {
            let unique = matches!(
                error.code(),
                "identity.identifier_taken" | "identity.group_name_taken"
            );
            scim_error(
                StatusCode::CONFLICT,
                unique.then_some("uniqueness"),
                error.message(),
            )
        }
        _ => {
            // Operators get the full story in the log; callers a generic
            // message.
            tracing::error!(
                code = error.code(),
                message = error.message(),
                detail = error.detail(),
                "a SCIM request failed"
            );
            scim_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
                "the request could not be completed",
            )
        }
    }
}

/// A refused token: `401` or `403` with the challenge, and a SCIM error.
fn refused(refusal: BearerRefusal) -> Response {
    let detail = match refusal {
        BearerRefusal::InsufficientScope => "the access token does not hold the scope scim",
        _ => "an access token of this tenant for urn:hodor:scim is required",
    };
    let (status, challenge) = challenge(refusal, SCIM_SCOPE, SURFACE);
    let mut response = scim_error(status, None, detail);
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

/// The address of the tenant's SCIM surface, as resources name it.
fn base(public_url: &str, slug: &str) -> String {
    format!("{}/t/{slug}/scim/v2", public_url.trim_end_matches('/'))
}

/// The calling client, as the actor of what it changes, or the answer
/// refusing its token.
async fn caller(
    state: &ScimState,
    tenant: &TenantContext,
    slug: &str,
    headers: &HeaderMap,
) -> Result<Caller, Box<Response>> {
    let Ok(token) = bearer(headers) else {
        return Err(Box::new(refused(BearerRefusal::InvalidToken(
            "the Authorization header is not a bearer token",
        ))));
    };
    let issuer = format!("{}/t/{slug}", state.public_url.trim_end_matches('/'));
    let caller = match state
        .access
        .caller(tenant, &issuer, SCIM_AUDIENCE, token)
        .await
    {
        Ok(Ok(caller)) => caller,
        Ok(Err(refusal)) => return Err(Box::new(refused(refusal))),
        Err(error) => return Err(Box::new(self::refusal(&error))),
    };
    if !caller.has_scope(SCIM_SCOPE) {
        return Err(Box::new(refused(BearerRefusal::InsufficientScope)));
    }
    Ok(Caller {
        actor: Actor::Client(ClientActorId::from_uuid(caller.client_id.as_uuid())),
        correlation_id: current_request_id().unwrap_or_else(CorrelationId::generate),
    })
}

/// The body of a `POST` or `PUT`, as JSON, when its media type is SCIM's
/// or JSON's.
fn body(headers: &HeaderMap, bytes: &Bytes) -> Result<Value, Box<Response>> {
    let media_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    let accepted = media_type.is_some_and(|media_type| {
        media_type.eq_ignore_ascii_case(SCIM_MEDIA_TYPE)
            || media_type.eq_ignore_ascii_case("application/json")
    });
    if !accepted {
        return Err(Box::new(scim_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            None,
            "the body is application/scim+json or application/json",
        )));
    }
    serde_json::from_slice(bytes).map_err(|_| {
        Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "the body is not JSON",
        ))
    })
}

/// The query parameters of a list, each the first of its name.
fn list_query<A: Attribute>(query: Option<&str>) -> Result<ListQuery<A>, DomainError> {
    let pairs: Vec<(String, String)> = form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .into_owned()
        .collect();
    let first = |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    ListQuery::read(&ListParameters {
        filter: first("filter"),
        sort_by: first("sortBy"),
        sort_order: first("sortOrder"),
        start_index: first("startIndex"),
        count: first("count"),
    })
}

/// The value of the path's parameter `name`, or nothing.
fn parameter(parameters: &RawPathParams, name: &str) -> String {
    parameters
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
        .unwrap_or_default()
}

/// The tenant, its slug and the caller of every handler.
type Context = (Extension<TenantContext>, Extension<TenantSlug>);

macro_rules! authenticated {
    ($state:expr, $tenant:expr, $slug:expr, $headers:expr) => {
        match caller(&$state, &$tenant, &$slug, &$headers).await {
            Ok(caller) => caller,
            Err(response) => return *response,
        }
    };
}

async fn service_provider(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers);
    scim(
        StatusCode::OK,
        &service_provider_config(&base(&state.public_url, &slug)),
    )
}

async fn list_resource_types(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers);
    let listed = resource_types(&base(&state.public_url, &slug));
    scim(
        StatusCode::OK,
        &list_response(listed.len() as u64, 1, listed),
    )
}

async fn one_resource_type(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers);
    let name = parameter(&parameters, "name");
    resource_type(&name, &base(&state.public_url, &slug))
        .map_or_else(not_found, |found| scim(StatusCode::OK, &found))
}

async fn list_schemas(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers);
    let listed = schemas(&base(&state.public_url, &slug));
    scim(
        StatusCode::OK,
        &list_response(listed.len() as u64, 1, listed),
    )
}

async fn one_schema(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers);
    let uri = parameter(&parameters, "uri");
    schema_named(&uri, &base(&state.public_url, &slug))
        .map_or_else(not_found, |found| scim(StatusCode::OK, &found))
}

fn created(document: &Value) -> Response {
    let mut response = scim(StatusCode::CREATED, document);
    if let Some(location) = document["meta"]["location"]
        .as_str()
        .and_then(|location| HeaderValue::from_str(location).ok())
    {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

async fn list_users(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers);
    let asked = match list_query::<UserAttribute>(query.as_deref()) {
        Ok(asked) => asked,
        Err(error) => return refusal(&error),
    };
    match state.provisioning.list_users(&tenant, &asked).await {
        Ok(listed) => {
            let base = base(&state.public_url, &slug);
            let resources = listed
                .resources
                .iter()
                .map(|resource| resource.document(&base))
                .collect();
            scim(
                StatusCode::OK,
                &list_response(listed.total, listed.start_index, resources),
            )
        }
        Err(error) => refusal(&error),
    }
}

async fn create_user(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let caller = authenticated!(state, tenant, slug, headers);
    let request = match body(&headers, &bytes).map(|value| read_user(&value)) {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => return refusal(&error),
        Err(response) => return *response,
    };
    match state
        .provisioning
        .create_user(&tenant, &request, caller)
        .await
    {
        Ok(resource) => created(&resource.document(&base(&state.public_url, &slug))),
        Err(error) => refusal(&error),
    }
}

async fn get_user(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers);
    let Ok(id) = parameter(&parameters, "id").parse::<UserId>() else {
        return not_found();
    };
    match state.provisioning.get_user(&tenant, id).await {
        Ok(resource) => scim(
            StatusCode::OK,
            &resource.document(&base(&state.public_url, &slug)),
        ),
        Err(error) => refusal(&error),
    }
}

async fn replace_user(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    parameters: RawPathParams,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let caller = authenticated!(state, tenant, slug, headers);
    let Ok(id) = parameter(&parameters, "id").parse::<UserId>() else {
        return not_found();
    };
    let request = match body(&headers, &bytes).map(|value| read_user(&value)) {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => return refusal(&error),
        Err(response) => return *response,
    };
    match state
        .provisioning
        .replace_user(&tenant, id, &request, caller)
        .await
    {
        Ok(resource) => scim(
            StatusCode::OK,
            &resource.document(&base(&state.public_url, &slug)),
        ),
        Err(error) => refusal(&error),
    }
}

async fn list_groups(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers);
    let asked = match list_query::<GroupAttribute>(query.as_deref()) {
        Ok(asked) => asked,
        Err(error) => return refusal(&error),
    };
    match state.provisioning.list_groups(&tenant, &asked).await {
        Ok(listed) => {
            let base = base(&state.public_url, &slug);
            let resources = listed
                .resources
                .iter()
                .map(|resource| resource.document(&base))
                .collect();
            scim(
                StatusCode::OK,
                &list_response(listed.total, listed.start_index, resources),
            )
        }
        Err(error) => refusal(&error),
    }
}

async fn create_group(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let caller = authenticated!(state, tenant, slug, headers);
    let request = match body(&headers, &bytes).map(|value| read_group(&value)) {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => return refusal(&error),
        Err(response) => return *response,
    };
    match state
        .provisioning
        .create_group(&tenant, &request, caller)
        .await
    {
        Ok(resource) => created(&resource.document(&base(&state.public_url, &slug))),
        Err(error) => refusal(&error),
    }
}

async fn get_group(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers);
    let Ok(id) = parameter(&parameters, "id").parse::<GroupId>() else {
        return not_found();
    };
    match state.provisioning.get_group(&tenant, id).await {
        Ok(resource) => scim(
            StatusCode::OK,
            &resource.document(&base(&state.public_url, &slug)),
        ),
        Err(error) => refusal(&error),
    }
}

async fn replace_group(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    parameters: RawPathParams,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let caller = authenticated!(state, tenant, slug, headers);
    let Ok(id) = parameter(&parameters, "id").parse::<GroupId>() else {
        return not_found();
    };
    let request = match body(&headers, &bytes).map(|value| read_group(&value)) {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => return refusal(&error),
        Err(response) => return *response,
    };
    match state
        .provisioning
        .replace_group(&tenant, id, &request, caller)
        .await
    {
        Ok(resource) => scim(
            StatusCode::OK,
            &resource.document(&base(&state.public_url, &slug)),
        ),
        Err(error) => refusal(&error),
    }
}

async fn delete_group(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    let caller = authenticated!(state, tenant, slug, headers);
    let Ok(id) = parameter(&parameters, "id").parse::<GroupId>() else {
        return not_found();
    };
    match state.provisioning.delete_group(&tenant, id, caller).await {
        Ok(()) => not_cached(StatusCode::NO_CONTENT.into_response()),
        Err(error) => refusal(&error),
    }
}

/// `PATCH`, `DELETE` of a user, bulk requests and searching with `POST`:
/// Issue-91 and later.
async fn not_supported(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug))): Context,
    method: Method,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers);
    scim_error(
        StatusCode::NOT_IMPLEMENTED,
        None,
        &format!("{method} is not supported here yet"),
    )
}

async fn no_such_route() -> Response {
    not_found()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_carry_the_status_as_a_string_and_the_scim_type_only_where_one_is_defined() {
        let filter = refusal(&DomainError::invalid(INVALID_FILTER, "too long"));
        assert_eq!(filter.status(), StatusCode::BAD_REQUEST);
        let taken = refusal(&DomainError::conflict("identity.identifier_taken", "taken"));
        assert_eq!(taken.status(), StatusCode::CONFLICT);
        let cycle = refusal(&DomainError::conflict("identity.group_cycle", "a cycle"));
        assert_eq!(cycle.status(), StatusCode::CONFLICT);
        let hidden = refusal(&DomainError::internal("database.error", "secret detail"));
        assert_eq!(hidden.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            hidden.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static(SCIM_MEDIA_TYPE))
        );
    }

    #[test]
    fn only_scim_and_json_bodies_are_read() {
        let with = |media_type: Option<&str>| {
            let mut headers = HeaderMap::new();
            if let Some(media_type) = media_type {
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_str(media_type).expect("a header"),
                );
            }
            body(&headers, &Bytes::from_static(b"{}")).map_err(|response| response.status())
        };
        assert!(with(Some("application/scim+json")).is_ok());
        assert!(with(Some("application/json; charset=utf-8")).is_ok());
        assert_eq!(
            with(Some("text/plain")),
            Err(StatusCode::UNSUPPORTED_MEDIA_TYPE)
        );
        assert_eq!(with(None), Err(StatusCode::UNSUPPORTED_MEDIA_TYPE));
    }
}
