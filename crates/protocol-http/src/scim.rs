//! The SCIM 2.0 server: other systems provision a tenant's users and
//! groups.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "Who may
//! call", "The surface", "Errors", "Changing with `PATCH`", "Versions" and
//! "Bulk requests", and `docs/api/api-spec.md`, "SCIM 2.0". These handlers
//! check the caller's token, read the request and write the answer in the
//! media type and the error schema of RFC 7644; what happens to users and
//! groups is the provisioning context's. Every change, alone or in a bulk
//! request, goes through [`perform`], so the two answer alike.

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
use hodor_oauth::api::{BearerRefusal, ForwardedIdentity, ResourceAccessService};
use hodor_provisioning::api::{
    Attribute, BULK_RESPONSE_SCHEMA, BulkMethod, ERROR_SCHEMA, GROUP_SHAPE, GroupAttribute,
    INVALID_FILTER, INVALID_PATH, INVALID_SYNTAX, ListParameters, ListQuery, MAX_BULK_BYTES,
    MUTABILITY, NO_TARGET, Precondition, ProvisioningService, TOO_MANY, USER_SHAPE, UserAttribute,
    VERSION_MISMATCH, check_bulk_id, list_response, method_of, read_bulk, read_group, read_patch,
    read_user, resolve_data, resolve_path, resource_type, resource_types, schema_named, schemas,
    service_provider_config,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

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
        .route("/Users", get(list_users).post(change_collection))
        .route("/Users/.search", post(not_supported))
        .route(
            "/Users/{id}",
            get(get_user)
                .put(change_one)
                .patch(change_one)
                .delete(change_one),
        )
        .route("/Groups", get(list_groups).post(change_collection))
        .route("/Groups/.search", post(not_supported))
        .route(
            "/Groups/{id}",
            get(get_group)
                .put(change_one)
                .patch(change_one)
                .delete(change_one),
        )
        .route("/Bulk", post(bulk))
        .route("/.search", any(not_supported))
        .fallback(no_such_route)
        .with_state(state)
}

/// A refusal, as RFC 7644, section 3.12, writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Failure {
    status: StatusCode,
    scim_type: Option<&'static str>,
    detail: String,
}

impl Failure {
    fn new(status: StatusCode, scim_type: Option<&'static str>, detail: impl Into<String>) -> Self {
        Self {
            status,
            scim_type,
            detail: detail.into(),
        }
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, None, "the resource does not exist")
    }

    fn document(&self) -> Value {
        let mut body = json!({
            "schemas": [ERROR_SCHEMA],
            "status": self.status.as_u16().to_string(),
            "detail": self.detail,
        });
        if let Some(scim_type) = self.scim_type {
            body["scimType"] = json!(scim_type);
        }
        body
    }

    fn response(&self) -> Response {
        scim(self.status, &self.document())
    }
}

/// The refusal of an error of a use case.
fn failure(error: &DomainError) -> Failure {
    match error.kind() {
        ErrorKind::Invalid => {
            let scim_type = match error.code() {
                INVALID_FILTER => "invalidFilter",
                INVALID_SYNTAX => "invalidSyntax",
                INVALID_PATH => "invalidPath",
                NO_TARGET => "noTarget",
                TOO_MANY => "tooMany",
                MUTABILITY => "mutability",
                _ => "invalidValue",
            };
            Failure::new(StatusCode::BAD_REQUEST, Some(scim_type), error.message())
        }
        ErrorKind::NotFound => Failure::not_found(),
        ErrorKind::Conflict if error.code() == VERSION_MISMATCH => {
            Failure::new(StatusCode::PRECONDITION_FAILED, None, error.message())
        }
        ErrorKind::Conflict => {
            let unique = matches!(
                error.code(),
                "identity.identifier_taken" | "identity.group_name_taken"
            );
            Failure::new(
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
            Failure::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
                "the request could not be completed",
            )
        }
    }
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

/// A refused token: `401` or `403` with the challenge, and a SCIM error.
fn refused(refusal: BearerRefusal) -> Response {
    let detail = match refusal {
        BearerRefusal::InsufficientScope => "the access token does not hold the scope scim",
        _ => "an access token of this tenant for urn:hodor:scim is required",
    };
    let (status, challenge) = challenge(refusal, SCIM_SCOPE, SURFACE);
    let mut response = Failure::new(status, None, detail).response();
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
/// refusing its token. A bound token must come with the certificate a
/// trusted proxy `forwarded`.
async fn caller(
    state: &ScimState,
    tenant: &TenantContext,
    slug: &str,
    headers: &HeaderMap,
    forwarded: Option<&Extension<ForwardedIdentity>>,
) -> Result<Caller, Box<Response>> {
    let Ok(token) = bearer(headers) else {
        return Err(Box::new(refused(BearerRefusal::InvalidToken(
            "the Authorization header is not a bearer token",
        ))));
    };
    let issuer = format!("{}/t/{slug}", state.public_url.trim_end_matches('/'));
    let caller = match state
        .access
        .caller(
            tenant,
            &issuer,
            SCIM_AUDIENCE,
            token,
            forwarded.map(|Extension(found)| found),
        )
        .await
    {
        Ok(Ok(caller)) => caller,
        Ok(Err(refusal)) => return Err(Box::new(refused(refusal))),
        Err(error) => return Err(Box::new(failure(&error).response())),
    };
    if !caller.has_scope(SCIM_SCOPE) {
        return Err(Box::new(refused(BearerRefusal::InsufficientScope)));
    }
    Ok(Caller {
        actor: Actor::Client(ClientActorId::from_uuid(caller.client_id.as_uuid())),
        correlation_id: current_request_id().unwrap_or_else(CorrelationId::generate),
    })
}

/// The body of a `POST`, `PUT` or `PATCH`, as JSON, when its media type
/// is SCIM's or JSON's.
fn body(headers: &HeaderMap, bytes: &Bytes) -> Result<Value, Failure> {
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
        return Err(Failure::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            None,
            "the body is application/scim+json or application/json",
        ));
    }
    serde_json::from_slice(bytes).map_err(|_| {
        Failure::new(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "the body is not JSON",
        )
    })
}

/// The precondition a header names, if the request has it.
fn precondition(headers: &HeaderMap, name: header::HeaderName) -> Option<Precondition> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(Precondition::read)
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

/// The tenant, its slug and what a trusted proxy forwarded about the
/// caller, for every handler.
type Context = (
    Extension<TenantContext>,
    Extension<TenantSlug>,
    Option<Extension<ForwardedIdentity>>,
);

macro_rules! authenticated {
    ($state:expr, $tenant:expr, $slug:expr, $headers:expr, $forwarded:expr) => {
        match caller(&$state, &$tenant, &$slug, &$headers, $forwarded.as_ref()).await {
            Ok(caller) => caller,
            Err(response) => return *response,
        }
    };
}

async fn service_provider(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug)), forwarded): Context,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers, forwarded);
    scim(
        StatusCode::OK,
        &service_provider_config(&base(&state.public_url, &slug)),
    )
}

async fn list_resource_types(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug)), forwarded): Context,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers, forwarded);
    let listed = resource_types(&base(&state.public_url, &slug));
    scim(
        StatusCode::OK,
        &list_response(listed.len() as u64, 1, listed),
    )
}

async fn one_resource_type(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug)), forwarded): Context,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers, forwarded);
    let name = parameter(&parameters, "name");
    resource_type(&name, &base(&state.public_url, &slug)).map_or_else(
        || Failure::not_found().response(),
        |found| scim(StatusCode::OK, &found),
    )
}

async fn list_schemas(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug)), forwarded): Context,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers, forwarded);
    let listed = schemas(&base(&state.public_url, &slug));
    scim(
        StatusCode::OK,
        &list_response(listed.len() as u64, 1, listed),
    )
}

async fn one_schema(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug)), forwarded): Context,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers, forwarded);
    let uri = parameter(&parameters, "uri");
    schema_named(&uri, &base(&state.public_url, &slug)).map_or_else(
        || Failure::not_found().response(),
        |found| scim(StatusCode::OK, &found),
    )
}

/// What a path of the surface names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Users,
    User(String),
    Groups,
    Group(String),
}

impl Target {
    fn read(path: &str) -> Option<Self> {
        let path = path.trim_start_matches('/');
        let (collection, id) = match path.split_once('/') {
            Some((collection, id)) if !id.is_empty() && !id.contains('/') => (collection, Some(id)),
            Some(_) => return None,
            None => (path, None),
        };
        match (collection, id) {
            ("Users", None) => Some(Self::Users),
            ("Users", Some(id)) => Some(Self::User(id.to_owned())),
            ("Groups", None) => Some(Self::Groups),
            ("Groups", Some(id)) => Some(Self::Group(id.to_owned())),
            _ => None,
        }
    }
}

/// What a change answers: its status, the resource when there is one,
/// and its version and address.
#[derive(Debug, Clone)]
struct Outcome {
    status: StatusCode,
    document: Option<Value>,
}

impl Outcome {
    fn version(&self) -> Option<&str> {
        self.document
            .as_ref()
            .and_then(|document| document["meta"]["version"].as_str())
    }

    fn location(&self) -> Option<&str> {
        self.document
            .as_ref()
            .and_then(|document| document["meta"]["location"].as_str())
    }

    fn response(&self) -> Response {
        let Some(document) = &self.document else {
            return not_cached(self.status.into_response());
        };
        let mut response = scim(self.status, document);
        let headers = response.headers_mut();
        if let Some(version) = self
            .version()
            .and_then(|version| HeaderValue::from_str(version).ok())
        {
            headers.insert(header::ETAG, version);
        }
        if self.status == StatusCode::CREATED
            && let Some(location) = self
                .location()
                .and_then(|location| HeaderValue::from_str(location).ok())
        {
            headers.insert(header::LOCATION, location);
        }
        response
    }
}

fn done(status: StatusCode, document: Value) -> Outcome {
    Outcome {
        status,
        document: Some(document),
    }
}

/// What one change asks for.
struct Change {
    method: BulkMethod,
    target: Target,
    data: Option<Value>,
    precondition: Option<Precondition>,
}

/// One change of the surface: `POST` on a collection, `PUT`, `PATCH` or
/// `DELETE` on a resource, with the body already read. Requests alone and
/// the operations of a bulk request go through here.
async fn perform(
    state: &ScimState,
    tenant: &TenantContext,
    base: &str,
    caller: Caller,
    change: Change,
) -> Result<Outcome, Failure> {
    let Change {
        method,
        target,
        data,
        precondition,
    } = change;
    let provisioning = &state.provisioning;
    let precondition = precondition.as_ref();
    let data = || {
        data.clone().ok_or_else(|| {
            Failure::new(
                StatusCode::BAD_REQUEST,
                Some("invalidSyntax"),
                "the operation has a body",
            )
        })
    };
    let user = |id: &str| id.parse::<UserId>().map_err(|_| Failure::not_found());
    let group = |id: &str| id.parse::<GroupId>().map_err(|_| Failure::not_found());
    let failed = |error: DomainError| failure(&error);
    match (method, target) {
        (BulkMethod::Post, Target::Users) => {
            let request = read_user(&data()?).map_err(failed)?;
            let created = provisioning
                .create_user(tenant, &request, caller)
                .await
                .map_err(failed)?;
            Ok(done(StatusCode::CREATED, created.document(base)))
        }
        (BulkMethod::Post, Target::Groups) => {
            let request = read_group(&data()?).map_err(failed)?;
            let created = provisioning
                .create_group(tenant, &request, caller)
                .await
                .map_err(failed)?;
            Ok(done(StatusCode::CREATED, created.document(base)))
        }
        (BulkMethod::Put, Target::User(id)) => {
            let id = user(&id)?;
            let request = read_user(&data()?).map_err(failed)?;
            let replaced = provisioning
                .replace_user(tenant, id, &request, precondition, caller)
                .await
                .map_err(failed)?;
            Ok(user_outcome(
                replaced.map(|resource| resource.document(base)),
            ))
        }
        (BulkMethod::Patch, Target::User(id)) => {
            let id = user(&id)?;
            let patch = read_patch(&data()?, &USER_SHAPE).map_err(failed)?;
            let patched = provisioning
                .patch_user(tenant, id, &patch, precondition, caller)
                .await
                .map_err(failed)?;
            Ok(user_outcome(
                patched.map(|resource| resource.document(base)),
            ))
        }
        (BulkMethod::Delete, Target::User(id)) => {
            provisioning
                .delete_user(tenant, user(&id)?, precondition, caller)
                .await
                .map_err(failed)?;
            Ok(Outcome {
                status: StatusCode::NO_CONTENT,
                document: None,
            })
        }
        (BulkMethod::Put, Target::Group(id)) => {
            let id = group(&id)?;
            let request = read_group(&data()?).map_err(failed)?;
            let replaced = provisioning
                .replace_group(tenant, id, &request, precondition, caller)
                .await
                .map_err(failed)?;
            Ok(done(StatusCode::OK, replaced.document(base)))
        }
        (BulkMethod::Patch, Target::Group(id)) => {
            let id = group(&id)?;
            let patch = read_patch(&data()?, &GROUP_SHAPE).map_err(failed)?;
            let patched = provisioning
                .patch_group(tenant, id, &patch, precondition, caller)
                .await
                .map_err(failed)?;
            Ok(done(StatusCode::OK, patched.document(base)))
        }
        (BulkMethod::Delete, Target::Group(id)) => {
            provisioning
                .delete_group(tenant, group(&id)?, precondition, caller)
                .await
                .map_err(failed)?;
            Ok(Outcome {
                status: StatusCode::NO_CONTENT,
                document: None,
            })
        }
        _ => Err(Failure::new(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "a change is POST on /Users or /Groups, or PUT, PATCH or DELETE on one of them",
        )),
    }
}

/// The answer to a change of a user: the user, or nothing when the change
/// deprovisioned and erased them.
fn user_outcome(document: Option<Value>) -> Outcome {
    match document {
        Some(document) => done(StatusCode::OK, document),
        None => Outcome {
            status: StatusCode::NO_CONTENT,
            document: None,
        },
    }
}

fn bulk_method(method: &Method) -> Option<BulkMethod> {
    match *method {
        Method::POST => Some(BulkMethod::Post),
        Method::PUT => Some(BulkMethod::Put),
        Method::PATCH => Some(BulkMethod::Patch),
        Method::DELETE => Some(BulkMethod::Delete),
        _ => None,
    }
}

/// `POST /Users` and `POST /Groups`.
async fn change_collection(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug)), forwarded): Context,
    uri: axum::http::Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let caller = authenticated!(state, tenant, slug, headers, forwarded);
    let target = if uri.path().ends_with("/Groups") {
        Target::Groups
    } else {
        Target::Users
    };
    let data = match body(&headers, &bytes) {
        Ok(data) => data,
        Err(failure) => return failure.response(),
    };
    let base = base(&state.public_url, &slug);
    match perform(
        &state,
        &tenant,
        &base,
        caller,
        Change {
            method: BulkMethod::Post,
            target,
            data: Some(data),
            precondition: None,
        },
    )
    .await
    {
        Ok(outcome) => outcome.response(),
        Err(failure) => failure.response(),
    }
}

/// `PUT`, `PATCH` and `DELETE` of one user or group, with `If-Match`.
async fn change_one(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug)), forwarded): Context,
    method: Method,
    uri: axum::http::Uri,
    parameters: RawPathParams,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let caller = authenticated!(state, tenant, slug, headers, forwarded);
    let Some(method) = bulk_method(&method) else {
        return Failure::not_found().response();
    };
    let id = parameter(&parameters, "id");
    let target = if uri.path().contains("/Groups/") {
        Target::Group(id)
    } else {
        Target::User(id)
    };
    let data = if method == BulkMethod::Delete {
        None
    } else {
        match body(&headers, &bytes) {
            Ok(data) => Some(data),
            Err(failure) => return failure.response(),
        }
    };
    let base = base(&state.public_url, &slug);
    match perform(
        &state,
        &tenant,
        &base,
        caller,
        Change {
            method,
            target,
            data,
            precondition: precondition(&headers, header::IF_MATCH),
        },
    )
    .await
    {
        Ok(outcome) => outcome.response(),
        Err(failure) => failure.response(),
    }
}

/// The answer to a `GET` of one resource at `version`: `304` when
/// `If-None-Match` names it.
fn read_one(headers: &HeaderMap, document: Value) -> Response {
    let outcome = done(StatusCode::OK, document);
    let unchanged = match (
        precondition(headers, header::IF_NONE_MATCH),
        outcome.version(),
    ) {
        (Some(precondition), Some(version)) => precondition.admits(version),
        _ => false,
    };
    if unchanged {
        let mut response = not_cached(StatusCode::NOT_MODIFIED.into_response());
        if let Some(version) = outcome
            .version()
            .and_then(|version| HeaderValue::from_str(version).ok())
        {
            response.headers_mut().insert(header::ETAG, version);
        }
        return response;
    }
    outcome.response()
}

async fn list_users(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug)), forwarded): Context,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers, forwarded);
    let asked = match list_query::<UserAttribute>(query.as_deref()) {
        Ok(asked) => asked,
        Err(error) => return failure(&error).response(),
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
        Err(error) => failure(&error).response(),
    }
}

async fn get_user(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug)), forwarded): Context,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers, forwarded);
    let Ok(id) = parameter(&parameters, "id").parse::<UserId>() else {
        return Failure::not_found().response();
    };
    match state.provisioning.get_user(&tenant, id).await {
        Ok(resource) => read_one(&headers, resource.document(&base(&state.public_url, &slug))),
        Err(error) => failure(&error).response(),
    }
}

async fn list_groups(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug)), forwarded): Context,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers, forwarded);
    let asked = match list_query::<GroupAttribute>(query.as_deref()) {
        Ok(asked) => asked,
        Err(error) => return failure(&error).response(),
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
        Err(error) => failure(&error).response(),
    }
}

async fn get_group(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug)), forwarded): Context,
    parameters: RawPathParams,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers, forwarded);
    let Ok(id) = parameter(&parameters, "id").parse::<GroupId>() else {
        return Failure::not_found().response();
    };
    match state.provisioning.get_group(&tenant, id).await {
        Ok(resource) => read_one(&headers, resource.document(&base(&state.public_url, &slug))),
        Err(error) => failure(&error).response(),
    }
}

/// The result of one operation of a bulk request.
fn bulk_result(method: &str, bulk_id: Option<&String>, result: &Result<Outcome, Failure>) -> Value {
    let mut entry = json!({ "method": method.to_ascii_uppercase() });
    if let Some(bulk_id) = bulk_id {
        entry["bulkId"] = json!(bulk_id);
    }
    match result {
        Ok(outcome) => {
            entry["status"] = json!(outcome.status.as_u16().to_string());
            if let Some(location) = outcome.location() {
                entry["location"] = json!(location);
            }
            if let Some(version) = outcome.version() {
                entry["version"] = json!(version);
            }
        }
        Err(failure) => {
            entry["status"] = json!(failure.status.as_u16().to_string());
            entry["response"] = failure.document();
        }
    }
    entry
}

/// `POST /Bulk`: each operation on its own, in order, with references
/// between them by `bulkId`.
async fn bulk(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug)), forwarded): Context,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let caller = authenticated!(state, tenant, slug, headers, forwarded);
    let too_large = || {
        Failure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            Some("tooMany"),
            format!("a bulk request holds at most {MAX_BULK_BYTES} bytes"),
        )
        .response()
    };
    if bytes.len() > MAX_BULK_BYTES {
        return too_large();
    }
    let value = match body(&headers, &bytes) {
        Ok(value) => value,
        Err(failure) => return failure.response(),
    };
    let request = match read_bulk(&value, bytes.len()) {
        Ok(request) => request,
        Err(error) if error.code() == TOO_MANY => {
            return Failure::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                Some("tooMany"),
                error.message(),
            )
            .response();
        }
        Err(error) => return failure(&error).response(),
    };
    let base = base(&state.public_url, &slug);
    let mut created: BTreeMap<String, String> = BTreeMap::new();
    let mut named: BTreeSet<String> = BTreeSet::new();
    let mut errors: u64 = 0;
    let mut results = Vec::with_capacity(request.operations.len());
    for operation in &request.operations {
        if request.fail_on_errors.is_some_and(|limit| errors >= limit) {
            break;
        }
        let result = async {
            let method = method_of(operation).map_err(|error| failure(&error))?;
            match &operation.bulk_id {
                Some(bulk_id) => {
                    check_bulk_id(bulk_id).map_err(|error| failure(&error))?;
                    if !named.insert(bulk_id.clone()) {
                        return Err(Failure::new(
                            StatusCode::BAD_REQUEST,
                            Some("invalidValue"),
                            format!("the bulkId {bulk_id} is used once in a request"),
                        ));
                    }
                }
                None if method == BulkMethod::Post => {
                    return Err(Failure::new(
                        StatusCode::BAD_REQUEST,
                        Some("invalidValue"),
                        "a POST of a bulk request has a bulkId",
                    ));
                }
                None => {}
            }
            let path = operation.path.as_deref().ok_or_else(|| {
                Failure::new(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "an operation has a path",
                )
            })?;
            let path = resolve_path(path, &created).map_err(|error| failure(&error))?;
            let data = operation
                .data
                .as_ref()
                .map(|data| resolve_data(data, &created))
                .transpose()
                .map_err(|error| failure(&error))?;
            let target = Target::read(&path).ok_or_else(|| {
                Failure::new(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "an operation's path is /Users, /Groups or one of their resources",
                )
            })?;
            perform(
                &state,
                &tenant,
                &base,
                caller,
                Change {
                    method,
                    target,
                    data,
                    precondition: operation.version.as_deref().map(Precondition::read),
                },
            )
            .await
        }
        .await;
        match &result {
            Ok(outcome) => {
                if let (Some(bulk_id), Some(id)) = (
                    &operation.bulk_id,
                    outcome
                        .document
                        .as_ref()
                        .and_then(|document| document["id"].as_str()),
                ) && outcome.status == StatusCode::CREATED
                {
                    created.insert(bulk_id.clone(), id.to_owned());
                }
            }
            Err(_) => errors += 1,
        }
        results.push(bulk_result(
            &operation.method,
            operation.bulk_id.as_ref(),
            &result,
        ));
    }
    scim(
        StatusCode::OK,
        &json!({ "schemas": [BULK_RESPONSE_SCHEMA], "Operations": results }),
    )
}

/// Searching with `POST`: not built yet.
async fn not_supported(
    State(state): State<ScimState>,
    (Extension(tenant), Extension(TenantSlug(slug)), forwarded): Context,
    method: Method,
    headers: HeaderMap,
) -> Response {
    authenticated!(state, tenant, slug, headers, forwarded);
    Failure::new(
        StatusCode::NOT_IMPLEMENTED,
        None,
        format!("{method} is not supported here yet"),
    )
    .response()
}

async fn no_such_route() -> Response {
    Failure::not_found().response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_carry_the_status_as_a_string_and_the_scim_type_only_where_one_is_defined() {
        let filter = failure(&DomainError::invalid(INVALID_FILTER, "too long"));
        assert_eq!(filter.status, StatusCode::BAD_REQUEST);
        assert_eq!(filter.document()["scimType"], "invalidFilter");
        let taken = failure(&DomainError::conflict("identity.identifier_taken", "taken"));
        assert_eq!(taken.status, StatusCode::CONFLICT);
        assert_eq!(taken.scim_type, Some("uniqueness"));
        let stale = failure(&DomainError::conflict(VERSION_MISMATCH, "stale"));
        assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
        assert!(stale.document().get("scimType").is_none());
        let cycle = failure(&DomainError::conflict("identity.group_cycle", "a cycle"));
        assert_eq!(cycle.status, StatusCode::CONFLICT);
        let hidden = failure(&DomainError::internal("database.error", "secret detail"));
        assert_eq!(hidden.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(hidden.detail, "the request could not be completed");
        assert_eq!(
            hidden.response().headers().get(header::CONTENT_TYPE),
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
            body(&headers, &Bytes::from_static(b"{}")).map_err(|failure| failure.status)
        };
        assert!(with(Some("application/scim+json")).is_ok());
        assert!(with(Some("application/json; charset=utf-8")).is_ok());
        assert_eq!(
            with(Some("text/plain")),
            Err(StatusCode::UNSUPPORTED_MEDIA_TYPE)
        );
        assert_eq!(with(None), Err(StatusCode::UNSUPPORTED_MEDIA_TYPE));
    }

    #[test]
    fn a_bulk_path_names_a_collection_or_one_resource() {
        assert_eq!(Target::read("/Users"), Some(Target::Users));
        assert_eq!(
            Target::read("Groups/x"),
            Some(Target::Group("x".to_owned()))
        );
        assert_eq!(Target::read("/Users/x/y"), None);
        assert_eq!(Target::read("/Elsewhere"), None);
    }
}
