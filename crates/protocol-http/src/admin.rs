//! The administration interface: users, sessions and the audit log of a
//! tenant, for the people who run it.
//!
//! Specified in `docs/api/admin-api.md`. Every request is checked before
//! anything else: the access token, whether its user may sign in, and
//! whether the user holds a role with the permission the route needs. A
//! request that is refused learns nothing about what it asked for, which
//! is why bodies and queries are read only after the check.

use crate::problem::Problem;
use crate::tenant::TenantSlug;
use axum::body::Bytes;
use axum::extract::{RawPathParams, RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, put};
use axum::{Extension, Json, Router};
use hodor_audit::api::{AuditRecord, AuditService};
use hodor_authorization::api::{AuthorizationService, Permission};
use hodor_credential::api::AccessTokenService;
use hodor_federation::api::{
    ChangeProvider, CreateProvider, FederationService, IdentityProvider, ProviderId, ProviderKind,
    ProviderSettings, ProviderStatus, callback_address,
};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, User, UserKind};
use hodor_kernel::{
    Actor, Caller, CorrelationId, Cursor, DomainError, Page, PageRequest, Secret, TenantContext,
    UserId,
};
use hodor_session::api::{Session, SessionId, SessionService};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;

/// The OpenAPI document of the interface, as served at `/openapi.json`.
pub const ADMIN_OPENAPI: &str = include_str!("../openapi/admin-v1.json");

/// Every operation of the interface with the permission it needs: method,
/// path as written in the OpenAPI document, permission. A test holds this
/// table and the document together, and every handler looks its
/// permission up here.
pub const ADMIN_OPERATIONS: &[(&str, &str, Permission)] = &[
    ("POST", "/users", Permission::UsersWrite),
    ("GET", "/users", Permission::UsersRead),
    ("GET", "/users/{user_id}", Permission::UsersRead),
    ("POST", "/users/{user_id}:suspend", Permission::UsersWrite),
    ("GET", "/users/{user_id}/sessions", Permission::SessionsRead),
    (
        "DELETE",
        "/sessions/{session_id}",
        Permission::SessionsRevoke,
    ),
    ("GET", "/audit-records", Permission::AuditRead),
    (
        "GET",
        "/identity-providers",
        Permission::IdentityProvidersRead,
    ),
    (
        "POST",
        "/identity-providers",
        Permission::IdentityProvidersWrite,
    ),
    (
        "GET",
        "/identity-providers/{provider_id}",
        Permission::IdentityProvidersRead,
    ),
    (
        "PATCH",
        "/identity-providers/{provider_id}",
        Permission::IdentityProvidersWrite,
    ),
    (
        "PUT",
        "/identity-providers/{provider_id}/client-secret",
        Permission::IdentityProvidersWrite,
    ),
    (
        "POST",
        "/identity-providers/{provider_id}:disable",
        Permission::IdentityProvidersWrite,
    ),
    (
        "POST",
        "/identity-providers/{provider_id}:enable",
        Permission::IdentityProvidersWrite,
    ),
];

/// What the administration handlers need.
#[derive(Clone)]
pub struct AdminState {
    /// Says which user an access token belongs to.
    pub tokens: AccessTokenService,
    /// Says whether a user may do something.
    pub authorization: AuthorizationService,
    /// The users.
    pub identity: IdentityService,
    /// Their sessions.
    pub sessions: SessionService,
    /// The audit log.
    pub audit: AuditService,
    /// The identity providers. `None` when this installation has no keys
    /// to keep their secrets with.
    pub federation: Option<FederationService>,
    /// The address people reach this installation at, without a path.
    pub public_url: String,
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState").finish_non_exhaustive()
    }
}

/// The routes of the administration interface, to be mounted under a
/// tenant at `/api/v1/admin`.
pub fn admin_routes(state: AdminState) -> Router {
    Router::new()
        .route("/openapi.json", get(openapi))
        .route("/users", get(list_users).post(create_user))
        // `POST /users/{user_id}:suspend` arrives here as well: the action
        // is part of the last segment.
        .route("/users/{user}", get(get_user).post(user_action))
        .route("/users/{user}/sessions", get(list_user_sessions))
        .route("/sessions/{session}", delete(revoke_session))
        .route("/audit-records", get(list_audit_records))
        .route(
            "/identity-providers",
            get(list_providers).post(create_provider),
        )
        // The two actions arrive here as well, as part of the last segment.
        .route(
            "/identity-providers/{provider}",
            get(get_provider)
                .patch(change_provider)
                .post(provider_action),
        )
        .route(
            "/identity-providers/{provider}/client-secret",
            put(change_provider_secret),
        )
        .with_state(state)
}

async fn openapi() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        ADMIN_OPENAPI,
    )
        .into_response()
}

fn problem(status: StatusCode, code: &'static str, detail: &'static str) -> Box<Response> {
    Box::new(Problem::new(status, code, detail).into_response())
}

fn failed(error: DomainError) -> Box<Response> {
    Box::new(Problem::from(error).into_response())
}

/// One answer whatever the reason: no token, a malformed one, an unknown,
/// expired or revoked one, another tenant's, or one whose user may not
/// sign in.
fn not_authenticated() -> Box<Response> {
    let mut response = problem(
        StatusCode::UNAUTHORIZED,
        "admin.not_authenticated",
        "a valid access token is required",
    );
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn forbidden() -> Box<Response> {
    problem(
        StatusCode::FORBIDDEN,
        "admin.forbidden",
        "this access token's user may not do this",
    )
}

/// The token of a request, from `Authorization: Bearer <token>`.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// Checks a request before anything else is done with it, and says who
/// makes it.
///
/// The permission is looked up by the operation's method and path, so that
/// what a route needs is written in one place. An operation that is not in
/// the table is refused.
async fn authorize(
    state: &AdminState,
    tenant: &TenantContext,
    headers: &HeaderMap,
    method: &str,
    path: &str,
) -> Result<Caller, Box<Response>> {
    let token = bearer(headers).ok_or_else(not_authenticated)?;
    let token = state
        .tokens
        .authenticate(tenant, token)
        .await
        .map_err(failed)?
        .ok_or_else(not_authenticated)?;
    let user_id = token.user_id();
    match state.identity.get(tenant, user_id).await {
        Ok(user) if user.may_sign_in() => {}
        Ok(_) => return Err(not_authenticated()),
        Err(error) if error.code() == "identity.user_not_found" => {
            return Err(not_authenticated());
        }
        Err(error) => return Err(failed(error)),
    }
    let permission = ADMIN_OPERATIONS
        .iter()
        .find(|(m, p, _)| *m == method && *p == path)
        .map(|(_, _, permission)| *permission)
        .ok_or_else(forbidden)?;
    let decision = state
        .authorization
        .check(tenant, user_id, permission)
        .await
        .map_err(failed)?;
    if !decision.is_allowed() {
        return Err(forbidden());
    }
    Ok(Caller {
        actor: Actor::User(user_id),
        correlation_id: CorrelationId::generate(),
    })
}

fn invalid_body() -> Box<Response> {
    problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        "request.body_invalid",
        "the body is not JSON of the expected shape",
    )
}

fn body<T: DeserializeOwned>(bytes: &Bytes) -> Result<T, Box<Response>> {
    serde_json::from_slice(bytes).map_err(|_| invalid_body())
}

/// The `limit` and `cursor` of a query. Neither needs decoding: a limit is
/// a number, and the cursors this interface gives out are identifiers and
/// numbers.
fn page_request(query: Option<&str>) -> Result<PageRequest, Box<Response>> {
    let invalid = || {
        problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.query_invalid",
            "limit must be a number from 1 to 200",
        )
    };
    let (mut limit, mut cursor) = (None, None);
    for (name, value) in query
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
    {
        match name {
            "limit" => {
                let asked: u32 = value.parse().map_err(|_| invalid())?;
                if !(1..=PageRequest::MAX_LIMIT).contains(&asked) {
                    return Err(invalid());
                }
                limit = Some(asked);
            }
            "cursor" => cursor = Some(Cursor::new(value)),
            _ => {}
        }
    }
    Ok(PageRequest::new(limit, cursor))
}

fn parameter<T: std::str::FromStr>(parameters: &RawPathParams, name: &str) -> Option<T> {
    parameters
        .iter()
        .find(|(key, _)| *key == name)
        .and_then(|(_, value)| value.parse().ok())
}

fn user_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "identity.user_not_found",
        "the user does not exist",
    ))
}

fn written(moment: time::OffsetDateTime) -> String {
    moment.format(&Rfc3339).unwrap_or_default()
}

fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Serialize)]
struct IdentifierBody {
    id: String,
    kind: &'static str,
    value: String,
    verified: bool,
    primary: bool,
}

#[derive(Debug, Serialize)]
struct UserBody {
    id: String,
    kind: &'static str,
    status: &'static str,
    status_reason: Option<String>,
    display_name: Option<String>,
    locale: Option<String>,
    identifiers: Vec<IdentifierBody>,
    created_at: String,
    updated_at: String,
}

impl From<&User> for UserBody {
    fn from(user: &User) -> Self {
        let state = user.snapshot();
        Self {
            id: state.id.to_string(),
            kind: state.kind.as_str(),
            status: state.status.as_str(),
            status_reason: state.status_reason.clone(),
            display_name: state.profile.display_name.clone(),
            locale: state.profile.locale.clone(),
            identifiers: state
                .identifiers
                .iter()
                .map(|identifier| IdentifierBody {
                    id: identifier.id.to_string(),
                    kind: identifier.value.kind().as_str(),
                    value: identifier.value.display().to_owned(),
                    verified: identifier.verified_at.is_some(),
                    primary: identifier.primary,
                })
                .collect(),
            created_at: written(state.created_at),
            updated_at: written(state.updated_at),
        }
    }
}

#[derive(Debug, Serialize)]
struct SessionBody {
    session_id: String,
    started_at: String,
    last_activity_at: String,
    expires_at: String,
    address: Option<String>,
    description: Option<String>,
}

impl From<&Session> for SessionBody {
    fn from(session: &Session) -> Self {
        let state = session.snapshot();
        Self {
            session_id: state.id.to_string(),
            started_at: written(state.started_at),
            last_activity_at: written(state.last_activity_at),
            expires_at: written(session.expires_at()),
            address: state.client.address.clone(),
            description: state.client.description.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct AuditRecordBody {
    sequence: u64,
    action: String,
    occurred_at: String,
    recorded_at: String,
    actor: Actor,
    correlation_id: String,
    details: serde_json::Value,
    previous_hash: String,
    hash: String,
}

impl From<AuditRecord> for AuditRecordBody {
    fn from(record: AuditRecord) -> Self {
        Self {
            sequence: record.sequence,
            action: record.action,
            occurred_at: written(record.occurred_at),
            recorded_at: written(record.recorded_at),
            actor: record.actor,
            correlation_id: record.correlation_id.to_string(),
            details: record.details,
            previous_hash: hexadecimal(&record.previous_hash),
            hash: hexadecimal(&record.hash),
        }
    }
}

#[derive(Debug, Serialize)]
struct PageBody<T> {
    items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

impl<T> From<Page<T>> for PageBody<T> {
    fn from(page: Page<T>) -> Self {
        Self {
            items: page.items,
            next_cursor: page.next_cursor.map(|cursor| cursor.as_str().to_owned()),
        }
    }
}

#[derive(Deserialize)]
struct NewUserBody {
    email: String,
    display_name: Option<String>,
    locale: Option<String>,
}

#[derive(Deserialize)]
struct SuspensionBody {
    reason: String,
}

/// Turns the two-step shape of every handler, check and then act, into
/// one response.
fn respond(result: Result<Response, Box<Response>>) -> Response {
    result.unwrap_or_else(|response| *response)
}

async fn create_user(
    State(state): State<AdminState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "POST", "/users").await?;
            let new: NewUserBody = body(&bytes)?;
            let command = CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, new.email)],
                profile: Profile {
                    display_name: new.display_name,
                    locale: new.locale,
                },
                // Created by an administrator, so already confirmed. The
                // address is verified when the person first recovers the
                // password, which is also how they get one.
                confirmed: true,
            };
            let user = state
                .identity
                .create(&tenant, command, caller)
                .await
                .map_err(failed)?;
            Ok((StatusCode::CREATED, Json(UserBody::from(&user))).into_response())
        }
        .await,
    )
}

async fn list_users(
    State(state): State<AdminState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/users").await?;
            let page = page_request(query.as_deref())?;
            let users = state.identity.list(&tenant, &page).await.map_err(failed)?;
            let body: PageBody<UserBody> = users.map(|user| UserBody::from(&user)).into();
            Ok(Json(body).into_response())
        }
        .await,
    )
}

async fn get_user(
    State(state): State<AdminState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/users/{user_id}").await?;
            let id: UserId = parameter(&parameters, "user").ok_or_else(user_not_found)?;
            let user = state.identity.get(&tenant, id).await.map_err(failed)?;
            Ok(Json(UserBody::from(&user)).into_response())
        }
        .await,
    )
}

/// `POST /users/{user_id}:suspend`. The action is part of the last
/// segment of the path; no other action exists yet.
async fn user_action(
    State(state): State<AdminState>,
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
                "/users/{user_id}:suspend",
            )
            .await?;
            let segment: String = parameter(&parameters, "user").ok_or_else(user_not_found)?;
            let Some(id) = segment.strip_suffix(":suspend") else {
                return Err(problem(
                    StatusCode::NOT_FOUND,
                    "route.not_found",
                    "there is no such action on a user",
                ));
            };
            let id: UserId = id.parse().map_err(|_| user_not_found())?;
            let suspension: SuspensionBody = body(&bytes)?;
            let user = state
                .identity
                .suspend(&tenant, id, &suspension.reason, caller)
                .await
                .map_err(failed)?;
            Ok(Json(UserBody::from(&user)).into_response())
        }
        .await,
    )
}

async fn list_user_sessions(
    State(state): State<AdminState>,
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
                "/users/{user_id}/sessions",
            )
            .await?;
            let id: UserId = parameter(&parameters, "user").ok_or_else(user_not_found)?;
            // A user that does not exist has no sessions to list.
            state.identity.get(&tenant, id).await.map_err(failed)?;
            let sessions = state
                .sessions
                .list_for_user(&tenant, id)
                .await
                .map_err(failed)?;
            let body = PageBody {
                items: sessions.iter().map(SessionBody::from).collect(),
                next_cursor: None,
            };
            Ok(Json(body).into_response())
        }
        .await,
    )
}

async fn revoke_session(
    State(state): State<AdminState>,
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
                "/sessions/{session_id}",
            )
            .await?;
            let not_found = || {
                failed(DomainError::not_found(
                    "session.not_found",
                    "the session does not exist",
                ))
            };
            let id: SessionId = parameter(&parameters, "session").ok_or_else(not_found)?;
            state
                .sessions
                .revoke(&tenant, id, "revoked_by_administrator", caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

async fn list_audit_records(
    State(state): State<AdminState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/audit-records").await?;
            let page = page_request(query.as_deref())?;
            let records = state.audit.page(&tenant, &page).await.map_err(failed)?;
            let body: PageBody<AuditRecordBody> = records.map(AuditRecordBody::from).into();
            Ok(Json(body).into_response())
        }
        .await,
    )
}

#[derive(Debug, Serialize)]
struct ProviderBody {
    id: String,
    alias: String,
    kind: &'static str,
    display_name: String,
    issuer: String,
    client_id: String,
    scopes: Vec<String>,
    creates_users: bool,
    trusts_email: bool,
    status: &'static str,
    callback_address: String,
    created_at: String,
    updated_at: String,
}

/// A provider as an administrator reads it. There is no field for the
/// client secret, so there is no way for one to be written out.
fn provider_body(provider: &IdentityProvider, public_url: &str, slug: &str) -> ProviderBody {
    let state = provider.snapshot();
    ProviderBody {
        id: state.id.to_string(),
        alias: state.alias.as_str().to_owned(),
        kind: state.kind.as_str(),
        display_name: state.settings.display_name.clone(),
        issuer: state.settings.issuer.clone(),
        client_id: state.settings.client_id.clone(),
        scopes: state.settings.scopes.clone(),
        creates_users: state.settings.creates_users,
        trusts_email: state.settings.trusts_email,
        status: state.status.as_str(),
        callback_address: callback_address(public_url, slug, state.alias.as_str()),
        created_at: written(state.created_at),
        updated_at: written(state.updated_at),
    }
}

#[derive(Debug, Serialize)]
struct ProvidersBody {
    items: Vec<ProviderBody>,
}

/// No `Debug`: this holds a client secret until it is sealed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewProviderBody {
    alias: String,
    kind: Option<String>,
    display_name: String,
    issuer: Option<String>,
    client_id: String,
    client_secret: String,
    scopes: Option<Vec<String>>,
    creates_users: Option<bool>,
    trusts_email: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderChangesBody {
    display_name: Option<String>,
    issuer: Option<String>,
    client_id: Option<String>,
    scopes: Option<Vec<String>>,
    creates_users: Option<bool>,
    trusts_email: Option<bool>,
}

/// No `Debug`: this holds a client secret until it is sealed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientSecretBody {
    client_secret: String,
}

fn provider_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "federation.provider_not_found",
        "there is no such identity provider",
    ))
}

/// The federation use cases, or the answer of an installation that has
/// no keys to keep secrets with.
fn federation(state: &AdminState) -> Result<&FederationService, Box<Response>> {
    state.federation.as_ref().ok_or_else(|| {
        problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "federation.not_configured",
            "this installation is not set up to keep the secrets of identity providers",
        )
    })
}

async fn list_providers(
    State(state): State<AdminState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/identity-providers").await?;
            let providers = federation(&state)?
                .providers(&tenant)
                .await
                .map_err(failed)?;
            let items = providers
                .iter()
                .map(|provider| provider_body(provider, &state.public_url, &slug))
                .collect();
            Ok(Json(ProvidersBody { items }).into_response())
        }
        .await,
    )
}

async fn create_provider(
    State(state): State<AdminState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller =
                authorize(&state, &tenant, &headers, "POST", "/identity-providers").await?;
            let new: NewProviderBody = body(&bytes)?;
            let kind = match new.kind.as_deref() {
                None | Some("openid_connect") => ProviderKind::OpenIdConnect,
                Some("github") => ProviderKind::GitHub,
                Some(_) => {
                    return Err(failed(DomainError::invalid(
                        "federation.kind_invalid",
                        "an identity provider is of the kind `openid_connect` or `github`",
                    )));
                }
            };
            // Only a kind that has an issuer of its own may leave it out.
            let issuer = new
                .issuer
                .or_else(|| ProviderSettings::default_issuer_for(kind).map(str::to_owned))
                .unwrap_or_default();
            let command = CreateProvider {
                alias: new.alias,
                kind,
                settings: ProviderSettings {
                    display_name: new.display_name,
                    issuer,
                    client_id: new.client_id,
                    scopes: new
                        .scopes
                        .unwrap_or_else(|| ProviderSettings::default_scopes_for(kind)),
                    creates_users: new.creates_users.unwrap_or(true),
                    trusts_email: new.trusts_email.unwrap_or(false),
                    directory: None,
                },
                client_secret: Secret::from(new.client_secret),
            };
            let provider = federation(&state)?
                .create_provider(&tenant, command, caller)
                .await
                .map_err(failed)?;
            let body = provider_body(&provider, &state.public_url, &slug);
            Ok((StatusCode::CREATED, Json(body)).into_response())
        }
        .await,
    )
}

async fn get_provider(
    State(state): State<AdminState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/identity-providers/{provider_id}";
            authorize(&state, &tenant, &headers, "GET", operation).await?;
            let id: ProviderId =
                parameter(&parameters, "provider").ok_or_else(provider_not_found)?;
            let provider = federation(&state)?
                .provider(&tenant, id)
                .await
                .map_err(failed)?;
            Ok(Json(provider_body(&provider, &state.public_url, &slug)).into_response())
        }
        .await,
    )
}

async fn change_provider(
    State(state): State<AdminState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/identity-providers/{provider_id}";
            let caller = authorize(&state, &tenant, &headers, "PATCH", operation).await?;
            let id: ProviderId =
                parameter(&parameters, "provider").ok_or_else(provider_not_found)?;
            let changes: ProviderChangesBody = body(&bytes)?;
            let federation = federation(&state)?;
            // What is left out stays as it is.
            let current = federation.provider(&tenant, id).await.map_err(failed)?;
            let now = current.snapshot().settings.clone();
            let settings = ProviderSettings {
                display_name: changes.display_name.unwrap_or(now.display_name),
                issuer: changes.issuer.unwrap_or(now.issuer),
                client_id: changes.client_id.unwrap_or(now.client_id),
                scopes: changes.scopes.unwrap_or(now.scopes),
                creates_users: changes.creates_users.unwrap_or(now.creates_users),
                trusts_email: changes.trusts_email.unwrap_or(now.trusts_email),
                // A directory's own settings are not changed here.
                directory: now.directory,
            };
            let provider = federation
                .change_provider(&tenant, ChangeProvider { id, settings }, caller)
                .await
                .map_err(failed)?;
            Ok(Json(provider_body(&provider, &state.public_url, &slug)).into_response())
        }
        .await,
    )
}

async fn change_provider_secret(
    State(state): State<AdminState>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/identity-providers/{provider_id}/client-secret";
            let caller = authorize(&state, &tenant, &headers, "PUT", operation).await?;
            let id: ProviderId =
                parameter(&parameters, "provider").ok_or_else(provider_not_found)?;
            let new: ClientSecretBody = body(&bytes)?;
            federation(&state)?
                .change_provider_secret(&tenant, id, &Secret::from(new.client_secret), caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

/// `POST /identity-providers/{provider_id}:disable` and `:enable`. The
/// action is part of the last segment of the path.
async fn provider_action(
    State(state): State<AdminState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let segment: String =
                parameter(&parameters, "provider").ok_or_else(provider_not_found)?;
            let (id, status, operation) = if let Some(id) = segment.strip_suffix(":disable") {
                (
                    id,
                    ProviderStatus::Disabled,
                    "/identity-providers/{provider_id}:disable",
                )
            } else if let Some(id) = segment.strip_suffix(":enable") {
                (
                    id,
                    ProviderStatus::Enabled,
                    "/identity-providers/{provider_id}:enable",
                )
            } else {
                // Checked like the others before it is answered, so that
                // a caller without a token learns nothing about paths.
                authorize(
                    &state,
                    &tenant,
                    &headers,
                    "POST",
                    "/identity-providers/{provider_id}:disable",
                )
                .await?;
                return Err(problem(
                    StatusCode::NOT_FOUND,
                    "route.not_found",
                    "there is no such action on an identity provider",
                ));
            };
            let caller = authorize(&state, &tenant, &headers, "POST", operation).await?;
            let id: ProviderId = id.parse().map_err(|_| provider_not_found())?;
            let provider = federation(&state)?
                .set_provider_status(&tenant, id, status, caller)
                .await
                .map_err(failed)?;
            Ok(Json(provider_body(&provider, &state.public_url, &slug)).into_response())
        }
        .await,
    )
}
