//! The administration interface: users, sessions, the audit log, identity
//! providers and keys of a tenant, for the people who run it.
//!
//! The same routes are served twice. The administration interface, for
//! programs, knows who is asking by an access token; the console
//! interface, for the admin console, by the person's session. The
//! handlers and the table of permissions are the same for both.
//!
//! Specified in `docs/api/admin-api.md` and `docs/api/console-interface.md`.
//! Applications, clients and resource servers are in [`applications`].
//! Every request is checked before
//! anything else: the access token, whether its user may sign in, and
//! whether the user holds a role with the permission the route needs. A
//! request that is refused learns nothing about what it asked for, which
//! is why bodies and queries are read only after the check.

use crate::interaction::{
    CSRF_HEADER, SESSION_COOKIE, cookie, csrf_token, refuse_other_origins, same,
};
use crate::problem::Problem;
use crate::tenant::TenantSlug;
use axum::body::Bytes;
use axum::extract::{RawPathParams, RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, put};
use axum::{Extension, Json, Router, middleware};
use hodor_audit::api::{AuditRecord, AuditService};
use hodor_authorization::api::{AuthorizationService, Permission};
use hodor_credential::api::AccessTokenService;
use hodor_federation::api::{
    ChangeProvider, CreateProvider, DirectorySettings, FederationService, IdentityProvider,
    ProviderId, ProviderKind, ProviderSettings, ProviderStatus, SamlSettings, callback_address,
    saml_metadata_address,
};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, User, UserKind};
use hodor_kernel::{
    Actor, Caller, Clock, CorrelationId, Cursor, Digest, DomainError, Page, PageRequest, Secret,
    TenantContext, UserId,
};
use hodor_keys::api::{KeyAlgorithm, KeyService, KeyUse, KeyVersion, KeyVersionId, RotationPolicy};
use hodor_oauth::api::ApplicationService;
use hodor_session::api::{Session, SessionId, SessionService};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

mod applications;

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
    ("GET", "/keys/{key_set}", Permission::KeysRead),
    ("POST", "/keys/{key_set}:rotate", Permission::KeysWrite),
    (
        "POST",
        "/keys/{key_set}/versions/{version_id}:revoke",
        Permission::KeysWrite,
    ),
    ("GET", "/applications", Permission::ApplicationsRead),
    ("POST", "/applications", Permission::ApplicationsWrite),
    (
        "GET",
        "/applications/{application_id}",
        Permission::ApplicationsRead,
    ),
    (
        "PATCH",
        "/applications/{application_id}",
        Permission::ApplicationsWrite,
    ),
    (
        "POST",
        "/applications/{application_id}:disable",
        Permission::ApplicationsWrite,
    ),
    (
        "POST",
        "/applications/{application_id}:enable",
        Permission::ApplicationsWrite,
    ),
    (
        "GET",
        "/applications/{application_id}/clients",
        Permission::ApplicationsRead,
    ),
    (
        "POST",
        "/applications/{application_id}/clients",
        Permission::ApplicationsWrite,
    ),
    ("GET", "/clients/{client_id}", Permission::ApplicationsRead),
    (
        "PATCH",
        "/clients/{client_id}",
        Permission::ApplicationsWrite,
    ),
    (
        "POST",
        "/clients/{client_id}:disable",
        Permission::ApplicationsWrite,
    ),
    (
        "POST",
        "/clients/{client_id}:enable",
        Permission::ApplicationsWrite,
    ),
    (
        "POST",
        "/clients/{client_id}/secrets",
        Permission::ApplicationsWrite,
    ),
    (
        "DELETE",
        "/clients/{client_id}/secrets/{secret_id}",
        Permission::ApplicationsWrite,
    ),
    (
        "POST",
        "/clients/{client_id}/keys",
        Permission::ApplicationsWrite,
    ),
    (
        "DELETE",
        "/clients/{client_id}/keys/{key_id}",
        Permission::ApplicationsWrite,
    ),
    ("GET", "/resource-servers", Permission::ApplicationsRead),
    ("POST", "/resource-servers", Permission::ApplicationsWrite),
    (
        "GET",
        "/resource-servers/{resource_server_id}",
        Permission::ApplicationsRead,
    ),
    (
        "PATCH",
        "/resource-servers/{resource_server_id}",
        Permission::ApplicationsWrite,
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
    /// The tenants' keys. `None` when this installation has no keys to
    /// wrap them with.
    pub keys: Option<KeyService>,
    /// How long a replaced signing key stays when it is rotated by hand.
    pub key_rotation: RotationPolicy,
    /// The applications, their clients and resource servers.
    pub applications: ApplicationService,
    /// The address people reach this installation at, without a path.
    pub public_url: String,
}

/// What the console interface needs on top of the administration
/// interface: it recognizes a person by their session.
#[derive(Clone)]
pub struct ConsoleState {
    /// Everything the shared handlers need.
    pub administration: AdminState,
    /// For deriving the CSRF token from a session's token.
    pub digest: Arc<dyn Digest>,
    /// For telling how old a sign-in is.
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ConsoleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsoleState").finish_non_exhaustive()
    }
}

/// How long after a sign-in the console interface still answers for it,
/// whatever the tenant allows its users.
pub const CONSOLE_SESSION_HOURS: i64 = 12;

/// How the console interface knows who is asking.
#[derive(Clone)]
struct BySession {
    digest: Arc<dyn Digest>,
    clock: Arc<dyn Clock>,
}

/// The state of the handlers: the same for both interfaces, with the way
/// the console interface recognizes a person when it is the one mounted.
#[derive(Clone)]
struct Shared {
    administration: AdminState,
    by_session: Option<BySession>,
}

impl std::ops::Deref for Shared {
    type Target = AdminState;

    fn deref(&self) -> &AdminState {
        &self.administration
    }
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState").finish_non_exhaustive()
    }
}

fn shared_routes() -> Router<Shared> {
    Router::new()
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
        // `POST /keys/{key_set}:rotate` arrives here as well, as part of
        // the last segment; so does `:revoke` on a version.
        .route(
            "/keys/{key_set}",
            get(list_key_versions).post(key_set_action),
        )
        .route(
            "/keys/{key_set}/versions/{version}",
            axum::routing::post(key_version_action),
        )
        .merge(applications::routes())
}

/// The routes of the administration interface, to be mounted under a
/// tenant at `/api/v1/admin`.
pub fn admin_routes(state: AdminState) -> Router {
    shared_routes()
        .route("/openapi.json", get(openapi))
        .with_state(Shared {
            administration: state,
            by_session: None,
        })
}

/// The routes of the console interface, to be mounted under a tenant at
/// `/console/api`: those of the administration interface, and `/me`.
pub fn console_routes(state: ConsoleState) -> Router {
    shared_routes()
        .route("/me", get(me))
        // Cookies are sent by the browser whoever asks, so a request that
        // changes something must come from this origin.
        .layer(middleware::from_fn(refuse_other_origins))
        .with_state(Shared {
            administration: state.administration,
            by_session: Some(BySession {
                digest: state.digest,
                clock: state.clock,
            }),
        })
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
    state: &Shared,
    tenant: &TenantContext,
    headers: &HeaderMap,
    method: &str,
    path: &str,
) -> Result<Caller, Box<Response>> {
    let user_id = match &state.by_session {
        None => by_token(state, tenant, headers).await?,
        Some(by_session) => {
            let person = by_session
                .recognize(state, tenant, headers, method != "GET")
                .await?;
            person.session.user_id()
        }
    };
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

/// Who an access token belongs to, if it is good and its user may sign in.
async fn by_token(
    state: &AdminState,
    tenant: &TenantContext,
    headers: &HeaderMap,
) -> Result<UserId, Box<Response>> {
    let token = bearer(headers).ok_or_else(not_authenticated)?;
    let token = state
        .tokens
        .authenticate(tenant, token)
        .await
        .map_err(failed)?
        .ok_or_else(not_authenticated)?;
    let user_id = token.user_id();
    match state.identity.get(tenant, user_id).await {
        Ok(user) if user.may_sign_in() => Ok(user_id),
        Ok(_) => Err(not_authenticated()),
        Err(error) if error.code() == "identity.user_not_found" => Err(not_authenticated()),
        Err(error) => Err(failed(error)),
    }
}

/// One answer whatever the reason: no session, an unknown, expired or
/// ended one, a sign-in too old for the console, or a user who may not
/// sign in.
fn console_not_authenticated() -> Box<Response> {
    problem(
        StatusCode::UNAUTHORIZED,
        "console.not_authenticated",
        "sign in to use the console",
    )
}

/// A person the console interface recognized by their session.
struct Person {
    session: Session,
    user: User,
    csrf_token: String,
    /// When the console stops answering for this sign-in.
    console_until: time::OffsetDateTime,
}

impl BySession {
    /// Says who a request comes from, by its session cookie. A request
    /// that changes something must also carry the session's CSRF token.
    async fn recognize(
        &self,
        state: &AdminState,
        tenant: &TenantContext,
        headers: &HeaderMap,
        changes_something: bool,
    ) -> Result<Person, Box<Response>> {
        let token = cookie(headers, SESSION_COOKIE).ok_or_else(console_not_authenticated)?;
        let session = state
            .sessions
            .find_by_token(tenant, token)
            .await
            .map_err(failed)?
            .ok_or_else(console_not_authenticated)?;
        let limit = session.snapshot().signed_in_at + time::Duration::hours(CONSOLE_SESSION_HOURS);
        if self.clock.now() >= limit {
            return Err(console_not_authenticated());
        }
        let user = match state.identity.get(tenant, session.user_id()).await {
            Ok(user) if user.may_sign_in() => user,
            Ok(_) => return Err(console_not_authenticated()),
            Err(error) if error.code() == "identity.user_not_found" => {
                return Err(console_not_authenticated());
            }
            Err(error) => return Err(failed(error)),
        };
        let csrf_token = csrf_token(self.digest.as_ref(), token);
        if changes_something {
            let presented = headers
                .get(CSRF_HEADER)
                .and_then(|value| value.to_str().ok());
            if !presented.is_some_and(|presented| same(presented, &csrf_token)) {
                return Err(problem(
                    StatusCode::FORBIDDEN,
                    "request.csrf_token_invalid",
                    "the request is missing its CSRF token, or the token is wrong",
                ));
            }
        }
        let console_until = limit.min(session.expires_at());
        Ok(Person {
            session,
            user,
            csrf_token,
            console_until,
        })
    }
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

#[derive(Debug, Serialize)]
struct MeBody {
    user: UserBody,
    roles: Vec<&'static str>,
    permissions: Vec<&'static str>,
    signed_in_at: String,
    console_until: String,
    csrf_token: String,
}

/// `GET /me`, on the console interface only: who the person is and what
/// they may do. It needs a session and no permission, so that the console
/// can tell a person without a role that they have no access.
async fn me(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            let by_session = state.by_session.as_ref().ok_or_else(forbidden)?;
            let person = by_session
                .recognize(&state, &tenant, &headers, false)
                .await?;
            let roles = state
                .authorization
                .roles_of(&tenant, person.user.id())
                .await
                .map_err(failed)?;
            let permissions = Permission::ALL
                .into_iter()
                .filter(|permission| roles.iter().any(|role| role.allows(*permission)))
                .map(Permission::as_str)
                .collect();
            Ok(Json(MeBody {
                user: UserBody::from(&person.user),
                roles: roles.iter().map(|role| role.as_str()).collect(),
                permissions,
                signed_in_at: written(person.session.snapshot().signed_in_at),
                console_until: written(person.console_until),
                csrf_token: person.csrf_token,
            })
            .into_response())
        }
        .await,
    )
}

/// Turns the two-step shape of every handler, check and then act, into
/// one response.
fn respond(result: Result<Response, Box<Response>>) -> Response {
    result.unwrap_or_else(|response| *response)
}

async fn create_user(
    State(state): State<Shared>,
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
    State(state): State<Shared>,
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
    State(state): State<Shared>,
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
    State(state): State<Shared>,
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
    callback_address: Option<String>,
    directory: Option<DirectoryBody>,
    saml: Option<SamlBody>,
    metadata_address: Option<String>,
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
        // Nobody leaves for a directory, so nobody comes back from one. A
        // SAML provider is given Hodor's metadata instead.
        callback_address: (!matches!(state.kind, ProviderKind::Ldap | ProviderKind::Saml))
            .then(|| callback_address(public_url, slug, state.alias.as_str())),
        directory: state
            .settings
            .directory
            .as_ref()
            .map(|directory| DirectoryBody {
                base: directory.base.clone(),
                filter: directory.filter.clone(),
                subject_attribute: directory.subject_attribute.clone(),
                email_attribute: directory.email_attribute.clone(),
                name_attribute: directory.name_attribute.clone(),
            }),
        saml: state.settings.saml.as_ref().map(|saml| SamlBody {
            single_sign_on_address: saml.single_sign_on_address.clone(),
            certificate: saml.certificate.clone(),
            email_attribute: saml.email_attribute.clone(),
            name_attribute: saml.name_attribute.clone(),
        }),
        metadata_address: (state.kind == ProviderKind::Saml)
            .then(|| saml_metadata_address(public_url, slug, state.alias.as_str())),
        created_at: written(state.created_at),
        updated_at: written(state.updated_at),
    }
}

/// What only a directory has, as an administrator reads and writes it.
#[derive(Debug, Serialize)]
struct DirectoryBody {
    base: String,
    filter: String,
    subject_attribute: String,
    email_attribute: String,
    name_attribute: String,
}

/// A directory's settings as given: what is left out is the usual, or,
/// in a change, what it was.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryInput {
    base: Option<String>,
    filter: Option<String>,
    subject_attribute: Option<String>,
    email_attribute: Option<String>,
    name_attribute: Option<String>,
}

impl DirectoryInput {
    /// These settings laid over `on`.
    fn over(self, on: DirectorySettings) -> DirectorySettings {
        DirectorySettings {
            base: self.base.unwrap_or(on.base),
            filter: self.filter.unwrap_or(on.filter),
            subject_attribute: self.subject_attribute.unwrap_or(on.subject_attribute),
            email_attribute: self.email_attribute.unwrap_or(on.email_attribute),
            name_attribute: self.name_attribute.unwrap_or(on.name_attribute),
        }
    }
}

/// What only a SAML identity provider has, as an administrator reads it.
#[derive(Debug, Serialize)]
struct SamlBody {
    single_sign_on_address: String,
    certificate: String,
    email_attribute: String,
    name_attribute: String,
}

/// A SAML identity provider's settings as given: what is left out is the
/// usual, or, in a change, what it was.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SamlInput {
    single_sign_on_address: Option<String>,
    certificate: Option<String>,
    email_attribute: Option<String>,
    name_attribute: Option<String>,
}

impl SamlInput {
    /// These settings laid over `on`.
    fn over(self, on: SamlSettings) -> SamlSettings {
        SamlSettings {
            single_sign_on_address: self
                .single_sign_on_address
                .unwrap_or(on.single_sign_on_address),
            certificate: self.certificate.unwrap_or(on.certificate),
            email_attribute: self.email_attribute.unwrap_or(on.email_attribute),
            name_attribute: self.name_attribute.unwrap_or(on.name_attribute),
        }
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
    /// None for a SAML provider.
    #[serde(default)]
    client_id: String,
    /// None for a SAML provider.
    #[serde(default)]
    client_secret: String,
    scopes: Option<Vec<String>>,
    creates_users: Option<bool>,
    trusts_email: Option<bool>,
    directory: Option<DirectoryInput>,
    saml: Option<SamlInput>,
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
    directory: Option<DirectoryInput>,
    saml: Option<SamlInput>,
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
    State(state): State<Shared>,
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
    State(state): State<Shared>,
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
                Some("ldap") => ProviderKind::Ldap,
                Some("saml") => ProviderKind::Saml,
                Some(_) => {
                    return Err(failed(DomainError::invalid(
                        "federation.kind_invalid",
                        "an identity provider is of the kind `openid_connect`, `github`, `ldap` or `saml`",
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
                    // Given for a SAML provider, laid over the usual
                    // attribute names; for any other kind it is refused.
                    saml: new
                        .saml
                        .map(|given| given.over(SamlSettings::new("", ""))),
                    display_name: new.display_name,
                    issuer,
                    client_id: new.client_id,
                    scopes: new
                        .scopes
                        .unwrap_or_else(|| ProviderSettings::default_scopes_for(kind)),
                    creates_users: new.creates_users.unwrap_or(true),
                    trusts_email: new.trusts_email.unwrap_or(false),
                    // Given for a directory, laid over the usual names;
                    // for any other kind it is refused when given.
                    directory: new
                        .directory
                        .map(|given| given.over(DirectorySettings::new("", ""))),
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
    State(state): State<Shared>,
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
    State(state): State<Shared>,
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
                saml: match (changes.saml, now.saml) {
                    (Some(given), Some(was)) => Some(given.over(was)),
                    (Some(given), None) => Some(given.over(SamlSettings::new("", ""))),
                    (None, was) => was,
                },
                display_name: changes.display_name.unwrap_or(now.display_name),
                issuer: changes.issuer.unwrap_or(now.issuer),
                client_id: changes.client_id.unwrap_or(now.client_id),
                scopes: changes.scopes.unwrap_or(now.scopes),
                creates_users: changes.creates_users.unwrap_or(now.creates_users),
                trusts_email: changes.trusts_email.unwrap_or(now.trusts_email),
                directory: match (changes.directory, now.directory) {
                    (Some(given), Some(was)) => Some(given.over(was)),
                    (Some(given), None) => Some(given.over(DirectorySettings::new("", ""))),
                    (None, was) => was,
                },
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
    State(state): State<Shared>,
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
    State(state): State<Shared>,
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

fn keys(state: &AdminState) -> Result<&KeyService, Box<Response>> {
    state.keys.as_ref().ok_or_else(|| {
        problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "keys.not_configured",
            "this installation is not set up to keep keys",
        )
    })
}

fn key_set_not_found() -> Box<Response> {
    problem(
        StatusCode::NOT_FOUND,
        "keys.key_set_not_found",
        "there is no such key set: it is sig or data",
    )
}

fn key_version_not_found() -> Box<Response> {
    problem(
        StatusCode::NOT_FOUND,
        "keys.version_not_found",
        "the key version does not exist",
    )
}

/// The key set named by the path: `sig` or `data`.
fn key_use(name: &str) -> Result<KeyUse, Box<Response>> {
    match name {
        "sig" => Ok(KeyUse::Signing),
        "data" => Ok(KeyUse::Data),
        _ => Err(key_set_not_found()),
    }
}

/// A key version, without anything of its key: the published key set is
/// where public keys are read.
#[derive(Debug, Serialize)]
struct KeyVersionBody {
    id: String,
    key_use: &'static str,
    algorithm: &'static str,
    state: &'static str,
    provider: String,
    created_at: String,
    activated_at: Option<String>,
    retiring_at: Option<String>,
    retire_after: Option<String>,
    retired_at: Option<String>,
    revoked_at: Option<String>,
    revocation_reason: Option<String>,
}

impl From<&KeyVersion> for KeyVersionBody {
    fn from(version: &KeyVersion) -> Self {
        let state = version.snapshot();
        Self {
            id: state.id.to_string(),
            key_use: version.key_use().as_str(),
            algorithm: state.algorithm.as_str(),
            state: state.state.as_str(),
            provider: state.provider.clone(),
            created_at: written(state.created_at),
            activated_at: state.activated_at.map(written),
            retiring_at: state.retiring_at.map(written),
            retire_after: state.retire_after.map(written),
            retired_at: state.retired_at.map(written),
            revoked_at: state.revoked_at.map(written),
            revocation_reason: state.revocation_reason.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct KeyVersionsBody {
    items: Vec<KeyVersionBody>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateBody {
    algorithm: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    reason: String,
}

async fn list_key_versions(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/keys/{key_set}").await?;
            let keys = keys(&state)?;
            let name: String = parameter(&parameters, "key_set").ok_or_else(key_set_not_found)?;
            let key_use = key_use(&name)?;
            let set = keys.key_set(&tenant, key_use).await.map_err(failed)?;
            let items = set.versions().iter().map(KeyVersionBody::from).collect();
            Ok(Json(KeyVersionsBody { items }).into_response())
        }
        .await,
    )
}

async fn key_set_action(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            // Checked before the action is read, so that a caller without a
            // token learns nothing about paths.
            let caller =
                authorize(&state, &tenant, &headers, "POST", "/keys/{key_set}:rotate").await?;
            let keys = keys(&state)?;
            let segment: String =
                parameter(&parameters, "key_set").ok_or_else(key_set_not_found)?;
            let Some(name) = segment.strip_suffix(":rotate") else {
                return Err(problem(
                    StatusCode::NOT_FOUND,
                    "route.not_found",
                    "there is no such action on a key set",
                ));
            };
            if key_use(name)? != KeyUse::Signing {
                return Err(problem(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "keys.rotation_not_offered",
                    "only the signing key set is rotated by hand",
                ));
            }
            let asked: RotateBody = if bytes.is_empty() {
                RotateBody::default()
            } else {
                body(&bytes)?
            };
            let algorithm = match asked.algorithm.as_deref() {
                None => KeyAlgorithm::DEFAULT_SIGNING,
                Some(name) => KeyAlgorithm::from_name(name).ok_or_else(|| {
                    problem(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "keys.algorithm_unsuitable",
                        "the algorithm does not sign: ES256, RS256 or PS256",
                    )
                })?,
            };
            let version = keys
                .rotate_now(&tenant, algorithm, &state.key_rotation, caller)
                .await
                .map_err(failed)?;
            Ok(Json(KeyVersionBody::from(&version)).into_response())
        }
        .await,
    )
}

async fn key_version_action(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/keys/{key_set}/versions/{version_id}:revoke";
            let caller = authorize(&state, &tenant, &headers, "POST", operation).await?;
            let keys = keys(&state)?;
            let name: String = parameter(&parameters, "key_set").ok_or_else(key_set_not_found)?;
            let key_use = key_use(&name)?;
            let segment: String =
                parameter(&parameters, "version").ok_or_else(key_version_not_found)?;
            let Some(id) = segment.strip_suffix(":revoke") else {
                return Err(problem(
                    StatusCode::NOT_FOUND,
                    "route.not_found",
                    "there is no such action on a key version",
                ));
            };
            let id: KeyVersionId = id.parse().map_err(|_| key_version_not_found())?;
            let asked: RevokeBody = body(&bytes)?;
            // A version of another key set is not found in this one.
            let set = keys.key_set(&tenant, key_use).await.map_err(failed)?;
            if set.version(id).is_none() {
                return Err(key_version_not_found());
            }
            let version = keys
                .revoke(&tenant, id, &asked.reason, caller)
                .await
                .map_err(failed)?;
            Ok(Json(KeyVersionBody::from(&version)).into_response())
        }
        .await,
    )
}
