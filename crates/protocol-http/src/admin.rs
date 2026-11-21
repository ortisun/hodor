//! The administration interface: users, sessions and the audit log of a
//! tenant, for the people who run it.
//!
//! The same routes are served twice. The administration interface, for
//! programs, knows who is asking by an access token; the console
//! interface, for the admin console, by the person's session. The
//! handlers and the table of permissions are the same for both.
//!
//! Specified in `docs/api/admin-api.md` and `docs/api/console-interface.md`.
//! Every request is checked before
//! anything else: the access token, whether its user may sign in, and
//! whether the user holds a role with the permission the route needs. A
//! request that is refused learns nothing about what it asked for, which
//! is why bodies and queries are read only after the check.

use crate::interaction::{
    CSRF_HEADER, SESSION_COOKIE, cookie, csrf_token, refuse_other_origins, same,
};
use crate::problem::Problem;
use axum::body::Bytes;
use axum::extract::{RawPathParams, RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Extension, Json, Router, middleware};
use hodor_audit::api::{AuditRecord, AuditService};
use hodor_authorization::api::{AuthorizationService, Permission};
use hodor_credential::api::AccessTokenService;
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, User, UserKind};
use hodor_kernel::{
    Actor, Caller, Clock, CorrelationId, Cursor, Digest, DomainError, Page, PageRequest,
    TenantContext, UserId,
};
use hodor_session::api::{Session, SessionId, SessionService};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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
