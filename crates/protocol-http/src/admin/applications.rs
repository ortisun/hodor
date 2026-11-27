//! Applications, clients and resource servers, as the administration and
//! console interfaces manage them.
//!
//! Specified in `docs/api/admin-api.md`, "Applications, clients and
//! resource servers". The rules are the OAuth context's; these handlers
//! translate them. A client's secret is written out in exactly two
//! answers, the one that creates the client and the one that makes a new
//! secret, and no type here that holds one is `Debug`.

use super::{Shared, authorize, body, failed, parameter, problem, respond, written};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawPathParams, State};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json};
use hodor_identity::api::{UserKind, UserStatus};
use hodor_kernel::{DomainError, ErrorKind, TenantContext, UserId};
use hodor_oauth::api::{
    Application, ApplicationId, ApplicationSettings, ApplicationType, AuthenticationMethod, Client,
    ClientId, ClientSecret, ClientSecretId, ClientSettings, ClientType, CreateClient,
    CreateResourceServer, ExchangeRule, GrantType, IdTokenAlgorithm, LinkerdIdentity,
    RequestObjectAlgorithm, ResourceServer, ResourceServerId, ResourceServerSettings, ResponseType,
    RotateSecret, ScopeDefinition, SpiffeId, Status, SubjectType, TokenPolicy, response_types_kept,
};
use serde::{Deserialize, Serialize};
use time::Duration;

/// More days than any lifetime the OAuth context accepts, so that a large
/// number given is refused by its rule instead of overflowing.
const MOST_DAYS: u32 = 100_000;

/// How long a new secret lives unless the request says.
const DEFAULT_LIFETIME_DAYS: u32 = 365;

/// How much longer the newest previous secret works unless the request
/// says.
const DEFAULT_KEEP_PREVIOUS_DAYS: u32 = 7;

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/applications",
            get(list_applications).post(create_application),
        )
        // `:disable` and `:enable` arrive here as well, as part of the last
        // segment.
        .route(
            "/applications/{application}",
            get(get_application)
                .patch(change_application)
                .post(application_action),
        )
        .route(
            "/applications/{application}/clients",
            get(list_clients).post(create_client),
        )
        .route(
            "/clients/{client}",
            get(get_client).patch(change_client).post(client_action),
        )
        .route("/clients/{client}/secrets", post(rotate_secret))
        .route("/clients/{client}/secrets/{secret}", delete(revoke_secret))
        .route("/clients/{client}/keys", post(add_key))
        .route("/clients/{client}/keys/{key}", delete(remove_key))
        .route(
            "/resource-servers",
            get(list_resource_servers).post(create_resource_server),
        )
        .route(
            "/resource-servers/{resource_server}",
            get(get_resource_server).patch(change_resource_server),
        )
}

fn application_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "oauth.application_not_found",
        "there is no such application",
    ))
}

fn client_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "oauth.client_not_found",
        "there is no such client",
    ))
}

fn secret_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "oauth.client_secret_not_found",
        "the client has no such secret",
    ))
}

fn resource_server_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "oauth.resource_server_not_found",
        "there is no such resource server",
    ))
}

/// A body that may be left out: an empty one is the same as `{}`.
fn optional_body<T: serde::de::DeserializeOwned + Default>(
    bytes: &Bytes,
) -> Result<T, Box<Response>> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        Ok(T::default())
    } else {
        body(bytes)
    }
}

fn days(given: Option<u32>, otherwise: u32) -> Duration {
    Duration::days(i64::from(given.unwrap_or(otherwise).min(MOST_DAYS)))
}

/// A list as both kinds of list in this interface answer it.
#[derive(Debug, Serialize)]
struct Items<T> {
    items: Vec<T>,
}

// Applications.

#[derive(Debug, Serialize)]
struct ApplicationBody {
    id: String,
    name: String,
    first_party: bool,
    status: &'static str,
    created_at: String,
    updated_at: String,
}

impl From<&Application> for ApplicationBody {
    fn from(application: &Application) -> Self {
        let state = application.snapshot();
        Self {
            id: state.id.to_string(),
            name: state.settings.name.clone(),
            first_party: state.settings.first_party,
            status: state.status.as_str(),
            created_at: written(state.created_at),
            updated_at: written(state.updated_at),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewApplicationBody {
    name: String,
    /// Required: whether people are asked for consent follows from it.
    first_party: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationChangesBody {
    name: Option<String>,
    first_party: Option<bool>,
}

async fn list_applications(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/applications").await?;
            let applications = state
                .applications
                .applications(&tenant)
                .await
                .map_err(failed)?;
            let items = applications.iter().map(ApplicationBody::from).collect();
            Ok(Json(Items { items }).into_response())
        }
        .await,
    )
}

async fn create_application(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "POST", "/applications").await?;
            let new: NewApplicationBody = body(&bytes)?;
            let application = state
                .applications
                .create_application(
                    &tenant,
                    ApplicationSettings {
                        name: new.name,
                        first_party: new.first_party,
                    },
                    caller,
                )
                .await
                .map_err(failed)?;
            Ok((
                StatusCode::CREATED,
                Json(ApplicationBody::from(&application)),
            )
                .into_response())
        }
        .await,
    )
}

async fn get_application(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/applications/{application_id}";
            authorize(&state, &tenant, &headers, "GET", operation).await?;
            let id: ApplicationId =
                parameter(&parameters, "application").ok_or_else(application_not_found)?;
            let application = state
                .applications
                .application(&tenant, id)
                .await
                .map_err(failed)?;
            Ok(Json(ApplicationBody::from(&application)).into_response())
        }
        .await,
    )
}

async fn change_application(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/applications/{application_id}";
            let caller = authorize(&state, &tenant, &headers, "PATCH", operation).await?;
            let id: ApplicationId =
                parameter(&parameters, "application").ok_or_else(application_not_found)?;
            let changes: ApplicationChangesBody = body(&bytes)?;
            // What is left out stays as it is.
            let current = state
                .applications
                .application(&tenant, id)
                .await
                .map_err(failed)?;
            let now = current.snapshot().settings.clone();
            let settings = ApplicationSettings {
                name: changes.name.unwrap_or(now.name),
                first_party: changes.first_party.unwrap_or(now.first_party),
            };
            let application = state
                .applications
                .change_application(&tenant, id, settings, caller)
                .await
                .map_err(failed)?;
            Ok(Json(ApplicationBody::from(&application)).into_response())
        }
        .await,
    )
}

/// The status an action in the last segment of a path asks for, the
/// identifier before it, and the operation it is in the table under.
fn action<'a>(
    segment: &'a str,
    disable: &'static str,
    enable: &'static str,
) -> Option<(&'a str, Status, &'static str)> {
    if let Some(id) = segment.strip_suffix(":disable") {
        Some((id, Status::Disabled, disable))
    } else {
        segment
            .strip_suffix(":enable")
            .map(|id| (id, Status::Enabled, enable))
    }
}

/// Checked like the actions that exist before it is answered, so that a
/// caller without a token learns nothing about paths.
async fn no_such_action(
    state: &Shared,
    tenant: &TenantContext,
    headers: &HeaderMap,
    operation: &'static str,
) -> Box<Response> {
    if let Err(refused) = authorize(state, tenant, headers, "POST", operation).await {
        return refused;
    }
    problem(
        StatusCode::NOT_FOUND,
        "route.not_found",
        "there is no such action",
    )
}

/// `POST /applications/{application_id}:disable` and `:enable`.
async fn application_action(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let disable = "/applications/{application_id}:disable";
            let segment: String =
                parameter(&parameters, "application").ok_or_else(application_not_found)?;
            let Some((id, status, operation)) =
                action(&segment, disable, "/applications/{application_id}:enable")
            else {
                return Err(no_such_action(&state, &tenant, &headers, disable).await);
            };
            let caller = authorize(&state, &tenant, &headers, "POST", operation).await?;
            let id: ApplicationId = id.parse().map_err(|_| application_not_found())?;
            let application = state
                .applications
                .set_application_status(&tenant, id, status, caller)
                .await
                .map_err(failed)?;
            Ok(Json(ApplicationBody::from(&application)).into_response())
        }
        .await,
    )
}

// Clients.

#[derive(Debug, Serialize)]
struct TokenPolicyBody {
    access_token_seconds: i64,
    id_token_seconds: i64,
    refresh_token_seconds: i64,
    refresh_idle_seconds: i64,
    consent_seconds: i64,
}

/// A token policy as given: what is left out is what it was, or the
/// default for a new client.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenPolicyInput {
    access_token_seconds: Option<u32>,
    id_token_seconds: Option<u32>,
    refresh_token_seconds: Option<u32>,
    refresh_idle_seconds: Option<u32>,
    consent_seconds: Option<u32>,
}

impl TokenPolicyInput {
    fn over(self, on: TokenPolicy) -> TokenPolicy {
        let seconds = |given: Option<u32>, was: Duration| {
            given.map_or(was, |seconds| Duration::seconds(i64::from(seconds)))
        };
        TokenPolicy {
            access_token: seconds(self.access_token_seconds, on.access_token),
            id_token: seconds(self.id_token_seconds, on.id_token),
            refresh_token: seconds(self.refresh_token_seconds, on.refresh_token),
            refresh_idle: seconds(self.refresh_idle_seconds, on.refresh_idle),
            consent: seconds(self.consent_seconds, on.consent),
        }
    }
}

#[derive(Debug, Serialize)]
struct SecretBody {
    id: String,
    created_at: String,
    expires_at: String,
}

#[derive(Debug, Serialize)]
struct KeyBody {
    kid: String,
    jwk: serde_json::Value,
    added_at: String,
}

#[derive(Debug, Serialize)]
struct ClientBody {
    id: String,
    application_id: String,
    name: String,
    #[serde(rename = "type")]
    client_type: &'static str,
    authentication_method: &'static str,
    grant_types: Vec<&'static str>,
    response_types: Vec<&'static str>,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
    require_pkce: bool,
    id_token_signed_response_alg: &'static str,
    /// How its UserInfo answers are signed, or `null` for answers in JSON.
    userinfo_signed_response_alg: Option<&'static str>,
    /// How it signs its request objects, or `null` when none is chosen.
    request_object_signing_alg: Option<&'static str>,
    /// Whether every request of it must be pushed first.
    require_pushed_authorization_requests: bool,
    /// Where it keeps request objects Hodor may fetch.
    request_uris: Vec<String>,
    /// Where its logout tokens are sent, or `null`.
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: bool,
    /// `public` or `pairwise`.
    subject_type: &'static str,
    /// The sector identifier address of a pairwise client, or `null`.
    sector_identifier_uri: Option<String>,
    /// Where a client using `private_key_jwt` publishes its keys, or
    /// `null`. What the address answers is never shown.
    jwks_uri: Option<String>,
    /// The `max_age` of a request that names none, or `null`.
    default_max_age: Option<u32>,
    /// The `acr_values` of a request that names none, in order.
    default_acr_values: Vec<String>,
    require_auth_time: bool,
    /// The service account or agent it acts as, or `null`.
    principal: Option<String>,
    exchange_rules: Vec<ExchangeRuleBody>,
    /// The SPIFFE identifier of a client using `spiffe_jwt` or
    /// `spiffe_x509`, or of one using `tls_client_auth`, or `null`.
    spiffe_id: Option<String>,
    /// The Linkerd identity of a client using `linkerd_identity`, or of
    /// one using `tls_client_auth`, or `null`.
    linkerd_identity: Option<String>,
    /// Whether its access tokens are bound to its certificate (RFC 8705).
    tls_client_certificate_bound_access_tokens: bool,
    /// `web` or `native`, as a registration named it, or `null`.
    application_type: Option<&'static str>,
    /// The addresses a person is shown, as a registration named them.
    client_uri: Option<String>,
    logo_uri: Option<String>,
    policy_uri: Option<String>,
    tos_uri: Option<String>,
    /// Whether it registered itself at the registration endpoint.
    registered: bool,
    token_policy: TokenPolicyBody,
    /// What identifies each secret and when it expires: never the secret
    /// or its hash.
    secrets: Vec<SecretBody>,
    keys: Vec<KeyBody>,
    status: &'static str,
    created_at: String,
    updated_at: String,
}

impl From<&Client> for ClientBody {
    fn from(client: &Client) -> Self {
        let state = client.snapshot();
        let settings = &state.settings;
        let policy = settings.token_policy;
        Self {
            id: state.id.to_string(),
            application_id: state.application_id.to_string(),
            name: settings.name.clone(),
            client_type: state.client_type.as_str(),
            authentication_method: settings.authentication_method.as_str(),
            grant_types: settings.grant_types.iter().map(|g| g.as_str()).collect(),
            response_types: settings
                .response_types
                .iter()
                .map(|kind| kind.as_str())
                .collect(),
            redirect_uris: settings.redirect_uris.clone(),
            post_logout_redirect_uris: settings.post_logout_redirect_uris.clone(),
            allowed_scopes: settings.allowed_scopes.clone(),
            require_pkce: settings.require_pkce,
            id_token_signed_response_alg: settings.id_token_algorithm.as_str(),
            userinfo_signed_response_alg: settings.userinfo_algorithm.map(IdTokenAlgorithm::as_str),
            request_object_signing_alg: settings
                .request_object_algorithm
                .map(RequestObjectAlgorithm::as_str),
            require_pushed_authorization_requests: settings.require_pushed_requests,
            request_uris: settings.request_uris.clone(),
            backchannel_logout_uri: settings.backchannel_logout_uri.clone(),
            backchannel_logout_session_required: settings.backchannel_logout_session_required,
            subject_type: settings.subject_type.as_str(),
            sector_identifier_uri: settings.sector_identifier_uri.clone(),
            jwks_uri: settings.jwks_uri.clone(),
            default_max_age: settings.default_max_age,
            default_acr_values: settings.default_acr_values.clone(),
            require_auth_time: settings.require_auth_time,
            principal: settings.principal.map(|principal| principal.to_string()),
            exchange_rules: settings
                .exchange_rules
                .iter()
                .map(|rule| ExchangeRuleBody {
                    subject_audience: rule.subject_audience.clone(),
                    audience: rule.audience.clone(),
                })
                .collect(),
            spiffe_id: settings
                .spiffe_id
                .as_ref()
                .map(|spiffe_id| spiffe_id.as_str().to_owned()),
            linkerd_identity: settings
                .linkerd_identity
                .as_ref()
                .map(|identity| identity.as_str().to_owned()),
            tls_client_certificate_bound_access_tokens: settings.certificate_bound_access_tokens,
            application_type: settings.application_type.map(ApplicationType::as_str),
            client_uri: settings.client_uri.clone(),
            logo_uri: settings.logo_uri.clone(),
            policy_uri: settings.policy_uri.clone(),
            tos_uri: settings.tos_uri.clone(),
            registered: client.is_registered(),
            token_policy: TokenPolicyBody {
                access_token_seconds: policy.access_token.whole_seconds(),
                id_token_seconds: policy.id_token.whole_seconds(),
                refresh_token_seconds: policy.refresh_token.whole_seconds(),
                refresh_idle_seconds: policy.refresh_idle.whole_seconds(),
                consent_seconds: policy.consent.whole_seconds(),
            },
            secrets: state
                .secrets
                .iter()
                .map(|secret| SecretBody {
                    id: secret.id.to_string(),
                    created_at: written(secret.created_at),
                    expires_at: written(secret.expires_at),
                })
                .collect(),
            keys: state
                .keys
                .iter()
                .map(|key| KeyBody {
                    kid: key.key_id.clone(),
                    // Stored as the JSON it was checked as.
                    jwk: serde_json::from_str(&key.jwk).unwrap_or(serde_json::Value::Null),
                    added_at: written(key.added_at),
                })
                .collect(),
            status: state.status.as_str(),
            created_at: written(state.created_at),
            updated_at: written(state.updated_at),
        }
    }
}

/// A new client, with its first secret when it has one. No `Debug`: this
/// holds the secret on its way out.
#[derive(Serialize)]
struct CreatedClientBody {
    #[serde(flatten)]
    client: ClientBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewClientBody {
    name: String,
    #[serde(rename = "type")]
    client_type: String,
    authentication_method: Option<String>,
    grant_types: Vec<String>,
    response_types: Option<Vec<String>>,
    redirect_uris: Option<Vec<String>>,
    post_logout_redirect_uris: Option<Vec<String>>,
    allowed_scopes: Option<Vec<String>>,
    require_pkce: Option<bool>,
    id_token_signed_response_alg: Option<String>,
    userinfo_signed_response_alg: Option<String>,
    request_object_signing_alg: Option<String>,
    require_pushed_authorization_requests: Option<bool>,
    request_uris: Option<Vec<String>>,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: Option<bool>,
    subject_type: Option<String>,
    sector_identifier_uri: Option<String>,
    jwks_uri: Option<String>,
    default_max_age: Option<u32>,
    default_acr_values: Option<Vec<String>>,
    require_auth_time: Option<bool>,
    token_policy: Option<TokenPolicyInput>,
    secret_lifetime_days: Option<u32>,
    principal: Option<String>,
    exchange_rules: Option<Vec<ExchangeRuleBody>>,
    spiffe_id: Option<String>,
    linkerd_identity: Option<String>,
    tls_client_certificate_bound_access_tokens: Option<bool>,
}

/// One exchange rule, as the interface writes it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeRuleBody {
    subject_audience: String,
    audience: String,
}

fn exchange_rules(given: Vec<ExchangeRuleBody>) -> Vec<ExchangeRule> {
    given
        .into_iter()
        .map(|rule| ExchangeRule {
            subject_audience: rule.subject_audience,
            audience: rule.audience,
        })
        .collect()
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientChangesBody {
    name: Option<String>,
    authentication_method: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    redirect_uris: Option<Vec<String>>,
    post_logout_redirect_uris: Option<Vec<String>>,
    allowed_scopes: Option<Vec<String>>,
    require_pkce: Option<bool>,
    id_token_signed_response_alg: Option<String>,
    /// Left out: unchanged; `null`: answers in JSON; a name: replaced.
    #[serde(default, deserialize_with = "present")]
    userinfo_signed_response_alg: Option<Option<String>>,
    /// Left out: unchanged; `null`: none chosen; a name: replaced.
    #[serde(default, deserialize_with = "present")]
    request_object_signing_alg: Option<Option<String>>,
    require_pushed_authorization_requests: Option<bool>,
    request_uris: Option<Vec<String>>,
    /// Left out: unchanged; `null`: removed; an address: replaced.
    #[serde(default, deserialize_with = "present")]
    backchannel_logout_uri: Option<Option<String>>,
    backchannel_logout_session_required: Option<bool>,
    subject_type: Option<String>,
    /// Left out: unchanged; `null`: removed; an address: replaced.
    #[serde(default, deserialize_with = "present")]
    sector_identifier_uri: Option<Option<String>>,
    /// Left out: unchanged, unless the change gives the client another
    /// method than `private_key_jwt`; `null`: removed; an address:
    /// replaced.
    #[serde(default, deserialize_with = "present")]
    jwks_uri: Option<Option<String>>,
    /// Left out: unchanged; `null`: removed; a number: replaced.
    #[serde(default, deserialize_with = "present")]
    default_max_age: Option<Option<u32>>,
    default_acr_values: Option<Vec<String>>,
    require_auth_time: Option<bool>,
    token_policy: Option<TokenPolicyInput>,
    /// Left out: unchanged; `null`: removed; an identifier: replaced.
    #[serde(default, deserialize_with = "present")]
    principal: Option<Option<String>>,
    exchange_rules: Option<Vec<ExchangeRuleBody>>,
    /// Left out: unchanged, unless the change gives the client the other
    /// identity or a method that takes none; `null`: removed; an
    /// identifier: replaced.
    #[serde(default, deserialize_with = "present")]
    spiffe_id: Option<Option<String>>,
    /// Left out: unchanged, unless the change gives the client the other
    /// identity or a method that takes none; `null`: removed; an
    /// identity: replaced.
    #[serde(default, deserialize_with = "present")]
    linkerd_identity: Option<Option<String>>,
    tls_client_certificate_bound_access_tokens: Option<bool>,
}

/// The identities a change leaves a client bound to. A field left out keeps
/// what the client had, unless the change gives the other identity, since
/// a client has one, or a method that does not take it, as a client that
/// moves away from a method loses its secrets or its keys.
fn changed_identities(
    changes: &ClientChangesBody,
    now: &ClientSettings,
    method: AuthenticationMethod,
) -> Result<(Option<SpiffeId>, Option<LinkerdIdentity>), Box<Response>> {
    let takes_spiffe_id = method.uses_spiffe_id() || method == AuthenticationMethod::TlsClientAuth;
    let takes_linkerd_identity = matches!(
        method,
        AuthenticationMethod::LinkerdIdentity | AuthenticationMethod::TlsClientAuth
    );
    let spiffe_id = match &changes.spiffe_id {
        Some(Some(given)) => Some(SpiffeId::parse(given).map_err(failed)?),
        Some(None) => None,
        None if !takes_spiffe_id || matches!(changes.linkerd_identity, Some(Some(_))) => None,
        None => now.spiffe_id.clone(),
    };
    let linkerd_identity = match &changes.linkerd_identity {
        Some(Some(given)) => Some(LinkerdIdentity::parse(given).map_err(failed)?),
        Some(None) => None,
        None if !takes_linkerd_identity || matches!(changes.spiffe_id, Some(Some(_))) => None,
        None => now.linkerd_identity.clone(),
    };
    Ok((spiffe_id, linkerd_identity))
}

/// A field that may be given as `null`, told apart from one left out.
fn present<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// The workload `given` names, if it is a service account or an agent of
/// the tenant that is not deleted: the OAuth context does not know what a
/// principal is, so the interface asks the identity context.
async fn principal_of(
    state: &Shared,
    tenant: &TenantContext,
    given: &str,
    grants: &[GrantType],
    method: AuthenticationMethod,
) -> Result<UserId, Box<Response>> {
    // Only an agent acts on a person's behalf, and only a service account
    // proves who it is with its SPIFFE identifier or its Linkerd identity.
    let exchanges = grants.contains(&GrantType::TokenExchange);
    let spiffe = method.uses_workload_identity();
    let refused = || {
        failed(DomainError::invalid(
            "oauth.client_principal_invalid",
            "a client's principal is a service account or an agent of the tenant; an agent \
             with the token exchange grant, a service account with `spiffe_jwt`, \
             `tls_client_auth`, `spiffe_x509` or `linkerd_identity`",
        ))
    };
    let id: UserId = given.parse().map_err(|_| refused())?;
    match state.identity.get(tenant, id).await {
        Ok(user)
            if user.kind().is_workload()
                && user.status() != UserStatus::Deleted
                && (!exchanges || user.kind() == UserKind::Agent)
                && (!spiffe || user.kind() == UserKind::ServiceAccount) =>
        {
            Ok(id)
        }
        Ok(_) => Err(refused()),
        Err(error) if error.kind() == ErrorKind::NotFound => Err(refused()),
        Err(error) => Err(failed(error)),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewSecretRequest {
    lifetime_days: Option<u32>,
    keep_previous_days: Option<u32>,
}

/// A new secret. No `Debug`: this holds the secret on its way out.
#[derive(Serialize)]
struct NewSecretBody {
    id: String,
    client_secret: String,
    created_at: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewKeyBody {
    jwk: serde_json::Value,
}

fn client_type(value: &str) -> Result<ClientType, Box<Response>> {
    match value {
        "confidential" => Ok(ClientType::Confidential),
        "public" => Ok(ClientType::Public),
        _ => Err(failed(DomainError::invalid(
            "oauth.client_type_invalid",
            "a client is `confidential` or `public`",
        ))),
    }
}

fn response_types(values: &[String]) -> Result<Vec<ResponseType>, Box<Response>> {
    values
        .iter()
        .map(|value| ResponseType::parse(value).map_err(failed))
        .collect()
}

fn grant_types(values: &[String]) -> Result<Vec<GrantType>, Box<Response>> {
    values
        .iter()
        .map(|value| GrantType::parse(value).map_err(failed))
        .collect()
}

async fn list_clients(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/applications/{application_id}/clients";
            authorize(&state, &tenant, &headers, "GET", operation).await?;
            let id: ApplicationId =
                parameter(&parameters, "application").ok_or_else(application_not_found)?;
            let clients = state
                .applications
                .clients(&tenant, id)
                .await
                .map_err(failed)?;
            let items = clients.iter().map(ClientBody::from).collect();
            Ok(Json(Items { items }).into_response())
        }
        .await,
    )
}

async fn create_client(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/applications/{application_id}/clients";
            let caller = authorize(&state, &tenant, &headers, "POST", operation).await?;
            let application_id: ApplicationId =
                parameter(&parameters, "application").ok_or_else(application_not_found)?;
            let new: NewClientBody = body(&bytes)?;
            let kind = client_type(&new.client_type)?;
            let mut settings = ClientSettings::new(
                &new.name,
                kind,
                grant_types(&new.grant_types)?,
                new.redirect_uris.unwrap_or_default(),
            );
            if let Some(method) = new.authentication_method {
                settings.authentication_method =
                    AuthenticationMethod::parse(&method).map_err(failed)?;
            }
            if let Some(given) = &new.response_types {
                settings.response_types = response_types(given)?;
            }
            settings.post_logout_redirect_uris = new.post_logout_redirect_uris.unwrap_or_default();
            settings.allowed_scopes = new.allowed_scopes.unwrap_or_default();
            if let Some(require_pkce) = new.require_pkce {
                settings.require_pkce = require_pkce;
            }
            if let Some(algorithm) = new.id_token_signed_response_alg {
                settings.id_token_algorithm =
                    IdTokenAlgorithm::parse(&algorithm).map_err(failed)?;
            }
            if let Some(algorithm) = new.userinfo_signed_response_alg {
                settings.userinfo_algorithm =
                    Some(IdTokenAlgorithm::parse_for_userinfo(&algorithm).map_err(failed)?);
            }
            if let Some(algorithm) = new.request_object_signing_alg {
                settings.request_object_algorithm =
                    Some(RequestObjectAlgorithm::parse(&algorithm).map_err(failed)?);
            }
            settings.require_pushed_requests =
                new.require_pushed_authorization_requests.unwrap_or(false);
            settings.request_uris = new.request_uris.unwrap_or_default();
            settings.backchannel_logout_uri = new.backchannel_logout_uri;
            settings.backchannel_logout_session_required =
                new.backchannel_logout_session_required.unwrap_or(false);
            if let Some(subject_type) = new.subject_type {
                settings.subject_type = SubjectType::parse(&subject_type).map_err(failed)?;
            }
            settings.sector_identifier_uri = new.sector_identifier_uri;
            settings.jwks_uri = new.jwks_uri;
            settings.default_max_age = new.default_max_age;
            settings.default_acr_values = new.default_acr_values.unwrap_or_default();
            settings.require_auth_time = new.require_auth_time.unwrap_or(false);
            if let Some(policy) = new.token_policy {
                settings.token_policy = policy.over(settings.token_policy);
            }
            if let Some(rules) = new.exchange_rules {
                settings.exchange_rules = exchange_rules(rules);
            }
            if let Some(spiffe_id) = &new.spiffe_id {
                settings.spiffe_id = Some(SpiffeId::parse(spiffe_id).map_err(failed)?);
            }
            if let Some(linkerd_identity) = &new.linkerd_identity {
                settings.linkerd_identity =
                    Some(LinkerdIdentity::parse(linkerd_identity).map_err(failed)?);
            }
            settings.certificate_bound_access_tokens = new
                .tls_client_certificate_bound_access_tokens
                .unwrap_or_default();
            if let Some(principal) = &new.principal {
                settings.principal = Some(
                    principal_of(
                        &state,
                        &tenant,
                        principal,
                        &settings.grant_types,
                        settings.authentication_method,
                    )
                    .await?,
                );
            }
            let (client, secret) = state
                .applications
                .create_client(
                    &tenant,
                    CreateClient {
                        application_id,
                        client_type: kind,
                        settings,
                        secret_lifetime: new
                            .secret_lifetime_days
                            .map(|given| days(Some(given), DEFAULT_LIFETIME_DAYS)),
                    },
                    caller,
                )
                .await
                .map_err(failed)?;
            let created = CreatedClientBody {
                client: ClientBody::from(&client),
                client_secret: secret.map(|secret| secret.expose().to_owned()),
            };
            Ok((StatusCode::CREATED, Json(created)).into_response())
        }
        .await,
    )
}

async fn get_client(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/clients/{client_id}").await?;
            let id: ClientId = parameter(&parameters, "client").ok_or_else(client_not_found)?;
            let client = state
                .applications
                .client(&tenant, id)
                .await
                .map_err(failed)?;
            Ok(Json(ClientBody::from(&client)).into_response())
        }
        .await,
    )
}

async fn change_client(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller =
                authorize(&state, &tenant, &headers, "PATCH", "/clients/{client_id}").await?;
            let id: ClientId = parameter(&parameters, "client").ok_or_else(client_not_found)?;
            let changes: ClientChangesBody = body(&bytes)?;
            // What is left out stays as it is; the whole is checked again.
            let current = state
                .applications
                .client(&tenant, id)
                .await
                .map_err(failed)?;
            let now = current.snapshot().settings.clone();
            let method = match &changes.authentication_method {
                Some(method) => AuthenticationMethod::parse(method).map_err(failed)?,
                None => now.authentication_method,
            };
            let (spiffe_id, linkerd_identity) = changed_identities(&changes, &now, method)?;
            let grants = match changes.grant_types {
                Some(given) => grant_types(&given)?,
                None => now.grant_types.clone(),
            };
            let settings = ClientSettings {
                name: changes.name.unwrap_or(now.name),
                authentication_method: method,
                response_types: match &changes.response_types {
                    Some(given) => response_types(given)?,
                    None => response_types_kept(&now.response_types, &grants),
                },
                grant_types: grants.clone(),
                redirect_uris: changes.redirect_uris.unwrap_or(now.redirect_uris),
                post_logout_redirect_uris: changes
                    .post_logout_redirect_uris
                    .unwrap_or(now.post_logout_redirect_uris),
                allowed_scopes: changes.allowed_scopes.unwrap_or(now.allowed_scopes),
                require_pkce: changes.require_pkce.unwrap_or(now.require_pkce),
                id_token_algorithm: match changes.id_token_signed_response_alg {
                    Some(algorithm) => IdTokenAlgorithm::parse(&algorithm).map_err(failed)?,
                    None => now.id_token_algorithm,
                },
                userinfo_algorithm: match changes.userinfo_signed_response_alg {
                    None => now.userinfo_algorithm,
                    Some(None) => None,
                    Some(Some(algorithm)) => {
                        Some(IdTokenAlgorithm::parse_for_userinfo(&algorithm).map_err(failed)?)
                    }
                },
                request_object_algorithm: match changes.request_object_signing_alg {
                    None => now.request_object_algorithm,
                    Some(None) => None,
                    Some(Some(algorithm)) => {
                        Some(RequestObjectAlgorithm::parse(&algorithm).map_err(failed)?)
                    }
                },
                require_pushed_requests: changes
                    .require_pushed_authorization_requests
                    .unwrap_or(now.require_pushed_requests),
                request_uris: changes.request_uris.unwrap_or(now.request_uris),
                backchannel_logout_uri: changes
                    .backchannel_logout_uri
                    .unwrap_or(now.backchannel_logout_uri),
                backchannel_logout_session_required: changes
                    .backchannel_logout_session_required
                    .unwrap_or(now.backchannel_logout_session_required),
                subject_type: match changes.subject_type {
                    Some(given) => SubjectType::parse(&given).map_err(failed)?,
                    None => now.subject_type,
                },
                sector_identifier_uri: changes
                    .sector_identifier_uri
                    .unwrap_or(now.sector_identifier_uri),
                // A client that moves away from `private_key_jwt` loses its
                // address, as it loses its keys.
                jwks_uri: match changes.jwks_uri {
                    Some(given) => given,
                    None if method == AuthenticationMethod::PrivateKeyJwt => now.jwks_uri,
                    None => None,
                },
                default_max_age: changes.default_max_age.unwrap_or(now.default_max_age),
                default_acr_values: changes.default_acr_values.unwrap_or(now.default_acr_values),
                require_auth_time: changes.require_auth_time.unwrap_or(now.require_auth_time),
                token_policy: changes
                    .token_policy
                    .map_or(now.token_policy, |given| given.over(now.token_policy)),
                principal: match &changes.principal {
                    // Kept, but checked again when the grants now exchange
                    // or the method now uses a SPIFFE identifier.
                    None => match now.principal {
                        Some(kept)
                            if grants.contains(&GrantType::TokenExchange)
                                || method.uses_workload_identity() =>
                        {
                            Some(
                                principal_of(&state, &tenant, &kept.to_string(), &grants, method)
                                    .await?,
                            )
                        }
                        kept => kept,
                    },
                    Some(None) => None,
                    Some(Some(given)) => {
                        Some(principal_of(&state, &tenant, given, &grants, method).await?)
                    }
                },
                exchange_rules: changes
                    .exchange_rules
                    .map_or(now.exchange_rules, exchange_rules),
                spiffe_id,
                linkerd_identity,
                certificate_bound_access_tokens: changes
                    .tls_client_certificate_bound_access_tokens
                    .unwrap_or(now.certificate_bound_access_tokens),
                // Set by a registration only: a change made here keeps them.
                application_type: now.application_type,
                client_uri: now.client_uri,
                logo_uri: now.logo_uri,
                policy_uri: now.policy_uri,
                tos_uri: now.tos_uri,
            };
            let client = state
                .applications
                .change_client(&tenant, id, settings, caller)
                .await
                .map_err(failed)?;
            Ok(Json(ClientBody::from(&client)).into_response())
        }
        .await,
    )
}

/// `POST /clients/{client_id}:disable` and `:enable`.
async fn client_action(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let disable = "/clients/{client_id}:disable";
            let segment: String = parameter(&parameters, "client").ok_or_else(client_not_found)?;
            let Some((id, status, operation)) =
                action(&segment, disable, "/clients/{client_id}:enable")
            else {
                return Err(no_such_action(&state, &tenant, &headers, disable).await);
            };
            let caller = authorize(&state, &tenant, &headers, "POST", operation).await?;
            let id: ClientId = id.parse().map_err(|_| client_not_found())?;
            let client = state
                .applications
                .set_client_status(&tenant, id, status, caller)
                .await
                .map_err(failed)?;
            Ok(Json(ClientBody::from(&client)).into_response())
        }
        .await,
    )
}

async fn rotate_secret(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/clients/{client_id}/secrets";
            let caller = authorize(&state, &tenant, &headers, "POST", operation).await?;
            let id: ClientId = parameter(&parameters, "client").ok_or_else(client_not_found)?;
            let asked: NewSecretRequest = optional_body(&bytes)?;
            let value = state
                .applications
                .rotate_client_secret(
                    &tenant,
                    id,
                    RotateSecret {
                        lifetime: days(asked.lifetime_days, DEFAULT_LIFETIME_DAYS),
                        keep_previous_for: days(
                            asked.keep_previous_days,
                            DEFAULT_KEEP_PREVIOUS_DAYS,
                        ),
                    },
                    caller,
                )
                .await
                .map_err(failed)?;
            // The new secret is the one made last.
            let client = state
                .applications
                .client(&tenant, id)
                .await
                .map_err(failed)?;
            let newest: Option<&ClientSecret> = client
                .snapshot()
                .secrets
                .iter()
                .max_by_key(|secret| secret.created_at);
            let newest = newest.ok_or_else(secret_not_found)?;
            let made = NewSecretBody {
                id: newest.id.to_string(),
                client_secret: value.expose().to_owned(),
                created_at: written(newest.created_at),
                expires_at: written(newest.expires_at),
            };
            Ok((StatusCode::CREATED, Json(made)).into_response())
        }
        .await,
    )
}

async fn revoke_secret(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/clients/{client_id}/secrets/{secret_id}";
            let caller = authorize(&state, &tenant, &headers, "DELETE", operation).await?;
            let id: ClientId = parameter(&parameters, "client").ok_or_else(client_not_found)?;
            let secret: ClientSecretId =
                parameter(&parameters, "secret").ok_or_else(secret_not_found)?;
            state
                .applications
                .revoke_client_secret(&tenant, id, secret, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

async fn add_key(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/clients/{client_id}/keys";
            let caller = authorize(&state, &tenant, &headers, "POST", operation).await?;
            let id: ClientId = parameter(&parameters, "client").ok_or_else(client_not_found)?;
            let new: NewKeyBody = body(&bytes)?;
            let client = state
                .applications
                .add_client_key(&tenant, id, &new.jwk.to_string(), caller)
                .await
                .map_err(failed)?;
            Ok((StatusCode::CREATED, Json(ClientBody::from(&client))).into_response())
        }
        .await,
    )
}

async fn remove_key(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/clients/{client_id}/keys/{key_id}";
            let caller = authorize(&state, &tenant, &headers, "DELETE", operation).await?;
            let id: ClientId = parameter(&parameters, "client").ok_or_else(client_not_found)?;
            // Decoded from the path: a `kid` may hold characters a path
            // writes with percent-encoding.
            let key: String = parameter(&parameters, "key").unwrap_or_default();
            state
                .applications
                .remove_client_key(&tenant, id, &key, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

// Resource servers.

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeBody {
    name: String,
    #[serde(default)]
    description: String,
}

impl From<ScopeBody> for ScopeDefinition {
    fn from(scope: ScopeBody) -> Self {
        Self {
            name: scope.name,
            description: scope.description,
        }
    }
}

#[derive(Debug, Serialize)]
struct ResourceServerBody {
    id: String,
    application_id: String,
    audience: String,
    name: String,
    scopes: Vec<ScopeBody>,
    created_at: String,
    updated_at: String,
}

impl From<&ResourceServer> for ResourceServerBody {
    fn from(server: &ResourceServer) -> Self {
        let state = server.snapshot();
        Self {
            id: state.id.to_string(),
            application_id: state.application_id.to_string(),
            audience: state.audience.as_str().to_owned(),
            name: state.settings.name.clone(),
            scopes: state
                .settings
                .scopes
                .iter()
                .map(|scope| ScopeBody {
                    name: scope.name.clone(),
                    description: scope.description.clone(),
                })
                .collect(),
            created_at: written(state.created_at),
            updated_at: written(state.updated_at),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewResourceServerBody {
    application_id: String,
    audience: String,
    name: String,
    #[serde(default)]
    scopes: Vec<ScopeBody>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceServerChangesBody {
    name: Option<String>,
    scopes: Option<Vec<ScopeBody>>,
}

async fn list_resource_servers(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/resource-servers").await?;
            let servers = state
                .applications
                .resource_servers(&tenant)
                .await
                .map_err(failed)?;
            let items = servers.iter().map(ResourceServerBody::from).collect();
            Ok(Json(Items { items }).into_response())
        }
        .await,
    )
}

async fn create_resource_server(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "POST", "/resource-servers").await?;
            let new: NewResourceServerBody = body(&bytes)?;
            let application_id: ApplicationId = new
                .application_id
                .parse()
                .map_err(|_| application_not_found())?;
            let server = state
                .applications
                .create_resource_server(
                    &tenant,
                    CreateResourceServer {
                        application_id,
                        audience: new.audience,
                        settings: ResourceServerSettings {
                            name: new.name,
                            scopes: new.scopes.into_iter().map(Into::into).collect(),
                        },
                    },
                    caller,
                )
                .await
                .map_err(failed)?;
            Ok((StatusCode::CREATED, Json(ResourceServerBody::from(&server))).into_response())
        }
        .await,
    )
}

async fn get_resource_server(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
) -> Response {
    respond(
        async {
            let operation = "/resource-servers/{resource_server_id}";
            authorize(&state, &tenant, &headers, "GET", operation).await?;
            let id: ResourceServerId =
                parameter(&parameters, "resource_server").ok_or_else(resource_server_not_found)?;
            let server = state
                .applications
                .resource_server(&tenant, id)
                .await
                .map_err(failed)?;
            Ok(Json(ResourceServerBody::from(&server)).into_response())
        }
        .await,
    )
}

async fn change_resource_server(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    parameters: RawPathParams,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let operation = "/resource-servers/{resource_server_id}";
            let caller = authorize(&state, &tenant, &headers, "PATCH", operation).await?;
            let id: ResourceServerId =
                parameter(&parameters, "resource_server").ok_or_else(resource_server_not_found)?;
            let changes: ResourceServerChangesBody = body(&bytes)?;
            let current = state
                .applications
                .resource_server(&tenant, id)
                .await
                .map_err(failed)?;
            let now = current.snapshot().settings.clone();
            let settings = ResourceServerSettings {
                name: changes.name.unwrap_or(now.name),
                scopes: changes.scopes.map_or(now.scopes, |given| {
                    given.into_iter().map(Into::into).collect()
                }),
            };
            let server = state
                .applications
                .change_resource_server(&tenant, id, settings, caller)
                .await
                .map_err(failed)?;
            Ok(Json(ResourceServerBody::from(&server)).into_response())
        }
        .await,
    )
}
