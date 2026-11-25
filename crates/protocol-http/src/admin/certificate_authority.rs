//! The certificate authority of a tenant, as the administration and
//! console interfaces manage it. Routed only when the installation turns
//! the authority on.
//!
//! Specified in `docs/api/admin-api.md`, "The certificate authority" and
//! "Intermediates".

use super::{
    PageBody, Shared, authorize, bearer, body, failed, forbidden, not_authenticated, page_request,
    parameter, problem, respond, written,
};
use crate::tenant::TenantSlug;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawPathParams, RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json};
use hodor_authorization::api::Permission;
use hodor_kernel::{Actor, Caller, CorrelationId, DomainError, Page, TenantContext, UserId};
use hodor_keys::api::{
    AuthorityId, AuthorityService, CertificateAuthority, IntermediateConstraints, IntermediateId,
    NameConstraints, NewAuthority, SignedIntermediate, to_pem,
};
use hodor_oauth::api::{ForwardedIdentity, ResourceAccessService, ResourceCaller};
use serde::{Deserialize, Serialize};

/// The audience an access token must name to sign intermediates.
pub const CERTIFICATE_AUTHORITY_AUDIENCE: &str = "urn:hodor:certificate-authority";
/// The scope such a token must hold.
const SIGN_SCOPE: &str = "certificate-authority:sign";

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/certificate-authority",
            get(read_authority)
                .post(create_authority)
                .delete(remove_authority),
        )
        .route("/certificate-authority:install", post(install_certificate))
        .route(
            "/certificate-authority/intermediates",
            get(list_intermediates).post(sign_intermediate),
        )
        // `POST …/{intermediate_id}:withdraw` arrives here too: the action
        // is part of the last segment.
        .route(
            "/certificate-authority/intermediates/{intermediate}",
            get(read_intermediate).post(withdraw_intermediate),
        )
}

/// The address of a tenant's published bundle.
#[must_use]
fn bundle_address(public_url: &str, slug: &str) -> String {
    format!(
        "{}/t/{slug}/certificate-authority/bundle",
        public_url.trim_end_matches('/')
    )
}

#[derive(Serialize)]
struct KeyBody {
    id: hodor_keys::api::KeyVersionId,
    provider: String,
    algorithm: &'static str,
}

#[derive(Serialize)]
struct AuthorityBody {
    id: AuthorityId,
    kind: &'static str,
    state: &'static str,
    trust_domains: Vec<String>,
    common_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifetime_days: Option<u32>,
    intermediate_lifetime_days: u32,
    for_development: bool,
    key: KeyBody,
    name_constraints: NameConstraints,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate_signing_request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate_sha256: Option<String>,
    chain: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_endpoint: Option<String>,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    activated_at: Option<String>,
    updated_at: String,
}

impl AuthorityBody {
    fn of(authority: &CertificateAuthority, public_url: &str, slug: &str) -> Self {
        let state = authority.snapshot();
        let certificate = state.certificate.as_ref();
        Self {
            id: state.id,
            kind: state.kind.as_str(),
            state: state.state.as_str(),
            trust_domains: state
                .trust_domains
                .iter()
                .map(ToString::to_string)
                .collect(),
            common_name: state.common_name.clone(),
            lifetime_days: state.lifetime_days,
            intermediate_lifetime_days: state.intermediate_lifetime_days,
            for_development: state.for_development,
            key: KeyBody {
                id: state.key.id,
                provider: state.key.provider.clone(),
                algorithm: "ES256",
            },
            name_constraints: authority.name_constraints(),
            certificate_signing_request: state
                .certificate_signing_request
                .as_ref()
                .filter(|_| certificate.is_none())
                .map(|request| to_pem("CERTIFICATE REQUEST", request)),
            certificate: certificate.map(|issued| to_pem("CERTIFICATE", &issued.der)),
            serial_number: certificate.map(|issued| issued.serial_number.clone()),
            not_before: certificate.map(|issued| written(issued.not_before)),
            not_after: certificate.map(|issued| written(issued.not_after)),
            certificate_sha256: certificate.map(|issued| issued.sha256.clone()),
            chain: state
                .chain
                .iter()
                .map(|der| to_pem("CERTIFICATE", der))
                .collect(),
            bundle_endpoint: certificate.map(|_| bundle_address(public_url, slug)),
            created_at: written(state.created_at),
            activated_at: state.activated_at.map(written),
            updated_at: written(state.updated_at),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewBody {
    kind: String,
    trust_domains: Vec<String>,
    common_name: Option<String>,
    lifetime_days: Option<u32>,
    intermediate_lifetime_days: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallBody {
    certificate: String,
    #[serde(default)]
    chain: Vec<String>,
}

#[derive(Serialize)]
struct IntermediateBody {
    id: IntermediateId,
    authority_id: AuthorityId,
    state: &'static str,
    serial_number: String,
    subject: String,
    uris: Vec<String>,
    dns_names: Vec<String>,
    name_constraints: IntermediateConstraints,
    not_before: String,
    not_after: String,
    certificate: String,
    chain: Vec<String>,
    certificate_sha256: String,
    public_key_sha256: String,
    request_sha256: String,
    signed_at: String,
    withdrawn_at: Option<String>,
    withdrawal_reason: Option<String>,
}

impl IntermediateBody {
    fn of(intermediate: &SignedIntermediate, chain: &[Vec<u8>]) -> Self {
        let state = intermediate.snapshot();
        Self {
            id: state.id,
            authority_id: state.authority_id,
            state: state.state.as_str(),
            serial_number: state.serial_number.clone(),
            subject: state.subject.clone(),
            uris: state.uris.clone(),
            dns_names: state.dns_names.clone(),
            name_constraints: state.constraints.clone(),
            not_before: written(state.not_before),
            not_after: written(state.not_after),
            certificate: to_pem("CERTIFICATE", &state.certificate),
            chain: chain.iter().map(|der| to_pem("CERTIFICATE", der)).collect(),
            certificate_sha256: state.certificate_sha256.clone(),
            public_key_sha256: state.public_key_sha256.clone(),
            request_sha256: state.request_sha256.clone(),
            signed_at: written(state.signed_at),
            withdrawn_at: state.withdrawn_at.map(written),
            withdrawal_reason: state.withdrawal_reason.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignBody {
    certificate_signing_request: String,
    lifetime_days: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WithdrawBody {
    reason: String,
}

/// The authority's use cases: there are always some where these routes
/// are mounted.
fn service(state: &Shared) -> Result<&AuthorityService, Box<Response>> {
    state.authority.as_ref().ok_or_else(|| {
        failed(DomainError::not_found(
            "keys.authority_not_found",
            "the tenant has no certificate authority",
        ))
    })
}

async fn read_authority(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/certificate-authority").await?;
            let found = service(&state)?.get(&tenant).await.map_err(failed)?;
            Ok(Json(AuthorityBody::of(&found, &state.public_url, &slug)).into_response())
        }
        .await,
    )
}

async fn create_authority(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller =
                authorize(&state, &tenant, &headers, "POST", "/certificate-authority").await?;
            let asked: NewBody = body(&bytes)?;
            let created = service(&state)?
                .create(
                    &tenant,
                    NewAuthority {
                        kind: asked.kind,
                        trust_domains: asked.trust_domains,
                        common_name: asked.common_name,
                        lifetime_days: asked.lifetime_days,
                        intermediate_lifetime_days: asked.intermediate_lifetime_days,
                    },
                    caller,
                )
                .await
                .map_err(failed)?;
            Ok((
                StatusCode::CREATED,
                Json(AuthorityBody::of(&created, &state.public_url, &slug)),
            )
                .into_response())
        }
        .await,
    )
}

async fn install_certificate(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let caller = authorize(
                &state,
                &tenant,
                &headers,
                "POST",
                "/certificate-authority:install",
            )
            .await?;
            let asked: InstallBody = body(&bytes)?;
            let installed = service(&state)?
                .install(&tenant, &asked.certificate, &asked.chain, caller)
                .await
                .map_err(failed)?;
            Ok(Json(AuthorityBody::of(&installed, &state.public_url, &slug)).into_response())
        }
        .await,
    )
}

async fn remove_authority(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            let caller = authorize(
                &state,
                &tenant,
                &headers,
                "DELETE",
                "/certificate-authority",
            )
            .await?;
            service(&state)?
                .remove(&tenant, caller)
                .await
                .map_err(failed)?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

fn intermediate_not_found() -> Box<Response> {
    failed(DomainError::not_found(
        "keys.intermediate_not_found",
        "the certificate authority signed no such intermediate",
    ))
}

/// Why an access token of the token endpoint may not sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigningRefusal {
    /// Not good here: `401`, as any credential that is not.
    NotAuthenticated,
    /// Good, and without the scope: `403`.
    Forbidden,
}

/// The service account a checked access token signs for: its client must
/// act as a service account, and the token hold the signing scope. Its
/// audience and everything else about it were checked already.
fn signing_workload(caller: &ResourceCaller) -> Result<UserId, SigningRefusal> {
    if caller.principal_kind.as_deref() != Some("service_account") {
        return Err(SigningRefusal::NotAuthenticated);
    }
    let Ok(workload) = caller.subject.parse::<UserId>() else {
        return Err(SigningRefusal::NotAuthenticated);
    };
    if !caller.has_scope(SIGN_SCOPE) {
        return Err(SigningRefusal::Forbidden);
    }
    Ok(workload)
}

/// Whether a bearer is an access token of the token endpoint, a JSON Web
/// Token, rather than a token or a key of the credential context, which
/// have no dot.
fn is_access_token_of_the_token_endpoint(token: &str) -> bool {
    token.split('.').count() == 3
}

/// Who signs with an access token of the token endpoint: checked through
/// the resource access use case for the audience of the certificate
/// authority, of a service account's client, with the signing scope, the
/// service account active and holding `certificate-authority:sign`.
async fn authorize_signing_token(
    state: &Shared,
    access: &ResourceAccessService,
    tenant: &TenantContext,
    slug: &str,
    token: &str,
    forwarded: Option<&ForwardedIdentity>,
) -> Result<Caller, Box<Response>> {
    let issuer = format!("{}/t/{slug}", state.public_url.trim_end_matches('/'));
    let found = access
        .caller(
            tenant,
            &issuer,
            CERTIFICATE_AUTHORITY_AUDIENCE,
            Some(token),
            forwarded,
        )
        .await
        .map_err(failed)?;
    let Ok(found) = found else {
        return Err(not_authenticated());
    };
    let workload = signing_workload(&found).map_err(|refusal| match refusal {
        SigningRefusal::NotAuthenticated => not_authenticated(),
        SigningRefusal::Forbidden => forbidden(),
    })?;
    match state.identity.get(tenant, workload).await {
        Ok(account)
            if account.is_workload_that_may_act()
                && account.kind() == hodor_identity::api::UserKind::ServiceAccount => {}
        Ok(_) => return Err(not_authenticated()),
        Err(error) if error.code() == "identity.user_not_found" => {
            return Err(not_authenticated());
        }
        Err(error) => return Err(failed(error)),
    }
    let decision = state
        .authorization
        .check(tenant, workload, Permission::CertificateAuthoritySign)
        .await
        .map_err(failed)?;
    if !decision.is_allowed() {
        return Err(forbidden());
    }
    Ok(Caller {
        actor: Actor::User(workload),
        correlation_id: CorrelationId::generate(),
    })
}

async fn sign_intermediate(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    forwarded: Option<Extension<ForwardedIdentity>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            // Only the administration interface takes an access token of
            // the token endpoint here; the console knows people by their
            // session alone.
            let signing_token = state
                .certificate_signing
                .as_ref()
                .filter(|_| state.by_session.is_none())
                .zip(bearer(&headers).filter(|token| is_access_token_of_the_token_endpoint(token)));
            let caller = match signing_token {
                Some((access, token)) => {
                    authorize_signing_token(
                        &state,
                        access,
                        &tenant,
                        &slug,
                        token,
                        forwarded.as_ref().map(|Extension(found)| found),
                    )
                    .await?
                }
                None => {
                    authorize(
                        &state,
                        &tenant,
                        &headers,
                        "POST",
                        "/certificate-authority/intermediates",
                    )
                    .await?
                }
            };
            let asked: SignBody = body(&bytes)?;
            let signed = service(&state)?
                .sign(
                    &tenant,
                    &asked.certificate_signing_request,
                    asked.lifetime_days,
                    caller,
                )
                .await
                .map_err(failed)?;
            Ok((
                StatusCode::CREATED,
                Json(IntermediateBody::of(&signed.intermediate, &signed.chain)),
            )
                .into_response())
        }
        .await,
    )
}

async fn list_intermediates(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    respond(
        async {
            authorize(
                &state,
                &tenant,
                &headers,
                "GET",
                "/certificate-authority/intermediates",
            )
            .await?;
            let page = page_request(query.as_deref())?;
            let (found, chain) = service(&state)?
                .intermediates(&tenant, &page)
                .await
                .map_err(failed)?;
            let page = Page {
                items: found
                    .items
                    .iter()
                    .map(|intermediate| IntermediateBody::of(intermediate, &chain))
                    .collect(),
                next_cursor: found.next_cursor,
            };
            Ok(Json(PageBody::from(page)).into_response())
        }
        .await,
    )
}

async fn read_intermediate(
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
                "/certificate-authority/intermediates/{intermediate_id}",
            )
            .await?;
            let id: IntermediateId =
                parameter(&parameters, "intermediate").ok_or_else(intermediate_not_found)?;
            let found = service(&state)?
                .intermediate(&tenant, id)
                .await
                .map_err(failed)?;
            Ok(Json(IntermediateBody::of(&found.intermediate, &found.chain)).into_response())
        }
        .await,
    )
}

/// `POST /certificate-authority/intermediates/{intermediate_id}:withdraw`.
/// The action is part of the last segment of the path.
async fn withdraw_intermediate(
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
                "/certificate-authority/intermediates/{intermediate_id}:withdraw",
            )
            .await?;
            let segment: String =
                parameter(&parameters, "intermediate").ok_or_else(intermediate_not_found)?;
            let Some(id) = segment.strip_suffix(":withdraw") else {
                return Err(problem(
                    StatusCode::NOT_FOUND,
                    "route.not_found",
                    "there is no such action on an intermediate",
                ));
            };
            let id: IntermediateId = id.parse().map_err(|_| intermediate_not_found())?;
            let asked: WithdrawBody = body(&bytes)?;
            let (withdrawn, chain) = service(&state)?
                .withdraw(&tenant, id, &asked.reason, caller)
                .await
                .map_err(failed)?;
            let first = withdrawn.first().ok_or_else(intermediate_not_found)?;
            Ok(Json(IntermediateBody::of(first, &chain)).into_response())
        }
        .await,
    )
}

#[cfg(test)]
mod tests {
    use super::{SigningRefusal, is_access_token_of_the_token_endpoint, signing_workload};
    use hodor_kernel::UserId;
    use hodor_oauth::api::{ApplicationId, ClientId, ResourceCaller};

    fn caller(principal_kind: Option<&str>, subject: &str, scopes: &[&str]) -> ResourceCaller {
        ResourceCaller {
            client_id: ClientId::generate(),
            application_id: ApplicationId::generate(),
            subject: subject.to_owned(),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            resource_server: None,
            principal_kind: principal_kind.map(str::to_owned),
        }
    }

    #[test]
    fn a_service_accounts_token_with_the_scope_signs_for_the_service_account() {
        let account = UserId::generate();
        assert_eq!(
            signing_workload(&caller(
                Some("service_account"),
                &account.to_string(),
                &["certificate-authority:sign"]
            )),
            Ok(account)
        );
    }

    #[test]
    fn a_token_of_anything_but_a_service_account_is_not_good_here() {
        let account = UserId::generate().to_string();
        for kind in [None, Some("agent"), Some("human"), Some("")] {
            assert_eq!(
                signing_workload(&caller(kind, &account, &["certificate-authority:sign"])),
                Err(SigningRefusal::NotAuthenticated),
                "{kind:?}"
            );
        }
        assert_eq!(
            signing_workload(&caller(
                Some("service_account"),
                "not-a-user",
                &["certificate-authority:sign"]
            )),
            Err(SigningRefusal::NotAuthenticated)
        );
    }

    #[test]
    fn a_token_without_the_signing_scope_is_forbidden() {
        let account = UserId::generate().to_string();
        for scopes in [
            &[][..],
            &["certificate-authority:write"][..],
            &["certificate-authority:signer"][..],
            &["authz:evaluate"][..],
        ] {
            assert_eq!(
                signing_workload(&caller(Some("service_account"), &account, scopes)),
                Err(SigningRefusal::Forbidden),
                "{scopes:?}"
            );
        }
    }

    #[test]
    fn only_a_json_web_token_is_taken_for_a_token_of_the_token_endpoint() {
        assert!(is_access_token_of_the_token_endpoint("eyJh.eyJz.c2ln"));
        for credential in [
            format!("hodor_at_{}", "a".repeat(64)),
            format!("hodor_ak_{}", "a".repeat(64)),
            "eyJh.eyJz".to_owned(),
            "a.b.c.d".to_owned(),
        ] {
            assert!(
                !is_access_token_of_the_token_endpoint(&credential),
                "{credential}"
            );
        }
    }
}
