//! The certificate authority of a tenant, as the administration and
//! console interfaces manage it. Routed only when the installation turns
//! the authority on.
//!
//! Specified in `docs/api/admin-api.md`, "The certificate authority".

use super::{Shared, authorize, body, failed, respond, written};
use crate::tenant::TenantSlug;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json};
use hodor_kernel::{DomainError, TenantContext};
use hodor_keys::api::{
    AuthorityId, AuthorityService, CertificateAuthority, NameConstraints, NewAuthority, to_pem,
};
use serde::{Deserialize, Serialize};

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/certificate-authority",
            get(read_authority)
                .post(create_authority)
                .delete(remove_authority),
        )
        .route("/certificate-authority:install", post(install_certificate))
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
