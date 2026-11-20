//! Tenant resolution from the URL.
//!
//! The tenant of a request comes from the path prefix `/t/{slug}` and from
//! nothing else: never from a header, query parameter or body. See
//! `docs/architecture/multi-tenancy.md`.

use crate::problem::Problem;
use axum::extract::{OriginalUri, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hodor_kernel::{DomainError, TenantContext};
use std::sync::Arc;

/// Whether a tenant may serve requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantStatus {
    /// Serving normally.
    Active,
    /// Data is kept but every request is refused.
    Suspended,
}

/// A tenant found for a slug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTenant {
    /// The context handlers will run under.
    pub context: TenantContext,
    /// Whether the tenant may serve requests.
    pub status: TenantStatus,
}

/// Finds tenants by slug. Implemented by the composition root on top of the
/// tenant context.
#[async_trait::async_trait]
pub trait TenantResolver: Send + Sync {
    /// Returns the tenant with this slug, or `None` if there is none.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup itself fails.
    async fn resolve(&self, slug: &str) -> Result<Option<ResolvedTenant>, DomainError>;
}

/// Same response whether the slug is malformed, unknown or absent, so that
/// tenant names cannot be probed by comparing answers.
fn not_found() -> Response {
    Problem::new(
        StatusCode::NOT_FOUND,
        "tenant.not_found",
        "the requested resource does not exist",
    )
    .into_response()
}

/// Slugs are lowercase letters, digits and hyphens, 2 to 63 characters,
/// starting with a letter or digit. Anything else cannot be a tenant and is
/// rejected without a lookup.
fn is_valid_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    (2..=63).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// Extracts the slug from a path of the form `/t/{slug}[/...]`.
fn slug_of(path: &str) -> Option<&str> {
    let mut segments = path.split('/').skip(1);
    (segments.next()? == "t").then(|| segments.next()).flatten()
}

/// Middleware for everything under `/t/{slug}`: resolves the tenant and
/// makes its [`TenantContext`] available to handlers as a request extension.
pub(crate) async fn resolve_tenant(
    State(resolver): State<Arc<dyn TenantResolver>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Inside a nested router the request URI has the prefix stripped; the
    // original one is kept in an extension.
    let path = request
        .extensions()
        .get::<OriginalUri>()
        .map_or_else(|| request.uri().path(), |original| original.0.path())
        .to_owned();
    let Some(slug) = slug_of(&path).filter(|slug| is_valid_slug(slug)) else {
        return not_found();
    };

    match resolver.resolve(slug).await {
        Ok(Some(tenant)) => match tenant.status {
            TenantStatus::Active => {
                tracing::Span::current().record(
                    "tenant_id",
                    tracing::field::display(tenant.context.tenant_id()),
                );
                request.extensions_mut().insert(tenant.context);
                next.run(request).await
            }
            TenantStatus::Suspended => Problem::new(
                StatusCode::FORBIDDEN,
                "tenant.suspended",
                "this tenant is suspended",
            )
            .into_response(),
        },
        Ok(None) => not_found(),
        Err(error) => Problem::from(error).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_is_the_second_path_segment_after_t() {
        assert_eq!(slug_of("/t/acme"), Some("acme"));
        assert_eq!(slug_of("/t/acme/oauth2/token"), Some("acme"));
        assert_eq!(slug_of("/x/acme"), None);
        assert_eq!(slug_of("/t"), None);
        assert_eq!(slug_of("/"), None);
    }

    #[test]
    fn slugs_are_validated_strictly() {
        for valid in ["ac", "acme", "acme-corp", "a1", "1a", &"a".repeat(63)] {
            assert!(is_valid_slug(valid), "{valid}");
        }
        for invalid in [
            "",
            "a",
            "-acme",
            "Acme",
            "ac me",
            "acme_corp",
            "acme.corp",
            "acmé",
            "..",
            &"a".repeat(64),
        ] {
            assert!(!is_valid_slug(invalid), "{invalid}");
        }
    }
}
