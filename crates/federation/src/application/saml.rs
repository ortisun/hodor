//! Signing in through a SAML identity provider, as its service provider.
//!
//! See `docs/architecture/contexts/federation.md`, "Signing in through a
//! SAML identity provider". The checks of a response are the crate
//! `hodor-saml`; this is what the federation context does around them.

use crate::application::openid::{AuthorizationRequest, VerifiedIdentity};
use crate::domain::link::Subject;
use crate::domain::provider::{IdentityProvider, SamlSettings};
use hodor_kernel::{RandomSource, Secret, Timestamp};
use hodor_saml::{AuthenticationRequest, Expected, ServiceProvider};
use std::sync::Arc;

/// The largest SAML response accepted as it is posted, in bytes.
pub const MAX_SAML_POSTED_BYTES: usize = hodor_saml::MAX_POSTED_BYTES;

/// The service provider side of SAML.
#[derive(Clone)]
pub struct SamlClient {
    random: Arc<dyn RandomSource>,
}

impl std::fmt::Debug for SamlClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SamlClient").finish_non_exhaustive()
    }
}

/// Hodor's entity identifier for one SAML provider, which is also the
/// address of its metadata.
#[must_use]
pub fn saml_metadata_address(public_url: &str, tenant_slug: &str, alias: &str) -> String {
    metadata_address_of(&saml_assertion_consumer_address(
        public_url,
        tenant_slug,
        alias,
    ))
}

/// The metadata address that goes with an assertion consumer address.
pub(crate) fn metadata_address_of(assertion_consumer_address: &str) -> String {
    format!("{assertion_consumer_address}/metadata")
}

/// Where one SAML provider posts its responses.
#[must_use]
pub fn saml_assertion_consumer_address(public_url: &str, tenant_slug: &str, alias: &str) -> String {
    format!(
        "{}/t/{tenant_slug}/interaction/sign-in/providers/{alias}/saml",
        public_url.trim_end_matches('/')
    )
}

/// Hodor, as the service provider of one SAML provider.
#[must_use]
pub fn saml_service_provider(public_url: &str, tenant_slug: &str, alias: &str) -> ServiceProvider {
    service_provider_at(&saml_assertion_consumer_address(
        public_url,
        tenant_slug,
        alias,
    ))
}

/// Hodor, as the service provider whose assertion consumer address this is.
pub(crate) fn service_provider_at(assertion_consumer_address: &str) -> ServiceProvider {
    ServiceProvider::new(
        metadata_address_of(assertion_consumer_address),
        assertion_consumer_address,
    )
}

/// The settings of a provider of the kind `saml`. Every such provider has
/// them: its settings were checked as a whole.
pub(crate) fn settings_of(provider: &IdentityProvider) -> Option<&SamlSettings> {
    provider.snapshot().settings.saml.as_ref()
}

impl SamlClient {
    /// Wires the client to its random source.
    #[must_use]
    pub fn new(random: Arc<dyn RandomSource>) -> Self {
        Self { random }
    }

    /// A new receipt for a posted response: 256 random bits in hexadecimal.
    pub(crate) fn receipt(&self) -> String {
        let mut receipt = [0_u8; 32];
        self.random.fill(&mut receipt);
        receipt.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Prepares one request: the address at the identity provider, the
    /// relay state made for it, and the request's identifier in place of a
    /// nonce. There is no code verifier.
    #[must_use]
    pub(crate) fn begin(
        &self,
        settings: &SamlSettings,
        service_provider: &ServiceProvider,
        now: Timestamp,
    ) -> AuthorizationRequest {
        let mut state = [0_u8; 32];
        self.random.fill(&mut state);
        let state: String = state.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut id = [0_u8; 20];
        self.random.fill(&mut id);
        let id = hodor_saml::request_id(id);
        let request = AuthenticationRequest {
            id: &id,
            service_provider,
            single_sign_on_address: &settings.single_sign_on_address,
            issue_instant: now,
        };
        AuthorizationRequest {
            url: request.redirect_address(&state),
            state,
            nonce: id,
            code_verifier: Secret::new(String::new()),
        }
    }

    /// Checks a kept response against the request it must answer, and says
    /// who the person is. A refusal carries the reason of `hodor-saml`.
    pub(crate) fn finish(
        provider: &IdentityProvider,
        settings: &SamlSettings,
        service_provider: &ServiceProvider,
        response: &str,
        request_id: &str,
        now: Timestamp,
    ) -> Result<VerifiedIdentity, &'static str> {
        // The certificate was checked when it was stored; it is read again
        // here, and refused the same way if it can no longer be used.
        let key = settings.key().map_err(|_| "certificate_unusable")?;
        let assertion = hodor_saml::check_response(
            response,
            &Expected {
                service_provider,
                issuer: &provider.snapshot().settings.issuer,
                key: &key,
                request_id,
                now,
            },
        )
        .map_err(|refusal| refusal.reason().as_str())?;
        let subject = Subject::parse(assertion.name_id()).map_err(|_| "subject")?;
        let text = |name: &str, longest: usize| {
            assertion
                .first_value(name)
                .map(str::trim)
                .filter(|value| !value.is_empty() && value.chars().count() <= longest)
                .map(str::to_owned)
        };
        Ok(VerifiedIdentity {
            subject,
            email: text(&settings.email_attribute, 254),
            // SAML has no way of saying whether an address is vouched for;
            // that is the provider's setting.
            email_verified: false,
            name: text(&settings.name_attribute, 200),
            locale: None,
        })
    }
}
