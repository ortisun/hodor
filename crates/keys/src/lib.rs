//! The keys context.
//!
//! Owns the keys a tenant's tokens are signed with and its secrets are
//! encrypted under: key sets per use, key versions and their lifecycle.
//! Also the keys of others a tenant trusts: its SPIFFE trust domains and
//! their bundles, given by an administrator or fetched from a bundle
//! endpoint and refreshed by the worker (Decision 0042). And the tenant's
//! certificate authority, when the installation turns it on (Decision
//! 0062).
//! It holds no cryptography: keys are made, kept and used by a
//! [`api::KeyProvider`].
//!
//! The specification is `docs/architecture/contexts/keys.md`; this crate
//! follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::authority::{AuthorityPorts, AuthorityService, NewAuthority};
    pub use crate::application::ports::{
        AuthorityStore, CertificateWriter, DueRefreshes, FirstFormatSecrets, KeyProvider, KeyStore,
        SealingStateStore, ToBeSigned, TrustDomainStore,
    };
    pub use crate::application::providers::KeyProviders;
    pub use crate::application::secret_box::{FORMAT as SEALED_FORMAT, LOST_RACE, TenantSecretBox};
    pub use crate::application::service::{KeyService, LOST_FIRST_RACE, RotationReport, Signature};
    pub use crate::application::trust_domains::{
        BundleRefresher, RefreshLease, RefreshOutcome, TrustDomainPorts, TrustDomainService,
        TrustSourceRequest,
    };
    pub use crate::domain::authority::{
        AuthorityId, AuthorityKey, AuthorityKind, AuthorityProfile, AuthorityRequest,
        AuthoritySetting, AuthorityState, BACKDATING, BUNDLE_REFRESH_HINT_SECONDS,
        CertificateAuthority, CertificateAuthoritySnapshot, CertificateFacts, DEFAULT_COMMON_NAME,
        DEFAULT_INTERMEDIATE_LIFETIME_DAYS, DEFAULT_ROOT_LIFETIME_DAYS, DEVELOPMENT_SUFFIX,
        EXCLUDED_IP_RANGES, FactsConstraints, IssuedCertificate, MAX_AUTHORITY_TRUST_DOMAINS,
        MAX_CHAIN_LENGTH, MAX_COMMON_NAME_LENGTH, MAX_INTERMEDIATE_LIFETIME_DAYS,
        MAX_ROOT_LIFETIME_DAYS, NameConstraints, PATH_LENGTH, authority_trust_domain, hexadecimal,
        to_pem,
    };
    pub use crate::domain::event::{AuthorityEvent, BundleSummary, KeyEvent, TrustDomainEvent};
    pub use crate::domain::key::{
        GeneratedKey, KeyAlgorithm, KeyMaterial, KeyState, KeyUse, KeyVersion, KeyVersionId,
        KeyVersionSnapshot, MAX_REASON_LENGTH, SignatureEncoding,
    };
    pub use crate::domain::key_set::{Activation, KeySet};
    pub use crate::domain::rotation::{RotationChange, RotationPolicy};
    pub use crate::domain::trust_domain::{
        BundleKey, CheckedSource, DEFAULT_REFRESH, FETCH_TIME_LIMIT, FetchOutcome, LONGEST_REFRESH,
        LONGEST_RETRY, MAX_BUNDLE_BYTES, MAX_BUNDLE_ELEMENTS, MAX_BUNDLE_ENDPOINT_LENGTH,
        MAX_ERROR_LENGTH, MAX_NAME_LENGTH, MAX_TRUST_DOMAINS, SHORTEST_REFRESH, SvidKind,
        TrustBundle, TrustDomain, TrustDomainId, TrustDomainName, TrustDomainSnapshot, TrustSource,
    };
}
