//! What happens to keys, as other contexts hear about it.
//!
//! Events carry identifiers, uses, algorithms and times. They never carry
//! key material, and the public key stays in the version's row.

use crate::domain::authority::AuthorityId;
use crate::domain::intermediate::IntermediateId;
use crate::domain::key::KeyVersionId;
use crate::domain::trust_domain::TrustDomainId;
use hodor_kernel::{DomainEvent, Timestamp};
use serde::Serialize;

/// An event of the keys context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum KeyEvent {
    /// A key version was made.
    VersionCreated {
        /// The version.
        version_id: KeyVersionId,
        /// `sig`, `enc` or `data`.
        key_use: &'static str,
        /// Such as `ES256`.
        algorithm: &'static str,
    },
    /// A key version became the active one of its algorithm.
    VersionActivated {
        /// The version.
        version_id: KeyVersionId,
        /// Such as `ES256`.
        algorithm: &'static str,
        /// The version it replaced, which started retiring.
        replaced_version_id: Option<KeyVersionId>,
        /// When the replaced version may retire.
        #[serde(with = "time::serde::rfc3339::option")]
        replaced_retire_after: Option<Timestamp>,
    },
    /// A retiring key version was retired.
    VersionRetired {
        /// The version.
        version_id: KeyVersionId,
        /// Such as `ES256`.
        algorithm: &'static str,
    },
    /// A key version was revoked.
    VersionRevoked {
        /// The version.
        version_id: KeyVersionId,
        /// Such as `ES256`.
        algorithm: &'static str,
        /// The state it was in.
        previous_state: &'static str,
        /// Why.
        reason: String,
    },
}

impl DomainEvent for KeyEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::VersionCreated { .. } => "keys.version_created",
            Self::VersionActivated { .. } => "keys.version_activated",
            Self::VersionRetired { .. } => "keys.version_retired",
            Self::VersionRevoked { .. } => "keys.version_revoked",
        }
    }
}

/// What a bundle is, in an event: never its keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleSummary {
    /// The SHA-256 of the bundle as it is kept, in hexadecimal.
    pub bundle_sha256: String,
    /// Its `spiffe_sequence`.
    pub sequence: Option<u64>,
    /// How many `x509-svid` authorities it holds.
    pub x509_authorities: usize,
    /// How many `jwt-svid` keys it holds.
    pub jwt_authorities: usize,
}

/// An event of trust domains. Never carries the address of a bundle
/// endpoint, which can hold a token, nor the keys of a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum TrustDomainEvent {
    /// A trust domain was added.
    Added {
        /// The trust domain.
        trust_domain_id: TrustDomainId,
        /// Its name.
        name: String,
        /// `uploaded`, `bundle_endpoint`, `mesh` or `authority`.
        source: &'static str,
        /// Its bundle, unless it is checked by the mesh.
        #[serde(flatten, skip_serializing_if = "Option::is_none")]
        bundle: Option<BundleSummary>,
    },
    /// An administrator replaced its source or bundle.
    Replaced {
        /// The trust domain.
        trust_domain_id: TrustDomainId,
        /// Its name.
        name: String,
        /// `uploaded`, `bundle_endpoint`, `mesh` or `authority`.
        source: &'static str,
        /// Its bundle, unless it is checked by the mesh.
        #[serde(flatten, skip_serializing_if = "Option::is_none")]
        bundle: Option<BundleSummary>,
    },
    /// The worker fetched a bundle that differs from the one in force, and
    /// put it in force.
    BundleRefreshed {
        /// The trust domain.
        trust_domain_id: TrustDomainId,
        /// Its name.
        name: String,
        /// The new bundle.
        #[serde(flatten)]
        bundle: BundleSummary,
        /// The sequence number of the bundle it replaced.
        previous_sequence: Option<u64>,
    },
    /// A fetch failed, or its bundle was refused, after the last one had
    /// read.
    RefreshFailed {
        /// The trust domain.
        trust_domain_id: TrustDomainId,
        /// Its name.
        name: String,
        /// The code of the reason.
        reason: String,
    },
    /// A trust domain was removed.
    Removed {
        /// The trust domain.
        trust_domain_id: TrustDomainId,
        /// Its name.
        name: String,
    },
}

impl DomainEvent for TrustDomainEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Added { .. } => "keys.trust_domain_added",
            Self::Replaced { .. } => "keys.trust_domain_replaced",
            Self::BundleRefreshed { .. } => "keys.trust_bundle_refreshed",
            Self::RefreshFailed { .. } => "keys.trust_bundle_refresh_failed",
            Self::Removed { .. } => "keys.trust_domain_removed",
        }
    }
}

/// An event of a tenant's certificate authority. Never carries a key, a
/// certificate or a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AuthorityEvent {
    /// An authority was created.
    Created {
        /// The authority.
        authority_id: AuthorityId,
        /// `root` or `intermediate`.
        kind: &'static str,
        /// The trust domains it signs for.
        trust_domains: Vec<String>,
        /// The identifier its key was made for.
        key_id: KeyVersionId,
        /// The provider that made the key.
        provider: String,
        /// Whether it was made on an installation set to `development`.
        for_development: bool,
    },
    /// The authority's key signed something.
    Signed {
        /// The authority.
        authority_id: AuthorityId,
        /// `certificate`, `certificate_signing_request` or
        /// `intermediate_certificate`.
        signed: &'static str,
        /// The SHA-256 of the part signed, in hexadecimal.
        signed_sha256: String,
        /// The serial number of a certificate signed.
        #[serde(skip_serializing_if = "Option::is_none")]
        serial_number: Option<String>,
        /// The trust domains it was signed for.
        trust_domains: Vec<String>,
        /// The intermediate signed, for an intermediate's certificate.
        #[serde(skip_serializing_if = "Option::is_none")]
        intermediate_id: Option<IntermediateId>,
        /// The SHA-256 of the request it was signed from, in hexadecimal.
        #[serde(skip_serializing_if = "Option::is_none")]
        request_sha256: Option<String>,
    },
    /// The authority got its certificate.
    Activated {
        /// The authority.
        authority_id: AuthorityId,
        /// Its certificate's serial number.
        serial_number: String,
        /// Its certificate's SHA-256, in hexadecimal.
        certificate_sha256: String,
        /// When its certificate expires.
        #[serde(with = "time::serde::rfc3339")]
        not_after: Timestamp,
    },
    /// An intermediate it signed was withdrawn: its key is refused.
    IntermediateWithdrawn {
        /// The authority that signed it.
        authority_id: AuthorityId,
        /// The intermediate.
        intermediate_id: IntermediateId,
        /// Its serial number.
        serial_number: String,
        /// The SHA-256 of its subject public key info, in hexadecimal.
        public_key_sha256: String,
        /// Why.
        reason: String,
    },
    /// The authority was removed.
    Removed {
        /// The authority.
        authority_id: AuthorityId,
        /// The identifier its key was made for; the key stays in its
        /// provider.
        key_id: KeyVersionId,
    },
}

impl DomainEvent for AuthorityEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Created { .. } => "keys.authority_created",
            Self::Signed { .. } => "keys.authority_signed",
            Self::Activated { .. } => "keys.authority_activated",
            Self::IntermediateWithdrawn { .. } => "keys.intermediate_withdrawn",
            Self::Removed { .. } => "keys.authority_removed",
        }
    }
}
