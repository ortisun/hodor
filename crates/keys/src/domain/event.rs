//! What happens to keys, as other contexts hear about it.
//!
//! Events carry identifiers, uses, algorithms and times. They never carry
//! key material, and the public key stays in the version's row.

use crate::domain::key::KeyVersionId;
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
