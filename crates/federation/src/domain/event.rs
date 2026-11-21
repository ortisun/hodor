//! What happens to providers and links, as other contexts hear about it.
//!
//! No event carries a secret, and none carries a subject: a subject
//! identifies a person at another organization, and events are kept for
//! a long time and read by many.

use crate::domain::provider::ProviderId;
use hodor_kernel::{DomainEvent, UserId};
use serde::Serialize;

/// An event of the federation context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum FederationEvent {
    /// A provider was added.
    ProviderCreated {
        /// The provider.
        provider_id: ProviderId,
        /// Its name in addresses.
        alias: String,
        /// How Hodor talks to it.
        kind: &'static str,
    },
    /// A provider's settings were changed.
    ProviderChanged {
        /// The provider.
        provider_id: ProviderId,
        /// Its name in addresses.
        alias: String,
    },
    /// A provider's secret was replaced.
    ProviderSecretChanged {
        /// The provider.
        provider_id: ProviderId,
        /// Its name in addresses.
        alias: String,
    },
    /// A provider stopped signing people in.
    ProviderDisabled {
        /// The provider.
        provider_id: ProviderId,
        /// Its name in addresses.
        alias: String,
    },
    /// A provider signs people in again.
    ProviderEnabled {
        /// The provider.
        provider_id: ProviderId,
        /// Its name in addresses.
        alias: String,
    },
    /// An external identity was linked to a user.
    IdentityLinked {
        /// The provider.
        provider_id: ProviderId,
        /// The user.
        user_id: UserId,
    },
    /// A link was removed.
    IdentityUnlinked {
        /// The provider.
        provider_id: ProviderId,
        /// The user.
        user_id: UserId,
    },
}

impl DomainEvent for FederationEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::ProviderCreated { .. } => "federation.provider_created",
            Self::ProviderChanged { .. } => "federation.provider_changed",
            Self::ProviderSecretChanged { .. } => "federation.provider_secret_changed",
            Self::ProviderDisabled { .. } => "federation.provider_disabled",
            Self::ProviderEnabled { .. } => "federation.provider_enabled",
            Self::IdentityLinked { .. } => "federation.identity_linked",
            Self::IdentityUnlinked { .. } => "federation.identity_unlinked",
        }
    }
}
