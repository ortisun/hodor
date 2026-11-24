//! The event types an endpoint can be subscribed to.
//!
//! A fixed list: an event of a type that is not here is never sent. Each
//! type is here because something outside Hodor may need to react to it,
//! and because its event carries identifiers, kinds and states, never a
//! secret. The events of this context are not here, so that a webhook
//! never announces a change to webhooks. See
//! `docs/architecture/contexts/webhooks.md`, "Which events are published".

use hodor_kernel::DomainError;
use serde::{Serialize, Serializer};

/// Every event type that is published, in the order the specification
/// lists them.
pub const CATALOG: &[&str] = &[
    "identity.user_created",
    "identity.user_activated",
    "identity.user_suspended",
    "identity.user_reactivated",
    "identity.user_deactivated",
    "identity.user_restored",
    "identity.user_deleted",
    "identity.profile_changed",
    "identity.identifier_added",
    "identity.identifier_verified",
    "identity.identifier_removed",
    "identity.primary_identifier_changed",
    "identity.group_created",
    "identity.group_changed",
    "identity.group_deleted",
    "identity.group_member_added",
    "identity.group_member_removed",
    "identity.organization_created",
    "identity.organization_changed",
    "identity.organization_deleted",
    "identity.organization_member_added",
    "identity.organization_member_changed",
    "identity.organization_member_removed",
    "identity.invitation_accepted",
    "session.started",
    "session.raised",
    "session.revoked",
    "authentication.succeeded",
    "authentication.failed",
    "authentication.locked_out",
    "authentication.registration_completed",
    "authentication.password_reset",
    "credential.password_changed",
    "credential.totp_enrolled",
    "credential.totp_removed",
    "credential.webauthn_registered",
    "credential.webauthn_removed",
    "credential.recovery_codes_generated",
    "federation.identity_linked",
    "federation.identity_unlinked",
    "oauth.consent_given",
    "oauth.consent_withdrawn",
    "oauth.grant_revoked",
];

/// Whether events of this type are published.
#[must_use]
pub fn is_published(event_type: &str) -> bool {
    CATALOG.contains(&event_type)
}

/// A type of the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventType(&'static str);

impl EventType {
    /// Reads a type of the catalog.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.event_type_unknown` unless the type is in the
    /// catalog.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        CATALOG
            .iter()
            .find(|known| **known == name)
            .map(|known| Self(known))
            .ok_or_else(|| {
                DomainError::invalid(
                    "webhooks.event_type_unknown",
                    "an event type is not one that can be subscribed to",
                )
                .with_detail(name.chars().take(100).collect::<String>())
            })
    }

    /// The type's name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl Serialize for EventType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_type_is_listed_once_and_reads_back() {
        let unique: BTreeSet<&str> = CATALOG.iter().copied().collect();
        assert_eq!(unique.len(), CATALOG.len());
        for name in CATALOG {
            assert_eq!(EventType::parse(name).map(EventType::as_str), Ok(*name));
            assert!(is_published(name));
        }
    }

    #[test]
    fn the_contexts_own_events_and_configuration_changes_are_not_published() {
        for name in [
            "webhooks.endpoint_registered",
            "webhooks.delivery_set_aside",
            "federation.provider_created",
            "keys.version_created",
            "oauth.access_token_issued",
            "identity.user_created ",
            "",
        ] {
            assert!(!is_published(name), "{name}");
            let error = EventType::parse(name).expect_err("refused");
            assert_eq!(error.code(), "webhooks.event_type_unknown");
        }
    }
}
