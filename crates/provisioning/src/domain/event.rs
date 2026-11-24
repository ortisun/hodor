//! What happens to what this context keeps, as other contexts hear about
//! it.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "Events".
//! Events carry identifiers and never values: a department or an employee
//! number is personal data and stays in the provisioning tables.

use hodor_kernel::{DomainEvent, GroupId, UserId};
use serde::Serialize;

/// An event of the provisioning context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ProvisioningEvent {
    /// What this context keeps of a user was set or changed.
    UserSupplementChanged {
        /// The user.
        user_id: UserId,
    },
    /// What this context keeps of a group was set or changed.
    GroupSupplementChanged {
        /// The group.
        group_id: GroupId,
    },
}

impl DomainEvent for ProvisioningEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::UserSupplementChanged { .. } => "provisioning.user_attributes_changed",
            Self::GroupSupplementChanged { .. } => "provisioning.group_attributes_changed",
        }
    }
}
