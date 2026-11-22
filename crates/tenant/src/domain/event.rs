//! What happens to tenants, as other contexts hear about it.

use crate::domain::settings::TenantSettings;
use hodor_kernel::{DomainEvent, TenantId, Timestamp};
use serde::Serialize;

/// An event of the tenant context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum TenantEvent {
    /// A tenant was created.
    Created {
        /// The new tenant.
        tenant_id: TenantId,
        /// Its slug.
        slug: String,
        /// Its display name.
        display_name: String,
    },
    /// Provisioning finished and the tenant serves requests.
    Activated {
        /// The tenant.
        tenant_id: TenantId,
    },
    /// The tenant was suspended.
    Suspended {
        /// The tenant.
        tenant_id: TenantId,
        /// Why it was suspended.
        reason: String,
    },
    /// The tenant returned to active.
    Reactivated {
        /// The tenant.
        tenant_id: TenantId,
    },
    /// Deletion was scheduled.
    DeletionScheduled {
        /// The tenant.
        tenant_id: TenantId,
        /// The moment after which its data may be purged.
        #[serde(with = "time::serde::rfc3339")]
        deletion_date: Timestamp,
    },
    /// A scheduled deletion was cancelled.
    DeletionCancelled {
        /// The tenant.
        tenant_id: TenantId,
    },
    /// The tenant was marked deleted.
    Deleted {
        /// The tenant.
        tenant_id: TenantId,
    },
    /// The tenant's settings were replaced.
    SettingsChanged {
        /// The tenant.
        tenant_id: TenantId,
        /// The new settings.
        settings: TenantSettings,
    },
}

impl DomainEvent for TenantEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Created { .. } => "tenant.created",
            Self::Activated { .. } => "tenant.activated",
            Self::Suspended { .. } => "tenant.suspended",
            Self::Reactivated { .. } => "tenant.reactivated",
            Self::DeletionScheduled { .. } => "tenant.deletion_scheduled",
            Self::DeletionCancelled { .. } => "tenant.deletion_cancelled",
            Self::Deleted { .. } => "tenant.deleted",
            Self::SettingsChanged { .. } => "tenant.settings_changed",
        }
    }
}
