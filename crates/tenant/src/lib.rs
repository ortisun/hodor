//! The tenant context.
//!
//! Owns tenants, the hard isolation boundary of Hodor: which tenants exist,
//! whether a tenant may serve requests, and which policies apply inside it.
//!
//! The specification is `docs/architecture/contexts/tenant.md`; this crate
//! follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::ports::{DirectoryEntry, TenantDirectory, TenantRepository};
    pub use crate::application::service::{CreateTenant, TenantService};
    pub use crate::domain::event::TenantEvent;
    pub use crate::domain::settings::{
        ACR_MULTI_FACTOR, ACR_SINGLE_FACTOR, AssuranceLevel, AssuranceLevels, AssuranceRequirement,
        AuthenticationPolicy, Deprovisioning, GroupPolicy, LockoutPolicy, PasswordPolicy,
        ProvisioningPolicy, RegistrationPolicy, SecondFactorPolicy, SessionPolicy, TenantSettings,
    };
    pub use crate::domain::slug::Slug;
    pub use crate::domain::tenant::{Tenant, TenantSnapshot, TenantStatus};
    pub use hodor_kernel::Caller;
}
