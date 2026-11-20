//! The tenant context.
//!
//! Owns tenants, the hard isolation boundary of Hodor: which tenants exist,
//! whether a tenant may serve requests, and which policies apply inside it.
//!
//! The specification is `docs/architecture/contexts/tenant.md`; this crate
//! follows it.

mod domain;

/// What other crates may use from this context.
pub mod api {
    pub use crate::domain::event::TenantEvent;
    pub use crate::domain::settings::{
        LockoutPolicy, PasswordPolicy, RegistrationPolicy, SessionPolicy, TenantSettings,
    };
    pub use crate::domain::slug::Slug;
    pub use crate::domain::tenant::{Tenant, TenantSnapshot, TenantStatus};
}
