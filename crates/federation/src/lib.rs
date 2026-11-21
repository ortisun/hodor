//! The federation context.
//!
//! Lets a person sign in to a tenant with an identity they already have
//! somewhere else. It knows the identity providers a tenant trusts and
//! which external identity belongs to which user.
//!
//! The specification of what is built is
//! `docs/architecture/contexts/federation.md`; this crate follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::ports::{LinkStore, ProviderStore};
    pub use crate::application::service::{ChangeProvider, CreateProvider, FederationService};
    pub use crate::domain::event::FederationEvent;
    pub use crate::domain::link::{ExternalIdentity, Subject};
    pub use crate::domain::provider::{
        Alias, IdentityProvider, ProviderId, ProviderKind, ProviderSettings, ProviderSnapshot,
        ProviderStatus,
    };
}
