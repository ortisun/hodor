//! The identity context.
//!
//! Owns users: who exists inside a tenant, how they are found, and whether
//! they may act. It does not know how a user proves who they are.
//!
//! The specification is `docs/architecture/contexts/identity.md`; this
//! crate follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::ports::UserRepository;
    pub use crate::application::service::{CreateUser, IdentityService};
    pub use crate::domain::event::UserEvent;
    pub use crate::domain::identifier::{
        IdentifierId, IdentifierKind, LoginIdentifier, NormalizedIdentifier,
    };
    pub use crate::domain::user::{Profile, User, UserKind, UserSnapshot, UserStatus};
}
