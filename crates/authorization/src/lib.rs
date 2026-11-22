//! The authorization context.
//!
//! Answers one question: may this user do this? Other parts of Hodor ask
//! it and obey the answer.
//!
//! The specification of what is built is
//! `docs/architecture/contexts/authorization.md`; this crate follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::ports::RoleAssignmentStore;
    pub use crate::application::service::AuthorizationService;
    pub use crate::domain::event::AuthorizationEvent;
    pub use crate::domain::role::{Decision, Effect, Permission, Role};
}
