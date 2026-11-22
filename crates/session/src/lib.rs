//! The session context.
//!
//! Owns sessions: the record that a user signed in to a tenant from a
//! browser, and for how long that remains true. It does not sign anyone
//! in; it is told that someone did.
//!
//! The specification is `docs/architecture/contexts/session.md`; this
//! crate follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::ports::SessionStore;
    pub use crate::application::service::{SessionService, StartSession};
    pub use crate::domain::event::SessionEvent;
    pub use crate::domain::session::{
        Assurance, ClientInfo, Session, SessionId, SessionSnapshot, SessionState, SessionTimeouts,
        SessionToken, TokenHash,
    };
}
