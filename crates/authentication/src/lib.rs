//! The authentication context.
//!
//! Decides whether someone has proved who they are: runs a sign-in from
//! the first step to the moment a session starts. It owns the procedure,
//! not the users, credentials or sessions.
//!
//! The specification is `docs/architecture/contexts/authentication.md`;
//! this crate follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::authenticators::{IdentifierAuthenticator, PasswordAuthenticator};
    pub use crate::application::guard::AttemptGuard;
    pub use crate::application::ports::AttemptStore;
    pub use crate::domain::attempt::{AttemptCounter, AttemptSubject, LockoutRules};
    pub use crate::domain::authenticator::{
        Authenticator, AuthenticatorTraits, Factor, StepInput, StepOutcome,
    };
    pub use crate::domain::engine::{FlowEngine, Progress};
    pub use crate::domain::event::AuthenticationEvent;
    pub use crate::domain::flow::{AuthFlow, FlowStep, Requirement};
    pub use crate::domain::transaction::{
        AuthTransaction, TransactionId, TransactionSnapshot, TransactionState, TransactionStatus,
    };
}
