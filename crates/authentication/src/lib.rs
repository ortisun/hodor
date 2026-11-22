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
    pub use crate::application::account::{AccountRequest, AccountService};
    pub use crate::application::authenticators::{
        IdentifierAuthenticator, PasskeyAuthenticator, PasswordAuthenticator,
        RecoveryCodeAuthenticator, TotpAuthenticator, WebAuthnAuthenticator,
    };
    pub use crate::application::factors::FactorService;
    pub use crate::application::guard::AttemptGuard;
    pub use crate::application::ports::{AttemptStore, TransactionStore, VerificationTokenStore};
    pub use crate::application::service::{AuthenticationService, SignIn, StartedSignIn};
    pub use crate::domain::attempt::{AttemptCounter, AttemptSubject, LockoutRules};
    pub use crate::domain::authenticator::{
        Authenticator, AuthenticatorTraits, ExternalInput, Factor, StepChallenge, StepInput,
        StepOutcome,
    };
    pub use crate::domain::engine::{FlowEngine, Progress};
    pub use crate::domain::event::AuthenticationEvent;
    pub use crate::domain::flow::{AuthFlow, Condition, FlowStep, Requirement};
    pub use crate::domain::transaction::{
        AuthTransaction, TransactionId, TransactionSnapshot, TransactionState, TransactionStatus,
    };
    pub use crate::domain::verification::{
        TokenPurpose, VerificationSecret, VerificationToken, VerificationTokenHash,
        VerificationTokenId, VerificationTokenSnapshot,
    };
}
