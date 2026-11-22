//! The credential context.
//!
//! Owns what a user proves their identity with, and answers one kind of
//! question: is this the right secret for this user? It does not decide
//! whether a sign-in succeeds.
//!
//! The specification is `docs/architecture/contexts/credential.md`; this
//! crate follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::access_tokens::{AccessTokenService, AccessTokenStore};
    pub use crate::application::ports::{PasswordHasher, PasswordStore, PasswordVerification};
    pub use crate::application::service::{CredentialService, NewPassword, PasswordCheck};
    pub use crate::domain::access_token::{
        AccessToken, AccessTokenEvent, AccessTokenHash, AccessTokenId, AccessTokenSecret,
        AccessTokenSnapshot,
    };
    pub use crate::domain::event::PasswordEvent;
    pub use crate::domain::password::{
        HistoricHash, MAX_PASSWORD_BYTES, PasswordHash, PasswordRecord, PasswordRules,
        check_acceptable,
    };
}
