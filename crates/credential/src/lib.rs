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
    pub use crate::application::recovery_codes::{
        RecoveryCodeCheck, RecoveryCodeService, RecoveryCodeStore,
    };
    pub use crate::application::service::{CredentialService, NewPassword, PasswordCheck};
    pub use crate::application::totp::{HmacSha1, TotpCheck, TotpService, TotpStore, totp_code_at};
    pub use crate::application::webauthn::{
        AssertionChallenge, BegunRegistration, WebAuthnService, WebAuthnStore,
    };
    pub use crate::domain::access_token::{
        AccessToken, AccessTokenEvent, AccessTokenHash, AccessTokenId, AccessTokenSecret,
        AccessTokenSnapshot,
    };
    pub use crate::domain::event::PasswordEvent;
    pub use crate::domain::password::{
        HistoricHash, MAX_PASSWORD_BYTES, PasswordHash, PasswordRecord, PasswordRules,
        check_acceptable,
    };
    pub use crate::domain::recovery_code::{
        CODE_CHARACTERS as RECOVERY_CODE_CHARACTERS, CODES_PER_SET as RECOVERY_CODES_PER_SET,
        RecoveryCodeEvent, RecoveryCodeSet, RecoveryCodeSetId, RecoveryCodes,
        read_code as read_recovery_code,
    };
    pub use crate::domain::totp::{
        ENROLLMENT_LIFETIME, SEALING_PURPOSE as TOTP_SEALING_PURPOSE, STEP_SECONDS, Totp,
        TotpEnrollment, TotpEvent, TotpId, TotpSnapshot, TotpStatus,
    };
    pub use crate::domain::webauthn::{
        AssertionResponse, Challenge, CoseAlgorithm, CreationOptions, CredentialDescriptor,
        PendingRegistration, PendingRegistrationSnapshot, RegistrationResponse, RelyingParty,
        RequestOptions, WebAuthnCredential, WebAuthnCredentialId, WebAuthnCredentialSnapshot,
        WebAuthnEvent, WebAuthnRegistrationId, user_handle,
    };
}
