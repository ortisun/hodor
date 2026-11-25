//! Enrolling a second factor during a sign-in: what a person may set up,
//! what a sign-in began, and what finishing it put in use.
//!
//! Specified in `docs/architecture/contexts/authentication.md`, "Enrolling
//! a second factor during a sign-in".

use hodor_credential::api::{TotpId, WebAuthnRegistrationId};
use hodor_kernel::{DomainError, Secret};

/// What a person sets up at the enrollment step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EnrollmentKind {
    /// An authenticator application, from its secret.
    AuthenticatorApplication,
    /// A security key.
    SecurityKey,
    /// A passkey: a discoverable credential, unlocked by the person.
    Passkey,
}

impl EnrollmentKind {
    /// Every kind, in the order the pages offer them.
    pub const ALL: [Self; 3] = [
        Self::AuthenticatorApplication,
        Self::SecurityKey,
        Self::Passkey,
    ];

    /// The name used in storage, in events and at the interaction
    /// interface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticatorApplication => "authenticator_application",
            Self::SecurityKey => "security_key",
            Self::Passkey => "passkey",
        }
    }

    /// The kind of this name, if it is one.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == name)
    }

    /// Reads a kind from its stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error for an unknown name.
    pub fn from_stored(name: &str) -> Result<Self, DomainError> {
        Self::parse(name).ok_or_else(|| {
            DomainError::internal(
                "authentication.stored_data_invalid",
                "the sign-in could not be loaded",
            )
            .with_detail(format!("unknown stored enrollment kind `{name}`"))
        })
    }
}

/// What a sign-in began enrolling, kept in its transaction until the step
/// is satisfied: the enrollment of an application, or the registration of
/// a key, in the credential context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BegunEnrollment {
    /// An authenticator application, by its enrollment waiting to be
    /// confirmed.
    AuthenticatorApplication(TotpId),
    /// A security key, by its pending registration.
    SecurityKey(WebAuthnRegistrationId),
    /// A passkey, by its pending registration.
    Passkey(WebAuthnRegistrationId),
}

impl BegunEnrollment {
    /// What is being set up.
    #[must_use]
    pub const fn kind(self) -> EnrollmentKind {
        match self {
            Self::AuthenticatorApplication(_) => EnrollmentKind::AuthenticatorApplication,
            Self::SecurityKey(_) => EnrollmentKind::SecurityKey,
            Self::Passkey(_) => EnrollmentKind::Passkey,
        }
    }
}

/// What finishing an enrollment put in use, and the recovery codes made
/// with it, which are shown once.
#[derive(Debug, Clone)]
pub struct Enrolled {
    /// What was set up.
    pub kind: EnrollmentKind,
    /// A new set of recovery codes; empty when the person had unused ones.
    pub recovery_codes: Vec<Secret<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_reads_back_from_its_name() {
        for kind in EnrollmentKind::ALL {
            assert_eq!(EnrollmentKind::parse(kind.as_str()), Some(kind));
            assert_eq!(EnrollmentKind::from_stored(kind.as_str()).ok(), Some(kind));
        }
        assert_eq!(EnrollmentKind::parse("totp"), None);
        assert_eq!(
            EnrollmentKind::from_stored("totp").map_err(|e| e.code().to_owned()),
            Err("authentication.stored_data_invalid".to_owned())
        );
    }

    #[test]
    fn a_begun_enrollment_says_what_is_set_up() {
        let registration = WebAuthnRegistrationId::generate();
        assert_eq!(
            BegunEnrollment::AuthenticatorApplication(TotpId::generate()).kind(),
            EnrollmentKind::AuthenticatorApplication
        );
        assert_eq!(
            BegunEnrollment::SecurityKey(registration).kind(),
            EnrollmentKind::SecurityKey
        );
        assert_eq!(
            BegunEnrollment::Passkey(registration).kind(),
            EnrollmentKind::Passkey
        );
    }
}
