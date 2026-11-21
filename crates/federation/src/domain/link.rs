//! Links: whose an external identity is.

use crate::domain::provider::ProviderId;
use hodor_kernel::{DomainError, Timestamp, UserId};
use std::fmt;

/// A provider's own, unchanging identifier for a person. Compared
/// exactly: no trimming, no change of case.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subject(String);

impl Subject {
    /// Checks and wraps a subject: 1 to 255 characters, none of them a
    /// control character. Nothing is changed.
    ///
    /// # Errors
    ///
    /// Returns `federation.subject_invalid`.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let length = value.chars().count();
        if (1..=255).contains(&length) && !value.chars().any(char::is_control) {
            Ok(Self(value.to_owned()))
        } else {
            Err(DomainError::invalid(
                "federation.subject_invalid",
                "a subject is 1 to 255 characters",
            ))
        }
    }

    /// The subject as text. It identifies a person at another
    /// organization: store it, compare it, do not log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// A subject identifies a person at another organization, so it is not
/// written out by accident.
impl fmt::Debug for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Subject([REDACTED])")
    }
}

/// The record that one external identity belongs to one user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalIdentity {
    /// The identity provider.
    pub provider_id: ProviderId,
    /// The provider's identifier for the person.
    pub subject: Subject,
    /// The user it belongs to.
    pub user_id: UserId,
    /// When the link was made.
    pub linked_at: Timestamp,
    /// When the link last signed the user in.
    pub last_used_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subject_is_kept_exactly_and_never_printed() {
        let subject = Subject::parse(" MiXed Case | 123 ").expect("valid");
        assert_eq!(subject.expose(), " MiXed Case | 123 ");
        assert_ne!(subject, Subject::parse("mixed case | 123").expect("valid"));
        assert_eq!(format!("{subject:?}"), "Subject([REDACTED])");
    }

    #[test]
    fn a_subject_has_a_length_and_no_control_characters() {
        for invalid in ["", "line\nbreak", "nul\0", &"a".repeat(256)] {
            let error = Subject::parse(invalid).expect_err("invalid");
            assert_eq!(error.code(), "federation.subject_invalid");
        }
        assert!(Subject::parse(&"a".repeat(255)).is_ok());
    }
}
