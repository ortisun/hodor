//! The name a tenant has in addresses.

use hodor_kernel::DomainError;
use std::fmt;

/// Slugs that cannot be chosen for a tenant.
const RESERVED: &[&str] = &["system", "platform", "admin", "api", "static", "health"];

/// The slug of the tenant that holds the platform administrators.
const SYSTEM: &str = "system";

/// A tenant's slug: the name used in `https://host/t/{slug}`.
///
/// A slug has 2 to 63 characters, contains only lowercase letters, digits
/// and hyphens, starts and ends with a letter or digit, and has no two
/// hyphens in a row. It never changes once the tenant exists.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Slug(String);

impl Slug {
    /// Shortest slug, in characters.
    pub const MIN_LENGTH: usize = 2;
    /// Longest slug, in characters.
    pub const MAX_LENGTH: usize = 63;

    /// Parses a slug chosen for an ordinary tenant. Reserved slugs are
    /// rejected.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if the value breaks a slug rule or is
    /// reserved.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let slug = Self::well_formed(value)?;
        if RESERVED.contains(&value) {
            return Err(DomainError::invalid(
                "tenant.slug_reserved",
                "this slug is reserved",
            ));
        }
        Ok(slug)
    }

    /// The slug of the system tenant. Only the bootstrap path uses it.
    #[must_use]
    pub fn system() -> Self {
        Self(SYSTEM.to_owned())
    }

    /// Rebuilds a slug read from storage, where reserved slugs such as
    /// `system` legitimately appear.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if the stored value is not a well-formed
    /// slug, which indicates corrupted data.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        Self::well_formed(value)
    }

    /// Whether this is the system tenant's slug.
    #[must_use]
    pub fn is_system(&self) -> bool {
        self.0 == SYSTEM
    }

    /// The slug as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn well_formed(value: &str) -> Result<Self, DomainError> {
        let bytes = value.as_bytes();
        let allowed =
            |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-';
        let edge =
            |byte: Option<&u8>| byte.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());

        let valid = (Self::MIN_LENGTH..=Self::MAX_LENGTH).contains(&bytes.len())
            && bytes.iter().all(allowed)
            && edge(bytes.first())
            && edge(bytes.last())
            && !value.contains("--");
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(DomainError::invalid(
                "tenant.slug_invalid",
                "a slug has 2 to 63 lowercase letters, digits or single hyphens, and starts and ends with a letter or digit",
            ))
        }
    }
}

impl fmt::Display for Slug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn well_formed_slugs_are_accepted() {
        for value in [
            "ac",
            "acme",
            "acme-corp",
            "a1",
            "1a",
            "a-b-c",
            &"a".repeat(63),
        ] {
            assert_eq!(Slug::parse(value).expect(value).as_str(), value);
        }
    }

    #[test]
    fn malformed_slugs_are_rejected() {
        for value in [
            "",
            "a",
            "-acme",
            "acme-",
            "ac--me",
            "Acme",
            "ac me",
            "acme_corp",
            "acme.corp",
            "acmé",
            "..",
            &"a".repeat(64),
        ] {
            let error = Slug::parse(value).expect_err(value);
            assert_eq!(error.code(), "tenant.slug_invalid", "{value}");
        }
    }

    #[test]
    fn reserved_slugs_cannot_be_chosen() {
        for value in RESERVED {
            let error = Slug::parse(value).expect_err(value);
            assert_eq!(error.code(), "tenant.slug_reserved", "{value}");
        }
    }

    #[test]
    fn the_system_slug_exists_only_through_its_own_constructor() {
        assert!(Slug::system().is_system());
        assert!(Slug::parse("system").is_err());
        assert!(Slug::from_stored("system").expect("stored").is_system());
        assert!(!Slug::parse("acme").expect("acme").is_system());
    }

    #[test]
    fn stored_values_must_still_be_well_formed() {
        assert!(Slug::from_stored("Not A Slug").is_err());
    }

    proptest! {
        #[test]
        fn anything_accepted_obeys_every_rule(value in "\\PC{0,70}") {
            if let Ok(slug) = Slug::parse(&value) {
                let text = slug.as_str();
                prop_assert_eq!(text, value.as_str());
                prop_assert!((Slug::MIN_LENGTH..=Slug::MAX_LENGTH).contains(&text.len()));
                prop_assert!(text.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
                prop_assert!(!text.starts_with('-') && !text.ends_with('-'));
                prop_assert!(!text.contains("--"));
                prop_assert!(!RESERVED.contains(&text));
            }
        }

        #[test]
        fn every_generated_slug_is_accepted(value in "[a-z0-9]([a-z0-9]|-[a-z0-9]){1,20}") {
            prop_assume!(!RESERVED.contains(&value.as_str()));
            prop_assert!(Slug::parse(&value).is_ok());
        }
    }
}
