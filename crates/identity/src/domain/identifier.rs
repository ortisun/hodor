//! Login identifiers: the names a user can be found by.

use hodor_kernel::{DomainError, Timestamp};

hodor_kernel::define_id!(
    /// Identifies one login identifier of a user.
    IdentifierId
);

/// What sort of name a login identifier is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IdentifierKind {
    /// A name chosen by the user, such as `ana.silva`.
    Username,
    /// An email address.
    Email,
}

impl IdentifierKind {
    /// The name used in storage and in events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Email => "email",
        }
    }

    /// Reads a kind from its stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error for an unknown name, which indicates
    /// corrupted data or a missing migration.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "username" => Ok(Self::Username),
            "email" => Ok(Self::Email),
            other => Err(DomainError::internal(
                "identity.identifier_kind_unknown",
                "the user could not be loaded",
            )
            .with_detail(format!("unknown stored identifier kind `{other}`"))),
        }
    }

    /// Whether the user must prove control of identifiers of this kind.
    #[must_use]
    pub const fn needs_verification(self) -> bool {
        matches!(self, Self::Email)
    }
}

/// A login identifier that has passed the rules of its kind.
///
/// It keeps two forms: the value as the user typed it, for display, and
/// the normalized value, which is what is compared and kept unique.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedIdentifier {
    kind: IdentifierKind,
    normalized: String,
    display: String,
}

impl NormalizedIdentifier {
    /// Validates and normalizes a value of the given kind.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if the value breaks a rule of its kind.
    pub fn parse(kind: IdentifierKind, value: &str) -> Result<Self, DomainError> {
        let display = value.trim();
        let normalized = match kind {
            IdentifierKind::Username => normalize_username(display),
            IdentifierKind::Email => normalize_email(display),
        };
        normalized
            .map(|normalized| Self {
                kind,
                normalized,
                display: display.to_owned(),
            })
            .ok_or_else(|| match kind {
                IdentifierKind::Username => DomainError::invalid(
                    "identity.username_invalid",
                    "a username has 3 to 64 letters, digits, dots, underscores or hyphens, and starts with a letter or digit",
                ),
                IdentifierKind::Email => DomainError::invalid(
                    "identity.email_invalid",
                    "this is not a valid email address",
                ),
            })
    }

    /// Interprets what a person typed in a login form: an email address if
    /// it contains `@`, a username otherwise.
    ///
    /// A value that is not a well-formed identifier of its kind matches
    /// nobody, so this returns `None` rather than an error: a login form
    /// must not reveal the rules of valid identifiers.
    #[must_use]
    pub fn from_login(value: &str) -> Option<Self> {
        let kind = if value.contains('@') {
            IdentifierKind::Email
        } else {
            IdentifierKind::Username
        };
        Self::parse(kind, value).ok()
    }

    /// Rebuilds an identifier read from storage.
    #[must_use]
    pub const fn from_stored(kind: IdentifierKind, normalized: String, display: String) -> Self {
        Self {
            kind,
            normalized,
            display,
        }
    }

    /// The kind of identifier.
    #[must_use]
    pub const fn kind(&self) -> IdentifierKind {
        self.kind
    }

    /// The form that is compared and kept unique.
    #[must_use]
    pub fn normalized(&self) -> &str {
        &self.normalized
    }

    /// The form the user typed.
    #[must_use]
    pub fn display(&self) -> &str {
        &self.display
    }

    /// Whether two identifiers are the same name, however they were typed.
    #[must_use]
    pub fn same_as(&self, other: &Self) -> bool {
        self.kind == other.kind && self.normalized == other.normalized
    }
}

fn normalize_username(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let valid = (3..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    valid.then(|| value.to_ascii_lowercase())
}

fn normalize_email(value: &str) -> Option<String> {
    if !value.is_ascii() || value.len() > 254 {
        return None;
    }
    let (local, host) = value.split_once('@')?;
    let local_ok = (1..=64).contains(&local.len())
        && !host.contains('@')
        && local.bytes().all(|b| b.is_ascii_graphic());
    let labels: Vec<&str> = host.split('.').collect();
    let host_ok = labels.len() >= 2
        && labels.iter().all(|label| {
            let bytes = label.as_bytes();
            (1..=63).contains(&bytes.len())
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
                && bytes[0] != b'-'
                && bytes[bytes.len() - 1] != b'-'
        });
    (local_ok && host_ok).then(|| value.to_ascii_lowercase())
}

/// A login identifier as it belongs to a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginIdentifier {
    /// Identifies this login identifier.
    pub id: IdentifierId,
    /// The validated name.
    pub value: NormalizedIdentifier,
    /// When the user proved control of it, if they did.
    pub verified_at: Option<Timestamp>,
    /// Whether it is the user's primary identifier of its kind.
    pub primary: bool,
    /// When it was added.
    pub created_at: Timestamp,
}

impl LoginIdentifier {
    /// Whether the user proved control of this identifier.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        self.verified_at.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn username(value: &str) -> Result<NormalizedIdentifier, DomainError> {
        NormalizedIdentifier::parse(IdentifierKind::Username, value)
    }

    fn email(value: &str) -> Result<NormalizedIdentifier, DomainError> {
        NormalizedIdentifier::parse(IdentifierKind::Email, value)
    }

    #[test]
    fn usernames_are_validated_and_lowercased() {
        for (typed, normalized) in [
            ("ana", "ana"),
            ("Ana.Silva", "ana.silva"),
            ("  ana_silva-2  ", "ana_silva-2"),
            ("9lives", "9lives"),
        ] {
            let parsed = username(typed).expect(typed);
            assert_eq!(parsed.normalized(), normalized);
            assert_eq!(parsed.display(), typed.trim());
        }
        for invalid in [
            "",
            "ab",
            ".ana",
            "_ana",
            "ana silva",
            "ana@home",
            "aná",
            &"a".repeat(65),
        ] {
            let error = username(invalid).expect_err(invalid);
            assert_eq!(error.code(), "identity.username_invalid", "{invalid}");
        }
    }

    #[test]
    fn email_addresses_are_validated_and_lowercased() {
        for (typed, normalized) in [
            ("ana@example.com", "ana@example.com"),
            (" Ana.Silva@Example.COM ", "ana.silva@example.com"),
            ("ana+news@mail.example.co.uk", "ana+news@mail.example.co.uk"),
        ] {
            assert_eq!(email(typed).expect(typed).normalized(), normalized);
        }
        for invalid in [
            "",
            "ana",
            "@example.com",
            "ana@",
            "ana@example",
            "ana@@example.com",
            "ana@a@example.com",
            "ana@-example.com",
            "ana@example-.com",
            "ana@exa mple.com",
            "ana silva@example.com",
            "ana@example..com",
            "aná@example.com",
            "ana@exämple.com",
            &format!("{}@example.com", "a".repeat(65)),
            &format!("ana@{}.com", "a".repeat(250)),
        ] {
            let error = email(invalid).expect_err(invalid);
            assert_eq!(error.code(), "identity.email_invalid", "{invalid}");
        }
    }

    #[test]
    fn dots_and_tags_in_an_email_address_are_kept() {
        let plain = email("anasilva@example.com").expect("valid");
        let dotted = email("ana.silva@example.com").expect("valid");
        let tagged = email("anasilva+shop@example.com").expect("valid");
        assert!(!plain.same_as(&dotted));
        assert!(!plain.same_as(&tagged));
    }

    #[test]
    fn a_typed_login_is_an_email_when_it_has_an_at_sign() {
        let as_email = NormalizedIdentifier::from_login("Ana@Example.com").expect("email");
        assert_eq!(as_email.kind(), IdentifierKind::Email);
        assert_eq!(as_email.normalized(), "ana@example.com");

        let as_username = NormalizedIdentifier::from_login("Ana.Silva").expect("username");
        assert_eq!(as_username.kind(), IdentifierKind::Username);

        // Malformed input matches nobody; it is not an error.
        assert_eq!(NormalizedIdentifier::from_login("not an identifier"), None);
        assert_eq!(NormalizedIdentifier::from_login("broken@"), None);
    }

    #[test]
    fn the_same_text_as_username_and_email_never_collide() {
        // A username cannot contain `@`, and an email must.
        assert!(username("ana@example.com").is_err());
        assert!(email("ana.silva").is_err());
    }

    #[test]
    fn stored_kinds_round_trip() {
        for kind in [IdentifierKind::Username, IdentifierKind::Email] {
            assert_eq!(
                IdentifierKind::from_stored(kind.as_str()).expect("known"),
                kind
            );
        }
        assert!(IdentifierKind::from_stored("phone").is_err());
    }

    fn kind() -> impl Strategy<Value = IdentifierKind> {
        prop_oneof![Just(IdentifierKind::Username), Just(IdentifierKind::Email)]
    }

    proptest! {
        /// Normalizing an already normalized value changes nothing.
        #[test]
        fn normalization_is_idempotent(kind in kind(), value in "\\PC{0,80}") {
            if let Ok(first) = NormalizedIdentifier::parse(kind, &value) {
                let second = NormalizedIdentifier::parse(kind, first.normalized())
                    .expect("a normalized value is valid");
                prop_assert_eq!(second.normalized(), first.normalized());
            }
        }

        /// Spellings that differ only in letter case or surrounding spaces
        /// are the same identifier.
        #[test]
        fn case_and_surrounding_spaces_do_not_matter(
            local in "[a-z0-9]{1,10}",
            host in "[a-z0-9]{1,10}\\.[a-z]{2,6}",
            flips in proptest::collection::vec(any::<bool>(), 30),
        ) {
            let address = format!("{local}@{host}");
            let shouted: String = address
                .chars()
                .zip(flips.iter().cycle())
                .map(|(c, flip)| if *flip { c.to_ascii_uppercase() } else { c })
                .collect();
            let plain = NormalizedIdentifier::parse(IdentifierKind::Email, &address).expect("valid");
            let other = NormalizedIdentifier::parse(IdentifierKind::Email, &format!("  {shouted} "))
                .expect("valid");
            prop_assert!(plain.same_as(&other));
        }

        /// Whatever is typed, a login is classified consistently and never
        /// panics.
        #[test]
        fn any_typed_login_is_handled(value in "\\PC{0,300}") {
            if let Some(found) = NormalizedIdentifier::from_login(&value) {
                prop_assert_eq!(found.kind() == IdentifierKind::Email, value.contains('@'));
            }
        }
    }
}
