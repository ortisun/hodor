//! Registration access tokens: what a registered client manages its
//! registration with (RFC 7592).
//!
//! See `docs/architecture/contexts/oauth.md`, "The registration access
//! token", and Decision 0084.

use hodor_kernel::{Digest, RandomSource, Secret};
use std::fmt;

/// What every token starts with, so that a token found anywhere is
/// recognized.
pub const REGISTRATION_ACCESS_TOKEN_PREFIX: &str = "hodor_rat_";
/// Number of hexadecimal characters after the prefix: 32 random bytes.
const TOKEN_LENGTH: usize = 64;

/// The token itself. Given in the answer of a registration or of a change,
/// and stored nowhere.
pub struct RegistrationAccessTokenValue(Secret<String>);

impl RegistrationAccessTokenValue {
    pub(crate) fn generate(random: &dyn RandomSource) -> Self {
        let mut bytes = [0_u8; 32];
        random.fill(&mut bytes);
        let mut value =
            String::with_capacity(REGISTRATION_ACCESS_TOKEN_PREFIX.len() + TOKEN_LENGTH);
        value.push_str(REGISTRATION_ACCESS_TOKEN_PREFIX);
        for byte in bytes {
            value.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            value.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        Self(Secret::from(value))
    }

    /// The token, to be given to the client and nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for RegistrationAccessTokenValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegistrationAccessTokenValue([REDACTED])")
    }
}

/// Whether `value` has the shape of a registration access token: the
/// prefix and 64 lowercase hexadecimal characters.
#[must_use]
pub fn looks_like_registration_access_token(value: &str) -> bool {
    value
        .strip_prefix(REGISTRATION_ACCESS_TOKEN_PREFIX)
        .is_some_and(|rest| {
            rest.len() == TOKEN_LENGTH
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// The SHA-256 of a token; what is stored, on the client.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegistrationAccessTokenHash([u8; 32]);

impl RegistrationAccessTokenHash {
    /// The hash of a token Hodor just made.
    #[must_use]
    pub(crate) fn of(value: &RegistrationAccessTokenValue, digest: &dyn Digest) -> Self {
        Self(digest.sha256(value.expose().as_bytes()))
    }

    /// The hash of a token as presented, or `None` if the value does not
    /// have the shape of one: nothing is computed for it.
    #[must_use]
    pub fn of_presented(value: &str, digest: &dyn Digest) -> Option<Self> {
        looks_like_registration_access_token(value).then(|| Self(digest.sha256(value.as_bytes())))
    }

    /// Rebuilds a hash read from storage.
    #[must_use]
    pub const fn from_stored(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The bytes, for storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compares two hashes in time that does not depend on where they
    /// differ.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
    }
}

impl fmt::Debug for RegistrationAccessTokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegistrationAccessTokenHash(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::random::testing::{CountingRandom, FakeDigest};

    #[test]
    fn a_token_has_the_recognizable_beginning_and_hashes_to_what_is_stored() {
        let value = RegistrationAccessTokenValue::generate(&CountingRandom::default());
        let expected: String = (0_u8..32).map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(value.expose(), format!("hodor_rat_{expected}"));
        assert!(looks_like_registration_access_token(value.expose()));
        let stored = RegistrationAccessTokenHash::of(&value, &FakeDigest);
        let presented =
            RegistrationAccessTokenHash::of_presented(value.expose(), &FakeDigest).expect("shape");
        assert!(stored.matches(&presented));
        assert_eq!(
            format!("{value:?}"),
            "RegistrationAccessTokenValue([REDACTED])"
        );
        assert_eq!(format!("{stored:?}"), "RegistrationAccessTokenHash(..)");
    }

    #[test]
    fn a_value_without_the_shape_has_no_hash() {
        for value in [
            "",
            "hodor_rat_",
            &format!("hodor_rat_{}", "AB".repeat(32)),
            &format!("hodor_rat_{}", "ab".repeat(31)),
            &format!("hodor_iat_{}", "ab".repeat(32)),
            &format!("hodor_rat_{}0", "ab".repeat(32)),
        ] {
            assert!(
                RegistrationAccessTokenHash::of_presented(value, &FakeDigest).is_none(),
                "{value}"
            );
        }
    }

    #[test]
    fn another_token_does_not_match() {
        let random = CountingRandom::default();
        let one = RegistrationAccessTokenValue::generate(&random);
        let other = RegistrationAccessTokenValue::generate(&random);
        assert!(
            !RegistrationAccessTokenHash::of(&one, &FakeDigest)
                .matches(&RegistrationAccessTokenHash::of(&other, &FakeDigest))
        );
    }
}
