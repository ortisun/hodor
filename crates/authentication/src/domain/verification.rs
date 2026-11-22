//! Verification tokens: what the link in a message carries.
//!
//! A token proves that whoever presents it read a message sent to an email
//! address. It is made and stored like a session token: 32 random bytes,
//! of which only the SHA-256 is kept.

use hodor_kernel::{Digest, DomainError, RandomSource, Secret, Timestamp, UserId};
use std::fmt;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies a verification token.
    VerificationTokenId
);

/// What a token lets its holder finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TokenPurpose {
    /// Creating an account for an email address that has none.
    Registration,
    /// Choosing a new password for a user.
    PasswordRecovery,
}

impl TokenPurpose {
    /// The name the purpose is stored under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::PasswordRecovery => "password_recovery",
        }
    }

    /// Reads a stored purpose.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if there is no such purpose.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        [Self::Registration, Self::PasswordRecovery]
            .into_iter()
            .find(|purpose| purpose.as_str() == value)
            .ok_or_else(|| {
                DomainError::invalid(
                    "authentication.unknown_token_purpose",
                    "there is no such token purpose",
                )
            })
    }

    /// How long a token of this purpose is good for.
    #[must_use]
    pub const fn lifetime(self) -> Duration {
        match self {
            Self::Registration => Duration::hours(24),
            Self::PasswordRecovery => Duration::hours(1),
        }
    }
}

/// The secret a link carries: 32 random bytes as 64 hexadecimal
/// characters. Returned once, when the token is made, and stored nowhere.
pub struct VerificationSecret(Secret<String>);

impl VerificationSecret {
    /// Number of characters in a secret.
    pub const LENGTH: usize = 64;

    fn generate(random: &dyn RandomSource) -> Self {
        let mut bytes = [0_u8; 32];
        random.fill(&mut bytes);
        let mut text = String::with_capacity(Self::LENGTH);
        for byte in bytes {
            text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        Self(Secret::from(text))
    }

    /// The secret, to be put in the link and nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for VerificationSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerificationSecret([REDACTED])")
    }
}

/// The SHA-256 of a token's secret; what is stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerificationTokenHash([u8; 32]);

impl VerificationTokenHash {
    /// The hash of a secret as presented, or `None` if the value does not
    /// have the shape of one. A malformed value cannot belong to any
    /// token, so nothing is computed or looked up for it.
    #[must_use]
    pub fn of_presented(value: &str, digest: &dyn Digest) -> Option<Self> {
        let well_formed = value.len() == VerificationSecret::LENGTH
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        well_formed.then(|| Self(digest.sha256(value.as_bytes())))
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
}

impl fmt::Debug for VerificationTokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerificationTokenHash(..)")
    }
}

/// Everything stored about a verification token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationTokenSnapshot {
    /// The token.
    pub id: VerificationTokenId,
    /// What it lets its holder finish.
    pub purpose: TokenPurpose,
    /// The hash of its secret.
    pub token_hash: VerificationTokenHash,
    /// The normalized email address the link was sent to.
    pub email: String,
    /// The user, for password recovery.
    pub user_id: Option<UserId>,
    /// The language asked for, used for later messages.
    pub locale: String,
    /// When it was made.
    pub created_at: Timestamp,
    /// When it stops being good.
    pub expires_at: Timestamp,
    /// When it was used up.
    pub used_at: Option<Timestamp>,
    /// When a newer token took its place.
    pub replaced_at: Option<Timestamp>,
}

/// A verification token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationToken {
    state: VerificationTokenSnapshot,
}

impl VerificationToken {
    /// Makes a token and returns it with its secret. The secret is not
    /// available again.
    #[must_use]
    pub fn issue(
        purpose: TokenPurpose,
        email: &str,
        user_id: Option<UserId>,
        locale: &str,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> (Self, VerificationSecret) {
        let secret = VerificationSecret::generate(random);
        let token = Self {
            state: VerificationTokenSnapshot {
                id: VerificationTokenId::generate(),
                purpose,
                token_hash: VerificationTokenHash(digest.sha256(secret.expose().as_bytes())),
                email: email.to_owned(),
                user_id,
                locale: locale.to_owned(),
                created_at: now,
                expires_at: now + purpose.lifetime(),
                used_at: None,
                replaced_at: None,
            },
        };
        (token, secret)
    }

    /// Rebuilds a token from storage.
    #[must_use]
    pub const fn from_snapshot(state: VerificationTokenSnapshot) -> Self {
        Self { state }
    }

    /// Everything stored about the token.
    #[must_use]
    pub const fn snapshot(&self) -> &VerificationTokenSnapshot {
        &self.state
    }

    /// The token's identifier.
    #[must_use]
    pub const fn id(&self) -> VerificationTokenId {
        self.state.id
    }

    /// Whether the token can still be used at `now`: unused, not replaced
    /// by a newer one, and not expired.
    #[must_use]
    pub fn is_good_at(&self, now: Timestamp) -> bool {
        self.state.used_at.is_none()
            && self.state.replaced_at.is_none()
            && now < self.state.expires_at
    }

    /// Records that the token was used up.
    pub const fn mark_used(&mut self, now: Timestamp) {
        self.state.used_at = Some(now);
    }

    /// Records that a newer token took this one's place.
    pub const fn mark_replaced(&mut self, now: Timestamp) {
        self.state.replaced_at = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::random::testing::{CountingRandom, FakeDigest};

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn issue(purpose: TokenPurpose) -> (VerificationToken, VerificationSecret) {
        VerificationToken::issue(
            purpose,
            "ana@example.com",
            None,
            "en",
            NOW,
            &CountingRandom::default(),
            &FakeDigest,
        )
    }

    #[test]
    fn a_new_token_is_good_until_it_expires() {
        let (registration, _) = issue(TokenPurpose::Registration);
        assert!(registration.is_good_at(NOW));
        assert!(registration.is_good_at(NOW + Duration::hours(24) - Duration::seconds(1)));
        assert!(!registration.is_good_at(NOW + Duration::hours(24)));

        let (recovery, _) = issue(TokenPurpose::PasswordRecovery);
        assert!(recovery.is_good_at(NOW + Duration::minutes(59)));
        assert!(!recovery.is_good_at(NOW + Duration::hours(1)));
    }

    #[test]
    fn a_used_or_replaced_token_is_no_longer_good() {
        let (mut used, _) = issue(TokenPurpose::Registration);
        used.mark_used(NOW);
        assert!(!used.is_good_at(NOW));

        let (mut replaced, _) = issue(TokenPurpose::Registration);
        replaced.mark_replaced(NOW);
        assert!(!replaced.is_good_at(NOW));
    }

    #[test]
    fn the_secret_hashes_to_what_is_stored_and_is_never_shown() {
        let (token, secret) = issue(TokenPurpose::Registration);
        assert_eq!(secret.expose().len(), VerificationSecret::LENGTH);
        assert_eq!(
            VerificationTokenHash::of_presented(secret.expose(), &FakeDigest),
            Some(token.snapshot().token_hash)
        );
        let shown = format!("{secret:?} {token:?}");
        assert!(!shown.contains(secret.expose()), "{shown}");
    }

    #[test]
    fn a_value_that_is_not_shaped_like_a_secret_has_no_hash() {
        for value in ["", "abc", &"g".repeat(64), &"A".repeat(64), &"a".repeat(65)] {
            assert_eq!(
                VerificationTokenHash::of_presented(value, &FakeDigest),
                None
            );
        }
        assert!(VerificationTokenHash::of_presented(&"a".repeat(64), &FakeDigest).is_some());
    }

    #[test]
    fn stored_purposes_round_trip() {
        for purpose in [TokenPurpose::Registration, TokenPurpose::PasswordRecovery] {
            assert_eq!(
                TokenPurpose::from_stored(purpose.as_str()).ok(),
                Some(purpose)
            );
        }
        assert!(TokenPurpose::from_stored("nope").is_err());
    }
}
