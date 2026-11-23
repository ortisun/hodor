//! Client secrets: what a confidential client proves who it is with at the
//! token endpoint, when it uses `client_secret_basic` or
//! `client_secret_post`.

use hodor_kernel::{Digest, DomainError, RandomSource, Secret, Timestamp};
use std::fmt;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies a client secret. Safe to show and to log: it grants
    /// nothing.
    ClientSecretId
);

/// What every secret starts with, so that tools that scan for leaked
/// secrets can recognize one.
const PREFIX: &str = "hodor_cs_";
/// Number of hexadecimal characters after the prefix: 32 random bytes.
const SECRET_LENGTH: usize = 64;

/// The secret itself. Returned once, when it is made, and stored nowhere.
pub struct ClientSecretValue(Secret<String>);

impl ClientSecretValue {
    fn generate(random: &dyn RandomSource) -> Self {
        let mut bytes = [0_u8; 32];
        random.fill(&mut bytes);
        let mut text = String::with_capacity(PREFIX.len() + SECRET_LENGTH);
        text.push_str(PREFIX);
        for byte in bytes {
            text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        Self(Secret::from(text))
    }

    /// The secret, to be handed to whoever asked for it and nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for ClientSecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientSecretValue([REDACTED])")
    }
}

/// The SHA-256 of a secret; what is stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientSecretHash([u8; 32]);

impl ClientSecretHash {
    /// The hash of a secret as presented, or `None` if the value does not
    /// have the shape of one. A malformed value cannot be any secret, so
    /// nothing is computed for it.
    #[must_use]
    pub fn of_presented(value: &str, digest: &dyn Digest) -> Option<Self> {
        let secret = value.strip_prefix(PREFIX)?;
        let well_formed = secret.len() == SECRET_LENGTH
            && secret
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

impl fmt::Debug for ClientSecretHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientSecretHash(..)")
    }
}

/// A stored secret of a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecret {
    /// Its identifier.
    pub id: ClientSecretId,
    /// The hash of the secret.
    pub hash: ClientSecretHash,
    /// When it was made.
    pub created_at: Timestamp,
    /// When it stops working.
    pub expires_at: Timestamp,
}

impl ClientSecret {
    /// The shortest time a secret may live.
    pub const SHORTEST_LIFETIME: Duration = Duration::days(1);
    /// The longest time a secret may live. There is no secret that does
    /// not expire.
    pub const LONGEST_LIFETIME: Duration = Duration::days(730);
    /// How long a secret lives unless the administrator chooses.
    pub const DEFAULT_LIFETIME: Duration = Duration::days(365);
    /// The longest a previous secret keeps working after a rotation.
    pub const LONGEST_OVERLAP: Duration = Duration::days(30);

    /// Makes a secret that lives for `lifetime`, and returns it with the
    /// secret itself, which is not available again.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the lifetime is shorter than a day or longer
    /// than 730 days.
    pub(crate) fn make(
        lifetime: Duration,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> Result<(Self, ClientSecretValue), DomainError> {
        if lifetime < Self::SHORTEST_LIFETIME || lifetime > Self::LONGEST_LIFETIME {
            return Err(DomainError::invalid(
                "oauth.client_secret_lifetime_invalid",
                "a client secret lives for at least one day and at most 730 days",
            ));
        }
        let value = ClientSecretValue::generate(random);
        let secret = Self {
            id: ClientSecretId::generate(),
            hash: ClientSecretHash(digest.sha256(value.expose().as_bytes())),
            created_at: now,
            expires_at: now + lifetime,
        };
        Ok((secret, value))
    }

    /// Whether the secret works at `now`.
    #[must_use]
    pub fn works_at(&self, now: Timestamp) -> bool {
        now < self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::random::testing::{CountingRandom, FakeDigest};

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    #[test]
    fn a_secret_has_the_recognizable_beginning_and_hashes_to_what_is_stored() {
        let (secret, value) = ClientSecret::make(
            ClientSecret::DEFAULT_LIFETIME,
            NOW,
            &CountingRandom::default(),
            &FakeDigest,
        )
        .expect("valid");
        assert!(value.expose().starts_with("hodor_cs_"));
        assert_eq!(value.expose().len(), 9 + 64);
        let presented =
            ClientSecretHash::of_presented(value.expose(), &FakeDigest).expect("well formed");
        assert!(presented.matches(&secret.hash));
        assert!(!presented.matches(&ClientSecretHash::from_stored([0; 32])));
        let shown = format!("{value:?} {secret:?}");
        assert!(!shown.contains(&value.expose()[9..]), "{shown}");
    }

    #[test]
    fn a_value_that_is_not_shaped_like_a_secret_has_no_hash() {
        let hex = "a".repeat(64);
        for value in [
            String::new(),
            hex.clone(),
            format!("hodor_cs_{}", "a".repeat(63)),
            format!("hodor_cs_{}", "A".repeat(64)),
            format!("hodor_at_{hex}"),
            format!(" hodor_cs_{hex}"),
        ] {
            assert!(
                ClientSecretHash::of_presented(&value, &FakeDigest).is_none(),
                "{value}"
            );
        }
    }

    #[test]
    fn there_is_no_secret_that_does_not_expire() {
        for lifetime in [
            Duration::ZERO,
            Duration::hours(23),
            Duration::days(731),
            Duration::days(-1),
        ] {
            let error = ClientSecret::make(lifetime, NOW, &CountingRandom::default(), &FakeDigest)
                .expect_err("refused");
            assert_eq!(error.code(), "oauth.client_secret_lifetime_invalid");
        }
        let (secret, _) = ClientSecret::make(
            Duration::days(1),
            NOW,
            &CountingRandom::default(),
            &FakeDigest,
        )
        .expect("one day");
        assert!(secret.works_at(NOW + Duration::hours(23)));
        assert!(!secret.works_at(NOW + Duration::days(1)));
    }
}
