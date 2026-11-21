//! Access tokens: what lets a program act as a user on the administration
//! interface, until OAuth access tokens exist.

use hodor_kernel::{Digest, DomainError, DomainEvent, RandomSource, Secret, Timestamp, UserId};
use serde::Serialize;
use std::fmt;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies an access token. Safe to show and to log: it grants
    /// nothing.
    AccessTokenId
);

/// What every token starts with, so that tools that scan for leaked
/// secrets can recognize one.
const PREFIX: &str = "hodor_at_";
/// Number of hexadecimal characters after the prefix: 32 random bytes.
const SECRET_LENGTH: usize = 64;
/// The longest note of what a token is for.
const MAX_DESCRIPTION_LENGTH: usize = 200;

/// The token itself. Returned once, when it is issued, and stored nowhere.
pub struct AccessTokenSecret(Secret<String>);

impl AccessTokenSecret {
    /// The shortest time a token may live.
    pub const SHORTEST_LIFETIME: Duration = Duration::minutes(1);
    /// The longest time a token may live. There is no token that does not
    /// expire.
    pub const LONGEST_LIFETIME: Duration = Duration::days(30);

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

    /// The token, to be handed to whoever asked for it and nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for AccessTokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessTokenSecret([REDACTED])")
    }
}

/// The SHA-256 of a token; what is stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccessTokenHash([u8; 32]);

impl AccessTokenHash {
    /// The hash of a token as presented, or `None` if the value does not
    /// have the shape of one. A malformed value cannot be any token, so
    /// nothing is computed or looked up for it.
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
}

impl fmt::Debug for AccessTokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessTokenHash(..)")
    }
}

/// Everything stored about an access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenSnapshot {
    /// The token's identifier.
    pub id: AccessTokenId,
    /// The user the token acts as.
    pub user_id: UserId,
    /// The hash of the token.
    pub token_hash: AccessTokenHash,
    /// What the token is for, as written by whoever issued it.
    pub description: String,
    /// When it was issued.
    pub created_at: Timestamp,
    /// When it stops working.
    pub expires_at: Timestamp,
    /// When it was revoked, if it was.
    pub revoked_at: Option<Timestamp>,
}

/// An access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    state: AccessTokenSnapshot,
}

impl AccessToken {
    /// Issues a token for a user and returns it with the token itself,
    /// which is not available again.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the lifetime is shorter than a minute or
    /// longer than 30 days, or if the description is empty, longer than
    /// 200 characters or has a control character.
    pub fn issue(
        user_id: UserId,
        description: &str,
        lifetime: Duration,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> Result<(Self, AccessTokenSecret), DomainError> {
        if lifetime < AccessTokenSecret::SHORTEST_LIFETIME
            || lifetime > AccessTokenSecret::LONGEST_LIFETIME
        {
            return Err(DomainError::invalid(
                "credential.access_token_lifetime_invalid",
                "an access token lives for at least one minute and at most 30 days",
            ));
        }
        let description = description.trim();
        if description.is_empty()
            || description.chars().count() > MAX_DESCRIPTION_LENGTH
            || description.chars().any(char::is_control)
        {
            return Err(DomainError::invalid(
                "credential.access_token_description_invalid",
                "say what the token is for, in at most 200 characters",
            ));
        }
        let secret = AccessTokenSecret::generate(random);
        let token = Self {
            state: AccessTokenSnapshot {
                id: AccessTokenId::generate(),
                user_id,
                token_hash: AccessTokenHash(digest.sha256(secret.expose().as_bytes())),
                description: description.to_owned(),
                created_at: now,
                expires_at: now + lifetime,
                revoked_at: None,
            },
        };
        Ok((token, secret))
    }

    /// Rebuilds a token from storage.
    #[must_use]
    pub const fn from_snapshot(state: AccessTokenSnapshot) -> Self {
        Self { state }
    }

    /// Everything stored about the token.
    #[must_use]
    pub const fn snapshot(&self) -> &AccessTokenSnapshot {
        &self.state
    }

    /// The token's identifier.
    #[must_use]
    pub const fn id(&self) -> AccessTokenId {
        self.state.id
    }

    /// The user the token acts as.
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.state.user_id
    }

    /// Whether the token works at `now`: not expired and not revoked.
    #[must_use]
    pub fn is_good_at(&self, now: Timestamp) -> bool {
        self.state.revoked_at.is_none() && now < self.state.expires_at
    }

    /// Ends the token. Returns the event if anything changed; revoking is
    /// final and repeating it changes nothing.
    pub fn revoke(&mut self, now: Timestamp) -> Option<AccessTokenEvent> {
        if self.state.revoked_at.is_some() {
            return None;
        }
        self.state.revoked_at = Some(now);
        Some(AccessTokenEvent::Revoked {
            user_id: self.state.user_id,
            token_id: self.state.id,
        })
    }

    /// The event that says the token was issued.
    #[must_use]
    pub const fn issued_event(&self) -> AccessTokenEvent {
        AccessTokenEvent::Issued {
            user_id: self.state.user_id,
            token_id: self.state.id,
            expires_at: self.state.expires_at,
        }
    }
}

/// An event about an access token. Carries identifiers and nothing derived
/// from the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AccessTokenEvent {
    /// A token was issued.
    Issued {
        /// The user it acts as.
        user_id: UserId,
        /// The token's identifier.
        token_id: AccessTokenId,
        /// When it stops working.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: Timestamp,
    },
    /// A token was revoked.
    Revoked {
        /// The user it acted as.
        user_id: UserId,
        /// The token's identifier.
        token_id: AccessTokenId,
    },
}

impl DomainEvent for AccessTokenEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Issued { .. } => "credential.access_token_issued",
            Self::Revoked { .. } => "credential.access_token_revoked",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::random::testing::{CountingRandom, FakeDigest};

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn issue(
        description: &str,
        lifetime: Duration,
    ) -> Result<(AccessToken, AccessTokenSecret), DomainError> {
        AccessToken::issue(
            UserId::generate(),
            description,
            lifetime,
            NOW,
            &CountingRandom::default(),
            &FakeDigest,
        )
    }

    #[test]
    fn a_token_has_the_recognizable_beginning_and_hashes_to_what_is_stored() {
        let (token, secret) = issue("first administrator", Duration::hours(1)).expect("valid");
        assert!(secret.expose().starts_with("hodor_at_"));
        assert_eq!(secret.expose().len(), 9 + 64);
        assert_eq!(
            AccessTokenHash::of_presented(secret.expose(), &FakeDigest),
            Some(token.snapshot().token_hash)
        );
        let shown = format!("{secret:?} {token:?}");
        assert!(!shown.contains(&secret.expose()[9..]), "{shown}");
    }

    #[test]
    fn a_value_that_is_not_shaped_like_a_token_has_no_hash() {
        let hex = "a".repeat(64);
        for value in [
            String::new(),
            hex.clone(),
            format!("hodor_at_{}", "a".repeat(63)),
            format!("hodor_at_{}", "A".repeat(64)),
            format!("hodor_at_{}", "g".repeat(64)),
            format!("Hodor_at_{hex}"),
            format!(" hodor_at_{hex}"),
        ] {
            assert_eq!(
                AccessTokenHash::of_presented(&value, &FakeDigest),
                None,
                "{value}"
            );
        }
        assert!(AccessTokenHash::of_presented(&format!("hodor_at_{hex}"), &FakeDigest).is_some());
    }

    #[test]
    fn a_token_works_until_it_expires_or_is_revoked() {
        let (mut token, _) = issue("automation", Duration::hours(1)).expect("valid");
        assert!(token.is_good_at(NOW));
        assert!(token.is_good_at(NOW + Duration::minutes(59)));
        assert!(!token.is_good_at(NOW + Duration::hours(1)));

        assert!(token.revoke(NOW + Duration::minutes(5)).is_some());
        assert!(!token.is_good_at(NOW + Duration::minutes(5)));
        assert_eq!(token.revoke(NOW + Duration::minutes(6)), None);
        assert_eq!(
            token.snapshot().revoked_at,
            Some(NOW + Duration::minutes(5))
        );
    }

    #[test]
    fn there_is_no_token_that_does_not_expire() {
        for lifetime in [
            Duration::seconds(59),
            Duration::ZERO,
            Duration::seconds(-1),
            Duration::days(30) + Duration::seconds(1),
            Duration::days(3650),
        ] {
            let error = issue("automation", lifetime).expect_err("refused");
            assert_eq!(error.code(), "credential.access_token_lifetime_invalid");
        }
        assert!(issue("automation", Duration::minutes(1)).is_ok());
        assert!(issue("automation", Duration::days(30)).is_ok());
    }

    #[test]
    fn a_token_says_what_it_is_for() {
        for description in ["", "   ", "two\nlines", &"x".repeat(201)] {
            let error = issue(description, Duration::hours(1)).expect_err("refused");
            assert_eq!(error.code(), "credential.access_token_description_invalid");
        }
        let (token, _) = issue("  nightly export  ", Duration::hours(1)).expect("valid");
        assert_eq!(token.snapshot().description, "nightly export");
    }
}
