//! Initial access tokens: what an administrator hands to a developer, who
//! presents it to register a client (RFC 7591, section 3).
//!
//! See `docs/architecture/contexts/oauth.md`, "Initial access tokens".

use crate::domain::event::OauthEvent;
use crate::domain::text;
use hodor_kernel::{Digest, DomainError, RandomSource, Secret, Timestamp};
use std::fmt;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies an initial access token. Safe to show and to log: it
    /// grants nothing.
    InitialAccessTokenId
);

/// What every token starts with, so that a token found anywhere is
/// recognized.
pub const INITIAL_ACCESS_TOKEN_PREFIX: &str = "hodor_iat_";
/// Number of hexadecimal characters after the prefix: 32 random bytes.
const TOKEN_LENGTH: usize = 64;
/// How many of the last characters are kept to tell tokens apart.
const HINT_LENGTH: usize = 4;

/// The shortest lifetime of a token.
pub const SHORTEST_INITIAL_ACCESS_TOKEN_LIFETIME: Duration = Duration::hours(1);
/// The longest lifetime of a token: there is none that does not expire.
pub const LONGEST_INITIAL_ACCESS_TOKEN_LIFETIME: Duration = Duration::days(90);
/// The lifetime of a token unless chosen.
pub const DEFAULT_INITIAL_ACCESS_TOKEN_LIFETIME: Duration = Duration::days(7);
/// The most registrations one token allows.
pub const MOST_REGISTRATIONS_PER_TOKEN: u32 = 1000;
/// The most active tokens a tenant holds.
pub const MAX_ACTIVE_INITIAL_ACCESS_TOKENS: usize = 100;

/// The token itself. Returned once, when it is made, and stored nowhere.
pub struct InitialAccessTokenValue(Secret<String>);

impl InitialAccessTokenValue {
    fn generate(random: &dyn RandomSource) -> Self {
        let mut bytes = [0_u8; 32];
        random.fill(&mut bytes);
        let mut value = String::with_capacity(INITIAL_ACCESS_TOKEN_PREFIX.len() + TOKEN_LENGTH);
        value.push_str(INITIAL_ACCESS_TOKEN_PREFIX);
        for byte in bytes {
            value.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            value.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        Self(Secret::from(value))
    }

    /// The token, to be handed to whoever asked for it and nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    fn hint(&self) -> String {
        let value = self.0.expose();
        value[value.len() - HINT_LENGTH..].to_owned()
    }
}

impl fmt::Debug for InitialAccessTokenValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InitialAccessTokenValue([REDACTED])")
    }
}

/// Whether `value` has the shape of an initial access token: the prefix
/// and 64 lowercase hexadecimal characters.
#[must_use]
pub fn looks_like_initial_access_token(value: &str) -> bool {
    value
        .strip_prefix(INITIAL_ACCESS_TOKEN_PREFIX)
        .is_some_and(|rest| {
            rest.len() == TOKEN_LENGTH
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// The SHA-256 of a token; what is stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InitialAccessTokenHash([u8; 32]);

impl InitialAccessTokenHash {
    /// The hash of a token as presented, or `None` if the value does not
    /// have the shape of one: nothing is computed or looked up for it.
    #[must_use]
    pub fn of_presented(value: &str, digest: &dyn Digest) -> Option<Self> {
        looks_like_initial_access_token(value).then(|| Self(digest.sha256(value.as_bytes())))
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

impl fmt::Debug for InitialAccessTokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InitialAccessTokenHash(..)")
    }
}

/// Where a token is in its life at a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialAccessTokenStatus {
    /// It allows a registration.
    Active,
    /// Its time passed.
    Expired,
    /// It allowed every registration it may.
    UsedUp,
    /// An administrator ended it.
    Revoked,
}

impl InitialAccessTokenStatus {
    /// The name the interfaces write.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::UsedUp => "used_up",
            Self::Revoked => "revoked",
        }
    }
}

/// What a token is made with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewInitialAccessToken {
    /// For administrators: whom it was handed to.
    pub name: String,
    /// How long it lives.
    pub lifetime: Duration,
    /// How many registrations it allows.
    pub max_registrations: u32,
}

/// Everything stored about a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialAccessTokenSnapshot {
    /// Its identifier.
    pub id: InitialAccessTokenId,
    /// The hash of the token.
    pub token_hash: InitialAccessTokenHash,
    /// The last four characters of the token.
    pub hint: String,
    /// Its name.
    pub name: String,
    /// How many registrations it allows.
    pub max_registrations: u32,
    /// How many registrations it has allowed.
    pub registrations: u32,
    /// When it was made.
    pub created_at: Timestamp,
    /// When it stops working.
    pub expires_at: Timestamp,
    /// When it last allowed a registration.
    pub last_used_at: Option<Timestamp>,
    /// When an administrator ended it.
    pub revoked_at: Option<Timestamp>,
}

/// An initial access token of a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialAccessToken {
    state: InitialAccessTokenSnapshot,
}

/// The one refusal of a presented token, whatever the reason.
pub(crate) fn token_invalid() -> DomainError {
    DomainError::new(
        hodor_kernel::ErrorKind::Unauthenticated,
        "oauth.initial_access_token_invalid",
        "the initial access token is not good in this tenant",
    )
}

impl InitialAccessToken {
    /// Makes a token, and returns it with the token itself, which is not
    /// available again, and the event that says so.
    ///
    /// # Errors
    ///
    /// `oauth.initial_access_token_name_invalid`,
    /// `oauth.initial_access_token_lifetime_invalid` or
    /// `oauth.initial_access_token_registrations_invalid`.
    pub fn create(
        new: NewInitialAccessToken,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> Result<(Self, InitialAccessTokenValue, OauthEvent), DomainError> {
        let name = text::name(&new.name, "oauth.initial_access_token_name_invalid")?;
        if new.lifetime < SHORTEST_INITIAL_ACCESS_TOKEN_LIFETIME
            || new.lifetime > LONGEST_INITIAL_ACCESS_TOKEN_LIFETIME
        {
            return Err(DomainError::invalid(
                "oauth.initial_access_token_lifetime_invalid",
                "an initial access token lives for 1 hour to 90 days",
            ));
        }
        if !(1..=MOST_REGISTRATIONS_PER_TOKEN).contains(&new.max_registrations) {
            return Err(DomainError::invalid(
                "oauth.initial_access_token_registrations_invalid",
                "an initial access token allows 1 to 1000 registrations",
            ));
        }
        let value = InitialAccessTokenValue::generate(random);
        let token = Self {
            state: InitialAccessTokenSnapshot {
                id: InitialAccessTokenId::generate(),
                token_hash: InitialAccessTokenHash(digest.sha256(value.expose().as_bytes())),
                hint: value.hint(),
                name,
                max_registrations: new.max_registrations,
                registrations: 0,
                created_at: now,
                expires_at: now + new.lifetime,
                last_used_at: None,
                revoked_at: None,
            },
        };
        let event = OauthEvent::InitialAccessTokenIssued {
            token_id: token.id(),
            name: token.state.name.clone(),
            max_registrations: token.state.max_registrations,
            expires_at: token.state.expires_at,
        };
        Ok((token, value, event))
    }

    /// Rebuilds a token from storage.
    #[must_use]
    pub const fn from_snapshot(state: InitialAccessTokenSnapshot) -> Self {
        Self { state }
    }

    /// Everything stored about it.
    #[must_use]
    pub const fn snapshot(&self) -> &InitialAccessTokenSnapshot {
        &self.state
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> InitialAccessTokenId {
        self.state.id
    }

    /// Where it is in its life at `now`. A revoked token is revoked
    /// whatever else holds; a token that both expired and was used up is
    /// used up.
    #[must_use]
    pub fn status(&self, now: Timestamp) -> InitialAccessTokenStatus {
        if self.state.revoked_at.is_some() {
            InitialAccessTokenStatus::Revoked
        } else if self.state.registrations >= self.state.max_registrations {
            InitialAccessTokenStatus::UsedUp
        } else if now >= self.state.expires_at {
            InitialAccessTokenStatus::Expired
        } else {
            InitialAccessTokenStatus::Active
        }
    }

    /// Whether it allows a registration at `now`.
    #[must_use]
    pub fn is_active(&self, now: Timestamp) -> bool {
        self.status(now) == InitialAccessTokenStatus::Active
    }

    /// Ends it at `now`. A token already revoked changes nothing, and
    /// says so with `None`.
    pub fn revoke(&mut self, now: Timestamp) -> Option<OauthEvent> {
        if self.state.revoked_at.is_some() {
            return None;
        }
        self.state.revoked_at = Some(now);
        Some(OauthEvent::InitialAccessTokenRevoked {
            token_id: self.id(),
        })
    }

    /// Spends one of its registrations at `now`.
    ///
    /// # Errors
    ///
    /// `oauth.initial_access_token_invalid` unless it is active: revoked,
    /// expired or used up, refused the same way.
    pub fn spend(&mut self, now: Timestamp) -> Result<OauthEvent, DomainError> {
        if !self.is_active(now) {
            return Err(token_invalid());
        }
        self.state.registrations += 1;
        self.state.last_used_at = Some(now);
        Ok(OauthEvent::InitialAccessTokenUsed {
            token_id: self.id(),
            registrations: self.state.registrations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::random::testing::{CountingRandom, FakeDigest};

    fn moment() -> Timestamp {
        Timestamp::UNIX_EPOCH + Duration::days(20_000)
    }

    fn new(max_registrations: u32) -> NewInitialAccessToken {
        NewInitialAccessToken {
            name: "  Partner portal team ".to_owned(),
            lifetime: DEFAULT_INITIAL_ACCESS_TOKEN_LIFETIME,
            max_registrations,
        }
    }

    fn made(max_registrations: u32) -> (InitialAccessToken, InitialAccessTokenValue) {
        let (token, value, _) = InitialAccessToken::create(
            new(max_registrations),
            moment(),
            &CountingRandom::default(),
            &FakeDigest,
        )
        .expect("valid");
        (token, value)
    }

    #[test]
    fn a_token_is_shown_once_and_kept_as_its_hash_with_a_hint() {
        let (token, value, event) =
            InitialAccessToken::create(new(3), moment(), &CountingRandom::default(), &FakeDigest)
                .expect("valid");
        assert!(looks_like_initial_access_token(value.expose()), "{value:?}");
        assert_eq!(format!("{value:?}"), "InitialAccessTokenValue([REDACTED])");
        let state = token.snapshot();
        assert_eq!(
            Some(state.token_hash),
            InitialAccessTokenHash::of_presented(value.expose(), &FakeDigest)
        );
        assert_eq!(state.hint, value.expose()[value.expose().len() - 4..]);
        assert_eq!(state.name, "Partner portal team");
        assert_eq!(state.expires_at, moment() + Duration::days(7));
        assert_eq!((state.registrations, state.max_registrations), (0, 3));
        assert_eq!(
            event,
            OauthEvent::InitialAccessTokenIssued {
                token_id: token.id(),
                name: "Partner portal team".to_owned(),
                max_registrations: 3,
                expires_at: moment() + Duration::days(7),
            }
        );
        let written = serde_json::to_string(&event).expect("serialized");
        assert!(!written.contains(value.expose()), "{written}");
    }

    #[test]
    fn a_value_without_the_shape_of_a_token_is_never_hashed() {
        for bad in [
            "",
            "hodor_iat_",
            "hodor_ak_0000000000000000000000000000000000000000000000000000000000000000",
            "hodor_iat_000000000000000000000000000000000000000000000000000000000000000",
            "hodor_iat_00000000000000000000000000000000000000000000000000000000000000000",
            "hodor_iat_000000000000000000000000000000000000000000000000000000000000000G",
            "HODOR_IAT_0000000000000000000000000000000000000000000000000000000000000000",
            "hodor_iat_000000000000000000000000000000000000000000000000000000000000000A",
        ] {
            assert_eq!(
                InitialAccessTokenHash::of_presented(bad, &FakeDigest),
                None,
                "{bad}"
            );
        }
    }

    #[test]
    fn a_name_a_lifetime_and_registrations_out_of_their_bounds_are_refused() {
        let refused = |new: NewInitialAccessToken| {
            InitialAccessToken::create(new, moment(), &CountingRandom::default(), &FakeDigest)
                .expect_err("refused")
                .code()
                .to_owned()
        };
        for name in ["", "   ", "two\nlines", &"x".repeat(101)] {
            assert_eq!(
                refused(NewInitialAccessToken {
                    name: name.to_owned(),
                    ..new(1)
                }),
                "oauth.initial_access_token_name_invalid"
            );
        }
        for lifetime in [
            Duration::minutes(59),
            Duration::days(90) + Duration::seconds(1),
            Duration::ZERO,
        ] {
            assert_eq!(
                refused(NewInitialAccessToken { lifetime, ..new(1) }),
                "oauth.initial_access_token_lifetime_invalid"
            );
        }
        for max_registrations in [0, 1001] {
            assert_eq!(
                refused(new(max_registrations)),
                "oauth.initial_access_token_registrations_invalid"
            );
        }
        for lifetime in [Duration::hours(1), Duration::days(90)] {
            assert!(
                InitialAccessToken::create(
                    NewInitialAccessToken {
                        lifetime,
                        ..new(1000)
                    },
                    moment(),
                    &CountingRandom::default(),
                    &FakeDigest
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn a_token_allows_as_many_registrations_as_it_was_made_for_and_no_more() {
        let (mut token, _) = made(2);
        assert_eq!(
            token.spend(moment()).expect("first"),
            OauthEvent::InitialAccessTokenUsed {
                token_id: token.id(),
                registrations: 1,
            }
        );
        token
            .spend(moment() + Duration::minutes(1))
            .expect("second");
        assert_eq!(
            token.snapshot().last_used_at,
            Some(moment() + Duration::minutes(1))
        );
        assert_eq!(token.status(moment()), InitialAccessTokenStatus::UsedUp);
        let error = token.spend(moment()).expect_err("used up");
        assert_eq!(error.code(), "oauth.initial_access_token_invalid");
        assert_eq!(error.kind(), hodor_kernel::ErrorKind::Unauthenticated);
        assert_eq!(token.snapshot().registrations, 2);
    }

    #[test]
    fn a_token_past_its_expiry_or_revoked_allows_nothing() {
        let (mut token, _) = made(5);
        let expiry = token.snapshot().expires_at;
        assert!(token.is_active(expiry - Duration::seconds(1)));
        assert_eq!(token.status(expiry), InitialAccessTokenStatus::Expired);
        assert_eq!(
            token.spend(expiry).expect_err("expired").code(),
            "oauth.initial_access_token_invalid"
        );
        assert_eq!(token.snapshot().registrations, 0);

        assert_eq!(
            token.revoke(moment()),
            Some(OauthEvent::InitialAccessTokenRevoked {
                token_id: token.id()
            })
        );
        assert_eq!(
            token.revoke(moment()),
            None,
            "revoking again changes nothing"
        );
        assert_eq!(token.status(moment()), InitialAccessTokenStatus::Revoked);
        assert_eq!(
            token.spend(moment()).expect_err("revoked").code(),
            "oauth.initial_access_token_invalid"
        );
    }

    #[test]
    fn each_status_has_its_name() {
        for (status, name) in [
            (InitialAccessTokenStatus::Active, "active"),
            (InitialAccessTokenStatus::Expired, "expired"),
            (InitialAccessTokenStatus::UsedUp, "used_up"),
            (InitialAccessTokenStatus::Revoked, "revoked"),
        ] {
            assert_eq!(status.as_str(), name);
        }
    }
}
