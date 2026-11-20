//! The session and its lifecycle.

use crate::domain::event::SessionEvent;
use hodor_kernel::{Digest, DomainError, RandomSource, Secret, Timestamp, UserId};
use std::fmt;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies a session. Safe to show and to log: it grants nothing.
    SessionId
);

/// How strongly the user proved who they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Assurance {
    /// One factor, for example a password.
    SingleFactor,
    /// More than one factor.
    MultiFactor,
}

impl Assurance {
    /// The name used in storage and in events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleFactor => "single_factor",
            Self::MultiFactor => "multi_factor",
        }
    }

    /// Reads an assurance from its stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error for an unknown name.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "single_factor" => Ok(Self::SingleFactor),
            "multi_factor" => Ok(Self::MultiFactor),
            other => Err(DomainError::internal(
                "session.stored_data_invalid",
                "the session could not be loaded",
            )
            .with_detail(format!("unknown stored assurance `{other}`"))),
        }
    }
}

/// How long a session lasts. Copied from the tenant's session policy when
/// the session starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTimeouts {
    /// How long the session survives without activity.
    pub idle: Duration,
    /// How long the session lasts at most, whatever the activity.
    pub absolute: Duration,
}

/// Where a session was started from, for the user's own review.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientInfo {
    /// The network address the request came from.
    pub address: Option<String>,
    /// What the browser said about itself.
    pub description: Option<String>,
}

impl ClientInfo {
    /// Longest browser description kept, in characters.
    pub const MAX_DESCRIPTION_LENGTH: usize = 256;

    fn trimmed(self) -> Self {
        Self {
            address: self.address,
            description: self
                .description
                .map(|d| d.chars().take(Self::MAX_DESCRIPTION_LENGTH).collect()),
        }
    }
}

/// The secret a browser presents: 32 random bytes as 64 hexadecimal
/// characters. Returned once, when a session starts or its token is
/// replaced, and stored nowhere.
pub struct SessionToken(Secret<String>);

impl SessionToken {
    /// Number of characters in a token.
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

    /// The token, to be handed to the browser and nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// The hash under which this token is stored.
    #[must_use]
    pub fn hash(&self, digest: &dyn Digest) -> TokenHash {
        TokenHash(digest.sha256(self.expose().as_bytes()))
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken([REDACTED])")
    }
}

/// The SHA-256 hash of a session token; what is stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    /// The hash of a token as presented by a browser, or `None` if the
    /// value does not have the shape of a token. A malformed value cannot
    /// belong to any session, so nothing is computed or looked up for it.
    #[must_use]
    pub fn of_presented(value: &str, digest: &dyn Digest) -> Option<Self> {
        let well_formed = value.len() == SessionToken::LENGTH
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

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenHash([REDACTED])")
    }
}

/// Whether a session is accepted at a given moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Accepted.
    Active,
    /// No activity for the idle timeout, or the absolute expiry passed.
    Expired,
    /// Ended on purpose.
    Revoked,
}

/// The state of a session as it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSnapshot {
    /// The session's identifier.
    pub id: SessionId,
    /// Whose session it is.
    pub user_id: UserId,
    /// The hash of the token.
    pub token_hash: TokenHash,
    /// When the user last proved who they are.
    pub signed_in_at: Timestamp,
    /// How strongly.
    pub assurance: Assurance,
    /// By which methods.
    pub methods: Vec<String>,
    /// When the session started.
    pub started_at: Timestamp,
    /// When it was last used, to the nearest minute.
    pub last_activity_at: Timestamp,
    /// How long it survives without activity.
    pub idle_timeout: Duration,
    /// The moment after which it ends whatever happens.
    pub absolute_expires_at: Timestamp,
    /// Where it was started from.
    pub client: ClientInfo,
    /// When it was ended on purpose, if it was.
    pub revoked_at: Option<Timestamp>,
    /// Why it was ended.
    pub revocation_reason: Option<String>,
}

/// A browser session of a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    state: SessionSnapshot,
}

impl Session {
    /// Activity closer together than this is not recorded, so that a busy
    /// session does not cause a write per request.
    pub const ACTIVITY_RESOLUTION: Duration = Duration::minutes(1);

    /// Starts a session and returns it with its token.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if the timeouts are not positive or the
    /// idle timeout exceeds the absolute one, or if no method is given.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        user_id: UserId,
        assurance: Assurance,
        methods: Vec<String>,
        timeouts: SessionTimeouts,
        client: ClientInfo,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> Result<(Self, SessionToken, SessionEvent), DomainError> {
        if timeouts.idle <= Duration::ZERO || timeouts.idle > timeouts.absolute {
            return Err(DomainError::invalid(
                "session.timeouts_invalid",
                "the idle timeout must be positive and no longer than the absolute timeout",
            ));
        }
        if methods.is_empty() {
            return Err(DomainError::invalid(
                "session.methods_missing",
                "a session records at least one sign-in method",
            ));
        }
        let token = SessionToken::generate(random);
        let id = SessionId::generate();
        let event = SessionEvent::Started {
            session_id: id,
            user_id,
            assurance: assurance.as_str(),
            methods: methods.clone(),
        };
        let session = Self {
            state: SessionSnapshot {
                id,
                user_id,
                token_hash: token.hash(digest),
                signed_in_at: now,
                assurance,
                methods,
                started_at: now,
                last_activity_at: now,
                idle_timeout: timeouts.idle,
                absolute_expires_at: now + timeouts.absolute,
                client: client.trimmed(),
                revoked_at: None,
                revocation_reason: None,
            },
        };
        Ok((session, token, event))
    }

    /// Rebuilds a session from stored state.
    #[must_use]
    pub const fn from_snapshot(state: SessionSnapshot) -> Self {
        Self { state }
    }

    /// The session's current state, for storage and for reading.
    #[must_use]
    pub const fn snapshot(&self) -> &SessionSnapshot {
        &self.state
    }

    /// The session's identifier.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.state.id
    }

    /// Whose session it is.
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.state.user_id
    }

    /// The moment the session stops being accepted if it is not used
    /// again: the earlier of the idle limit and the absolute expiry.
    #[must_use]
    pub fn expires_at(&self) -> Timestamp {
        (self.state.last_activity_at + self.state.idle_timeout).min(self.state.absolute_expires_at)
    }

    /// Whether the session is accepted at `now`. Computed from the stored
    /// times; nothing has to run for a session to expire.
    #[must_use]
    pub fn state_at(&self, now: Timestamp) -> SessionState {
        if self.state.revoked_at.is_some() {
            SessionState::Revoked
        } else if now >= self.expires_at() {
            SessionState::Expired
        } else {
            SessionState::Active
        }
    }

    /// Records that the session was used. Returns whether anything changed
    /// and needs storing: nothing does for a session that is not active, or
    /// that was used less than a minute ago.
    pub fn record_activity(&mut self, now: Timestamp) -> bool {
        if self.state_at(now) != SessionState::Active
            || now < self.state.last_activity_at + Self::ACTIVITY_RESOLUTION
        {
            return false;
        }
        self.state.last_activity_at = now;
        true
    }

    /// Ends the session on purpose. Returns `None` if it was already
    /// revoked: revoking is final and repeating it changes nothing.
    pub fn revoke(&mut self, reason: &str, now: Timestamp) -> Option<SessionEvent> {
        if self.state.revoked_at.is_some() {
            return None;
        }
        self.state.revoked_at = Some(now);
        self.state.revocation_reason = Some(reason.to_owned());
        Some(SessionEvent::Revoked {
            session_id: self.state.id,
            user_id: self.state.user_id,
            reason: reason.to_owned(),
        })
    }

    /// Gives the session a new token; the old one is useless from now on.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error unless the session is active.
    pub fn replace_token(
        &mut self,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> Result<SessionToken, DomainError> {
        if self.state_at(now) != SessionState::Active {
            return Err(DomainError::conflict(
                "session.not_active",
                "the session is no longer active",
            ));
        }
        let token = SessionToken::generate(random);
        self.state.token_hash = token.hash(digest);
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::DomainEvent as _;
    use hodor_kernel::random::testing::{CountingRandom, FakeDigest};
    use proptest::prelude::*;

    const START: Timestamp = Timestamp::UNIX_EPOCH;
    const TIMEOUTS: SessionTimeouts = SessionTimeouts {
        idle: Duration::minutes(30),
        absolute: Duration::hours(12),
    };

    fn started(timeouts: SessionTimeouts) -> (Session, SessionToken) {
        let (session, token, _) = Session::start(
            UserId::generate(),
            Assurance::SingleFactor,
            vec!["password".to_owned()],
            timeouts,
            ClientInfo::default(),
            START,
            &CountingRandom::default(),
            &FakeDigest,
        )
        .expect("start");
        (session, token)
    }

    #[test]
    fn a_token_is_64_hexadecimal_characters_and_only_its_hash_is_kept() {
        let (session, token) = started(TIMEOUTS);
        assert_eq!(token.expose().len(), 64);
        assert!(token.expose().bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(
            TokenHash::of_presented(token.expose(), &FakeDigest),
            Some(session.snapshot().token_hash)
        );
        let printed = format!("{session:?} {token:?}");
        assert!(
            !printed.contains(token.expose()),
            "the token is never printed"
        );
    }

    #[test]
    fn a_value_without_the_shape_of_a_token_has_no_hash() {
        let (_, token) = started(TIMEOUTS);
        let upper = token.expose().to_uppercase();
        for malformed in [
            "",
            "short",
            &token.expose()[1..],
            &upper,
            &format!("{}0", token.expose()),
        ] {
            assert_eq!(
                TokenHash::of_presented(malformed, &FakeDigest),
                None,
                "{malformed}"
            );
        }
    }

    #[test]
    fn starting_announces_the_facts_but_not_the_token() {
        let (_, token, event) = Session::start(
            UserId::generate(),
            Assurance::MultiFactor,
            vec!["password".to_owned(), "totp".to_owned()],
            TIMEOUTS,
            ClientInfo::default(),
            START,
            &CountingRandom::default(),
            &FakeDigest,
        )
        .expect("start");
        assert_eq!(event.event_type(), "session.started");
        let printed = format!("{event:?}");
        assert!(printed.contains("multi_factor") && printed.contains("totp"));
        assert!(!printed.contains(token.expose()));
    }

    #[test]
    fn a_session_expires_after_the_idle_timeout_without_activity() {
        let (mut session, _) = started(TIMEOUTS);
        assert_eq!(
            session.state_at(START + Duration::minutes(29)),
            SessionState::Active
        );
        assert_eq!(
            session.state_at(START + Duration::minutes(30)),
            SessionState::Expired
        );

        // Activity moves the idle limit forward.
        assert!(session.record_activity(START + Duration::minutes(29)));
        assert_eq!(
            session.state_at(START + Duration::minutes(58)),
            SessionState::Active
        );
        assert_eq!(
            session.state_at(START + Duration::minutes(59)),
            SessionState::Expired
        );
    }

    #[test]
    fn activity_is_recorded_at_most_once_a_minute() {
        let (mut session, _) = started(TIMEOUTS);
        assert!(!session.record_activity(START + Duration::seconds(59)));
        assert!(session.record_activity(START + Duration::seconds(60)));
        assert!(!session.record_activity(START + Duration::seconds(90)));
    }

    #[test]
    fn an_expired_session_does_not_come_back() {
        let (mut session, _) = started(TIMEOUTS);
        let late = START + Duration::minutes(31);
        assert!(!session.record_activity(late));
        assert_eq!(session.state_at(late), SessionState::Expired);
    }

    #[test]
    fn revoking_is_final_and_announced_once() {
        let (mut session, _) = started(TIMEOUTS);
        let event = session.revoke("signed out", START).expect("first");
        assert_eq!(event.event_type(), "session.revoked");
        assert_eq!(session.revoke("again", START), None);
        assert_eq!(session.state_at(START), SessionState::Revoked);
        assert_eq!(
            session.snapshot().revocation_reason.as_deref(),
            Some("signed out")
        );
        assert!(!session.record_activity(START + Duration::minutes(5)));
    }

    #[test]
    fn replacing_the_token_makes_the_old_one_useless() {
        let (mut session, old) = started(TIMEOUTS);
        // A source that has already produced the first token's bytes, as
        // one shared source would have.
        let random = CountingRandom::default();
        random.fill(&mut [0_u8; 32]);
        let new = session
            .replace_token(START, &random, &FakeDigest)
            .expect("replace");
        assert_ne!(new.expose(), old.expose());
        assert_ne!(old.hash(&FakeDigest), session.snapshot().token_hash);
        assert_eq!(new.hash(&FakeDigest), session.snapshot().token_hash);

        session.revoke("signed out", START);
        let error = session
            .replace_token(START, &CountingRandom::default(), &FakeDigest)
            .expect_err("revoked");
        assert_eq!(error.code(), "session.not_active");
    }

    #[test]
    fn invalid_starts_are_refused() {
        let start = |timeouts, methods: Vec<String>| {
            Session::start(
                UserId::generate(),
                Assurance::SingleFactor,
                methods,
                timeouts,
                ClientInfo::default(),
                START,
                &CountingRandom::default(),
                &FakeDigest,
            )
            .map(|_| ())
        };
        let password = || vec!["password".to_owned()];
        let inverted = SessionTimeouts {
            idle: Duration::hours(13),
            absolute: Duration::hours(12),
        };
        let zero = SessionTimeouts {
            idle: Duration::ZERO,
            absolute: Duration::hours(12),
        };
        assert_eq!(
            start(inverted, password()).expect_err("inverted").code(),
            "session.timeouts_invalid"
        );
        assert_eq!(
            start(zero, password()).expect_err("zero").code(),
            "session.timeouts_invalid"
        );
        assert_eq!(
            start(TIMEOUTS, vec![]).expect_err("no method").code(),
            "session.methods_missing"
        );
    }

    #[test]
    fn a_long_browser_description_is_cut() {
        let client = ClientInfo {
            address: Some("203.0.113.9".to_owned()),
            description: Some("x".repeat(1000)),
        };
        let (session, _, _) = Session::start(
            UserId::generate(),
            Assurance::SingleFactor,
            vec!["password".to_owned()],
            TIMEOUTS,
            client,
            START,
            &CountingRandom::default(),
            &FakeDigest,
        )
        .expect("start");
        assert_eq!(
            session
                .snapshot()
                .client
                .description
                .as_ref()
                .map(String::len),
            Some(256)
        );
    }

    proptest! {
        /// No pattern of use keeps a session alive past its absolute
        /// expiry, and a session never comes back once it is not active.
        #[test]
        fn no_activity_extends_a_session_past_its_absolute_expiry(
            idle_minutes in 1_i64..120,
            absolute_minutes in 1_i64..600,
            steps in proptest::collection::vec(0_i64..4000, 1..80),
        ) {
            prop_assume!(idle_minutes <= absolute_minutes);
            let timeouts = SessionTimeouts {
                idle: Duration::minutes(idle_minutes),
                absolute: Duration::minutes(absolute_minutes),
            };
            let (mut session, _) = started(timeouts);
            let absolute_expiry = session.snapshot().absolute_expires_at;
            let mut now = START;
            let mut ended = false;
            for seconds in steps {
                now += Duration::seconds(seconds);
                let state = session.state_at(now);
                if ended {
                    prop_assert_eq!(state, SessionState::Expired, "an ended session stays ended");
                }
                if now >= absolute_expiry {
                    prop_assert_eq!(state, SessionState::Expired);
                }
                ended = state != SessionState::Active;
                let changed = session.record_activity(now);
                prop_assert!(!(changed && ended), "activity is not recorded on an ended session");
                prop_assert!(session.expires_at() <= absolute_expiry);
                prop_assert_eq!(session.snapshot().absolute_expires_at, absolute_expiry);
            }
        }
    }
}
