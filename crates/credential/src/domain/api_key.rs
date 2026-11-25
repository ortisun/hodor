//! API keys: what a service account or an agent presents, as it is, to
//! Hodor's administration interface and Authorization API.
//!
//! See `docs/architecture/contexts/credential.md`, "API keys".

use hodor_kernel::{Digest, DomainError, DomainEvent, RandomSource, Secret, Timestamp, UserId};
use serde::Serialize;
use std::fmt;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies an API key. Safe to show and to log: it grants nothing.
    ApiKeyId
);

hodor_kernel::define_id!(
    /// The application a key asks the Authorization API for, by the
    /// identifier the OAuth context gave it. This context does not know
    /// applications: whoever makes the key checks that it is one.
    KeyApplicationId
);

/// What every key starts with: Hodor, and `ak` for an API key, so that a
/// key found anywhere is recognized.
pub const API_KEY_PREFIX: &str = "hodor_ak_";
/// Number of hexadecimal characters after the prefix: 32 random bytes.
const SECRET_LENGTH: usize = 64;
/// How many of the last characters are kept to tell keys apart.
const HINT_LENGTH: usize = 4;
/// The longest name.
const MAX_NAME_LENGTH: usize = 100;
/// The most scopes a key holds.
pub const MAX_API_KEY_SCOPES: usize = 50;
/// The longest scope.
const MAX_SCOPE_LENGTH: usize = 128;
/// The most keys that work a workload may hold.
pub const MAX_API_KEYS: usize = 10;

/// Why a key is revoked by an administrator.
pub const REVOKED_BY_ADMINISTRATOR: &str = "revoked_by_administrator";

/// The key itself. Returned once, when it is made, and stored nowhere.
pub struct ApiKeySecret(Secret<String>);

impl ApiKeySecret {
    fn generate(random: &dyn RandomSource) -> Self {
        let mut bytes = [0_u8; 32];
        random.fill(&mut bytes);
        let mut text = String::with_capacity(API_KEY_PREFIX.len() + SECRET_LENGTH);
        text.push_str(API_KEY_PREFIX);
        for byte in bytes {
            text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        Self(Secret::from(text))
    }

    /// The key, to be handed to whoever asked for it and nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    fn hint(&self) -> String {
        let text = self.0.expose();
        text[text.len() - HINT_LENGTH..].to_owned()
    }
}

impl fmt::Debug for ApiKeySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKeySecret([REDACTED])")
    }
}

/// Whether `value` has the shape of an API key: the prefix and 64
/// lowercase hexadecimal characters.
#[must_use]
pub fn looks_like_api_key(value: &str) -> bool {
    value.strip_prefix(API_KEY_PREFIX).is_some_and(|secret| {
        secret.len() == SECRET_LENGTH
            && secret
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The SHA-256 of a key; what is stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApiKeyHash([u8; 32]);

impl ApiKeyHash {
    /// The hash of a key as presented, or `None` if the value does not
    /// have the shape of one: nothing is computed or looked up for it.
    #[must_use]
    pub fn of_presented(value: &str, digest: &dyn Digest) -> Option<Self> {
        looks_like_api_key(value).then(|| Self(digest.sha256(value.as_bytes())))
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

impl fmt::Debug for ApiKeyHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKeyHash(..)")
    }
}

/// Where a key is in its life at a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyStatus {
    /// It works.
    Active,
    /// Its time passed.
    Expired,
    /// It was ended.
    Revoked,
}

impl ApiKeyStatus {
    /// The name the interfaces write.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

/// What a key is made with, besides its holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeySettings {
    /// For administrators.
    pub name: String,
    /// What it may be used for. Which names are scopes is the
    /// authorization context's rule, checked by whoever makes the key.
    pub scopes: Vec<String>,
    /// The application it asks the Authorization API for, if any.
    pub application: Option<KeyApplicationId>,
}

/// Everything stored about a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeySnapshot {
    /// Its identifier.
    pub id: ApiKeyId,
    /// The service account or agent that holds it.
    pub holder_id: UserId,
    /// The hash of the key.
    pub key_hash: ApiKeyHash,
    /// The last four characters of the key.
    pub hint: String,
    /// Its name, scopes and application.
    pub settings: ApiKeySettings,
    /// When it was made.
    pub created_at: Timestamp,
    /// When it stops working.
    pub expires_at: Timestamp,
    /// When it was last accepted.
    pub last_used_at: Option<Timestamp>,
    /// When it was revoked.
    pub revoked_at: Option<Timestamp>,
    /// Why it was revoked.
    pub revocation_reason: Option<String>,
    /// The key that replaced it, once rotated.
    pub replaced_by: Option<ApiKeyId>,
}

/// An API key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKey {
    state: ApiKeySnapshot,
}

/// The shortest lifetime of a key.
pub const SHORTEST_API_KEY_LIFETIME: Duration = Duration::days(1);
/// The longest lifetime of a key: there is none that does not expire.
pub const LONGEST_API_KEY_LIFETIME: Duration = Duration::days(365);
/// The lifetime of a key unless chosen.
pub const DEFAULT_API_KEY_LIFETIME: Duration = Duration::days(90);
/// The longest an old key keeps working after a rotation.
pub const LONGEST_API_KEY_OVERLAP: Duration = Duration::days(30);
/// How long an old key keeps working after a rotation unless chosen.
pub const DEFAULT_API_KEY_OVERLAP: Duration = Duration::days(7);
/// A use is written at most this often.
pub const LAST_USE_PRECISION: Duration = Duration::minutes(1);

fn check_lifetime(lifetime: Duration) -> Result<(), DomainError> {
    if lifetime < SHORTEST_API_KEY_LIFETIME || lifetime > LONGEST_API_KEY_LIFETIME {
        return Err(DomainError::invalid(
            "credential.api_key_lifetime_invalid",
            "an API key lives for 1 to 365 days",
        ));
    }
    Ok(())
}

impl ApiKeySettings {
    /// The settings, tidied, if they follow the rules of a key: a name of
    /// 1 to 100 characters without control characters, and 1 to 50
    /// scopes, each 1 to 128 printable characters without spaces, each
    /// once.
    ///
    /// # Errors
    ///
    /// `Invalid` with code `credential.api_key_name_invalid` or
    /// `credential.api_key_scopes_invalid`.
    pub fn checked(self) -> Result<Self, DomainError> {
        let name = self.name.trim().to_owned();
        if name.is_empty()
            || name.chars().count() > MAX_NAME_LENGTH
            || name.chars().any(char::is_control)
        {
            return Err(DomainError::invalid(
                "credential.api_key_name_invalid",
                "an API key's name has 1 to 100 characters, without control characters",
            ));
        }
        let mut scopes: Vec<String> = Vec::with_capacity(self.scopes.len());
        for scope in self.scopes {
            if !scopes.contains(&scope) {
                scopes.push(scope);
            }
        }
        let well_formed = |scope: &String| {
            !scope.is_empty()
                && scope.len() <= MAX_SCOPE_LENGTH
                && scope.bytes().all(|b| b.is_ascii_graphic())
        };
        if scopes.is_empty() || scopes.len() > MAX_API_KEY_SCOPES || !scopes.iter().all(well_formed)
        {
            return Err(DomainError::invalid(
                "credential.api_key_scopes_invalid",
                "an API key holds 1 to 50 scopes, each 1 to 128 printable characters",
            ));
        }
        Ok(Self {
            name,
            scopes,
            application: self.application,
        })
    }
}

impl ApiKey {
    /// Makes a key for `holder`, and returns it with the key itself,
    /// which is not available again, and the event that says so.
    ///
    /// # Errors
    ///
    /// `Invalid` if the settings or the lifetime break their rules.
    pub fn create(
        holder: UserId,
        settings: ApiKeySettings,
        lifetime: Duration,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> Result<(Self, ApiKeySecret, ApiKeyEvent), DomainError> {
        let settings = settings.checked()?;
        check_lifetime(lifetime)?;
        let (key, secret) = Self::made(holder, settings, lifetime, now, random, digest);
        let event = ApiKeyEvent::Created {
            holder_id: holder,
            api_key_id: key.id(),
            scopes: key.state.settings.scopes.clone(),
            expires_at: key.state.expires_at,
        };
        Ok((key, secret, event))
    }

    fn made(
        holder: UserId,
        settings: ApiKeySettings,
        lifetime: Duration,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> (Self, ApiKeySecret) {
        let secret = ApiKeySecret::generate(random);
        let key = Self {
            state: ApiKeySnapshot {
                id: ApiKeyId::generate(),
                holder_id: holder,
                key_hash: ApiKeyHash(digest.sha256(secret.expose().as_bytes())),
                hint: secret.hint(),
                settings,
                created_at: now,
                expires_at: now + lifetime,
                last_used_at: None,
                revoked_at: None,
                revocation_reason: None,
                replaced_by: None,
            },
        };
        (key, secret)
    }

    /// Rebuilds a key from storage.
    #[must_use]
    pub const fn from_snapshot(state: ApiKeySnapshot) -> Self {
        Self { state }
    }

    /// Everything stored about it.
    #[must_use]
    pub const fn snapshot(&self) -> &ApiKeySnapshot {
        &self.state
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> ApiKeyId {
        self.state.id
    }

    /// The workload that holds it.
    #[must_use]
    pub const fn holder_id(&self) -> UserId {
        self.state.holder_id
    }

    /// Its scopes.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.state.settings.scopes
    }

    /// Whether it holds `scope`.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.state.settings.scopes.iter().any(|held| held == scope)
    }

    /// The application it asks the Authorization API for.
    #[must_use]
    pub const fn application(&self) -> Option<KeyApplicationId> {
        self.state.settings.application
    }

    /// Where it is at `now`.
    #[must_use]
    pub fn status_at(&self, now: Timestamp) -> ApiKeyStatus {
        if self.state.revoked_at.is_some() {
            ApiKeyStatus::Revoked
        } else if now >= self.state.expires_at {
            ApiKeyStatus::Expired
        } else {
            ApiKeyStatus::Active
        }
    }

    /// Whether it works at `now`: neither revoked nor expired.
    #[must_use]
    pub fn is_good_at(&self, now: Timestamp) -> bool {
        self.status_at(now) == ApiKeyStatus::Active
    }

    /// Replaces the key with a new one living `lifetime`, with the same
    /// holder and settings. This key keeps working for `overlap` more, and
    /// never longer than it would have; it then names the new one. Returns
    /// the new key, the key itself, once, and the event.
    ///
    /// # Errors
    ///
    /// `Conflict` with code `credential.api_key_not_rotatable` for a key
    /// that was replaced, revoked or expired; `Invalid` for a lifetime or
    /// an overlap that breaks its rule.
    pub fn rotate(
        &mut self,
        lifetime: Duration,
        overlap: Duration,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> Result<(Self, ApiKeySecret, ApiKeyEvent), DomainError> {
        if self.state.replaced_by.is_some() || !self.is_good_at(now) {
            return Err(DomainError::conflict(
                "credential.api_key_not_rotatable",
                "only a key that works and was not replaced can be rotated",
            ));
        }
        check_lifetime(lifetime)?;
        if overlap.is_negative() || overlap > LONGEST_API_KEY_OVERLAP {
            return Err(DomainError::invalid(
                "credential.api_key_overlap_invalid",
                "an old key keeps working for 0 to 30 days",
            ));
        }
        let (next, secret) = Self::made(
            self.state.holder_id,
            self.state.settings.clone(),
            lifetime,
            now,
            random,
            digest,
        );
        self.state.expires_at = self.state.expires_at.min(now + overlap);
        self.state.replaced_by = Some(next.id());
        let event = ApiKeyEvent::Rotated {
            holder_id: self.state.holder_id,
            api_key_id: self.state.id,
            replaced_by: next.id(),
            old_expires_at: self.state.expires_at,
            expires_at: next.state.expires_at,
        };
        Ok((next, secret, event))
    }

    /// Ends the key, with `reason`. Returns the event if anything changed;
    /// revoking is final and repeating it changes nothing.
    pub fn revoke(&mut self, reason: &str, now: Timestamp) -> Option<ApiKeyEvent> {
        if self.state.revoked_at.is_some() {
            return None;
        }
        self.state.revoked_at = Some(now);
        self.state.revocation_reason = Some(reason.to_owned());
        Some(ApiKeyEvent::Revoked {
            holder_id: self.state.holder_id,
            api_key_id: self.state.id,
            reason: reason.to_owned(),
        })
    }
}

/// An event about an API key. Carries identifiers and scopes, never the
/// key, its hash or its hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ApiKeyEvent {
    /// A key was made.
    Created {
        /// The workload that holds it.
        holder_id: UserId,
        /// The key's identifier.
        api_key_id: ApiKeyId,
        /// What it may be used for.
        scopes: Vec<String>,
        /// When it stops working.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: Timestamp,
    },
    /// A key was replaced by a new one.
    Rotated {
        /// The workload that holds them.
        holder_id: UserId,
        /// The old key.
        api_key_id: ApiKeyId,
        /// The new key.
        replaced_by: ApiKeyId,
        /// When the old key now stops working.
        #[serde(with = "time::serde::rfc3339")]
        old_expires_at: Timestamp,
        /// When the new key stops working.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: Timestamp,
    },
    /// A key was revoked.
    Revoked {
        /// The workload that held it.
        holder_id: UserId,
        /// The key's identifier.
        api_key_id: ApiKeyId,
        /// Why.
        reason: String,
    },
}

impl DomainEvent for ApiKeyEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Created { .. } => "credential.api_key_created",
            Self::Rotated { .. } => "credential.api_key_rotated",
            Self::Revoked { .. } => "credential.api_key_revoked",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::random::testing::{CountingRandom, FakeDigest};

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn settings(scopes: &[&str]) -> ApiKeySettings {
        ApiKeySettings {
            name: "Nightly export".to_owned(),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            application: None,
        }
    }

    fn create(scopes: &[&str]) -> (ApiKey, ApiKeySecret, ApiKeyEvent) {
        ApiKey::create(
            UserId::generate(),
            settings(scopes),
            DEFAULT_API_KEY_LIFETIME,
            NOW,
            &CountingRandom::default(),
            &FakeDigest,
        )
        .expect("a key")
    }

    #[test]
    fn a_key_is_recognized_by_its_prefix_and_hashes_to_what_is_stored() {
        let (key, secret, event) = create(&["users:read"]);
        assert!(secret.expose().starts_with("hodor_ak_"));
        assert_eq!(secret.expose().len(), 9 + 64);
        assert!(looks_like_api_key(secret.expose()));
        assert_eq!(
            ApiKeyHash::of_presented(secret.expose(), &FakeDigest),
            Some(key.snapshot().key_hash)
        );
        assert_eq!(
            key.snapshot().hint,
            secret.expose()[secret.expose().len() - 4..]
        );
        let shown = format!("{secret:?} {key:?} {event:?}");
        assert!(!shown.contains(&secret.expose()[9..]), "{shown}");
        assert_eq!(event.event_type(), "credential.api_key_created");
    }

    #[test]
    fn a_value_that_is_not_shaped_like_a_key_has_no_hash() {
        let hex = "a".repeat(64);
        for value in [
            String::new(),
            hex.clone(),
            format!("hodor_ak_{}", "a".repeat(63)),
            format!("hodor_ak_{}", "a".repeat(65)),
            format!("hodor_ak_{}", "A".repeat(64)),
            format!("hodor_ak_{}", "g".repeat(64)),
            format!("hodor_at_{hex}"),
            format!("Hodor_ak_{hex}"),
        ] {
            assert_eq!(
                ApiKeyHash::of_presented(&value, &FakeDigest),
                None,
                "{value}"
            );
        }
    }

    #[test]
    fn the_settings_and_the_lifetime_follow_their_rules() {
        let mut long = settings(&["users:read"]);
        long.name = "x".repeat(101);
        let too_many: Vec<String> = (0..51).map(|i| format!("scope:{i}")).collect();
        let cases = [
            (settings(&[]), "credential.api_key_scopes_invalid"),
            (
                settings(&["has space"]),
                "credential.api_key_scopes_invalid",
            ),
            (
                ApiKeySettings {
                    scopes: too_many,
                    ..settings(&[])
                },
                "credential.api_key_scopes_invalid",
            ),
            (long, "credential.api_key_name_invalid"),
            (
                ApiKeySettings {
                    name: "  ".to_owned(),
                    ..settings(&["users:read"])
                },
                "credential.api_key_name_invalid",
            ),
        ];
        for (asked, code) in cases {
            assert_eq!(asked.checked().expect_err("refused").code(), code);
        }
        let tidy = settings(&["users:read", "users:read", "authz:evaluate"])
            .checked()
            .expect("valid");
        assert_eq!(tidy.scopes, ["users:read", "authz:evaluate"]);
        for lifetime in [Duration::hours(23), Duration::days(366)] {
            let refused = ApiKey::create(
                UserId::generate(),
                settings(&["users:read"]),
                lifetime,
                NOW,
                &CountingRandom::default(),
                &FakeDigest,
            );
            assert_eq!(
                refused.expect_err("refused").code(),
                "credential.api_key_lifetime_invalid"
            );
        }
    }

    #[test]
    fn a_key_works_until_it_expires_or_is_revoked() {
        let (mut key, _, _) = create(&["users:read"]);
        assert_eq!(key.status_at(NOW), ApiKeyStatus::Active);
        let end = NOW + DEFAULT_API_KEY_LIFETIME;
        assert_eq!(key.status_at(end), ApiKeyStatus::Expired);
        assert!(!key.is_good_at(end));
        let event = key.revoke(REVOKED_BY_ADMINISTRATOR, NOW).expect("revoked");
        assert_eq!(event.event_type(), "credential.api_key_revoked");
        assert_eq!(key.status_at(NOW), ApiKeyStatus::Revoked);
        assert!(key.revoke("again", NOW).is_none(), "revoking is final");
    }

    #[test]
    fn rotation_makes_a_new_key_and_keeps_the_old_one_for_the_overlap() {
        let (mut old, first, _) = create(&["users:read"]);
        let later = NOW + Duration::days(10);
        // A source already used once, so that the new key differs.
        let random = CountingRandom::default();
        random.fill(&mut [0_u8; 32]);
        let (next, second, event) = old
            .rotate(
                DEFAULT_API_KEY_LIFETIME,
                DEFAULT_API_KEY_OVERLAP,
                later,
                &random,
                &FakeDigest,
            )
            .expect("rotated");
        assert_ne!(first.expose(), second.expose());
        assert_eq!(next.holder_id(), old.holder_id());
        assert_eq!(next.scopes(), old.scopes());
        assert_eq!(old.snapshot().replaced_by, Some(next.id()));
        assert_eq!(old.snapshot().expires_at, later + DEFAULT_API_KEY_OVERLAP);
        assert_eq!(next.snapshot().expires_at, later + DEFAULT_API_KEY_LIFETIME);
        assert_eq!(event.event_type(), "credential.api_key_rotated");
        // Only the newest of a line rotates.
        let again = old.rotate(
            DEFAULT_API_KEY_LIFETIME,
            Duration::ZERO,
            later,
            &CountingRandom::default(),
            &FakeDigest,
        );
        assert_eq!(
            again.expect_err("refused").code(),
            "credential.api_key_not_rotatable"
        );
        // The overlap never lengthens a key, and is bounded.
        let (mut short, _, _) = ApiKey::create(
            UserId::generate(),
            settings(&["users:read"]),
            Duration::days(2),
            NOW,
            &CountingRandom::default(),
            &FakeDigest,
        )
        .expect("a key");
        short
            .rotate(
                DEFAULT_API_KEY_LIFETIME,
                LONGEST_API_KEY_OVERLAP,
                NOW,
                &CountingRandom::default(),
                &FakeDigest,
            )
            .expect("rotated");
        assert_eq!(short.snapshot().expires_at, NOW + Duration::days(2));
        let (mut bounded, _, _) = create(&["users:read"]);
        let refused = bounded.rotate(
            DEFAULT_API_KEY_LIFETIME,
            Duration::days(31),
            NOW,
            &CountingRandom::default(),
            &FakeDigest,
        );
        assert_eq!(
            refused.expect_err("refused").code(),
            "credential.api_key_overlap_invalid"
        );
    }
}
