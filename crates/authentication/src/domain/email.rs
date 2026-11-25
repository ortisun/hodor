//! What is sent to sign in by email: a code or a link, kept as the
//! SHA-256 of its secret and belonging to the sign-in that asked for it.
//!
//! Specified in `docs/architecture/contexts/authentication.md`, "Signing
//! in with a code or a link by email".

use crate::domain::transaction::{AuthTransaction, TransactionId};
use hodor_kernel::{Digest, DomainError, RandomSource, Secret, Timestamp, UserId};
use std::fmt;
use time::Duration;

/// The two ways of signing in by email.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EmailMethod {
    /// A code the person types.
    Code,
    /// A link the person opens in the browser that asked for it.
    Link,
}

impl EmailMethod {
    /// The kind of the authenticator, the key of its alternative, the
    /// method recorded for it, and the name it is stored under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Code => "email_code",
            Self::Link => "email_link",
        }
    }

    /// Reads a stored method.
    ///
    /// # Errors
    ///
    /// Returns an internal error for a name that is not a method.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        [Self::Code, Self::Link]
            .into_iter()
            .find(|method| method.as_str() == value)
            .ok_or_else(|| {
                DomainError::internal(
                    "authentication.stored_data_invalid",
                    "the sign-in could not be loaded",
                )
                .with_detail(format!("unknown stored email method `{value}`"))
            })
    }
}

/// The code or the token of a link, as it is sent. It never goes anywhere
/// but into the message.
pub struct EmailSecret(Secret<String>);

impl EmailSecret {
    /// How many digits a code has.
    pub const CODE_DIGITS: usize = 6;
    /// How many hexadecimal characters the token of a link has.
    pub const TOKEN_LENGTH: usize = 64;

    /// Makes the secret of a method: six digits, or 32 random bytes written
    /// as 64 hexadecimal characters.
    pub(crate) fn generate(method: EmailMethod, random: &dyn RandomSource) -> Self {
        match method {
            EmailMethod::Code => {
                // Eight random bytes reduced to a million values: the bias
                // is below one in ten thousand billion.
                let mut bytes = [0_u8; 8];
                random.fill(&mut bytes);
                let value = u64::from_be_bytes(bytes) % 1_000_000;
                Self(Secret::from(format!("{value:06}")))
            }
            EmailMethod::Link => {
                let mut bytes = [0_u8; 32];
                random.fill(&mut bytes);
                let mut text = String::with_capacity(Self::TOKEN_LENGTH);
                for byte in bytes {
                    text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
                    text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
                }
                Self(Secret::from(text))
            }
        }
    }

    /// The secret, to be put into the message.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for EmailSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EmailSecret([REDACTED])")
    }
}

/// The SHA-256 of a code or of a link's token: all that is stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EmailSecretHash([u8; 32]);

impl EmailSecretHash {
    /// The hash of what a person presented for `method`, or `None` when it
    /// cannot be one: anything but six digits for a code, anything but 64
    /// lowercase hexadecimal characters for a link. Spaces around a code
    /// are not part of it.
    #[must_use]
    pub fn of_presented(method: EmailMethod, value: &str, digest: &dyn Digest) -> Option<Self> {
        let value = match method {
            EmailMethod::Code => value.trim(),
            EmailMethod::Link => value,
        };
        let well_formed = match method {
            EmailMethod::Code => {
                value.len() == EmailSecret::CODE_DIGITS && value.bytes().all(|b| b.is_ascii_digit())
            }
            EmailMethod::Link => {
                value.len() == EmailSecret::TOKEN_LENGTH
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }
        };
        well_formed.then(|| Self(digest.sha256(value.as_bytes())))
    }

    /// A hash read back from storage.
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

impl fmt::Debug for EmailSecretHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EmailSecretHash(..)")
    }
}

/// What was sent for a sign-in, as it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailSignInSnapshot {
    /// The sign-in it belongs to.
    pub transaction_id: TransactionId,
    /// A code or a link.
    pub method: EmailMethod,
    /// The SHA-256 of the code or of the token.
    pub secret_hash: EmailSecretHash,
    /// A digest of the address asked about, made as the identifier step
    /// makes it: what attempts are counted by.
    pub identifier_key: [u8; 32],
    /// The person it signs in, or nobody when the address belongs to no
    /// one who may sign in.
    pub user_id: Option<UserId>,
    /// When it was made.
    pub created_at: Timestamp,
    /// When it stops being good.
    pub expires_at: Timestamp,
    /// When it was used, if it was.
    pub used_at: Option<Timestamp>,
}

/// A code or a link sent for one sign-in. Good once, for ten minutes and
/// never past its sign-in, and only when it belongs to someone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailSignIn {
    state: EmailSignInSnapshot,
}

impl EmailSignIn {
    /// How long a code or a link lives, at most.
    pub const LIFETIME: Duration = Duration::minutes(10);

    /// Makes a code or a link for `transaction`, which the person asked
    /// for at `now`. Returns it and the secret to send; for nobody the
    /// secret is made all the same and never sent.
    #[must_use]
    pub fn issue(
        transaction: &AuthTransaction,
        method: EmailMethod,
        identifier_key: [u8; 32],
        user_id: Option<UserId>,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> (Self, EmailSecret) {
        let secret = EmailSecret::generate(method, random);
        let sent = Self {
            state: EmailSignInSnapshot {
                transaction_id: transaction.id(),
                method,
                secret_hash: EmailSecretHash(digest.sha256(secret.expose().as_bytes())),
                identifier_key,
                user_id,
                created_at: now,
                expires_at: (now + Self::LIFETIME).min(transaction.snapshot().expires_at),
                used_at: None,
            },
        };
        (sent, secret)
    }

    /// Rebuilds what was sent from storage.
    #[must_use]
    pub const fn from_snapshot(state: EmailSignInSnapshot) -> Self {
        Self { state }
    }

    /// The stored state.
    #[must_use]
    pub const fn snapshot(&self) -> &EmailSignInSnapshot {
        &self.state
    }

    /// Whether `presented`, for `method`, signs in at `now`: unused,
    /// unexpired, of this method, belonging to someone, with this hash.
    #[must_use]
    pub fn accepts(
        &self,
        method: EmailMethod,
        presented: &EmailSecretHash,
        now: Timestamp,
    ) -> bool {
        self.state.method == method
            && self.state.used_at.is_none()
            && now < self.state.expires_at
            && self.state.user_id.is_some()
            && &self.state.secret_hash == presented
    }

    /// Records that it was used at `now`.
    pub fn mark_used(&mut self, now: Timestamp) {
        self.state.used_at = Some(now);
    }
}

/// What using a code or a link up led to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailUse {
    /// It was good and is now used: it signs in this person.
    Accepted(UserId),
    /// It was the right one, and another request used it a moment ago.
    AlreadyUsed,
    /// Anything else: wrong, expired, of the other method, belonging to
    /// nobody, or nothing was asked for.
    Refused,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::flow::AuthFlow;
    use hodor_kernel::random::testing::{CountingRandom, FakeDigest};
    use hodor_session::api::ClientInfo;

    fn transaction(now: Timestamp) -> AuthTransaction {
        AuthTransaction::start(&AuthFlow::built_in(), ClientInfo::default(), [0; 32], now)
    }

    #[test]
    fn a_code_is_six_digits_and_a_token_sixty_four_hexadecimal_characters() {
        let random = CountingRandom::default();
        for _ in 0..50 {
            let code = EmailSecret::generate(EmailMethod::Code, &random);
            assert_eq!(code.expose().len(), 6);
            assert!(code.expose().bytes().all(|b| b.is_ascii_digit()));
            let token = EmailSecret::generate(EmailMethod::Link, &random);
            assert!(
                EmailSecretHash::of_presented(EmailMethod::Link, token.expose(), &FakeDigest)
                    .is_some()
            );
        }
        assert_eq!(
            format!("{:?}", EmailSecret::generate(EmailMethod::Code, &random)),
            "EmailSecret([REDACTED])"
        );
    }

    #[test]
    fn only_what_could_have_been_sent_has_a_hash() {
        let code =
            |value: &str| EmailSecretHash::of_presented(EmailMethod::Code, value, &FakeDigest);
        assert!(code("123456").is_some());
        assert_eq!(code(" 123456 "), code("123456"));
        for wrong in ["12345", "1234567", "12 456", "abcdef", "", "١٢٣٤٥٦"] {
            assert!(code(wrong).is_none(), "{wrong}");
        }
        let link =
            |value: &str| EmailSecretHash::of_presented(EmailMethod::Link, value, &FakeDigest);
        assert!(link(&"a".repeat(64)).is_some());
        assert!(link(&"A".repeat(64)).is_none());
        assert!(link(&"a".repeat(63)).is_none());
        assert!(link("123456").is_none());
    }

    #[test]
    fn what_is_sent_lives_ten_minutes_and_never_past_its_sign_in() {
        let start = Timestamp::UNIX_EPOCH;
        let sign_in = transaction(start);
        let random = CountingRandom::default();
        let user = Some(UserId::generate());
        let (early, _) = EmailSignIn::issue(
            &sign_in,
            EmailMethod::Code,
            [1; 32],
            user,
            start,
            &random,
            &FakeDigest,
        );
        assert_eq!(early.snapshot().expires_at, start + Duration::minutes(10));
        let late_moment = start + Duration::minutes(7);
        let (late, _) = EmailSignIn::issue(
            &sign_in,
            EmailMethod::Code,
            [1; 32],
            user,
            late_moment,
            &random,
            &FakeDigest,
        );
        assert_eq!(late.snapshot().expires_at, sign_in.snapshot().expires_at);
        assert_eq!(late.snapshot().transaction_id, sign_in.id());
    }

    #[test]
    fn it_accepts_only_its_own_secret_once_in_time_and_for_someone() {
        let start = Timestamp::UNIX_EPOCH;
        let sign_in = transaction(start);
        let random = CountingRandom::default();
        let (mut sent, secret) = EmailSignIn::issue(
            &sign_in,
            EmailMethod::Code,
            [1; 32],
            Some(UserId::generate()),
            start,
            &random,
            &FakeDigest,
        );
        let right = EmailSecretHash::of_presented(EmailMethod::Code, secret.expose(), &FakeDigest)
            .expect("well formed");
        let soon = start + Duration::minutes(1);
        assert!(sent.accepts(EmailMethod::Code, &right, soon));
        assert!(!sent.accepts(EmailMethod::Link, &right, soon));
        assert!(!sent.accepts(EmailMethod::Code, &right, start + Duration::minutes(10)));
        let other = if secret.expose() == "000000" {
            "000001"
        } else {
            "000000"
        };
        let wrong = EmailSecretHash::of_presented(EmailMethod::Code, other, &FakeDigest)
            .expect("well formed");
        assert!(!sent.accepts(EmailMethod::Code, &wrong, soon));
        sent.mark_used(soon);
        assert!(!sent.accepts(EmailMethod::Code, &right, soon));

        let (nobodys, secret) = EmailSignIn::issue(
            &sign_in,
            EmailMethod::Code,
            [1; 32],
            None,
            start,
            &random,
            &FakeDigest,
        );
        let right = EmailSecretHash::of_presented(EmailMethod::Code, secret.expose(), &FakeDigest)
            .expect("well formed");
        assert!(
            !nobodys.accepts(EmailMethod::Code, &right, soon),
            "nobody is signed in by it"
        );
    }

    #[test]
    fn methods_are_stored_by_name() {
        for method in [EmailMethod::Code, EmailMethod::Link] {
            assert_eq!(
                EmailMethod::from_stored(method.as_str()).expect("known"),
                method
            );
        }
        assert!(EmailMethod::from_stored("sms").is_err());
    }
}
