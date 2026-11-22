//! Authenticator applications: time-based one-time passwords (RFC 6238).
//!
//! The rules of `docs/architecture/contexts/credential.md`, "Authenticator
//! applications". The keyed hash itself is computed behind a port; this
//! module turns its result into six digits and decides which codes are
//! right.

use hodor_kernel::{DomainEvent, SealedSecret, Secret, Timestamp, UserId};
use serde::Serialize;
use std::fmt;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies a user's authenticator application, or an enrollment of
    /// one waiting to be confirmed.
    TotpId
);

/// The length of a secret, in bytes: 160 bits, as RFC 4226 recommends.
pub(crate) const SECRET_BYTES: usize = 20;
/// How long a code is the current one, in seconds.
pub const STEP_SECONDS: i64 = 30;
/// How many digits a code has.
pub(crate) const DIGITS: usize = 6;
/// How many steps before and after the current one are accepted, for a
/// phone whose clock is off.
pub(crate) const TOLERATED_STEPS: u64 = 1;
/// How long an enrollment waits to be confirmed.
pub const ENROLLMENT_LIFETIME: Duration = Duration::minutes(10);
/// The purpose the secret is sealed for.
pub const SEALING_PURPOSE: &str = "credential.totp_secret";

/// The step a moment falls in: whole steps since the Unix epoch. A moment
/// before the epoch is step zero.
#[must_use]
pub(crate) fn step_at(moment: Timestamp) -> u64 {
    u64::try_from(moment.unix_timestamp().div_euclid(STEP_SECONDS)).unwrap_or(0)
}

/// The code of a step, from the HMAC-SHA-1 of the step's big-endian bytes
/// under the secret, by the dynamic truncation of RFC 4226, section 5.3.
#[must_use]
pub(crate) fn code_from_mac(mac: &[u8; 20]) -> u32 {
    let offset = usize::from(mac[19] & 0x0f);
    let binary = (u32::from(mac[offset]) & 0x7f) << 24
        | u32::from(mac[offset + 1]) << 16
        | u32::from(mac[offset + 2]) << 8
        | u32::from(mac[offset + 3]);
    binary % 1_000_000
}

/// What a person typed, as a code, if it has the shape of one: six digits
/// once spaces are taken out.
#[must_use]
pub(crate) fn parse_code(typed: &str) -> Option<u32> {
    let digits: String = typed.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() != DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The steps a code typed at `moment` may belong to, oldest first.
#[must_use]
pub(crate) fn candidate_steps(moment: Timestamp) -> Vec<u64> {
    let now = step_at(moment);
    (now.saturating_sub(TOLERATED_STEPS)..=now.saturating_add(TOLERATED_STEPS)).collect()
}

/// Whether an application waits to be confirmed or is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpStatus {
    /// Enrollment began and was not confirmed yet.
    Pending,
    /// In use: its codes are accepted at sign-in.
    Active,
}

impl TotpStatus {
    /// The stored name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
        }
    }

    /// Reads a stored name.
    #[must_use]
    pub fn parse(stored: &str) -> Option<Self> {
        match stored {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            _ => None,
        }
    }
}

/// Everything stored about an authenticator application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpSnapshot {
    /// Identifies it.
    pub id: TotpId,
    /// The user it belongs to.
    pub user_id: UserId,
    /// Pending or active.
    pub status: TotpStatus,
    /// The secret, sealed for the tenant and [`SEALING_PURPOSE`].
    pub sealed_secret: SealedSecret,
    /// When enrollment began.
    pub created_at: Timestamp,
    /// When it was confirmed; empty while pending.
    pub confirmed_at: Option<Timestamp>,
    /// The step of the last accepted code.
    pub last_used_step: Option<u64>,
}

/// A user's authenticator application, or an enrollment of one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Totp {
    state: TotpSnapshot,
}

impl Totp {
    /// A new enrollment of a secret already sealed, waiting to be
    /// confirmed.
    #[must_use]
    pub fn begin(user_id: UserId, sealed_secret: SealedSecret, now: Timestamp) -> Self {
        Self {
            state: TotpSnapshot {
                id: TotpId::generate(),
                user_id,
                status: TotpStatus::Pending,
                sealed_secret,
                created_at: now,
                confirmed_at: None,
                last_used_step: None,
            },
        }
    }

    /// Rebuilds one read from storage.
    #[must_use]
    pub const fn from_snapshot(state: TotpSnapshot) -> Self {
        Self { state }
    }

    /// What is stored.
    #[must_use]
    pub const fn snapshot(&self) -> &TotpSnapshot {
        &self.state
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> TotpId {
        self.state.id
    }

    /// Whether an enrollment can still be confirmed at `now`.
    #[must_use]
    pub fn can_be_confirmed_at(&self, now: Timestamp) -> bool {
        self.state.status == TotpStatus::Pending
            && now < self.state.created_at + ENROLLMENT_LIFETIME
    }

    /// Puts a pending enrollment in use, with the step of the code that
    /// confirmed it counted as used.
    pub fn confirm(&mut self, step: u64, now: Timestamp) -> TotpEvent {
        self.state.status = TotpStatus::Active;
        self.state.confirmed_at = Some(now);
        self.state.last_used_step = Some(step);
        TotpEvent::Enrolled {
            user_id: self.state.user_id,
        }
    }

    /// Whether a code of `step` may still be accepted: it must be later
    /// than the step of the last accepted code.
    #[must_use]
    pub fn accepts_step(&self, step: u64) -> bool {
        self.state.last_used_step.is_none_or(|last| step > last)
    }
}

/// What a person is given once, when enrollment begins.
pub struct TotpEnrollment {
    secret: Secret<String>,
    address: Secret<String>,
}

impl TotpEnrollment {
    /// Writes the secret in the forms an authenticator application reads:
    /// Base32, and an `otpauth://totp/` address naming the issuer and the
    /// account.
    #[must_use]
    pub fn new(secret: &[u8], issuer: &str, account: &str) -> Self {
        let encoded = base32(secret);
        let label = format!("{}:{}", escape(issuer), escape(account));
        let address = format!(
            "otpauth://totp/{label}?secret={encoded}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}",
            escape(issuer)
        );
        Self {
            secret: Secret::from(encoded),
            address: Secret::from(address),
        }
    }

    /// The secret in Base32, for typing into an application by hand.
    #[must_use]
    pub fn secret(&self) -> &str {
        self.secret.expose()
    }

    /// The `otpauth://` address, for a QR code.
    #[must_use]
    pub fn address(&self) -> &str {
        self.address.expose()
    }
}

impl fmt::Debug for TotpEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpEnrollment([REDACTED])")
    }
}

/// Base32 of RFC 4648, without padding, as authenticator applications
/// expect.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut text = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            text.push(char::from(ALPHABET[((buffer >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        text.push(char::from(
            ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
    }
    text
}

/// Percent-encodes everything but unreserved characters, for a part of
/// the `otpauth://` address.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    escaped
}

/// An event about a user's authenticator application. Never carries the
/// secret or a code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum TotpEvent {
    /// An application was put in use.
    Enrolled {
        /// The user.
        user_id: UserId,
    },
    /// An application was removed.
    Removed {
        /// The user.
        user_id: UserId,
    },
}

impl DomainEvent for TotpEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Enrolled { .. } => "credential.totp_enrolled",
            Self::Removed { .. } => "credential.totp_removed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_truncation_of_rfc_4226_gives_its_test_codes() {
        // RFC 4226, appendix D: the HMAC-SHA-1 of counter 0 under the
        // secret "12345678901234567890", and its code.
        let mac = [
            0xcc, 0x93, 0xcf, 0x18, 0x50, 0x8d, 0x94, 0x93, 0x4c, 0x64, 0xb6, 0x5d, 0x8b, 0xa7,
            0x66, 0x7f, 0xb7, 0xcd, 0xe4, 0xb0,
        ];
        assert_eq!(code_from_mac(&mac), 755_224);
    }

    #[test]
    fn a_code_is_six_digits_and_spaces_do_not_count() {
        assert_eq!(parse_code("123456"), Some(123_456));
        assert_eq!(parse_code("123 456"), Some(123_456));
        assert_eq!(parse_code("000001"), Some(1));
        assert_eq!(parse_code("12345"), None);
        assert_eq!(parse_code("1234567"), None);
        assert_eq!(parse_code("12345a"), None);
        assert_eq!(parse_code("１２３４５６"), None);
        assert_eq!(parse_code(""), None);
    }

    #[test]
    fn steps_are_thirty_seconds_from_the_epoch() {
        let at = |seconds: i64| Timestamp::from_unix_timestamp(seconds).expect("moment");
        assert_eq!(step_at(at(59)), 1);
        assert_eq!(step_at(at(1_111_111_109)), 37_037_036);
        assert_eq!(candidate_steps(at(59)), vec![0, 1, 2]);
        assert_eq!(candidate_steps(at(0)), vec![0, 1]);
    }

    #[test]
    fn a_step_is_accepted_only_after_the_last_one_used() {
        let mut totp = Totp::begin(
            UserId::generate(),
            SealedSecret::from_stored(vec![1]),
            Timestamp::UNIX_EPOCH,
        );
        assert!(totp.accepts_step(0));
        totp.confirm(10, Timestamp::UNIX_EPOCH);
        assert!(!totp.accepts_step(9));
        assert!(!totp.accepts_step(10));
        assert!(totp.accepts_step(11));
    }

    #[test]
    fn an_enrollment_waits_ten_minutes() {
        let start = Timestamp::UNIX_EPOCH;
        let mut totp = Totp::begin(
            UserId::generate(),
            SealedSecret::from_stored(vec![1]),
            start,
        );
        assert!(totp.can_be_confirmed_at(start + Duration::minutes(9)));
        assert!(!totp.can_be_confirmed_at(start + ENROLLMENT_LIFETIME));
        totp.confirm(1, start);
        assert!(!totp.can_be_confirmed_at(start));
    }

    #[test]
    fn the_secret_is_written_in_base32_of_rfc_4648() {
        // RFC 4648, section 10, without the padding.
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fo"), "MZXQ");
        assert_eq!(base32(b"foo"), "MZXW6");
        assert_eq!(base32(b"foob"), "MZXW6YQ");
        assert_eq!(base32(b"fooba"), "MZXW6YTB");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn the_address_names_the_issuer_and_the_account() {
        let enrollment =
            TotpEnrollment::new(b"12345678901234567890", "Acme Inc", "ana@example.com");
        assert_eq!(enrollment.secret(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(
            enrollment.address(),
            "otpauth://totp/Acme%20Inc:ana%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Acme%20Inc&algorithm=SHA1&digits=6&period=30"
        );
        assert_eq!(format!("{enrollment:?}"), "TotpEnrollment([REDACTED])");
    }
}
