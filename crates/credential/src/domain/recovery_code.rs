//! Recovery codes: single-use codes a person writes down, used in place of
//! a second factor they lost.
//!
//! The rules of `docs/architecture/contexts/credential.md`, "Recovery
//! codes". Hashing is done behind the kernel's `Digest` port; this module
//! makes codes, reads what was typed, and holds a set.

use hodor_kernel::{DomainEvent, Secret, Timestamp, UserId};
use serde::Serialize;
use std::fmt;

hodor_kernel::define_id!(
    /// Identifies a user's set of recovery codes.
    RecoveryCodeSetId
);

/// How many codes a set has.
pub const CODES_PER_SET: usize = 10;
/// How many characters a code has, without the hyphens.
pub const CODE_CHARACTERS: usize = 16;
/// How many characters are shown together, between hyphens.
const GROUP: usize = 4;
/// The characters of a code: digits and capitals without `I`, `L`, `O`
/// and `U`, five bits each.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// How many random bytes make a code: 16 characters of 5 bits are 80 bits.
pub(crate) const RANDOM_BYTES: usize = CODE_CHARACTERS * 5 / 8;

/// A code made from 80 random bits, written as four groups of four
/// characters.
#[must_use]
pub(crate) fn code_from_bytes(bytes: &[u8; RANDOM_BYTES]) -> String {
    let mut characters = String::with_capacity(CODE_CHARACTERS + CODE_CHARACTERS / GROUP);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            if !characters.is_empty() && (characters.len() + 1) % (GROUP + 1) == 0 {
                characters.push('-');
            }
            characters.push(char::from(ALPHABET[((buffer >> bits) & 0x1f) as usize]));
        }
    }
    characters
}

/// What a person typed, read as a code if it is one: lowercase counts as
/// uppercase, spaces and hyphens are ignored, `O` is read as `0` and `I`
/// and `L` as `1`. The answer is the sixteen characters without hyphens,
/// the form that is hashed.
#[must_use]
pub fn read_code(typed: &str) -> Option<String> {
    let mut read = String::with_capacity(CODE_CHARACTERS);
    for character in typed.chars() {
        let character = match character.to_ascii_uppercase() {
            ' ' | '-' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        if !character.is_ascii() || !ALPHABET.contains(&(character as u8)) {
            return None;
        }
        read.push(character);
    }
    (read.len() == CODE_CHARACTERS).then_some(read)
}

/// A user's set of recovery codes, as stored: only the hash of each code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCodeSet {
    /// Identifies the set.
    pub id: RecoveryCodeSetId,
    /// The user it belongs to.
    pub user_id: UserId,
    /// When it was generated.
    pub created_at: Timestamp,
    /// The SHA-256 of each code, as [`read_code`] gives it.
    pub code_hashes: Vec<[u8; 32]>,
}

/// The codes of a new set, shown once.
pub struct RecoveryCodes {
    codes: Vec<Secret<String>>,
}

impl RecoveryCodes {
    pub(crate) fn new(codes: Vec<String>) -> Self {
        Self {
            codes: codes.into_iter().map(Secret::from).collect(),
        }
    }

    /// The codes, in four groups of four characters.
    pub fn codes(&self) -> impl Iterator<Item = &str> {
        self.codes.iter().map(|code| code.expose().as_str())
    }

    /// How many codes there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.codes.len()
    }

    /// Whether there are none; never, for a set Hodor made.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.codes.is_empty()
    }
}

impl fmt::Debug for RecoveryCodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCodes([REDACTED])")
    }
}

/// An event about a user's recovery codes. Never carries a code or its
/// hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum RecoveryCodeEvent {
    /// A set was made in place of any earlier one.
    Generated {
        /// The user.
        user_id: UserId,
    },
    /// A code was accepted.
    Used {
        /// The user.
        user_id: UserId,
        /// How many unused codes are left.
        remaining: u32,
    },
    /// The set was removed.
    Removed {
        /// The user.
        user_id: UserId,
    },
}

impl DomainEvent for RecoveryCodeEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Generated { .. } => "credential.recovery_codes_generated",
            Self::Used { .. } => "credential.recovery_code_used",
            Self::Removed { .. } => "credential.recovery_codes_removed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_is_four_groups_of_four_characters_of_the_alphabet() {
        let code = code_from_bytes(&[0xff; RANDOM_BYTES]);
        assert_eq!(code, "ZZZZ-ZZZZ-ZZZZ-ZZZZ");
        let code = code_from_bytes(&[0; RANDOM_BYTES]);
        assert_eq!(code, "0000-0000-0000-0000");
        // 0x08 0x86 0x42 ... is 00001 00010 00011 00100 ... in five bits.
        let code = code_from_bytes(&[0x08, 0x86, 0x42, 0x98, 0xe8, 0x4a, 0x96, 0xc6, 0xb9, 0xf0]);
        assert_eq!(code, "1234-5678-9ABC-DEFG");
    }

    #[test]
    fn every_bit_of_the_random_bytes_counts() {
        let base = code_from_bytes(&[0; RANDOM_BYTES]);
        for byte in 0..RANDOM_BYTES {
            for bit in 0..8 {
                let mut bytes = [0; RANDOM_BYTES];
                bytes[byte] = 1 << bit;
                assert_ne!(code_from_bytes(&bytes), base, "byte {byte}, bit {bit}");
            }
        }
    }

    #[test]
    fn what_is_typed_is_read_generously() {
        let expected = Some("7K2MQX9D4HVNR8TA".to_owned());
        assert_eq!(read_code("7K2M-QX9D-4HVN-R8TA"), expected);
        assert_eq!(read_code("7k2m qx9d 4hvn r8ta"), expected);
        assert_eq!(read_code(" 7K2MQX9D4HVNR8TA "), expected);
        assert_eq!(
            read_code("0OIL-0000-0000-0000"),
            Some("0011000000000000".to_owned())
        );
    }

    #[test]
    fn what_is_not_a_code_is_not_read() {
        assert_eq!(read_code(""), None);
        assert_eq!(read_code("7K2M-QX9D-4HVN-R8T"), None);
        assert_eq!(read_code("7K2M-QX9D-4HVN-R8TAA"), None);
        // `U` is not in the alphabet, and nothing is read as it.
        assert_eq!(read_code("UK2M-QX9D-4HVN-R8TA"), None);
        assert_eq!(read_code("7K2M_QX9D_4HVN_R8TA"), None);
        assert_eq!(read_code("７K2M-QX9D-4HVN-R8TA"), None);
        assert_eq!(read_code("123456"), None);
    }

    #[test]
    fn a_new_set_does_not_show_its_codes_in_debug_output() {
        let codes = RecoveryCodes::new(vec!["7K2M-QX9D-4HVN-R8TA".to_owned()]);
        assert_eq!(format!("{codes:?}"), "RecoveryCodes([REDACTED])");
        assert_eq!(codes.codes().collect::<Vec<_>>(), ["7K2M-QX9D-4HVN-R8TA"]);
    }

    #[test]
    fn events_carry_the_user_and_no_code() {
        let user_id = UserId::generate();
        let used = RecoveryCodeEvent::Used {
            user_id,
            remaining: 9,
        };
        assert_eq!(used.event_type(), "credential.recovery_code_used");
        let payload = serde_json::to_string(&used).expect("payload");
        assert_eq!(
            payload,
            format!("{{\"user_id\":\"{}\",\"remaining\":9}}", user_id.as_uuid())
        );
    }
}
