//! Secrets at rest with AES-256-GCM from `aws-lc-rs`.
//!
//! See `docs/security/secrets-at-rest.md` for the layout of a sealed
//! secret and for how keys are configured and changed.

use aws_lc_rs::aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_kernel::sealing::unreadable;
use hodor_kernel::{DomainError, SealedSecret, Secret, SecretBox, TenantContext};
use zeroize::Zeroize as _;

const FORMAT: u8 = 1;
const KEY_BYTES: usize = 32;
const MAX_IDENTIFIER: usize = 32;
const MAX_PURPOSE: usize = 128;
/// Bound into every ciphertext, so that it is never mistaken for one made
/// for another use of the same key.
const DOMAIN: &[u8] = b"hodor-secret-v1";

struct Key {
    identifier: String,
    key: RandomizedNonceKey,
}

/// The configured keys. The first seals; every one opens.
pub struct SecretKeys {
    keys: Vec<Key>,
}

impl std::fmt::Debug for SecretKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let identifiers: Vec<&str> = self
            .keys
            .iter()
            .map(|key| key.identifier.as_str())
            .collect();
        f.debug_struct("SecretKeys")
            .field("identifiers", &identifiers)
            .finish_non_exhaustive()
    }
}

fn configuration(message: String) -> DomainError {
    DomainError::invalid("secret.keys_invalid", message)
}

fn is_identifier(text: &str) -> bool {
    (1..=MAX_IDENTIFIER).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

impl SecretKeys {
    /// No keys: nothing can be sealed or opened, and trying says so.
    #[must_use]
    pub const fn none() -> Self {
        Self { keys: Vec::new() }
    }

    /// Reads the `HODOR_SECRET_KEYS` setting: `identifier:key` pairs
    /// separated by commas, each key 32 bytes in Base64.
    ///
    /// # Errors
    ///
    /// Returns `secret.keys_invalid`, naming the pair at fault by its
    /// position and never by its contents.
    pub fn parse(setting: &Secret<String>) -> Result<Self, DomainError> {
        let mut keys: Vec<Key> = Vec::new();
        for (position, pair) in setting.expose().split(',').enumerate() {
            let number = position + 1;
            let (identifier, encoded) = pair
                .trim()
                .split_once(':')
                .ok_or_else(|| configuration(format!("key {number} is not `identifier:key`")))?;
            if !is_identifier(identifier) {
                return Err(configuration(format!(
                    "the identifier of key {number} must be 1 to 32 lowercase letters, digits and hyphens"
                )));
            }
            if keys.iter().any(|key| key.identifier == identifier) {
                return Err(configuration(format!(
                    "the identifier of key {number} is used twice"
                )));
            }
            let mut bytes = STANDARD
                .decode(encoded.trim())
                .map_err(|_| configuration(format!("key {number} is not Base64")))?;
            let key = if bytes.len() == KEY_BYTES {
                RandomizedNonceKey::new(&AES_256_GCM, &bytes).ok()
            } else {
                None
            };
            bytes.zeroize();
            let key = key.ok_or_else(|| configuration(format!("key {number} is not 32 bytes")))?;
            keys.push(Key {
                identifier: identifier.to_owned(),
                key,
            });
        }
        Ok(Self { keys })
    }

    /// A new key for the setting, in Base64, drawn from `random`.
    #[must_use]
    pub fn generate(random: &dyn hodor_kernel::RandomSource) -> Secret<String> {
        let mut bytes = [0_u8; KEY_BYTES];
        random.fill(&mut bytes);
        let encoded = STANDARD.encode(bytes);
        bytes.zeroize();
        Secret::new(encoded)
    }
}

/// What is authenticated with a ciphertext without being stored: the
/// tenant and the purpose it was sealed for.
fn associated_data(tenant: &TenantContext, purpose: &str) -> Vec<u8> {
    let tenant = tenant.tenant_id().to_string();
    let mut data = Vec::with_capacity(DOMAIN.len() + tenant.len() + purpose.len() + 2);
    data.extend_from_slice(DOMAIN);
    data.push(0);
    data.extend_from_slice(tenant.as_bytes());
    data.push(0);
    data.extend_from_slice(purpose.as_bytes());
    data
}

fn check_purpose(purpose: &str) -> Result<(), DomainError> {
    let usable = (1..=MAX_PURPOSE).contains(&purpose.len())
        && purpose.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'_'
        });
    if usable {
        Ok(())
    } else {
        Err(DomainError::internal(
            "secret.purpose_invalid",
            "a stored secret could not be handled",
        )
        .with_detail("a purpose is lowercase letters, digits, dots and underscores"))
    }
}

/// The identifier of the key a sealed secret names, and what follows it.
fn split(sealed: &[u8]) -> Option<(&str, &[u8])> {
    let (&format, rest) = sealed.split_first()?;
    let (&length, rest) = rest.split_first()?;
    if format != FORMAT || rest.len() < usize::from(length) {
        return None;
    }
    let (identifier, rest) = rest.split_at(usize::from(length));
    let identifier = std::str::from_utf8(identifier).ok()?;
    is_identifier(identifier).then_some((identifier, rest))
}

impl SecretBox for SecretKeys {
    fn seal(
        &self,
        tenant: &TenantContext,
        purpose: &str,
        secret: &Secret<Vec<u8>>,
    ) -> Result<SealedSecret, DomainError> {
        check_purpose(purpose)?;
        let current = self.keys.first().ok_or_else(|| {
            DomainError::internal(
                "secret.keys_missing",
                "this installation is not set up to keep secrets",
            )
            .with_detail("HODOR_SECRET_KEYS is not set")
        })?;

        let mut ciphertext = secret.expose().clone();
        let nonce = current
            .key
            .seal_in_place_append_tag(Aad::from(associated_data(tenant, purpose)), &mut ciphertext)
            .map_err(|_| {
                ciphertext.zeroize();
                DomainError::internal("secret.sealing_failed", "a secret could not be stored")
            })?;

        let identifier = current.identifier.as_bytes();
        let mut sealed = Vec::with_capacity(2 + identifier.len() + NONCE_LEN + ciphertext.len());
        sealed.push(FORMAT);
        // An identifier is at most 32 bytes, checked when the keys are read.
        sealed.push(u8::try_from(identifier.len()).unwrap_or(u8::MAX));
        sealed.extend_from_slice(identifier);
        sealed.extend_from_slice(nonce.as_ref());
        sealed.extend_from_slice(&ciphertext);
        Ok(SealedSecret::from_stored(sealed))
    }

    fn open(
        &self,
        tenant: &TenantContext,
        purpose: &str,
        sealed: &SealedSecret,
    ) -> Result<Secret<Vec<u8>>, DomainError> {
        check_purpose(purpose)?;
        let (identifier, rest) =
            split(sealed.as_bytes()).ok_or_else(|| unreadable("not a sealed secret"))?;
        let key = self
            .keys
            .iter()
            .find(|key| key.identifier == identifier)
            .ok_or_else(|| unreadable("sealed with a key that is not configured"))?;
        if rest.len() < NONCE_LEN {
            return Err(unreadable("too short to be a sealed secret"));
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| unreadable("too short to be a sealed secret"))?;

        let mut buffer = ciphertext.to_vec();
        let length = key
            .key
            .open_in_place(
                nonce,
                Aad::from(associated_data(tenant, purpose)),
                &mut buffer,
            )
            .map(|plaintext| plaintext.len())
            .map_err(|_| {
                unreadable("changed, or sealed for another tenant or purpose, or with another key")
            })?;
        buffer.truncate(length);
        Ok(Secret::new(buffer))
    }

    fn needs_resealing(&self, sealed: &SealedSecret) -> bool {
        let current = self.keys.first().map(|key| key.identifier.as_str());
        split(sealed.as_bytes()).map(|(identifier, _)| identifier) != current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OsRandom;
    use hodor_kernel::TenantId;

    const PURPOSE: &str = "federation.client_secret";

    fn setting(pairs: &[(&str, &Secret<String>)]) -> Secret<String> {
        let pairs: Vec<String> = pairs
            .iter()
            .map(|(identifier, key)| format!("{identifier}:{}", key.expose()))
            .collect();
        Secret::new(pairs.join(","))
    }

    fn keys(pairs: &[(&str, &Secret<String>)]) -> SecretKeys {
        SecretKeys::parse(&setting(pairs)).expect("keys")
    }

    fn tenant() -> TenantContext {
        TenantContext::assume(TenantId::generate())
    }

    fn secret() -> Secret<Vec<u8>> {
        Secret::new(b"the client secret of a provider".to_vec())
    }

    #[test]
    fn a_secret_comes_back_and_is_not_in_what_is_stored() {
        let key = SecretKeys::generate(&OsRandom);
        let keys = keys(&[("2026-11", &key)]);
        let tenant = tenant();

        let sealed = keys.seal(&tenant, PURPOSE, &secret()).expect("seal");
        let stored = sealed.as_bytes();
        assert!(
            !stored
                .windows(secret().expose().len())
                .any(|window| window == secret().expose().as_slice()),
            "the secret is not stored in the clear"
        );
        // Format, identifier length, identifier, nonce, ciphertext, tag.
        assert_eq!(stored.len(), 2 + 7 + 12 + secret().expose().len() + 16);
        assert_eq!(&stored[..9], b"\x01\x072026-11");

        let opened = keys.open(&tenant, PURPOSE, &sealed).expect("open");
        assert_eq!(opened.expose(), secret().expose());
        assert!(!keys.needs_resealing(&sealed));
    }

    #[test]
    fn sealing_the_same_secret_twice_gives_different_bytes() {
        let key = SecretKeys::generate(&OsRandom);
        let keys = keys(&[("a", &key)]);
        let tenant = tenant();
        let first = keys.seal(&tenant, PURPOSE, &secret()).expect("seal");
        let second = keys.seal(&tenant, PURPOSE, &secret()).expect("seal");
        assert_ne!(first, second);
    }

    #[test]
    fn a_secret_opens_only_for_its_own_tenant_and_purpose() {
        let key = SecretKeys::generate(&OsRandom);
        let keys = keys(&[("a", &key)]);
        let (tenant, other) = (tenant(), tenant());
        let sealed = keys.seal(&tenant, PURPOSE, &secret()).expect("seal");

        for (tenant, purpose) in [(&other, PURPOSE), (&tenant, "ldap.bind_password")] {
            let error = keys
                .open(tenant, purpose, &sealed)
                .expect_err("must not open");
            assert_eq!(error.code(), "secret.unreadable");
        }
    }

    #[test]
    fn any_changed_bit_is_refused() {
        let key = SecretKeys::generate(&OsRandom);
        let keys = keys(&[("a", &key)]);
        let tenant = tenant();
        let sealed = keys.seal(&tenant, PURPOSE, &secret()).expect("seal");

        for position in 0..sealed.as_bytes().len() {
            for bit in 0..8 {
                let mut bytes = sealed.as_bytes().to_vec();
                bytes[position] ^= 1 << bit;
                let error = keys
                    .open(&tenant, PURPOSE, &SealedSecret::from_stored(bytes))
                    .expect_err("a changed secret must not open");
                assert_eq!(
                    error.code(),
                    "secret.unreadable",
                    "byte {position} bit {bit}"
                );
            }
        }
        for length in 0..sealed.as_bytes().len() {
            let cut = SealedSecret::from_stored(sealed.as_bytes()[..length].to_vec());
            assert!(
                keys.open(&tenant, PURPOSE, &cut).is_err(),
                "cut to {length}"
            );
        }
    }

    #[test]
    fn a_new_first_key_seals_while_the_old_one_still_opens() {
        let (old, new) = (
            SecretKeys::generate(&OsRandom),
            SecretKeys::generate(&OsRandom),
        );
        let tenant = tenant();
        let before = keys(&[("2026-05", &old)]);
        let sealed_before = before.seal(&tenant, PURPOSE, &secret()).expect("seal");

        let after = keys(&[("2026-11", &new), ("2026-05", &old)]);
        let opened = after
            .open(&tenant, PURPOSE, &sealed_before)
            .expect("the old key opens");
        assert_eq!(opened.expose(), secret().expose());
        assert!(after.needs_resealing(&sealed_before));

        let sealed_after = after.seal(&tenant, PURPOSE, &secret()).expect("seal");
        assert_eq!(&sealed_after.as_bytes()[2..9], b"2026-11");
        assert!(!after.needs_resealing(&sealed_after));

        // Once the old key is removed, what it sealed is gone; what the
        // new one sealed is not.
        let later = keys(&[("2026-11", &new)]);
        assert!(later.open(&tenant, PURPOSE, &sealed_before).is_err());
        assert!(later.open(&tenant, PURPOSE, &sealed_after).is_ok());
        // And the same identifier with another key does not open it.
        let impostor = keys(&[("2026-05", &new)]);
        assert!(impostor.open(&tenant, PURPOSE, &sealed_before).is_err());
    }

    #[test]
    fn without_keys_nothing_is_sealed_or_opened() {
        let tenant = tenant();
        let error = SecretKeys::none()
            .seal(&tenant, PURPOSE, &secret())
            .expect_err("no key");
        assert_eq!(error.code(), "secret.keys_missing");

        let key = SecretKeys::generate(&OsRandom);
        let sealed = keys(&[("a", &key)])
            .seal(&tenant, PURPOSE, &secret())
            .expect("seal");
        let error = SecretKeys::none()
            .open(&tenant, PURPOSE, &sealed)
            .expect_err("no key");
        assert_eq!(error.code(), "secret.unreadable");
    }

    #[test]
    fn an_empty_secret_is_a_secret_too() {
        let key = SecretKeys::generate(&OsRandom);
        let keys = keys(&[("a", &key)]);
        let tenant = tenant();
        let sealed = keys
            .seal(&tenant, PURPOSE, &Secret::new(Vec::new()))
            .expect("seal");
        assert!(
            keys.open(&tenant, PURPOSE, &sealed)
                .expect("open")
                .expose()
                .is_empty()
        );
    }

    #[test]
    fn a_purpose_that_is_not_a_plain_name_is_refused() {
        let key = SecretKeys::generate(&OsRandom);
        let keys = keys(&[("a", &key)]);
        for purpose in ["", "With Spaces", "a\0b", &"a".repeat(129)] {
            let error = keys
                .seal(&tenant(), purpose, &secret())
                .expect_err("purpose");
            assert_eq!(error.code(), "secret.purpose_invalid");
        }
    }

    #[test]
    fn a_wrong_setting_is_refused_without_repeating_it() {
        let good = SecretKeys::generate(&OsRandom);
        let short = Secret::new(STANDARD.encode([7_u8; 16]));
        let not_base64 = Secret::new("not base64 at all!".to_owned());
        for (pairs, expected) in [
            (vec![("UPPER", &good)], "identifier of key 1"),
            (vec![("", &good)], "identifier of key 1"),
            (vec![("a", &good), ("a", &good)], "key 2 is used twice"),
            (vec![("a", &short)], "key 1 is not 32 bytes"),
            (
                vec![("a", &good), ("b", &not_base64)],
                "key 2 is not Base64",
            ),
        ] {
            let error = SecretKeys::parse(&setting(&pairs)).expect_err("must be refused");
            assert_eq!(error.code(), "secret.keys_invalid");
            let said = format!("{error:?}");
            assert!(said.contains(expected), "{said}");
            for (_, key) in &pairs {
                assert!(
                    !said.contains(key.expose().as_str()),
                    "the key is not repeated"
                );
            }
        }
        let error = SecretKeys::parse(&Secret::new("no-colon".to_owned())).expect_err("refused");
        assert_eq!(error.code(), "secret.keys_invalid");
    }

    #[test]
    fn printing_the_keys_shows_identifiers_only() {
        let key = SecretKeys::generate(&OsRandom);
        let said = format!("{:?}", keys(&[("2026-11", &key)]));
        assert!(said.contains("2026-11"));
        assert!(!said.contains(key.expose().as_str()));
    }

    #[test]
    fn a_generated_key_is_32_random_bytes() {
        let (first, second) = (
            SecretKeys::generate(&OsRandom),
            SecretKeys::generate(&OsRandom),
        );
        assert_ne!(first.expose(), second.expose());
        assert_eq!(STANDARD.decode(first.expose()).expect("Base64").len(), 32);
    }
}
