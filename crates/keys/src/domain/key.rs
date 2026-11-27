//! A key version: one key, made once, and where it is in its lifecycle.

use crate::domain::event::KeyEvent;
use hodor_kernel::{DomainError, PublicKey, SignatureAlgorithm, Timestamp};
use std::fmt;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies a key version. Published as the key identifier of a
    /// signing key; safe to show and to log: it grants nothing.
    KeyVersionId
);

/// What the keys of a key set are for. A tenant has one key set per use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyUse {
    /// Signing the tokens Hodor issues.
    Signing,
    /// Decrypting what others encrypt for Hodor. No algorithm is offered
    /// for it yet.
    Encryption,
    /// Encrypting the tenant's secrets at rest.
    Data,
}

impl KeyUse {
    /// The name used in storage and in events: `sig`, `enc` or `data`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signing => "sig",
            Self::Encryption => "enc",
            Self::Data => "data",
        }
    }

    /// Reads a use from its stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error for an unknown name.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "sig" => Ok(Self::Signing),
            "enc" => Ok(Self::Encryption),
            "data" => Ok(Self::Data),
            other => Err(stored_data_invalid(format!("unknown key use `{other}`"))),
        }
    }
}

/// The algorithms a key version can be made for. The algorithm decides
/// the use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyAlgorithm {
    /// ECDSA on the P-256 curve with SHA-256. The default for signing.
    Es256,
    /// RSA with PKCS#1 version 1.5 padding and SHA-256, for interoperability.
    Rs256,
    /// RSA with PSS padding and SHA-256, for interoperability. A key of
    /// its own, never the key of `Rs256`.
    Ps256,
    /// EdDSA on the Ed25519 curve (RFC 8037).
    EdDsa,
    /// AES-256-GCM, for data keys.
    A256Gcm,
}

impl KeyAlgorithm {
    /// The algorithm a tenant signs with unless told otherwise.
    pub const DEFAULT_SIGNING: Self = Self::Es256;

    /// Every algorithm offered, in a fixed order.
    pub const ALL: [Self; 5] = [
        Self::Es256,
        Self::Rs256,
        Self::Ps256,
        Self::EdDsa,
        Self::A256Gcm,
    ];

    /// The name used in storage, in events and in published keys.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Rs256 => "RS256",
            Self::Ps256 => "PS256",
            Self::EdDsa => "EdDSA",
            Self::A256Gcm => "A256GCM",
        }
    }

    /// Reads an algorithm from its name. Any other name, `none` among them,
    /// is refused by not being one of these.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.as_str() == name)
    }

    /// Reads an algorithm from its stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error for an unknown name.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        Self::from_name(value)
            .ok_or_else(|| stored_data_invalid(format!("unknown key algorithm `{value}`")))
    }

    /// The key set the keys of this algorithm belong to.
    #[must_use]
    pub const fn key_use(self) -> KeyUse {
        match self {
            Self::Es256 | Self::Rs256 | Self::Ps256 | Self::EdDsa => KeyUse::Signing,
            Self::A256Gcm => KeyUse::Data,
        }
    }

    /// The signature algorithm of a signing key, as signatures are checked.
    #[must_use]
    pub const fn signature(self) -> Option<SignatureAlgorithm> {
        match self {
            Self::Es256 => Some(SignatureAlgorithm::Es256),
            Self::Rs256 => Some(SignatureAlgorithm::Rs256),
            Self::Ps256 => Some(SignatureAlgorithm::Ps256),
            Self::EdDsa => Some(SignatureAlgorithm::EdDsa),
            Self::A256Gcm => None,
        }
    }
}

/// How a signature is written. An RSA or an EdDSA signature is the same
/// bytes either way; an ECDSA signature is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureEncoding {
    /// As JSON Web Signatures write it (RFC 7518, section 3.4): an ECDSA
    /// signature is its two numbers, 32 bytes each for P-256, one after
    /// the other. What tokens carry.
    Jose,
    /// As X.509 certificates write it (RFC 3279, section 2.2.3): an ECDSA
    /// signature is an ASN.1 sequence of its two integers, in DER. What
    /// certificates carry.
    Der,
}

impl SignatureEncoding {
    /// The name used in logs: `jose` or `der`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Jose => "jose",
            Self::Der => "der",
        }
    }
}

/// Where a key version is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyState {
    /// Made, not yet in use.
    Pending,
    /// The one version of its algorithm that signs or encrypts.
    Active,
    /// Replaced; still checks and decrypts until its time has passed.
    Retiring,
    /// Retired after its time; used for nothing.
    Retired,
    /// No longer trusted; used for nothing.
    Revoked,
}

impl KeyState {
    /// The name used in storage and in events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }

    /// Reads a state from its stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error for an unknown name.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "retiring" => Ok(Self::Retiring),
            "retired" => Ok(Self::Retired),
            "revoked" => Ok(Self::Revoked),
            other => Err(stored_data_invalid(format!("unknown key state `{other}`"))),
        }
    }
}

/// What a key provider hands back for a key it made: bytes only that
/// provider can turn back into the key. This context never reads them;
/// they are printed as their length only.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyMaterial(Vec<u8>);

impl KeyMaterial {
    /// Wraps bytes from a provider or from storage.
    #[must_use]
    pub const fn from_stored(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes to store or to hand back to the provider that made them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyMaterial({} bytes)", self.0.len())
    }
}

/// What a provider answers when it makes a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedKey {
    /// The public key, for a signing key; nothing for a data key.
    pub public_key: Option<PublicKey>,
    /// The key itself, as only the provider can use it.
    pub material: KeyMaterial,
}

/// The stored state of a key version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyVersionSnapshot {
    /// The version.
    pub id: KeyVersionId,
    /// What it is made for. Decides the use.
    pub algorithm: KeyAlgorithm,
    /// Where it is in its lifecycle.
    pub state: KeyState,
    /// Which provider made it, such as `local`.
    pub provider: String,
    /// The key, as the provider handed it back.
    pub material: KeyMaterial,
    /// The public key of a signing key.
    pub public_key: Option<PublicKey>,
    /// When it was made.
    pub created_at: Timestamp,
    /// When it became active.
    pub activated_at: Option<Timestamp>,
    /// When it started retiring.
    pub retiring_at: Option<Timestamp>,
    /// The moment after which a retiring version may be retired.
    pub retire_after: Option<Timestamp>,
    /// When it was retired.
    pub retired_at: Option<Timestamp>,
    /// When it was revoked.
    pub revoked_at: Option<Timestamp>,
    /// Why it was revoked.
    pub revocation_reason: Option<String>,
}

/// One key, made once and never changed, and its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyVersion {
    state: KeyVersionSnapshot,
}

/// Longest revocation reason kept, in characters.
pub const MAX_REASON_LENGTH: usize = 200;

/// Longest name of a provider.
const MAX_PROVIDER_LENGTH: usize = 32;

impl KeyVersion {
    /// A new pending version of a key a provider just made.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` `keys.algorithm_unsuitable` if the algorithm has no
    /// use the key could be put to, and an internal error if the provider
    /// answered something that does not fit the algorithm.
    pub fn create(
        id: KeyVersionId,
        algorithm: KeyAlgorithm,
        provider: &str,
        generated: GeneratedKey,
        now: Timestamp,
    ) -> Result<(Self, KeyEvent), DomainError> {
        let provider_usable = (1..=MAX_PROVIDER_LENGTH).contains(&provider.len())
            && provider
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        if !provider_usable {
            return Err(provider_answer_invalid("the provider's name is not usable"));
        }
        if generated.material.as_bytes().is_empty() {
            return Err(provider_answer_invalid(
                "the provider answered no key material",
            ));
        }
        match (algorithm.signature(), &generated.public_key) {
            (Some(signature), Some(key)) if signature.fits(key) => {}
            (None, None) => {}
            _ => {
                return Err(provider_answer_invalid(
                    "the public key does not fit the algorithm",
                ));
            }
        }
        let version = Self {
            state: KeyVersionSnapshot {
                id,
                algorithm,
                state: KeyState::Pending,
                provider: provider.to_owned(),
                material: generated.material,
                public_key: generated.public_key,
                created_at: now,
                activated_at: None,
                retiring_at: None,
                retire_after: None,
                retired_at: None,
                revoked_at: None,
                revocation_reason: None,
            },
        };
        let event = KeyEvent::VersionCreated {
            version_id: id,
            key_use: algorithm.key_use().as_str(),
            algorithm: algorithm.as_str(),
        };
        Ok((version, event))
    }

    /// Rebuilds a version from storage.
    #[must_use]
    pub const fn from_snapshot(state: KeyVersionSnapshot) -> Self {
        Self { state }
    }

    /// The stored state.
    #[must_use]
    pub const fn snapshot(&self) -> &KeyVersionSnapshot {
        &self.state
    }

    /// The version's identifier.
    #[must_use]
    pub const fn id(&self) -> KeyVersionId {
        self.state.id
    }

    /// What the key is made for.
    #[must_use]
    pub const fn algorithm(&self) -> KeyAlgorithm {
        self.state.algorithm
    }

    /// The key set the version belongs to.
    #[must_use]
    pub const fn key_use(&self) -> KeyUse {
        self.state.algorithm.key_use()
    }

    /// Where the version is in its lifecycle.
    #[must_use]
    pub const fn state(&self) -> KeyState {
        self.state.state
    }

    /// The key as the provider handed it back.
    #[must_use]
    pub const fn material(&self) -> &KeyMaterial {
        &self.state.material
    }

    /// The public key of a signing key.
    #[must_use]
    pub const fn public_key(&self) -> Option<&PublicKey> {
        self.state.public_key.as_ref()
    }

    /// Whether a signature made with this version may still be checked, or
    /// something it encrypted decrypted.
    #[must_use]
    pub const fn checks(&self) -> bool {
        matches!(self.state.state, KeyState::Active | KeyState::Retiring)
    }

    pub(crate) fn activate(&mut self, now: Timestamp) -> Result<(), DomainError> {
        if self.state.state != KeyState::Pending {
            return Err(DomainError::conflict(
                "keys.not_pending",
                "only a key version that was never used can be activated",
            ));
        }
        self.state.state = KeyState::Active;
        self.state.activated_at = Some(now);
        Ok(())
    }

    /// Sets an active version to retire after `retire_after`.
    pub(crate) fn start_retiring(&mut self, now: Timestamp, retire_after: Timestamp) {
        debug_assert_eq!(self.state.state, KeyState::Active);
        self.state.state = KeyState::Retiring;
        self.state.retiring_at = Some(now);
        self.state.retire_after = Some(retire_after);
    }

    pub(crate) fn retire(&mut self, now: Timestamp) -> Result<KeyEvent, DomainError> {
        if self.state.state != KeyState::Retiring {
            return Err(DomainError::conflict(
                "keys.not_retiring",
                "only a key version that is retiring can be retired",
            ));
        }
        if self.state.retire_after.is_some_and(|after| now < after) {
            return Err(DomainError::conflict(
                "keys.still_needed",
                "the key version may still be needed to check what it signed",
            ));
        }
        self.state.state = KeyState::Retired;
        self.state.retired_at = Some(now);
        Ok(KeyEvent::VersionRetired {
            version_id: self.state.id,
            algorithm: self.state.algorithm.as_str(),
        })
    }

    pub(crate) fn revoke(
        &mut self,
        reason: &str,
        now: Timestamp,
    ) -> Result<Option<KeyEvent>, DomainError> {
        let reason = reason.trim();
        if reason.is_empty() || reason.chars().count() > MAX_REASON_LENGTH {
            return Err(DomainError::invalid(
                "keys.reason_invalid",
                "a revocation needs a reason of at most 200 characters",
            ));
        }
        if self.state.state == KeyState::Revoked {
            return Ok(None);
        }
        let previous = self.state.state;
        self.state.state = KeyState::Revoked;
        self.state.revoked_at = Some(now);
        self.state.revocation_reason = Some(reason.to_owned());
        Ok(Some(KeyEvent::VersionRevoked {
            version_id: self.state.id,
            algorithm: self.state.algorithm.as_str(),
            previous_state: previous.as_str(),
            reason: reason.to_owned(),
        }))
    }
}

/// The overlap an activation is given must not be negative.
pub(crate) fn check_overlap(overlap: Duration) -> Result<(), DomainError> {
    if overlap.is_negative() {
        return Err(DomainError::invalid(
            "keys.overlap_invalid",
            "the time a replaced key version stays must not be negative",
        ));
    }
    Ok(())
}

fn stored_data_invalid(detail: String) -> DomainError {
    DomainError::internal(
        "keys.stored_data_invalid",
        "the key version could not be loaded",
    )
    .with_detail(detail)
}

fn provider_answer_invalid(detail: &str) -> DomainError {
    DomainError::internal("keys.provider_failed", "a key could not be made").with_detail(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p256() -> PublicKey {
        PublicKey::P256 {
            x: vec![1; 32],
            y: vec![2; 32],
        }
    }

    fn generated(public_key: Option<PublicKey>) -> GeneratedKey {
        GeneratedKey {
            public_key,
            material: KeyMaterial::from_stored(vec![7; 16]),
        }
    }

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn pending(algorithm: KeyAlgorithm) -> KeyVersion {
        let public_key = match algorithm {
            KeyAlgorithm::Es256 => Some(p256()),
            KeyAlgorithm::Rs256 | KeyAlgorithm::Ps256 => Some(PublicKey::Rsa {
                modulus: vec![1; 256],
                exponent: vec![1, 0, 1],
            }),
            KeyAlgorithm::EdDsa => Some(PublicKey::Ed25519 { x: vec![3; 32] }),
            KeyAlgorithm::A256Gcm => None,
        };
        KeyVersion::create(
            KeyVersionId::generate(),
            algorithm,
            "local",
            generated(public_key),
            NOW,
        )
        .expect("a valid version")
        .0
    }

    #[test]
    fn every_algorithm_is_read_back_from_its_name_and_none_is_refused() {
        for algorithm in KeyAlgorithm::ALL {
            assert_eq!(KeyAlgorithm::from_name(algorithm.as_str()), Some(algorithm));
            assert_eq!(KeyAlgorithm::from_stored(algorithm.as_str()), Ok(algorithm));
        }
        assert_eq!(KeyAlgorithm::from_name("EdDSA"), Some(KeyAlgorithm::EdDsa));
        for name in ["none", "HS256", "es256", "Ed25519", "EDDSA", ""] {
            assert_eq!(KeyAlgorithm::from_name(name), None);
        }
    }

    #[test]
    fn the_algorithm_decides_the_use_and_no_algorithm_is_for_encryption_yet() {
        assert_eq!(KeyAlgorithm::Es256.key_use(), KeyUse::Signing);
        assert_eq!(KeyAlgorithm::Rs256.key_use(), KeyUse::Signing);
        assert_eq!(KeyAlgorithm::Ps256.key_use(), KeyUse::Signing);
        assert_eq!(KeyAlgorithm::EdDsa.key_use(), KeyUse::Signing);
        assert_eq!(
            KeyAlgorithm::EdDsa.signature(),
            Some(SignatureAlgorithm::EdDsa)
        );
        assert_eq!(KeyAlgorithm::A256Gcm.key_use(), KeyUse::Data);
        assert!(
            KeyAlgorithm::ALL
                .iter()
                .all(|algorithm| algorithm.key_use() != KeyUse::Encryption)
        );
        assert_eq!(KeyAlgorithm::DEFAULT_SIGNING, KeyAlgorithm::Es256);
    }

    #[test]
    fn uses_and_states_are_read_back_from_their_stored_names() {
        for key_use in [KeyUse::Signing, KeyUse::Encryption, KeyUse::Data] {
            assert_eq!(KeyUse::from_stored(key_use.as_str()), Ok(key_use));
        }
        for state in [
            KeyState::Pending,
            KeyState::Active,
            KeyState::Retiring,
            KeyState::Retired,
            KeyState::Revoked,
        ] {
            assert_eq!(KeyState::from_stored(state.as_str()), Ok(state));
        }
        assert_eq!(
            KeyState::from_stored("expired")
                .expect_err("unknown")
                .code(),
            "keys.stored_data_invalid"
        );
    }

    #[test]
    fn key_material_is_printed_as_its_length_only() {
        let material = KeyMaterial::from_stored(b"private".to_vec());
        assert_eq!(format!("{material:?}"), "KeyMaterial(7 bytes)");
    }

    #[test]
    fn a_new_version_is_pending_and_its_event_names_use_and_algorithm() {
        let id = KeyVersionId::generate();
        let (version, event) = KeyVersion::create(
            id,
            KeyAlgorithm::Es256,
            "local",
            generated(Some(p256())),
            NOW,
        )
        .expect("valid");
        assert_eq!(version.state(), KeyState::Pending);
        assert!(!version.checks());
        assert_eq!(
            event,
            KeyEvent::VersionCreated {
                version_id: id,
                key_use: "sig",
                algorithm: "ES256",
            }
        );
    }

    #[test]
    fn a_provider_answer_that_does_not_fit_the_algorithm_is_refused() {
        let rsa = PublicKey::Rsa {
            modulus: vec![1; 256],
            exponent: vec![1, 0, 1],
        };
        let ed25519 = PublicKey::Ed25519 { x: vec![3; 32] };
        let cases = [
            (KeyAlgorithm::Es256, generated(Some(rsa.clone()))),
            (KeyAlgorithm::Rs256, generated(Some(p256()))),
            (KeyAlgorithm::EdDsa, generated(Some(p256()))),
            (KeyAlgorithm::EdDsa, generated(None)),
            (KeyAlgorithm::Es256, generated(Some(ed25519.clone()))),
            (KeyAlgorithm::Ps256, generated(Some(ed25519))),
            (KeyAlgorithm::Es256, generated(None)),
            (KeyAlgorithm::A256Gcm, generated(Some(p256()))),
            (
                KeyAlgorithm::A256Gcm,
                GeneratedKey {
                    public_key: None,
                    material: KeyMaterial::from_stored(Vec::new()),
                },
            ),
        ];
        for (algorithm, answer) in cases {
            let error =
                KeyVersion::create(KeyVersionId::generate(), algorithm, "local", answer, NOW)
                    .expect_err("must be refused");
            assert_eq!(error.code(), "keys.provider_failed");
        }
        for provider in ["", "Local", "local-provider", &"x".repeat(33)] {
            let error = KeyVersion::create(
                KeyVersionId::generate(),
                KeyAlgorithm::Es256,
                provider,
                generated(Some(p256())),
                NOW,
            )
            .expect_err("must be refused");
            assert_eq!(error.code(), "keys.provider_failed");
        }
    }

    #[test]
    fn only_a_pending_version_is_activated() {
        let mut version = pending(KeyAlgorithm::Es256);
        version.activate(NOW).expect("pending activates");
        assert_eq!(version.state(), KeyState::Active);
        assert_eq!(version.snapshot().activated_at, Some(NOW));
        assert!(version.checks());
        assert_eq!(
            version.activate(NOW).expect_err("not pending").code(),
            "keys.not_pending"
        );
    }

    #[test]
    fn a_retiring_version_retires_only_once_its_time_has_passed() {
        let mut version = pending(KeyAlgorithm::Rs256);
        assert_eq!(
            version.retire(NOW).expect_err("pending").code(),
            "keys.not_retiring"
        );
        version.activate(NOW).expect("activate");
        let after = NOW + Duration::hours(1);
        version.start_retiring(NOW, after);
        assert!(version.checks());
        assert_eq!(
            version
                .retire(after - Duration::seconds(1))
                .expect_err("too early")
                .code(),
            "keys.still_needed"
        );
        let event = version.retire(after).expect("retire on time");
        assert_eq!(version.state(), KeyState::Retired);
        assert!(!version.checks());
        assert_eq!(
            event,
            KeyEvent::VersionRetired {
                version_id: version.id(),
                algorithm: "RS256",
            }
        );
    }

    #[test]
    fn revoking_is_final_needs_a_reason_and_can_be_repeated_without_effect() {
        for state_before in [KeyState::Pending, KeyState::Active] {
            let mut version = pending(KeyAlgorithm::Ps256);
            if state_before == KeyState::Active {
                version.activate(NOW).expect("activate");
            }
            for reason in ["", "   ", &"x".repeat(201)] {
                assert_eq!(
                    version.revoke(reason, NOW).expect_err("no reason").code(),
                    "keys.reason_invalid"
                );
            }
            let event = version
                .revoke("  leaked  ", NOW)
                .expect("revoke")
                .expect("an event");
            assert_eq!(
                event,
                KeyEvent::VersionRevoked {
                    version_id: version.id(),
                    algorithm: "PS256",
                    previous_state: state_before.as_str(),
                    reason: "leaked".to_owned(),
                }
            );
            assert_eq!(version.state(), KeyState::Revoked);
            assert!(!version.checks());
            assert_eq!(version.revoke("again", NOW).expect("no change"), None);
            assert_eq!(
                version.snapshot().revocation_reason.as_deref(),
                Some("leaked")
            );
            assert_eq!(
                version.activate(NOW).expect_err("revoked").code(),
                "keys.not_pending"
            );
        }
    }

    #[test]
    fn a_negative_overlap_is_refused() {
        assert!(check_overlap(Duration::ZERO).is_ok());
        assert_eq!(
            check_overlap(Duration::seconds(-1))
                .expect_err("negative")
                .code(),
            "keys.overlap_invalid"
        );
    }
}
