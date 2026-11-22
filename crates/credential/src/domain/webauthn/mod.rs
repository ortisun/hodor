//! WebAuthn credentials: security keys and platform authenticators.
//!
//! The checks of registration and of an answer to a challenge, in the
//! order of `docs/architecture/contexts/credential.md`, as functions over
//! bytes. Signatures go through the kernel's `SignatureVerifier` and hashes
//! through its `Digest`; nothing here is cryptography of its own
//! (Decision 0024).

pub(crate) mod cbor;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{
    Digest, DomainError, DomainEvent, PublicKey, RandomSource, SignatureAlgorithm,
    SignatureVerifier, Timestamp, UserId,
};
use serde::{Deserialize, Serialize};
use time::Duration;

hodor_kernel::define_id!(
    /// Hodor's identifier of a WebAuthn credential. Not the identifier the
    /// authenticator made, which is [`WebAuthnCredentialSnapshot::credential_id`].
    WebAuthnCredentialId
);

hodor_kernel::define_id!(
    /// Refers to a registration that was asked for and not yet finished.
    WebAuthnRegistrationId
);

/// How long a person has to finish a registration, and how long the
/// browser is told to wait for the authenticator.
pub(crate) const CEREMONY_LIFETIME: Duration = Duration::minutes(5);
/// The longest credential identifier the specification allows.
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;
/// The longest name a person may give a credential, in characters.
const MAX_NAME_CHARACTERS: usize = 64;
/// The name of a credential the person did not name.
const DEFAULT_NAME: &str = "Security key";
/// The smallest RSA modulus accepted, in bytes: 2,048 bits.
const MIN_RSA_MODULUS_BYTES: usize = 256;
/// How authenticators are reached, as browsers name it. Anything else the
/// browser says is dropped.
const KNOWN_TRANSPORTS: [&str; 6] = ["usb", "nfc", "ble", "internal", "hybrid", "smart-card"];

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const FLAG_BACKED_UP: u8 = 0x10;
const FLAG_ATTESTED_CREDENTIAL: u8 = 0x40;
const FLAG_EXTENSIONS: u8 = 0x80;

/// The signature algorithms a credential may use, by their COSE numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseAlgorithm {
    /// ECDSA on P-256 with SHA-256: COSE `-7`.
    Es256,
    /// RSA with PKCS#1 v1.5 padding and SHA-256: COSE `-257`.
    Rs256,
}

impl CoseAlgorithm {
    /// The COSE number.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Es256 => -7,
            Self::Rs256 => -257,
        }
    }

    /// The algorithm of a COSE number, if it is one Hodor accepts.
    #[must_use]
    pub const fn from_code(code: i64) -> Option<Self> {
        match code {
            -7 => Some(Self::Es256),
            -257 => Some(Self::Rs256),
            _ => None,
        }
    }

    const fn signature(self) -> SignatureAlgorithm {
        match self {
            Self::Es256 => SignatureAlgorithm::Es256,
            Self::Rs256 => SignatureAlgorithm::Rs256,
        }
    }
}

/// Who credentials are made for: derived from the installation's public
/// address, and the same for every tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    id: String,
    origin: String,
}

impl RelyingParty {
    /// The name browsers may show when a credential is made.
    pub const NAME: &'static str = "Hodor";

    /// The relying party of an installation whose public address is
    /// `address`, such as `https://id.example.com`.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` when the address is not `http` or `https` with a
    /// host name: an address by number cannot be a relying party.
    pub fn from_public_address(address: &str) -> Result<Self, DomainError> {
        let refuse = || {
            DomainError::invalid(
                "credential.webauthn_public_address_invalid",
                "the public address cannot name a WebAuthn relying party",
            )
            .with_detail(format!("public address `{address}`"))
        };
        let lowered = address.trim().to_ascii_lowercase();
        let (scheme, rest) = lowered.split_once("://").ok_or_else(refuse)?;
        if scheme != "https" && scheme != "http" {
            return Err(refuse());
        }
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host = authority
            .rsplit_once(':')
            .map_or(authority, |(host, port)| {
                if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
                    host
                } else {
                    authority
                }
            });
        let is_name = !host.is_empty()
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            && !host.bytes().all(|b| b.is_ascii_digit() || b == b'.');
        if !is_name || authority.contains('@') {
            return Err(refuse());
        }
        Ok(Self {
            id: host.to_owned(),
            origin: format!("{scheme}://{authority}"),
        })
    }

    /// The relying party identifier: the host.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The origin pages are served from.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// 32 random bytes an authenticator must sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge(pub [u8; 32]);

impl Challenge {
    /// A fresh challenge.
    #[must_use]
    pub fn generate(random: &dyn RandomSource) -> Self {
        let mut bytes = [0_u8; 32];
        random.fill(&mut bytes);
        Self(bytes)
    }

    /// The challenge as the browser and the client data carry it.
    #[must_use]
    pub fn encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The user handle given to authenticators: the 16 bytes of the user's
/// identifier.
#[must_use]
pub fn user_handle(user: UserId) -> Vec<u8> {
    user.as_uuid().as_bytes().to_vec()
}

/// The state of a WebAuthn credential as it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnCredentialSnapshot {
    /// Hodor's identifier of the credential.
    pub id: WebAuthnCredentialId,
    /// The user it belongs to.
    pub user_id: UserId,
    /// The identifier the authenticator made.
    pub credential_id: Vec<u8>,
    /// The public key, as the COSE key the authenticator sent.
    pub public_key: Vec<u8>,
    /// The key's algorithm.
    pub algorithm: CoseAlgorithm,
    /// The counter last reported.
    pub sign_count: u32,
    /// Whether the credential may be backed up.
    pub backup_eligible: bool,
    /// Whether it is backed up.
    pub backed_up: bool,
    /// Whether it is discoverable, when the browser said.
    pub discoverable: Option<bool>,
    /// How the authenticator is reached.
    pub transports: Vec<String>,
    /// The name the person gave it.
    pub name: String,
    /// When it was registered.
    pub created_at: Timestamp,
    /// When it was last used.
    pub last_used_at: Option<Timestamp>,
}

/// A WebAuthn credential: a public key Hodor checks signatures with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnCredential {
    state: WebAuthnCredentialSnapshot,
}

impl WebAuthnCredential {
    /// Rebuilds a credential from stored state.
    #[must_use]
    pub const fn from_snapshot(state: WebAuthnCredentialSnapshot) -> Self {
        Self { state }
    }

    /// The credential's state.
    #[must_use]
    pub const fn snapshot(&self) -> &WebAuthnCredentialSnapshot {
        &self.state
    }

    /// Hodor's identifier of the credential.
    #[must_use]
    pub const fn id(&self) -> WebAuthnCredentialId {
        self.state.id
    }

    /// The user it belongs to.
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.state.user_id
    }

    /// How the browser is told about this credential.
    #[must_use]
    pub fn descriptor(&self) -> CredentialDescriptor {
        CredentialDescriptor {
            kind: "public-key",
            id: encode(&self.state.credential_id),
            transports: self.state.transports.clone(),
        }
    }

    /// Records a verified answer: the new counter and backup state.
    pub(crate) fn record_use(&mut self, sign_count: u32, backed_up: bool, now: Timestamp) {
        self.state.sign_count = sign_count;
        self.state.backed_up = backed_up;
        self.state.last_used_at = Some(now);
    }

    /// The event of its registration.
    #[must_use]
    pub const fn registered_event(&self) -> WebAuthnEvent {
        WebAuthnEvent::Registered {
            user_id: self.state.user_id,
            credential_id: self.state.id,
        }
    }
}

/// The state of a registration that was asked for and not yet finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRegistrationSnapshot {
    /// Refers to the registration.
    pub id: WebAuthnRegistrationId,
    /// Who asked.
    pub user_id: UserId,
    /// The challenge the authenticator must sign.
    pub challenge: Challenge,
    /// When it was asked for.
    pub created_at: Timestamp,
    /// When it can no longer be finished.
    pub expires_at: Timestamp,
}

/// A registration that was asked for and not yet finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRegistration {
    state: PendingRegistrationSnapshot,
}

impl PendingRegistration {
    /// A new registration for a user, with a fresh challenge.
    #[must_use]
    pub fn begin(user_id: UserId, random: &dyn RandomSource, now: Timestamp) -> Self {
        Self {
            state: PendingRegistrationSnapshot {
                id: WebAuthnRegistrationId::generate(),
                user_id,
                challenge: Challenge::generate(random),
                created_at: now,
                expires_at: now + CEREMONY_LIFETIME,
            },
        }
    }

    /// Rebuilds a registration from stored state.
    #[must_use]
    pub const fn from_snapshot(state: PendingRegistrationSnapshot) -> Self {
        Self { state }
    }

    /// The registration's state.
    #[must_use]
    pub const fn snapshot(&self) -> &PendingRegistrationSnapshot {
        &self.state
    }

    /// Whether it can still be finished by this user at `now`.
    #[must_use]
    pub fn is_good_for(&self, user_id: UserId, now: Timestamp) -> bool {
        self.state.user_id == user_id && now < self.state.expires_at
    }
}

/// A credential as the browser is told about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialDescriptor {
    /// Always `public-key`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// The credential identifier, in base64url.
    pub id: String,
    /// How the authenticator is reached.
    pub transports: Vec<String>,
}

/// The relying party, as the browser is told about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelyingPartyEntity {
    /// The relying party identifier.
    pub id: String,
    /// The name browsers may show.
    pub name: &'static str,
}

/// The user, as the authenticator is told about them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserEntity {
    /// The user handle, in base64url.
    pub id: String,
    /// What the person signs in with.
    pub name: String,
    /// The name the person goes by.
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// An algorithm the authenticator may make a key for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialParameter {
    /// Always `public-key`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// The COSE number of the algorithm.
    pub alg: i32,
}

/// What kind of authenticator and verification is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AuthenticatorSelection {
    /// Whether a discoverable credential is wanted.
    #[serde(rename = "residentKey")]
    pub resident_key: &'static str,
    /// Whether the authenticator should verify the person.
    #[serde(rename = "userVerification")]
    pub user_verification: &'static str,
}

/// Extensions asked of the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CreationExtensions {
    /// Ask the browser to say whether the credential is discoverable.
    #[serde(rename = "credProps")]
    pub cred_props: bool,
}

/// The options of a registration: `PublicKeyCredentialCreationOptionsJSON`
/// of the WebAuthn specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreationOptions {
    /// The relying party.
    pub rp: RelyingPartyEntity,
    /// The user.
    pub user: UserEntity,
    /// The challenge, in base64url.
    pub challenge: String,
    /// The algorithms accepted, preferred first.
    #[serde(rename = "pubKeyCredParams")]
    pub parameters: Vec<CredentialParameter>,
    /// How long the browser waits, in milliseconds.
    pub timeout: u32,
    /// The user's credentials, not to be registered again.
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    /// What is asked of the authenticator.
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: AuthenticatorSelection,
    /// Always `none`.
    pub attestation: &'static str,
    /// The extensions asked for.
    pub extensions: CreationExtensions,
}

/// The options of a challenge: `PublicKeyCredentialRequestOptionsJSON` of
/// the WebAuthn specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestOptions {
    /// The challenge, in base64url.
    pub challenge: String,
    /// The relying party identifier.
    #[serde(rename = "rpId")]
    pub rp_id: String,
    /// The credentials that may answer.
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<CredentialDescriptor>,
    /// Whether the authenticator should verify the person.
    #[serde(rename = "userVerification")]
    pub user_verification: &'static str,
    /// How long the browser waits, in milliseconds.
    pub timeout: u32,
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
const TIMEOUT_MILLISECONDS: u32 = CEREMONY_LIFETIME.whole_milliseconds() as u32;

/// The options of a registration for `user`, who already has `existing`.
#[must_use]
pub(crate) fn creation_options(
    relying_party: &RelyingParty,
    pending: &PendingRegistration,
    name: &str,
    display_name: &str,
    existing: &[WebAuthnCredential],
) -> CreationOptions {
    let parameter = |algorithm: CoseAlgorithm| CredentialParameter {
        kind: "public-key",
        alg: algorithm.code(),
    };
    CreationOptions {
        rp: RelyingPartyEntity {
            id: relying_party.id.clone(),
            name: RelyingParty::NAME,
        },
        user: UserEntity {
            id: encode(&user_handle(pending.state.user_id)),
            name: name.to_owned(),
            display_name: display_name.to_owned(),
        },
        challenge: pending.state.challenge.encoded(),
        parameters: vec![
            parameter(CoseAlgorithm::Es256),
            parameter(CoseAlgorithm::Rs256),
        ],
        timeout: TIMEOUT_MILLISECONDS,
        exclude_credentials: existing
            .iter()
            .map(WebAuthnCredential::descriptor)
            .collect(),
        authenticator_selection: AuthenticatorSelection {
            resident_key: "preferred",
            user_verification: "discouraged",
        },
        attestation: "none",
        extensions: CreationExtensions { cred_props: true },
    }
}

/// The options of a challenge that `credentials` may answer.
#[must_use]
pub(crate) fn request_options(
    relying_party: &RelyingParty,
    challenge: &Challenge,
    credentials: &[WebAuthnCredential],
) -> RequestOptions {
    RequestOptions {
        challenge: challenge.encoded(),
        rp_id: relying_party.id.clone(),
        allow_credentials: credentials
            .iter()
            .map(WebAuthnCredential::descriptor)
            .collect(),
        user_verification: "discouraged",
        timeout: TIMEOUT_MILLISECONDS,
    }
}

/// What the browser sends to finish a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationResponse {
    /// The client data, as the bytes the browser made.
    pub client_data: Vec<u8>,
    /// The attestation object, as the authenticator made it.
    pub attestation_object: Vec<u8>,
    /// How the authenticator is reached, as the browser said.
    pub transports: Vec<String>,
    /// Whether the credential is discoverable, as the browser said.
    pub discoverable: Option<bool>,
    /// The name the person gives it.
    pub name: Option<String>,
}

impl RegistrationResponse {
    /// Reads a registration whose byte strings are in base64url without
    /// padding, as the interaction interface carries them.
    #[must_use]
    pub fn from_base64url(
        client_data: &str,
        attestation_object: &str,
        transports: Vec<String>,
        discoverable: Option<bool>,
        name: Option<String>,
    ) -> Option<Self> {
        Some(Self {
            client_data: URL_SAFE_NO_PAD.decode(client_data).ok()?,
            attestation_object: URL_SAFE_NO_PAD.decode(attestation_object).ok()?,
            transports,
            discoverable,
            name,
        })
    }
}

/// What the browser sends as an answer to a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionResponse {
    /// The identifier of the credential that answered.
    pub credential_id: Vec<u8>,
    /// The client data, as the bytes the browser made.
    pub client_data: Vec<u8>,
    /// The authenticator data.
    pub authenticator_data: Vec<u8>,
    /// The signature.
    pub signature: Vec<u8>,
    /// The user handle, when the authenticator gave one.
    pub user_handle: Option<Vec<u8>>,
}

impl AssertionResponse {
    /// Reads an answer whose values are in base64url without padding, as
    /// the interaction interface carries them.
    #[must_use]
    pub fn from_base64url(
        credential_id: &str,
        client_data: &str,
        authenticator_data: &str,
        signature: &str,
        user_handle: Option<&str>,
    ) -> Option<Self> {
        let decode = |value: &str| URL_SAFE_NO_PAD.decode(value).ok();
        Some(Self {
            credential_id: decode(credential_id)?,
            client_data: decode(client_data)?,
            authenticator_data: decode(authenticator_data)?,
            signature: decode(signature)?,
            user_handle: match user_handle.filter(|handle| !handle.is_empty()) {
                Some(handle) => Some(decode(handle)?),
                None => None,
            },
        })
    }
}

/// Why a registration or an answer was refused. Never shown to the
/// person: the reason for a test, and for the detail of an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The client data is not JSON of the expected shape.
    ClientDataUnreadable,
    /// The client data is for another ceremony.
    WrongType,
    /// The client data carries another challenge.
    WrongChallenge,
    /// The client data names another origin.
    WrongOrigin,
    /// The client data says the page was framed by another site.
    CrossOrigin,
    /// The attestation object is not what an authenticator writes.
    AttestationUnreadable,
    /// The authenticator data cannot be read.
    AuthenticatorDataUnreadable,
    /// The authenticator data is for another relying party.
    WrongRelyingParty,
    /// The user was not present.
    UserNotPresent,
    /// A registration carries no credential, or an answer carries one.
    CredentialDataMisplaced,
    /// The authenticator says the credential is backed up but may not be,
    /// or whether it may be changed since registration.
    BackupFlagsInconsistent,
    /// The credential identifier is too long.
    CredentialIdTooLong,
    /// The public key is not one Hodor accepts.
    UnacceptableKey,
    /// The credential is not the user's.
    UnknownCredential,
    /// The user handle is not the user's.
    WrongUser,
    /// The signature does not verify.
    BadSignature,
}

impl Refusal {
    const fn name(self) -> &'static str {
        match self {
            Self::ClientDataUnreadable => "client_data_unreadable",
            Self::WrongType => "wrong_type",
            Self::WrongChallenge => "wrong_challenge",
            Self::WrongOrigin => "wrong_origin",
            Self::CrossOrigin => "cross_origin",
            Self::AttestationUnreadable => "attestation_unreadable",
            Self::AuthenticatorDataUnreadable => "authenticator_data_unreadable",
            Self::WrongRelyingParty => "wrong_relying_party",
            Self::UserNotPresent => "user_not_present",
            Self::CredentialDataMisplaced => "credential_data_misplaced",
            Self::BackupFlagsInconsistent => "backup_flags_inconsistent",
            Self::CredentialIdTooLong => "credential_id_too_long",
            Self::UnacceptableKey => "unacceptable_key",
            Self::UnknownCredential => "unknown_credential",
            Self::WrongUser => "wrong_user",
            Self::BadSignature => "bad_signature",
        }
    }

    /// The error a refused registration is answered with.
    #[must_use]
    pub(crate) fn registration_error(self) -> DomainError {
        DomainError::invalid(
            "credential.webauthn_registration_refused",
            "the security key's answer could not be accepted",
        )
        .with_detail(self.name())
    }
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

fn check_client_data(
    bytes: &[u8],
    kind: &str,
    challenge: &Challenge,
    relying_party: &RelyingParty,
) -> Result<(), Refusal> {
    let data: ClientData =
        serde_json::from_slice(bytes).map_err(|_| Refusal::ClientDataUnreadable)?;
    if data.kind != kind {
        return Err(Refusal::WrongType);
    }
    if data.challenge != challenge.encoded() {
        return Err(Refusal::WrongChallenge);
    }
    if data.origin != relying_party.origin {
        return Err(Refusal::WrongOrigin);
    }
    if data.cross_origin == Some(true) {
        return Err(Refusal::CrossOrigin);
    }
    Ok(())
}

/// The credential an authenticator made, as its data carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AttestedCredential {
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
}

/// The authenticator data, read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthenticatorData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    attested: Option<AttestedCredential>,
}

impl AuthenticatorData {
    fn read(bytes: &[u8]) -> Result<Self, Refusal> {
        let unreadable = || Refusal::AuthenticatorDataUnreadable;
        if bytes.len() < 37 {
            return Err(unreadable());
        }
        let rp_id_hash: [u8; 32] = bytes[..32].try_into().map_err(|_| unreadable())?;
        let flags = bytes[32];
        let sign_count = u32::from_be_bytes(bytes[33..37].try_into().map_err(|_| unreadable())?);
        let mut position = 37;
        let attested = if flags & FLAG_ATTESTED_CREDENTIAL == 0 {
            None
        } else {
            // 16 bytes of the authenticator's model, then the length of the
            // credential identifier.
            let header = bytes.get(position..position + 18).ok_or_else(unreadable)?;
            let length = usize::from(u16::from_be_bytes([header[16], header[17]]));
            if length > MAX_CREDENTIAL_ID_BYTES {
                return Err(Refusal::CredentialIdTooLong);
            }
            position += 18;
            let credential_id = bytes
                .get(position..position + length)
                .ok_or_else(unreadable)?
                .to_vec();
            position += length;
            let (_, used) = cbor::read(&bytes[position..]).map_err(|_| unreadable())?;
            let public_key = bytes[position..position + used].to_vec();
            position += used;
            Some(AttestedCredential {
                credential_id,
                public_key,
            })
        };
        if flags & FLAG_EXTENSIONS != 0 {
            let (extensions, used) = cbor::read(&bytes[position..]).map_err(|_| unreadable())?;
            if !matches!(extensions, cbor::Value::Map(_)) {
                return Err(unreadable());
            }
            position += used;
        }
        if position != bytes.len() {
            return Err(unreadable());
        }
        Ok(Self {
            rp_id_hash,
            flags,
            sign_count,
            attested,
        })
    }

    const fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    fn check_common(
        &self,
        relying_party: &RelyingParty,
        digest: &dyn Digest,
    ) -> Result<(), Refusal> {
        if self.rp_id_hash != digest.sha256(relying_party.id.as_bytes()) {
            return Err(Refusal::WrongRelyingParty);
        }
        if !self.has(FLAG_USER_PRESENT) {
            return Err(Refusal::UserNotPresent);
        }
        if self.has(FLAG_BACKED_UP) && !self.has(FLAG_BACKUP_ELIGIBLE) {
            return Err(Refusal::BackupFlagsInconsistent);
        }
        Ok(())
    }
}

/// The key of a COSE key, if it is one Hodor accepts.
fn read_key(cose: &[u8]) -> Result<(CoseAlgorithm, PublicKey), Refusal> {
    let refuse = || Refusal::UnacceptableKey;
    let key = cbor::read_exactly(cose).map_err(|_| refuse())?;
    let integer = |label: i128| key.get_integer(label).and_then(cbor::Value::as_integer);
    let bytes = |label: i128| key.get_integer(label).and_then(cbor::Value::as_bytes);
    let algorithm = integer(3)
        .and_then(|code| i64::try_from(code).ok())
        .and_then(CoseAlgorithm::from_code)
        .ok_or_else(refuse)?;
    match (integer(1), algorithm) {
        // EC2 on P-256.
        (Some(2), CoseAlgorithm::Es256) => {
            let (Some(1), Some(x), Some(y)) = (integer(-1), bytes(-2), bytes(-3)) else {
                return Err(refuse());
            };
            if x.len() != 32 || y.len() != 32 {
                return Err(refuse());
            }
            Ok((
                algorithm,
                PublicKey::P256 {
                    x: x.to_vec(),
                    y: y.to_vec(),
                },
            ))
        }
        // RSA.
        (Some(3), CoseAlgorithm::Rs256) => {
            let (Some(modulus), Some(exponent)) = (bytes(-1), bytes(-2)) else {
                return Err(refuse());
            };
            let first = modulus
                .iter()
                .position(|b| *b != 0)
                .unwrap_or(modulus.len());
            if modulus.len() - first < MIN_RSA_MODULUS_BYTES || exponent.is_empty() {
                return Err(refuse());
            }
            Ok((
                algorithm,
                PublicKey::Rsa {
                    modulus: modulus[first..].to_vec(),
                    exponent: exponent.to_vec(),
                },
            ))
        }
        _ => Err(refuse()),
    }
}

/// Turns an ECDSA signature in DER, `SEQUENCE { INTEGER r, INTEGER s }`,
/// into the 64 bytes `r` then `s` the port takes. Anything that is not
/// strict DER of that shape is refused.
fn der_to_fixed(der: &[u8]) -> Option<Vec<u8>> {
    let integer = |input: &[u8]| -> Option<([u8; 32], usize)> {
        let (&tag, rest) = input.split_first()?;
        let (&length, rest) = rest.split_first()?;
        let length = usize::from(length);
        if tag != 0x02 || length == 0 || length > 33 || rest.len() < length {
            return None;
        }
        let value = &rest[..length];
        // Negative, or not in its shortest form.
        if value[0] & 0x80 != 0 || (length > 1 && value[0] == 0 && value[1] & 0x80 == 0) {
            return None;
        }
        let value = if value[0] == 0 && length > 1 {
            &value[1..]
        } else {
            value
        };
        if value.len() > 32 {
            return None;
        }
        let mut fixed = [0_u8; 32];
        fixed[32 - value.len()..].copy_from_slice(value);
        Some((fixed, 2 + length))
    };
    let (&tag, rest) = der.split_first()?;
    let (&length, body) = rest.split_first()?;
    if tag != 0x30 || length >= 0x80 || usize::from(length) != body.len() {
        return None;
    }
    let (r, used) = integer(body)?;
    let (s, used_too) = integer(&body[used..])?;
    if used + used_too != body.len() {
        return None;
    }
    let mut fixed = r.to_vec();
    fixed.extend_from_slice(&s);
    Some(fixed)
}

/// Checks what an authenticator answered to a registration and makes the
/// credential. The caller has already used up `pending` and checked that
/// it was good for the user.
///
/// # Errors
///
/// Returns why the answer is refused.
pub(crate) fn check_registration(
    relying_party: &RelyingParty,
    pending: &PendingRegistration,
    response: RegistrationResponse,
    digest: &dyn Digest,
    now: Timestamp,
) -> Result<WebAuthnCredential, Refusal> {
    check_client_data(
        &response.client_data,
        "webauthn.create",
        &pending.state.challenge,
        relying_party,
    )?;
    let object = cbor::read_exactly(&response.attestation_object)
        .map_err(|_| Refusal::AttestationUnreadable)?;
    // The statement is not checked, whatever its format: only that it is
    // there, as the specification shapes the object.
    let well_formed = matches!(object.get_text("fmt"), Some(cbor::Value::Text(_)))
        && matches!(object.get_text("attStmt"), Some(cbor::Value::Map(_)));
    let authenticator_data = object
        .get_text("authData")
        .and_then(cbor::Value::as_bytes)
        .filter(|_| well_formed)
        .ok_or(Refusal::AttestationUnreadable)?;
    let data = AuthenticatorData::read(authenticator_data)?;
    data.check_common(relying_party, digest)?;
    let attested = data
        .attested
        .clone()
        .ok_or(Refusal::CredentialDataMisplaced)?;
    let (algorithm, _) = read_key(&attested.public_key)?;

    let mut transports: Vec<String> = response
        .transports
        .into_iter()
        .filter(|transport| KNOWN_TRANSPORTS.contains(&transport.as_str()))
        .collect();
    transports.sort();
    transports.dedup();
    let name = response
        .name
        .map(|name| {
            name.trim()
                .chars()
                .take(MAX_NAME_CHARACTERS)
                .collect::<String>()
        })
        .filter(|name| !name.is_empty() && !name.chars().any(char::is_control))
        .unwrap_or_else(|| DEFAULT_NAME.to_owned());
    Ok(WebAuthnCredential {
        state: WebAuthnCredentialSnapshot {
            id: WebAuthnCredentialId::generate(),
            user_id: pending.state.user_id,
            credential_id: attested.credential_id,
            public_key: attested.public_key,
            algorithm,
            sign_count: data.sign_count,
            backup_eligible: data.has(FLAG_BACKUP_ELIGIBLE),
            backed_up: data.has(FLAG_BACKED_UP),
            discoverable: response.discoverable,
            transports,
            name,
            created_at: now,
            last_used_at: None,
        },
    })
}

/// What checking an answer to a challenge concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssertionCheck {
    /// Every check passed; these are what is stored next.
    Verified {
        /// The counter reported.
        sign_count: u32,
        /// Whether the credential is backed up now.
        backed_up: bool,
    },
    /// Everything verified except the counter, which did not grow: the
    /// credential was copied.
    CounterNotIncreased,
    /// A check failed.
    Refused(Refusal),
}

/// Checks an answer to `challenge` by `credential`, which the caller found
/// among the user's by the identifier the answer names.
#[must_use]
pub(crate) fn check_assertion(
    relying_party: &RelyingParty,
    challenge: &Challenge,
    credential: &WebAuthnCredential,
    response: &AssertionResponse,
    digest: &dyn Digest,
    verifier: &dyn SignatureVerifier,
) -> AssertionCheck {
    match verify_assertion(
        relying_party,
        challenge,
        credential,
        response,
        digest,
        verifier,
    ) {
        Ok(check) => check,
        Err(refusal) => AssertionCheck::Refused(refusal),
    }
}

fn verify_assertion(
    relying_party: &RelyingParty,
    challenge: &Challenge,
    credential: &WebAuthnCredential,
    response: &AssertionResponse,
    digest: &dyn Digest,
    verifier: &dyn SignatureVerifier,
) -> Result<AssertionCheck, Refusal> {
    let stored = &credential.state;
    if response.credential_id != stored.credential_id {
        return Err(Refusal::UnknownCredential);
    }
    if response
        .user_handle
        .as_ref()
        .is_some_and(|handle| *handle != user_handle(stored.user_id))
    {
        return Err(Refusal::WrongUser);
    }
    check_client_data(
        &response.client_data,
        "webauthn.get",
        challenge,
        relying_party,
    )?;
    let data = AuthenticatorData::read(&response.authenticator_data)?;
    data.check_common(relying_party, digest)?;
    if data.attested.is_some() {
        return Err(Refusal::CredentialDataMisplaced);
    }
    if data.has(FLAG_BACKUP_ELIGIBLE) != stored.backup_eligible {
        return Err(Refusal::BackupFlagsInconsistent);
    }
    let (algorithm, key) = read_key(&stored.public_key)?;
    let signature = match algorithm {
        CoseAlgorithm::Es256 => der_to_fixed(&response.signature).ok_or(Refusal::BadSignature)?,
        CoseAlgorithm::Rs256 => response.signature.clone(),
    };
    let mut message = response.authenticator_data.clone();
    message.extend_from_slice(&digest.sha256(&response.client_data));
    if !verifier.verify(algorithm.signature(), &key, &message, &signature) {
        return Err(Refusal::BadSignature);
    }
    if (stored.sign_count != 0 || data.sign_count != 0) && data.sign_count <= stored.sign_count {
        return Ok(AssertionCheck::CounterNotIncreased);
    }
    Ok(AssertionCheck::Verified {
        sign_count: data.sign_count,
        backed_up: data.has(FLAG_BACKED_UP),
    })
}

/// An event about a WebAuthn credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum WebAuthnEvent {
    /// A credential was registered.
    Registered {
        /// The user.
        user_id: UserId,
        /// Hodor's identifier of the credential.
        credential_id: WebAuthnCredentialId,
    },
    /// An answer came with a counter that did not grow.
    CounterNotIncreased {
        /// The user.
        user_id: UserId,
        /// Hodor's identifier of the credential.
        credential_id: WebAuthnCredentialId,
    },
}

impl DomainEvent for WebAuthnEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Registered { .. } => "credential.webauthn_registered",
            Self::CounterNotIncreased { .. } => "credential.webauthn_counter_not_increased",
        }
    }
}

#[cfg(test)]
mod tests;
