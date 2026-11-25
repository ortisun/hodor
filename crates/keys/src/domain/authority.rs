//! The certificate authority of a tenant: its request, its key, its
//! certificate and the name constraints that keep it to the tenant's
//! trust domains.
//!
//! See `docs/architecture/contexts/keys.md`, "The certificate authority of
//! a tenant", and Decision 0062.

use crate::domain::key::{
    GeneratedKey, KeyAlgorithm, KeyMaterial, KeyState, KeyVersion, KeyVersionId, KeyVersionSnapshot,
};
use crate::domain::trust_domain::{TrustBundle, TrustDomainName};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hodor_kernel::{DomainError, PublicKey, Timestamp};
use serde::Serialize;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies a tenant's certificate authority.
    AuthorityId
);

/// The most trust domains an authority may sign for.
pub const MAX_AUTHORITY_TRUST_DOMAINS: usize = 10;
/// The longest common name of an authority's certificate.
pub const MAX_COMMON_NAME_LENGTH: usize = 64;
/// The common name of an authority unless the administrator gives one.
pub const DEFAULT_COMMON_NAME: &str = "Hodor certificate authority";
/// What the common name of an authority made for development ends with.
pub const DEVELOPMENT_SUFFIX: &str = " (development)";
/// A root's lifetime unless the administrator gives one: five years.
pub const DEFAULT_ROOT_LIFETIME_DAYS: u32 = 1826;
/// The longest lifetime of a root.
pub const MAX_ROOT_LIFETIME_DAYS: u32 = 3650;
/// The longest an intermediate the authority signs may live, unless set.
pub const DEFAULT_INTERMEDIATE_LIFETIME_DAYS: u32 = 30;
/// The bound on the intermediates it signs may be at most a year.
pub const MAX_INTERMEDIATE_LIFETIME_DAYS: u32 = 365;
/// The path length of the authority: it signs intermediates, which sign
/// workloads, and nothing deeper.
pub const PATH_LENGTH: u8 = 1;
/// The address ranges every certificate below the authority is kept from.
pub const EXCLUDED_IP_RANGES: [&str; 2] = ["0.0.0.0/0", "::/0"];
/// The refresh hint of the published bundle, in seconds.
pub const BUNDLE_REFRESH_HINT_SECONDS: u64 = 300;
/// How long before it is made a certificate's validity starts, for clocks
/// that disagree.
pub const BACKDATING: Duration = Duration::minutes(1);
/// The most certificates above an intermediate an administrator may give.
pub const MAX_CHAIN_LENGTH: usize = 5;

/// Whether the installation offers the authority, from
/// `HODOR_CERTIFICATE_AUTHORITY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthoritySetting {
    /// Nothing of the authority exists.
    Off,
    /// A tenant may create its authority on a provider that signs inside
    /// itself.
    On,
    /// The same, and the local provider is accepted.
    Development,
}

impl AuthoritySetting {
    /// Reads the setting; unset or empty is `off`.
    ///
    /// # Errors
    ///
    /// Returns `keys.authority_setting_invalid` for any other value.
    pub fn parse(value: Option<&str>) -> Result<Self, DomainError> {
        match value.map(str::trim) {
            None | Some("" | "off") => Ok(Self::Off),
            Some("on") => Ok(Self::On),
            Some("development") => Ok(Self::Development),
            Some(_) => Err(DomainError::invalid(
                "keys.authority_setting_invalid",
                "HODOR_CERTIFICATE_AUTHORITY is `off`, `on` or `development`",
            )),
        }
    }
}

/// What the authority is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityKind {
    /// Its certificate is signed by its own key.
    Root,
    /// Its certificate is signed by a root the tenant keeps outside Hodor.
    Intermediate,
}

impl AuthorityKind {
    /// The name it is stored and answered under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Intermediate => "intermediate",
        }
    }

    /// Reads a stored or given name.
    ///
    /// # Errors
    ///
    /// Returns `keys.authority_request_invalid`.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        match name {
            "root" => Ok(Self::Root),
            "intermediate" => Ok(Self::Intermediate),
            _ => Err(request_invalid("the kind is `root` or `intermediate`")),
        }
    }
}

/// Where the authority is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityState {
    /// An intermediate whose certificate was not installed yet.
    AwaitingCertificate,
    /// It has its certificate.
    Active,
}

impl AuthorityState {
    /// The name it is stored and answered under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingCertificate => "awaiting_certificate",
            Self::Active => "active",
        }
    }

    /// Reads a stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error for an unknown name.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        match name {
            "awaiting_certificate" => Ok(Self::AwaitingCertificate),
            "active" => Ok(Self::Active),
            _ => Err(DomainError::internal(
                "keys.stored_data_invalid",
                "the certificate authority could not be loaded",
            )),
        }
    }
}

fn request_invalid(detail: &str) -> DomainError {
    DomainError::invalid(
        "keys.authority_request_invalid",
        "an authority is a `root` or an `intermediate`, with a common name of 1 to 64 \
         characters, a root's lifetime of 1 to 3650 days and a bound of 1 to 365 days on the \
         intermediates it signs",
    )
    .with_detail(detail.to_owned())
}

fn trust_domain_invalid(detail: String) -> DomainError {
    DomainError::invalid(
        "keys.authority_trust_domain_invalid",
        "an authority signs for 1 to 10 trust domains, each a DNS name: labels of lowercase \
         letters, digits and `-`, separated by `.`",
    )
    .with_detail(detail)
}

/// Reads a trust domain of an authority: a trust domain's name that is
/// also a DNS name, so that a DNS name constraint can hold it.
///
/// # Errors
///
/// Returns `keys.authority_trust_domain_invalid`.
pub fn authority_trust_domain(name: &str) -> Result<TrustDomainName, DomainError> {
    let parsed = TrustDomainName::parse(name)
        .map_err(|_| trust_domain_invalid(format!("`{name}` is not a trust domain's name")))?;
    let dns = name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        });
    if dns {
        Ok(parsed)
    } else {
        Err(trust_domain_invalid(format!("`{name}` is not a DNS name")))
    }
}

/// The name constraints the authority's certificate carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NameConstraints {
    /// The hosts a URI below the authority must have, exactly.
    pub permitted_uris: Vec<String>,
    /// The DNS names, and the names under them, a certificate below it
    /// may name.
    pub permitted_dns_names: Vec<String>,
    /// The address ranges no certificate below it may name: all of them.
    pub excluded_ip_ranges: Vec<String>,
}

impl NameConstraints {
    /// The constraints of an authority of these trust domains.
    #[must_use]
    pub fn for_trust_domains(trust_domains: &[TrustDomainName]) -> Self {
        let names: Vec<String> = trust_domains
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        Self {
            permitted_uris: names.clone(),
            permitted_dns_names: names,
            excluded_ip_ranges: EXCLUDED_IP_RANGES.map(str::to_owned).to_vec(),
        }
    }
}

/// What the certificate of an authority, or the request for it, says of
/// it: what a [`crate::api::CertificateWriter`] writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityProfile {
    /// The common name of its subject.
    pub common_name: String,
    /// Its name constraints.
    pub name_constraints: NameConstraints,
}

/// An authority as an administrator asks for it, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRequest {
    kind: AuthorityKind,
    trust_domains: Vec<TrustDomainName>,
    common_name: String,
    lifetime_days: Option<u32>,
    intermediate_lifetime_days: u32,
    for_development: bool,
}

impl AuthorityRequest {
    /// Checks a request. Under `development`, the common name says so.
    ///
    /// # Errors
    ///
    /// Returns `keys.authority_request_invalid` or
    /// `keys.authority_trust_domain_invalid`.
    pub fn new(
        kind: &str,
        trust_domains: &[String],
        common_name: Option<&str>,
        lifetime_days: Option<u32>,
        intermediate_lifetime_days: Option<u32>,
        for_development: bool,
    ) -> Result<Self, DomainError> {
        let kind = AuthorityKind::parse(kind)?;
        if trust_domains.is_empty() || trust_domains.len() > MAX_AUTHORITY_TRUST_DOMAINS {
            return Err(trust_domain_invalid(format!(
                "{} trust domains, not 1 to 10",
                trust_domains.len()
            )));
        }
        let mut names: Vec<TrustDomainName> = Vec::with_capacity(trust_domains.len());
        for name in trust_domains {
            let parsed = authority_trust_domain(name)?;
            if names.contains(&parsed) {
                return Err(trust_domain_invalid(format!("`{name}` twice")));
            }
            names.push(parsed);
        }
        let mut common_name = common_name.unwrap_or(DEFAULT_COMMON_NAME).to_owned();
        let length = common_name.chars().count();
        if length == 0
            || length > MAX_COMMON_NAME_LENGTH
            || common_name.chars().any(char::is_control)
        {
            return Err(request_invalid(
                "a common name of 1 to 64 printable characters",
            ));
        }
        if for_development {
            common_name.push_str(DEVELOPMENT_SUFFIX);
        }
        let lifetime_days = match (kind, lifetime_days) {
            (AuthorityKind::Root, None) => Some(DEFAULT_ROOT_LIFETIME_DAYS),
            (AuthorityKind::Root, Some(days)) if (1..=MAX_ROOT_LIFETIME_DAYS).contains(&days) => {
                Some(days)
            }
            (AuthorityKind::Root, Some(_)) => {
                return Err(request_invalid("a root lives 1 to 3650 days"));
            }
            (AuthorityKind::Intermediate, None) => None,
            (AuthorityKind::Intermediate, Some(_)) => {
                return Err(request_invalid(
                    "an intermediate's lifetime is set by the root that signs it",
                ));
            }
        };
        let intermediate_lifetime_days =
            intermediate_lifetime_days.unwrap_or(DEFAULT_INTERMEDIATE_LIFETIME_DAYS);
        if !(1..=MAX_INTERMEDIATE_LIFETIME_DAYS).contains(&intermediate_lifetime_days)
            || lifetime_days.is_some_and(|root| intermediate_lifetime_days >= root)
        {
            return Err(request_invalid(
                "the intermediates it signs live 1 to 365 days, and less than the root",
            ));
        }
        Ok(Self {
            kind,
            trust_domains: names,
            common_name,
            lifetime_days,
            intermediate_lifetime_days,
            for_development,
        })
    }

    /// A root or an intermediate.
    #[must_use]
    pub const fn kind(&self) -> AuthorityKind {
        self.kind
    }

    /// The trust domains it signs for.
    #[must_use]
    pub fn trust_domains(&self) -> &[TrustDomainName] {
        &self.trust_domains
    }

    /// A root's lifetime.
    #[must_use]
    pub const fn lifetime(&self) -> Option<Duration> {
        match self.lifetime_days {
            Some(days) => Some(Duration::days(days as i64)),
            None => None,
        }
    }

    /// What its certificate says of it.
    #[must_use]
    pub fn profile(&self) -> AuthorityProfile {
        AuthorityProfile {
            common_name: self.common_name.clone(),
            name_constraints: NameConstraints::for_trust_domains(&self.trust_domains),
        }
    }
}

/// The authority's key: made by a key provider for the authority's own
/// identifier, and never a version of a key set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityKey {
    /// The identifier the key was made for.
    pub id: KeyVersionId,
    /// The provider that made it.
    pub provider: String,
    /// What the provider handed back.
    pub material: KeyMaterial,
    /// Its public key, on P-256.
    pub public_key: PublicKey,
}

impl AuthorityKey {
    /// The key a provider just made.
    ///
    /// # Errors
    ///
    /// Returns an internal error if the provider answered no P-256 key.
    pub fn new(
        id: KeyVersionId,
        provider: &str,
        generated: GeneratedKey,
    ) -> Result<Self, DomainError> {
        match generated.public_key {
            Some(public_key @ PublicKey::P256 { .. })
                if !generated.material.as_bytes().is_empty() =>
            {
                Ok(Self {
                    id,
                    provider: provider.to_owned(),
                    material: generated.material,
                    public_key,
                })
            }
            _ => Err(DomainError::internal(
                "keys.provider_answer_invalid",
                "the key provider answered something that is not a P-256 key",
            )),
        }
    }

    /// The key as a provider is given it to sign: an ES256 version of the
    /// authority's identifier, never stored as one.
    #[must_use]
    pub fn version(&self, now: Timestamp) -> KeyVersion {
        KeyVersion::from_snapshot(KeyVersionSnapshot {
            id: self.id,
            algorithm: KeyAlgorithm::Es256,
            state: KeyState::Active,
            provider: self.provider.clone(),
            material: self.material.clone(),
            public_key: Some(self.public_key.clone()),
            created_at: now,
            activated_at: Some(now),
            retiring_at: None,
            retire_after: None,
            retired_at: None,
            revoked_at: None,
            revocation_reason: None,
        })
    }
}

/// The authority's own certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCertificate {
    /// The certificate, in DER.
    pub der: Vec<u8>,
    /// Its serial number, in lowercase hexadecimal.
    pub serial_number: String,
    /// When its validity starts.
    pub not_before: Timestamp,
    /// When its validity ends.
    pub not_after: Timestamp,
    /// Its SHA-256, in lowercase hexadecimal.
    pub sha256: String,
}

/// What a certificate says of itself, as a [`crate::api::CertificateWriter`]
/// reads it: what installing a certificate checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateFacts {
    /// The certificate, in DER.
    pub der: Vec<u8>,
    /// Its serial number, in lowercase hexadecimal.
    pub serial_number: String,
    /// When its validity starts.
    pub not_before: Timestamp,
    /// When its validity ends.
    pub not_after: Timestamp,
    /// Its public key, when it is on P-256.
    pub public_key: Option<PublicKey>,
    /// Whether its basic constraints make it an authority.
    pub is_authority: bool,
    /// Whether its key usage allows signing certificates.
    pub signs_certificates: bool,
    /// Its name constraints, if it has them.
    pub name_constraints: Option<FactsConstraints>,
}

/// The permitted subtrees of a certificate's name constraints.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FactsConstraints {
    /// Permitted URI hosts.
    pub permitted_uris: Vec<String>,
    /// Permitted DNS names.
    pub permitted_dns_names: Vec<String>,
    /// How many permitted subtrees are of another kind.
    pub permitted_other: usize,
}

fn unsuitable(detail: &str) -> DomainError {
    DomainError::invalid(
        "keys.authority_certificate_unsuitable",
        "the certificate must hold the authority's key, be an authority that signs \
         certificates, be valid now, and carry name constraints within the authority's trust \
         domains",
    )
    .with_detail(detail.to_owned())
}

/// Everything about an authority, for storage and for reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthoritySnapshot {
    /// The identifier.
    pub id: AuthorityId,
    /// A root or an intermediate.
    pub kind: AuthorityKind,
    /// Awaiting its certificate, or active.
    pub state: AuthorityState,
    /// The trust domains it signs for.
    pub trust_domains: Vec<TrustDomainName>,
    /// The common name of its certificate.
    pub common_name: String,
    /// A root's lifetime, in days.
    pub lifetime_days: Option<u32>,
    /// The longest an intermediate it signs may live, in days.
    pub intermediate_lifetime_days: u32,
    /// Whether it was made on an installation set to `development`.
    pub for_development: bool,
    /// Its key.
    pub key: AuthorityKey,
    /// An intermediate's request, in DER.
    pub certificate_signing_request: Option<Vec<u8>>,
    /// Its certificate, once active.
    pub certificate: Option<IssuedCertificate>,
    /// The certificates above an intermediate, in DER, as given.
    pub chain: Vec<Vec<u8>>,
    /// When it was made.
    pub created_at: Timestamp,
    /// When it became active.
    pub activated_at: Option<Timestamp>,
    /// When it last changed.
    pub updated_at: Timestamp,
    /// Incremented on every stored change.
    pub version: u32,
}

/// A tenant's certificate authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthority {
    state: CertificateAuthoritySnapshot,
}

impl CertificateAuthority {
    fn made(
        id: AuthorityId,
        request: &AuthorityRequest,
        key: AuthorityKey,
        now: Timestamp,
    ) -> CertificateAuthoritySnapshot {
        CertificateAuthoritySnapshot {
            id,
            kind: request.kind,
            state: AuthorityState::AwaitingCertificate,
            trust_domains: request.trust_domains.clone(),
            common_name: request.common_name.clone(),
            lifetime_days: request.lifetime_days,
            intermediate_lifetime_days: request.intermediate_lifetime_days,
            for_development: request.for_development,
            key,
            certificate_signing_request: None,
            certificate: None,
            chain: Vec::new(),
            created_at: now,
            activated_at: None,
            updated_at: now,
            version: 0,
        }
    }

    /// A root, with the certificate its own key signed: active at once.
    #[must_use]
    pub fn root(
        id: AuthorityId,
        request: &AuthorityRequest,
        key: AuthorityKey,
        certificate: IssuedCertificate,
        now: Timestamp,
    ) -> Self {
        let mut state = Self::made(id, request, key, now);
        state.state = AuthorityState::Active;
        state.certificate = Some(certificate);
        state.activated_at = Some(now);
        Self { state }
    }

    /// An intermediate awaiting its certificate, with the request its key
    /// signed.
    #[must_use]
    pub fn intermediate(
        id: AuthorityId,
        request: &AuthorityRequest,
        key: AuthorityKey,
        certificate_signing_request: Vec<u8>,
        now: Timestamp,
    ) -> Self {
        let mut state = Self::made(id, request, key, now);
        state.certificate_signing_request = Some(certificate_signing_request);
        Self { state }
    }

    /// Rebuilds an authority from storage.
    #[must_use]
    pub const fn from_snapshot(state: CertificateAuthoritySnapshot) -> Self {
        Self { state }
    }

    /// Everything about it.
    #[must_use]
    pub const fn snapshot(&self) -> &CertificateAuthoritySnapshot {
        &self.state
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> AuthorityId {
        self.state.id
    }

    /// Where it is.
    #[must_use]
    pub const fn state(&self) -> AuthorityState {
        self.state.state
    }

    /// The trust domains it signs for.
    #[must_use]
    pub fn trust_domains(&self) -> &[TrustDomainName] {
        &self.state.trust_domains
    }

    /// Its key.
    #[must_use]
    pub const fn key(&self) -> &AuthorityKey {
        &self.state.key
    }

    /// Its certificate, once active.
    #[must_use]
    pub const fn certificate(&self) -> Option<&IssuedCertificate> {
        self.state.certificate.as_ref()
    }

    /// The version it was read at.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.state.version
    }

    /// Its name constraints.
    #[must_use]
    pub fn name_constraints(&self) -> NameConstraints {
        NameConstraints::for_trust_domains(&self.state.trust_domains)
    }

    /// Installs an intermediate's certificate, signed by the tenant's own
    /// root, and the certificates above it. The certificate must hold the
    /// authority's key, be an authority that signs certificates, be valid
    /// at `now`, and carry name constraints within the authority's trust
    /// domains.
    ///
    /// # Errors
    ///
    /// Returns `keys.authority_not_awaiting_certificate` unless it awaits
    /// one, and `keys.authority_certificate_unsuitable` with the reason.
    pub fn install(
        &mut self,
        certificate: CertificateFacts,
        sha256: String,
        chain: Vec<Vec<u8>>,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        if self.state.state != AuthorityState::AwaitingCertificate {
            return Err(DomainError::conflict(
                "keys.authority_not_awaiting_certificate",
                "only an intermediate authority awaiting its certificate can be given one",
            ));
        }
        if chain.len() > MAX_CHAIN_LENGTH {
            return Err(unsuitable("a chain of more than 5 certificates"));
        }
        if certificate.public_key.as_ref() != Some(&self.state.key.public_key) {
            return Err(unsuitable("it does not hold the authority's key"));
        }
        if !certificate.is_authority {
            return Err(unsuitable(
                "its basic constraints do not make it an authority",
            ));
        }
        if !certificate.signs_certificates {
            return Err(unsuitable(
                "its key usage does not allow signing certificates",
            ));
        }
        if now < certificate.not_before || now >= certificate.not_after {
            return Err(unsuitable("it is not valid now"));
        }
        let Some(constraints) = &certificate.name_constraints else {
            return Err(unsuitable("it carries no name constraints"));
        };
        let within = |name: &str| {
            self.state.trust_domains.iter().any(|domain| {
                let domain = domain.as_str();
                name == domain
                    || name
                        .strip_suffix(domain)
                        .is_some_and(|head| head.ends_with('.'))
            })
        };
        let uris_are_trust_domains = !constraints.permitted_uris.is_empty()
            && constraints.permitted_uris.iter().all(|uri| {
                self.state
                    .trust_domains
                    .iter()
                    .any(|domain| domain.as_str() == uri)
            });
        if !uris_are_trust_domains {
            return Err(unsuitable(
                "its permitted URIs are not all trust domains of the authority",
            ));
        }
        if !constraints
            .permitted_dns_names
            .iter()
            .all(|name| within(name))
        {
            return Err(unsuitable(
                "its permitted DNS names reach past the authority's trust domains",
            ));
        }
        if constraints.permitted_other > 0 {
            return Err(unsuitable("it permits names of another kind"));
        }
        let state = &mut self.state;
        state.certificate = Some(IssuedCertificate {
            der: certificate.der,
            serial_number: certificate.serial_number,
            not_before: certificate.not_before,
            not_after: certificate.not_after,
            sha256,
        });
        state.chain = chain;
        state.state = AuthorityState::Active;
        state.activated_at = Some(now);
        state.updated_at = now;
        Ok(())
    }

    /// The bundle it publishes: its certificate and its key, once active.
    ///
    /// # Errors
    ///
    /// Returns an internal error if the bundle does not read, which would
    /// be a fault of this code.
    pub fn bundle(&self) -> Result<Option<TrustBundle>, DomainError> {
        let (Some(certificate), Some(activated_at)) =
            (&self.state.certificate, self.state.activated_at)
        else {
            return Ok(None);
        };
        let PublicKey::P256 { x, y } = &self.state.key.public_key else {
            return Ok(None);
        };
        let document = serde_json::json!({
            "keys": [{
                "use": "x509-svid",
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
                "x5c": [STANDARD.encode(&certificate.der)],
            }],
            "spiffe_sequence": activated_at.unix_timestamp().max(0),
            "spiffe_refresh_hint": BUNDLE_REFRESH_HINT_SECONDS,
        });
        TrustBundle::parse(document.to_string().as_bytes()).map(Some)
    }
}

/// Writes DER as PEM, with lines of 64 characters.
#[must_use]
pub fn to_pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(line));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

/// Lowercase hexadecimal.
#[must_use]
pub fn hexadecimal(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut written = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(written, "{byte:02x}");
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> AuthorityKey {
        AuthorityKey {
            id: KeyVersionId::generate(),
            provider: "openbao".to_owned(),
            material: KeyMaterial::from_stored(vec![1]),
            public_key: PublicKey::P256 {
                x: vec![1; 32],
                y: vec![2; 32],
            },
        }
    }

    fn request(kind: &str, names: &[&str]) -> Result<AuthorityRequest, DomainError> {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        AuthorityRequest::new(kind, &names, None, None, None, false)
    }

    fn now() -> Timestamp {
        Timestamp::from_unix_timestamp(1_800_000_000).expect("time")
    }

    #[test]
    fn the_setting_is_off_unless_said_otherwise() {
        assert_eq!(
            AuthoritySetting::parse(None).ok(),
            Some(AuthoritySetting::Off)
        );
        assert_eq!(
            AuthoritySetting::parse(Some("")).ok(),
            Some(AuthoritySetting::Off)
        );
        assert_eq!(
            AuthoritySetting::parse(Some("on")).ok(),
            Some(AuthoritySetting::On)
        );
        assert_eq!(
            AuthoritySetting::parse(Some("development")).ok(),
            Some(AuthoritySetting::Development)
        );
        assert!(AuthoritySetting::parse(Some("yes")).is_err());
    }

    #[test]
    fn trust_domains_must_be_dns_names_one_to_ten_and_distinct() {
        for name in ["prod.example.com", "cluster.local", "a", "x-1.y"] {
            assert!(authority_trust_domain(name).is_ok(), "{name}");
        }
        for name in [
            "under_score.example",
            "-lead.example",
            "trail-.example",
            "a..b",
            ".a",
            "A.b",
            "",
        ] {
            assert_eq!(
                authority_trust_domain(name)
                    .map(|_| ())
                    .expect_err("refused")
                    .code(),
                "keys.authority_trust_domain_invalid",
                "{name}"
            );
        }
        assert!(request("root", &[]).is_err());
        assert!(request("root", &["a.example", "a.example"]).is_err());
        let eleven: Vec<String> = (0..11).map(|n| format!("d{n}.example")).collect();
        assert!(AuthorityRequest::new("root", &eleven, None, None, None, false).is_err());
    }

    #[test]
    fn a_request_has_bounded_lifetimes_and_says_when_it_is_for_development() {
        let root = request("root", &["a.example"]).expect("root");
        assert_eq!(root.lifetime(), Some(Duration::days(1826)));
        assert_eq!(root.profile().common_name, DEFAULT_COMMON_NAME);
        let names = vec!["a.example".to_owned()];
        assert!(AuthorityRequest::new("root", &names, None, Some(3651), None, false).is_err());
        assert!(AuthorityRequest::new("root", &names, None, Some(10), Some(10), false).is_err());
        assert!(AuthorityRequest::new("root", &names, None, None, Some(366), false).is_err());
        assert!(
            AuthorityRequest::new("intermediate", &names, None, Some(30), None, false).is_err()
        );
        assert!(AuthorityRequest::new("leaf", &names, None, None, None, false).is_err());
        assert!(AuthorityRequest::new("root", &names, Some(""), None, None, false).is_err());
        let development =
            AuthorityRequest::new("intermediate", &names, Some("Meshes"), None, None, true)
                .expect("intermediate");
        assert_eq!(development.profile().common_name, "Meshes (development)");
        assert_eq!(development.lifetime(), None);
    }

    #[test]
    fn the_name_constraints_permit_the_trust_domains_and_exclude_every_address() {
        let request = request("root", &["a.example", "b.example"]).expect("root");
        let constraints = request.profile().name_constraints;
        assert_eq!(constraints.permitted_uris, ["a.example", "b.example"]);
        assert_eq!(constraints.permitted_dns_names, ["a.example", "b.example"]);
        assert_eq!(constraints.excluded_ip_ranges, ["0.0.0.0/0", "::/0"]);
    }

    fn facts(key: &AuthorityKey) -> CertificateFacts {
        CertificateFacts {
            der: vec![0x30],
            serial_number: "01".to_owned(),
            not_before: now() - Duration::days(1),
            not_after: now() + Duration::days(30),
            public_key: Some(key.public_key.clone()),
            is_authority: true,
            signs_certificates: true,
            name_constraints: Some(FactsConstraints {
                permitted_uris: vec!["a.example".to_owned()],
                permitted_dns_names: vec!["a.example".to_owned(), "x.a.example".to_owned()],
                permitted_other: 0,
            }),
        }
    }

    fn awaiting() -> CertificateAuthority {
        let request = request("intermediate", &["a.example", "b.example"]).expect("request");
        CertificateAuthority::intermediate(
            AuthorityId::generate(),
            &request,
            key(),
            vec![0x30],
            now(),
        )
    }

    #[test]
    fn an_installed_certificate_must_fit_the_authority() {
        let reason = |change: &dyn Fn(&mut CertificateFacts)| {
            let mut authority = awaiting();
            let mut facts = facts(authority.key());
            change(&mut facts);
            authority
                .install(facts, "00".to_owned(), Vec::new(), now())
                .map(|()| String::new())
                .unwrap_or_else(|error| error.detail().unwrap_or_default().to_owned())
        };
        assert_eq!(reason(&|_| {}), "");
        assert!(
            reason(&|f| f.public_key = Some(PublicKey::P256 {
                x: vec![3; 32],
                y: vec![2; 32]
            }))
            .contains("key")
        );
        assert!(reason(&|f| f.is_authority = false).contains("authority"));
        assert!(reason(&|f| f.signs_certificates = false).contains("key usage"));
        assert!(reason(&|f| f.not_after = now()).contains("valid"));
        assert!(reason(&|f| f.name_constraints = None).contains("no name constraints"));
        assert!(
            reason(
                &|f| f.name_constraints.as_mut().expect("c").permitted_uris =
                    vec!["c.example".to_owned()]
            )
            .contains("URIs")
        );
        assert!(
            reason(&|f| f
                .name_constraints
                .as_mut()
                .expect("c")
                .permitted_uris
                .clear())
            .contains("URIs")
        );
        assert!(
            reason(
                &|f| f.name_constraints.as_mut().expect("c").permitted_dns_names =
                    vec!["example".to_owned()]
            )
            .contains("DNS")
        );
        assert!(
            reason(
                &|f| f.name_constraints.as_mut().expect("c").permitted_dns_names =
                    vec!["xa.example".to_owned()]
            )
            .contains("DNS")
        );
        assert!(
            reason(&|f| f.name_constraints.as_mut().expect("c").permitted_other = 1)
                .contains("another kind")
        );
    }

    #[test]
    fn only_an_authority_awaiting_its_certificate_takes_one_and_then_publishes_a_bundle() {
        let mut authority = awaiting();
        assert_eq!(authority.bundle().expect("bundle"), None);
        let given = facts(authority.key());
        authority
            .install(given.clone(), "00".to_owned(), vec![vec![0x30]], now())
            .expect("installed");
        assert_eq!(authority.state(), AuthorityState::Active);
        let again = authority.install(given, "00".to_owned(), Vec::new(), now());
        assert_eq!(
            again.expect_err("once").code(),
            "keys.authority_not_awaiting_certificate"
        );
        let bundle = authority.bundle().expect("reads").expect("a bundle");
        assert_eq!(bundle.sequence(), Some(1_800_000_000));
        assert_eq!(bundle.refresh_hint(), Some(300));
        assert_eq!(
            bundle.authorities(crate::domain::trust_domain::SvidKind::X509),
            1
        );
    }

    #[test]
    fn pem_has_lines_of_sixty_four_characters() {
        let pem = to_pem("CERTIFICATE", &[7; 100]);
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines[0], "-----BEGIN CERTIFICATE-----");
        assert_eq!(lines[1].len(), 64);
        assert_eq!(lines.last().copied(), Some("-----END CERTIFICATE-----"));
        assert_eq!(hexadecimal(&[0, 171]), "00ab");
    }
}
