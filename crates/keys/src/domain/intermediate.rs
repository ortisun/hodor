//! The intermediates a tenant's certificate authority signs for its
//! meshes: what a certificate signing request must be, what Hodor writes
//! whatever it asks, and withdrawal.
//!
//! See `docs/architecture/contexts/keys.md`, "Signing intermediates", and
//! Decision 0071.

use crate::domain::authority::{AuthorityId, AuthorityState, BACKDATING, CertificateAuthority};
use crate::domain::key::MAX_REASON_LENGTH;
use hodor_kernel::{DomainError, PublicKey, Timestamp};
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies an intermediate the tenant's authority signed.
    IntermediateId
);

/// The largest certificate signing request read, in bytes of PEM.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// The most subject alternative names an intermediate may have.
pub const MAX_INTERMEDIATE_NAMES: usize = 20;
/// The most DNS names permitted, and the most excluded, in its name
/// constraints.
pub const MAX_CONSTRAINED_NAMES: usize = 20;
/// The longest subject kept, as text, in characters.
pub const MAX_SUBJECT_LENGTH: usize = 1000;
/// The smallest RSA key signed, in bits.
pub const MIN_RSA_BITS: u32 = 3072;
/// The largest RSA key signed, in bits: what `rustls-webpki` checks.
pub const MAX_RSA_BITS: u32 = 8192;

/// The key of a certificate signing request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestKey {
    /// ECDSA on P-256, with its point.
    P256(PublicKey),
    /// ECDSA on P-384.
    P384,
    /// RSA, of this many bits.
    Rsa(u32),
    /// Anything else, named for the refusal.
    Other(String),
}

/// The name constraints a request asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestedConstraints {
    /// Permitted DNS names.
    pub permitted_dns_names: Vec<String>,
    /// Excluded DNS names.
    pub excluded_dns_names: Vec<String>,
    /// How many permitted URI subtrees.
    pub permitted_uris: usize,
    /// How many excluded URI subtrees.
    pub excluded_uris: usize,
    /// How many permitted address ranges.
    pub permitted_addresses: usize,
    /// How many permitted subtrees of another kind.
    pub permitted_other: usize,
    /// How many excluded subtrees of another kind than DNS names, URIs and
    /// addresses.
    pub excluded_other: usize,
}

/// What a certificate signing request says, as a
/// [`crate::api::CertificateWriter`] reads it once its signature checked
/// with its own key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFacts {
    /// The request, in DER.
    pub der: Vec<u8>,
    /// Its subject, in DER, as it is written.
    pub subject: Vec<u8>,
    /// Its subject, as text for people.
    pub subject_text: String,
    /// Its subject public key info, in DER.
    pub public_key_info: Vec<u8>,
    /// Its key.
    pub key: RequestKey,
    /// Whether its requested basic constraints say `cA`; `None` when it
    /// asks for no basic constraints.
    pub authority: Option<bool>,
    /// The path length it asks for, if any.
    pub path_length: Option<u32>,
    /// The URIs of its subject alternative names.
    pub uris: Vec<String>,
    /// The DNS names of its subject alternative names.
    pub dns_names: Vec<String>,
    /// The names of another kind, each described, such as `an IP address`.
    pub other_names: Vec<String>,
    /// Its subject alternative names extension's value, in DER, as written.
    pub alternative_names: Option<Vec<u8>>,
    /// The name constraints it asks for.
    pub constraints: Option<RequestedConstraints>,
}

/// The name constraints Hodor writes into an intermediate: DNS names and
/// addresses, never URIs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IntermediateConstraints {
    /// The DNS names, and the names under them, a certificate below it may
    /// name.
    pub permitted_dns_names: Vec<String>,
    /// The DNS names no certificate below it may name.
    pub excluded_dns_names: Vec<String>,
    /// Every address: `0.0.0.0/0` and `::/0`.
    pub excluded_ip_ranges: Vec<String>,
}

impl IntermediateConstraints {
    fn new(permitted_dns_names: Vec<String>, excluded_dns_names: Vec<String>) -> Self {
        Self {
            permitted_dns_names,
            excluded_dns_names,
            excluded_ip_ranges: crate::domain::authority::EXCLUDED_IP_RANGES
                .map(str::to_owned)
                .to_vec(),
        }
    }
}

fn refused(code: &'static str, message: &'static str, detail: String) -> DomainError {
    DomainError::invalid(code, message).with_detail(detail)
}

/// A request that does not read, does not prove its key, or names no
/// subject.
#[must_use]
pub fn request_invalid(detail: &str) -> DomainError {
    refused(
        "keys.intermediate_request_invalid",
        "the certificate signing request must be one PKCS#10 request in PEM of at most 16 \
         kibibytes, signed by its own key, with a subject",
        detail.to_owned(),
    )
}

fn outside(detail: String) -> DomainError {
    refused(
        "keys.intermediate_name_outside_trust_domains",
        "every name of the request must be a URI whose host is a trust domain of the authority, \
         or a DNS name that is one or under one; at most 20",
        detail,
    )
}

fn widened(detail: String) -> DomainError {
    refused(
        "keys.intermediate_constraints_widened",
        "the name constraints asked for may only narrow the authority's: permitted DNS names \
         that are its trust domains or under them, at most 20, and nothing else permitted",
        detail,
    )
}

fn unsupported(detail: String) -> DomainError {
    refused(
        "keys.intermediate_constraints_unsupported",
        "an intermediate carries no URI constraint, and excludes only DNS names and addresses",
        detail,
    )
}

fn key_unsuitable(detail: String) -> DomainError {
    refused(
        "keys.intermediate_key_unsuitable",
        "the key must be ECDSA on P-256 or P-384, or RSA of 3072 to 8192 bits, and not the \
         authority's own",
        detail,
    )
}

fn lifetime_invalid(detail: String) -> DomainError {
    refused(
        "keys.intermediate_lifetime_invalid",
        "an intermediate lives at least a day, at most the authority's bound on intermediates, \
         and no longer than the authority",
        detail,
    )
}

/// Whether `name` is a DNS name: labels of 1 to 63 lowercase letters,
/// digits and `-`, not starting or ending with `-`, 253 characters at
/// most.
fn is_dns_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

/// Whether `name`, lowercased, is `domain` or a name under it.
fn is_within(name: &str, domain: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == domain
        || name
            .strip_suffix(domain)
            .is_some_and(|head| head.len() > 1 && head.ends_with('.'))
}

/// The host of a URI with an authority part, lowercased, without a name
/// and password or a port.
fn uri_host(uri: &str) -> Option<String> {
    let (_, rest) = uri.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host.starts_with('[') {
        return None;
    }
    let host = host.split(':').next().unwrap_or_default();
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Checks a request against the authority, in the order the keys context
/// says, and answers the name constraints its certificate carries.
///
/// # Errors
///
/// Returns `keys.intermediate_not_an_authority`,
/// `keys.intermediate_path_length_invalid`,
/// `keys.intermediate_name_outside_trust_domains`,
/// `keys.intermediate_constraints_widened`,
/// `keys.intermediate_constraints_unsupported` or
/// `keys.intermediate_key_unsuitable`, each with the reason.
pub(crate) fn check_request(
    request: &RequestFacts,
    authority: &CertificateAuthority,
) -> Result<IntermediateConstraints, DomainError> {
    if request.authority != Some(true) {
        return Err(refused(
            "keys.intermediate_not_an_authority",
            "the request must ask for an authority: basic constraints with `cA`",
            match request.authority {
                None => "it asks for no basic constraints".to_owned(),
                Some(_) => "its basic constraints say it is not an authority".to_owned(),
            },
        ));
    }
    if let Some(length) = request.path_length.filter(|length| *length > 0) {
        return Err(refused(
            "keys.intermediate_path_length_invalid",
            "an intermediate signs workloads and nothing deeper: the request asks for no path \
             length, or for zero",
            format!("it asks for a path length of {length}"),
        ));
    }

    let domains: Vec<&str> = authority
        .trust_domains()
        .iter()
        .map(|name| name.as_str())
        .collect();
    // DNS names may be within a trust domain, or within a DNS name the
    // authority permits besides them.
    let dns_domains = authority.dns_domains();
    let within_any = |name: &str| dns_domains.iter().any(|domain| is_within(name, domain));
    let names = request.uris.len() + request.dns_names.len() + request.other_names.len();
    if names > MAX_INTERMEDIATE_NAMES {
        return Err(outside(format!("{names} names, more than 20")));
    }
    if let Some(other) = request.other_names.first() {
        return Err(outside(format!("it names {other}")));
    }
    for uri in &request.uris {
        let fits = uri_host(uri).is_some_and(|host| domains.contains(&host.as_str()));
        if !fits {
            return Err(outside(format!("`{uri}`")));
        }
    }
    if let Some(name) = request.dns_names.iter().find(|name| !within_any(name)) {
        return Err(outside(format!("`{name}`")));
    }

    let asked = request.constraints.clone().unwrap_or_default();
    if asked.permitted_dns_names.len() > MAX_CONSTRAINED_NAMES {
        return Err(widened(format!(
            "{} permitted DNS names, more than 20",
            asked.permitted_dns_names.len()
        )));
    }
    if let Some(name) = asked
        .permitted_dns_names
        .iter()
        .find(|name| !is_dns_name(name) || !within_any(name))
    {
        return Err(widened(format!(
            "it permits `{name}`, which is not within the authority's trust domains or the DNS \
             names it permits"
        )));
    }
    if asked.permitted_addresses > 0 {
        return Err(widened("it permits addresses".to_owned()));
    }
    if asked.permitted_other > 0 {
        return Err(widened(
            "it permits names of another kind than DNS names".to_owned(),
        ));
    }
    if asked.permitted_uris + asked.excluded_uris > 0 {
        return Err(unsupported("it asks for URI constraints".to_owned()));
    }
    if asked.excluded_other > 0 {
        return Err(unsupported(
            "it excludes names of another kind than DNS names and addresses".to_owned(),
        ));
    }
    if asked.excluded_dns_names.len() > MAX_CONSTRAINED_NAMES {
        return Err(unsupported(format!(
            "{} excluded DNS names, more than 20",
            asked.excluded_dns_names.len()
        )));
    }
    if let Some(name) = asked
        .excluded_dns_names
        .iter()
        .find(|name| !is_dns_name(name))
    {
        return Err(unsupported(format!(
            "it excludes `{name}`, which is not a DNS name"
        )));
    }

    match &request.key {
        RequestKey::P256(key) if key == &authority.key().public_key => {
            return Err(key_unsuitable("it is the authority's own key".to_owned()));
        }
        RequestKey::P256(_) | RequestKey::P384 => {}
        RequestKey::Rsa(bits) if (MIN_RSA_BITS..=MAX_RSA_BITS).contains(bits) => {}
        RequestKey::Rsa(bits) => {
            return Err(key_unsuitable(format!("an RSA key of {bits} bits")));
        }
        RequestKey::Other(kind) => return Err(key_unsuitable(format!("a key of {kind}"))),
    }

    let permitted = if asked.permitted_dns_names.is_empty() {
        dns_domains
            .iter()
            .map(|domain| (*domain).to_owned())
            .collect()
    } else {
        asked.permitted_dns_names.clone()
    };
    Ok(IntermediateConstraints::new(
        permitted,
        asked.excluded_dns_names,
    ))
}

/// The validity of an intermediate signed at `now` for `lifetime_days`,
/// or the authority's bound: from a minute before `now`.
///
/// # Errors
///
/// Returns `keys.intermediate_lifetime_invalid`, and an internal error if
/// the authority has no certificate.
pub(crate) fn validity(
    lifetime_days: Option<u32>,
    authority: &CertificateAuthority,
    now: Timestamp,
) -> Result<(Timestamp, Timestamp), DomainError> {
    let bound = authority.snapshot().intermediate_lifetime_days;
    let days = lifetime_days.unwrap_or(bound);
    if days == 0 || days > bound {
        return Err(lifetime_invalid(format!(
            "{days} days, and the authority's bound is {bound}"
        )));
    }
    let not_after = now + Duration::days(i64::from(days));
    let Some(certificate) = authority.certificate() else {
        return Err(not_active());
    };
    if not_after > certificate.not_after {
        return Err(lifetime_invalid(format!(
            "it would end after the authority, which ends at {}",
            certificate.not_after
        )));
    }
    Ok((now - BACKDATING, not_after))
}

/// The authority awaits its certificate.
#[must_use]
pub(crate) fn not_active() -> DomainError {
    DomainError::conflict(
        "keys.authority_not_active",
        "the certificate authority signs nothing until its certificate is installed",
    )
}

/// Refuses an authority that is not active.
///
/// # Errors
///
/// Returns `keys.authority_not_active`.
pub(crate) fn check_active(authority: &CertificateAuthority) -> Result<(), DomainError> {
    if authority.state() == AuthorityState::Active && authority.certificate().is_some() {
        Ok(())
    } else {
        Err(not_active())
    }
}

/// The trust domains of the authority the permitted names fall under, in
/// the authority's order.
#[must_use]
pub(crate) fn trust_domains_signed_for(
    constraints: &IntermediateConstraints,
    authority: &CertificateAuthority,
) -> Vec<String> {
    authority
        .trust_domains()
        .iter()
        .map(|name| name.as_str())
        .filter(|domain| {
            constraints
                .permitted_dns_names
                .iter()
                .any(|name| is_within(name, domain))
        })
        .map(str::to_owned)
        .collect()
}

/// Where an intermediate is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntermediateState {
    /// Signed, and trusted under the authority.
    Active,
    /// Withdrawn: its key is refused.
    Withdrawn,
}

impl IntermediateState {
    /// The name it is stored and answered under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Withdrawn => "withdrawn",
        }
    }

    /// Reads a stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error for an unknown name.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        match name {
            "active" => Ok(Self::Active),
            "withdrawn" => Ok(Self::Withdrawn),
            _ => Err(DomainError::internal(
                "keys.stored_data_invalid",
                "an intermediate could not be loaded",
            )),
        }
    }
}

/// Everything about an intermediate, for storage and for reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntermediateSnapshot {
    /// The identifier.
    pub id: IntermediateId,
    /// The authority that signed it.
    pub authority_id: AuthorityId,
    /// Active or withdrawn.
    pub state: IntermediateState,
    /// Its serial number, in lowercase hexadecimal.
    pub serial_number: String,
    /// Its subject, as text.
    pub subject: String,
    /// The URIs of its subject alternative names.
    pub uris: Vec<String>,
    /// The DNS names of its subject alternative names.
    pub dns_names: Vec<String>,
    /// The name constraints written into it.
    pub constraints: IntermediateConstraints,
    /// The certificate, in DER.
    pub certificate: Vec<u8>,
    /// The SHA-256 of the certificate, in hexadecimal.
    pub certificate_sha256: String,
    /// The SHA-256 of its subject public key info, in hexadecimal.
    pub public_key_sha256: String,
    /// The SHA-256 of the request it was signed from, in hexadecimal.
    pub request_sha256: String,
    /// When its validity starts.
    pub not_before: Timestamp,
    /// When its validity ends.
    pub not_after: Timestamp,
    /// When it was signed.
    pub signed_at: Timestamp,
    /// When it was withdrawn.
    pub withdrawn_at: Option<Timestamp>,
    /// Why.
    pub withdrawal_reason: Option<String>,
    /// Incremented on every stored change.
    pub version: u32,
}

/// An intermediate the tenant's authority signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIntermediate {
    state: IntermediateSnapshot,
}

impl SignedIntermediate {
    /// An intermediate just signed: active.
    #[must_use]
    pub const fn signed(state: IntermediateSnapshot) -> Self {
        Self { state }
    }

    /// Rebuilds an intermediate from storage.
    #[must_use]
    pub const fn from_snapshot(state: IntermediateSnapshot) -> Self {
        Self { state }
    }

    /// Everything about it.
    #[must_use]
    pub const fn snapshot(&self) -> &IntermediateSnapshot {
        &self.state
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> IntermediateId {
        self.state.id
    }

    /// Whether it is withdrawn.
    #[must_use]
    pub fn is_withdrawn(&self) -> bool {
        self.state.state == IntermediateState::Withdrawn
    }

    /// The version it was read at.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.state.version
    }

    /// Withdraws it, for `reason`: 1 to 200 characters.
    ///
    /// # Errors
    ///
    /// Returns `keys.intermediate_reason_invalid`, and
    /// `keys.intermediate_withdrawn` if it is withdrawn already.
    pub fn withdraw(&mut self, reason: &str, now: Timestamp) -> Result<(), DomainError> {
        let reason = check_reason(reason)?;
        if self.is_withdrawn() {
            return Err(DomainError::conflict(
                "keys.intermediate_withdrawn",
                "the intermediate is withdrawn already",
            ));
        }
        self.state.state = IntermediateState::Withdrawn;
        self.state.withdrawn_at = Some(now);
        self.state.withdrawal_reason = Some(reason);
        Ok(())
    }
}

/// Checks a reason for withdrawing: 1 to 200 characters, without control
/// characters, trimmed.
///
/// # Errors
///
/// Returns `keys.intermediate_reason_invalid`.
pub(crate) fn check_reason(reason: &str) -> Result<String, DomainError> {
    let reason = reason.trim();
    if reason.is_empty()
        || reason.chars().count() > MAX_REASON_LENGTH
        || reason.chars().any(char::is_control)
    {
        return Err(DomainError::invalid(
            "keys.intermediate_reason_invalid",
            "a reason for withdrawing is 1 to 200 printable characters",
        ));
    }
    Ok(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::authority::{
        AuthorityKey, AuthorityRequest, CertificateAuthority, IssuedCertificate,
    };
    use crate::domain::key::{KeyMaterial, KeyVersionId};
    use time::OffsetDateTime;

    fn authority(names: &[&str]) -> CertificateAuthority {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        let request =
            AuthorityRequest::new("root", &names, None, Some(365), Some(30), false).expect("ok");
        let now = OffsetDateTime::now_utc();
        CertificateAuthority::root(
            AuthorityId::generate(),
            &request,
            AuthorityKey {
                id: KeyVersionId::generate(),
                provider: "openbao".to_owned(),
                material: KeyMaterial::from_stored(vec![1]),
                public_key: PublicKey::P256 {
                    x: vec![1; 32],
                    y: vec![2; 32],
                },
            },
            IssuedCertificate {
                der: vec![0x30],
                serial_number: "01".to_owned(),
                not_before: now,
                not_after: now + Duration::days(365),
                sha256: "00".to_owned(),
            },
            now,
        )
    }

    fn asking() -> RequestFacts {
        RequestFacts {
            der: vec![0x30],
            subject: vec![0x30],
            subject_text: "CN=issuer".to_owned(),
            public_key_info: vec![0x30],
            key: RequestKey::P256(PublicKey::P256 {
                x: vec![7; 32],
                y: vec![8; 32],
            }),
            authority: Some(true),
            path_length: None,
            uris: Vec::new(),
            dns_names: Vec::new(),
            other_names: Vec::new(),
            alternative_names: None,
            constraints: None,
        }
    }

    /// A change to a request that breaks a rule.
    type Change = Box<dyn Fn(&mut RequestFacts)>;

    fn code(result: Result<IntermediateConstraints, DomainError>) -> String {
        result.expect_err("refused").code().to_owned()
    }

    #[test]
    fn a_request_for_an_authority_within_the_trust_domains_is_given_their_dns_names() {
        let authority = authority(&["prod.example.com", "cluster.local"]);
        let mut request = asking();
        request.path_length = Some(0);
        request.uris = vec!["spiffe://cluster.local/ns/istio-system".to_owned()];
        request.dns_names = vec![
            "identity.linkerd.cluster.local".to_owned(),
            "prod.example.com".to_owned(),
        ];
        let written = check_request(&request, &authority).expect("signed");
        assert_eq!(
            written.permitted_dns_names,
            ["prod.example.com", "cluster.local"]
        );
        assert!(written.excluded_dns_names.is_empty());
        assert_eq!(written.excluded_ip_ranges, ["0.0.0.0/0", "::/0"]);
        assert_eq!(
            trust_domains_signed_for(&written, &authority),
            ["prod.example.com", "cluster.local"]
        );
    }

    #[test]
    fn the_additional_dns_names_of_the_authority_are_permitted_too() {
        let names = vec!["east.example".to_owned()];
        let request = AuthorityRequest::new("root", &names, None, Some(365), Some(30), false)
            .expect("ok")
            .with_additional_dns_names(&["istio-system.svc".to_owned()])
            .expect("a DNS name");
        let now = OffsetDateTime::now_utc();
        let authority = CertificateAuthority::root(
            AuthorityId::generate(),
            &request,
            authority(&["east.example"]).key().clone(),
            IssuedCertificate {
                der: vec![0x30],
                serial_number: "01".to_owned(),
                not_before: now,
                not_after: now + Duration::days(365),
                sha256: "00".to_owned(),
            },
            now,
        );
        let written = check_request(&asking(), &authority).expect("signed");
        assert_eq!(
            written.permitted_dns_names,
            ["east.example", "istio-system.svc"]
        );
        assert_eq!(
            trust_domains_signed_for(&written, &authority),
            ["east.example"]
        );
        let mut naming = asking();
        naming.dns_names = vec!["istiod.istio-system.svc".to_owned()];
        assert!(check_request(&naming, &authority).is_ok());
        naming.uris = vec!["spiffe://istio-system.svc/ns/x".to_owned()];
        assert_eq!(
            code(check_request(&naming, &authority)),
            "keys.intermediate_name_outside_trust_domains"
        );
        let mut narrowed = asking();
        narrowed.constraints = Some(RequestedConstraints {
            permitted_dns_names: vec!["istio-system.svc".to_owned()],
            ..RequestedConstraints::default()
        });
        assert_eq!(
            check_request(&narrowed, &authority)
                .expect("narrowed")
                .permitted_dns_names,
            ["istio-system.svc"]
        );
    }

    #[test]
    fn a_request_narrows_and_excludes_dns_names() {
        let authority = authority(&["prod.example.com", "cluster.local"]);
        let mut request = asking();
        request.constraints = Some(RequestedConstraints {
            permitted_dns_names: vec!["linkerd.cluster.local".to_owned()],
            excluded_dns_names: vec!["admin.linkerd.cluster.local".to_owned()],
            ..RequestedConstraints::default()
        });
        let written = check_request(&request, &authority).expect("signed");
        assert_eq!(written.permitted_dns_names, ["linkerd.cluster.local"]);
        assert_eq!(written.excluded_dns_names, ["admin.linkerd.cluster.local"]);
        assert_eq!(
            trust_domains_signed_for(&written, &authority),
            ["cluster.local"]
        );
    }

    #[test]
    fn each_broken_rule_is_refused_with_its_own_code() {
        let authority = authority(&["cluster.local"]);
        let case = |change: &dyn Fn(&mut RequestFacts)| {
            let mut request = asking();
            change(&mut request);
            code(check_request(&request, &authority))
        };
        let constraints = |change: &dyn Fn(&mut RequestedConstraints)| {
            let mut asked = RequestedConstraints::default();
            change(&mut asked);
            asked
        };
        let cases: Vec<(&str, Change)> = vec![
            (
                "keys.intermediate_not_an_authority",
                Box::new(|r| r.authority = None),
            ),
            (
                "keys.intermediate_not_an_authority",
                Box::new(|r| r.authority = Some(false)),
            ),
            (
                "keys.intermediate_path_length_invalid",
                Box::new(|r| r.path_length = Some(1)),
            ),
            (
                "keys.intermediate_name_outside_trust_domains",
                Box::new(|r| r.uris = vec!["spiffe://other.local/x".to_owned()]),
            ),
            (
                "keys.intermediate_name_outside_trust_domains",
                Box::new(|r| r.uris = vec!["spiffe://sub.cluster.local/x".to_owned()]),
            ),
            (
                "keys.intermediate_name_outside_trust_domains",
                Box::new(|r| r.dns_names = vec!["cluster.local.evil".to_owned()]),
            ),
            (
                "keys.intermediate_name_outside_trust_domains",
                Box::new(|r| r.dns_names = vec!["evilcluster.local".to_owned()]),
            ),
            (
                "keys.intermediate_name_outside_trust_domains",
                Box::new(|r| r.other_names = vec!["an IP address".to_owned()]),
            ),
            (
                "keys.intermediate_name_outside_trust_domains",
                Box::new(|r| r.dns_names = vec!["a.cluster.local".to_owned(); 21]),
            ),
            (
                "keys.intermediate_constraints_widened",
                Box::new(move |r| {
                    r.constraints = Some(constraints(&|c| {
                        c.permitted_dns_names = vec!["example.com".to_owned()];
                    }));
                }),
            ),
            (
                "keys.intermediate_constraints_widened",
                Box::new(move |r| {
                    r.constraints = Some(constraints(&|c| {
                        c.permitted_dns_names = vec!["local".to_owned()];
                    }));
                }),
            ),
            (
                "keys.intermediate_constraints_widened",
                Box::new(move |r| {
                    r.constraints = Some(constraints(&|c| c.permitted_addresses = 1));
                }),
            ),
            (
                "keys.intermediate_constraints_widened",
                Box::new(move |r| r.constraints = Some(constraints(&|c| c.permitted_other = 1))),
            ),
            (
                "keys.intermediate_constraints_unsupported",
                Box::new(move |r| r.constraints = Some(constraints(&|c| c.permitted_uris = 1))),
            ),
            (
                "keys.intermediate_constraints_unsupported",
                Box::new(move |r| r.constraints = Some(constraints(&|c| c.excluded_uris = 1))),
            ),
            (
                "keys.intermediate_constraints_unsupported",
                Box::new(move |r| r.constraints = Some(constraints(&|c| c.excluded_other = 1))),
            ),
            (
                "keys.intermediate_key_unsuitable",
                Box::new(|r| r.key = RequestKey::Rsa(2048)),
            ),
            (
                "keys.intermediate_key_unsuitable",
                Box::new(|r| r.key = RequestKey::Other("Ed25519".to_owned())),
            ),
            (
                "keys.intermediate_key_unsuitable",
                Box::new(|r| {
                    r.key = RequestKey::P256(PublicKey::P256 {
                        x: vec![1; 32],
                        y: vec![2; 32],
                    });
                }),
            ),
        ];
        for (expected, change) in cases {
            assert_eq!(case(change.as_ref()), expected);
        }
        let mut rsa = asking();
        rsa.key = RequestKey::Rsa(3072);
        assert!(check_request(&rsa, &authority).is_ok());
        rsa.key = RequestKey::P384;
        assert!(check_request(&rsa, &authority).is_ok());
    }

    #[test]
    fn the_lifetime_is_the_bound_unless_shorter_and_never_past_the_authority() {
        let authority = authority(&["cluster.local"]);
        let now = OffsetDateTime::now_utc();
        let (not_before, not_after) = validity(None, &authority, now).expect("the bound");
        assert_eq!(not_before, now - BACKDATING);
        assert_eq!(not_after, now + Duration::days(30));
        let (_, two) = validity(Some(2), &authority, now).expect("two days");
        assert_eq!(two, now + Duration::days(2));
        for days in [0, 31] {
            assert_eq!(
                validity(Some(days), &authority, now)
                    .expect_err("refused")
                    .code(),
                "keys.intermediate_lifetime_invalid"
            );
        }
        let late = now + Duration::days(340);
        assert_eq!(
            validity(None, &authority, late)
                .expect_err("past the authority")
                .code(),
            "keys.intermediate_lifetime_invalid"
        );
    }

    #[test]
    fn an_intermediate_is_withdrawn_once_for_a_reason() {
        let now = OffsetDateTime::now_utc();
        let mut intermediate = SignedIntermediate::signed(IntermediateSnapshot {
            id: IntermediateId::generate(),
            authority_id: AuthorityId::generate(),
            state: IntermediateState::Active,
            serial_number: "01".to_owned(),
            subject: "CN=issuer".to_owned(),
            uris: Vec::new(),
            dns_names: Vec::new(),
            constraints: IntermediateConstraints::new(vec!["cluster.local".to_owned()], vec![]),
            certificate: vec![0x30],
            certificate_sha256: "aa".to_owned(),
            public_key_sha256: "bb".to_owned(),
            request_sha256: "cc".to_owned(),
            not_before: now,
            not_after: now + Duration::days(1),
            signed_at: now,
            withdrawn_at: None,
            withdrawal_reason: None,
            version: 0,
        });
        for reason in ["", "   ", &"x".repeat(201), "a\nb"] {
            assert_eq!(
                intermediate
                    .withdraw(reason, now)
                    .expect_err("refused")
                    .code(),
                "keys.intermediate_reason_invalid"
            );
        }
        intermediate.withdraw(" leaked ", now).expect("withdrawn");
        assert!(intermediate.is_withdrawn());
        assert_eq!(
            intermediate.snapshot().withdrawal_reason.as_deref(),
            Some("leaked")
        );
        assert_eq!(
            intermediate
                .withdraw("again", now)
                .expect_err("once")
                .code(),
            "keys.intermediate_withdrawn"
        );
    }
}
