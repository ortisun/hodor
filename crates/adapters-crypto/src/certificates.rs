//! The certificates of a tenant's certificate authority, and Hodor's own
//! chain checking of a path under one.
//!
//! `X509Certificates` writes the part to be signed of the authority's
//! certificate and of its certificate signing request with `rcgen`, puts
//! the key provider's signature on it, and reads a certificate an
//! administrator installs with `x509-parser`. It signs nothing: `rcgen`
//! is handed a key that only remembers what it was asked to sign.
//!
//! `check_path` checks a path with `rustls-webpki`, which does not read
//! name constraints on URIs, and checks those itself (`UriConstraints`).
//!
//! See `docs/architecture/contexts/keys.md`, "The certificate authority of
//! a tenant", and Decision 0062.

use hodor_kernel::{DomainError, PublicKey, Timestamp};
use hodor_keys::api::{
    AuthorityProfile, CertificateFacts, CertificateWriter, FactsConstraints, PATH_LENGTH,
    ToBeSigned, hexadecimal,
};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, RemoteKeyPair, SerialNumber,
};
use rustls_pki_types::{CertificateDer, Der, TrustAnchor, UnixTime};
use std::sync::{Arc, Mutex};
use x509_parser::prelude::{FromDer as _, GeneralName, X509Certificate};

/// The object identifier of name constraints, 2.5.29.30.
const NAME_CONSTRAINTS: [u64; 4] = [2, 5, 29, 30];
/// The object identifier of basic constraints, 2.5.29.19.
const BASIC_CONSTRAINTS: [u64; 4] = [2, 5, 29, 19];
/// `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2, in DER.
const ECDSA_WITH_SHA256: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// The organization every authority's subject names.
const ORGANIZATION: &str = "Hodor";

/// A DER element: its tag, its length and `content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(u8::try_from(length).unwrap_or(0));
    } else {
        let bytes = length.to_be_bytes();
        let skip = bytes.iter().take_while(|byte| **byte == 0).count();
        let significant = &bytes[skip..];
        out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0));
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

/// One DER element read: its tag, its content, the whole element and what
/// follows it.
type Element<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// What a key that remembers was asked to sign.
type Asked = Arc<Mutex<Option<Vec<u8>>>>;

/// Reads one DER element.
fn read_tlv(input: &[u8]) -> Option<Element<'_>> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |length, byte| (length << 8) | usize::from(*byte));
        (length, &rest[count..])
    };
    if rest.len() < length {
        return None;
    }
    let header = input.len() - rest.len();
    Some((
        tag,
        &rest[..length],
        &input[..header + length],
        &rest[length..],
    ))
}

/// The name constraints extension of an authority, in DER: each trust
/// domain permitted as a URI host and as a DNS name, and every IPv4 and
/// IPv6 address excluded.
fn name_constraints(profile: &AuthorityProfile) -> Vec<u8> {
    let constraints = &profile.name_constraints;
    let mut permitted = Vec::new();
    for host in &constraints.permitted_uris {
        permitted.extend(tlv(0x30, &tlv(0x86, host.as_bytes())));
    }
    for name in &constraints.permitted_dns_names {
        permitted.extend(tlv(0x30, &tlv(0x82, name.as_bytes())));
    }
    // `0.0.0.0/0` and `::/0`: an address of zeros under a mask of zeros.
    let mut excluded = tlv(0x30, &tlv(0x87, &[0; 8]));
    excluded.extend(tlv(0x30, &tlv(0x87, &[0; 32])));
    let mut content = tlv(0xa0, &permitted);
    content.extend(tlv(0xa1, &excluded));
    tlv(0x30, &content)
}

fn critical(oid: &[u64], content: Vec<u8>) -> CustomExtension {
    let mut extension = CustomExtension::from_oid_content(oid, content);
    extension.set_criticality(true);
    extension
}

pub(crate) fn subject(profile: &AuthorityProfile) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, ORGANIZATION);
    name.push(DnType::CommonName, profile.common_name.as_str());
    name
}

fn write_failed(error: &rcgen::Error) -> DomainError {
    DomainError::internal(
        "keys.certificate_not_written",
        "the authority's certificate could not be written",
    )
    .with_detail(error.to_string())
}

/// A key `rcgen` signs with that keeps what it is asked to sign and
/// answers no real signature: the key provider signs it afterwards.
struct Remembers {
    public_key: Vec<u8>,
    asked: Asked,
}

impl RemoteKeyPair for Remembers {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        *self.asked.lock().unwrap_or_else(|e| e.into_inner()) = Some(message.to_vec());
        Ok(vec![0; 8])
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

/// A key that remembers what it signs, and where it is kept.
pub(crate) fn remembering(public_key: &PublicKey) -> Result<(KeyPair, Asked), DomainError> {
    let PublicKey::P256 { x, y } = public_key else {
        return Err(DomainError::internal(
            "keys.certificate_not_written",
            "an authority's key is on P-256",
        ));
    };
    let mut point = vec![0x04];
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    let asked = Arc::new(Mutex::new(None));
    let key = KeyPair::from_remote(Box::new(Remembers {
        public_key: point,
        asked: asked.clone(),
    }))
    .map_err(|error| write_failed(&error))?;
    Ok((key, asked))
}

pub(crate) fn taken(asked: &Asked) -> Result<Vec<u8>, DomainError> {
    asked
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .ok_or_else(|| {
            DomainError::internal(
                "keys.certificate_not_written",
                "nothing was given to be signed",
            )
        })
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

fn timestamp(time: x509_parser::time::ASN1Time) -> Result<Timestamp, DomainError> {
    Timestamp::from_unix_timestamp(time.timestamp())
        .map_err(|_| unsuitable("a validity that cannot be read"))
}

/// Writes and reads the certificates of tenants' authorities.
#[derive(Debug, Clone, Copy, Default)]
pub struct X509Certificates;

impl CertificateWriter for X509Certificates {
    fn root_to_be_signed(
        &self,
        profile: &AuthorityProfile,
        public_key: &PublicKey,
        not_before: Timestamp,
        not_after: Timestamp,
    ) -> Result<ToBeSigned, DomainError> {
        let mut serial = [0u8; 16];
        aws_lc_rs::rand::fill(&mut serial).map_err(|_| {
            DomainError::internal("keys.certificate_not_written", "no random serial number")
        })?;
        // Positive, and sixteen bytes long.
        serial[0] = (serial[0] & 0x7f) | 0x01;
        let mut params = CertificateParams::default();
        params.distinguished_name = subject(profile);
        params.not_before = not_before;
        params.not_after = not_after;
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(PATH_LENGTH));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.custom_extensions = vec![critical(&NAME_CONSTRAINTS, name_constraints(profile))];
        let (key, asked) = remembering(public_key)?;
        params
            .self_signed(&key)
            .map_err(|error| write_failed(&error))?;
        Ok(ToBeSigned {
            bytes: taken(&asked)?,
            serial_number: hexadecimal(&serial),
        })
    }

    fn request_to_be_signed(
        &self,
        profile: &AuthorityProfile,
        public_key: &PublicKey,
    ) -> Result<Vec<u8>, DomainError> {
        let mut params = CertificateParams::default();
        params.distinguished_name = subject(profile);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        // `rcgen` writes no basic constraints in a request: they are
        // written here, as the root's are.
        let basic = tlv(0x30, &[0x01, 0x01, 0xff, 0x02, 0x01, PATH_LENGTH]);
        params.custom_extensions = vec![
            critical(&BASIC_CONSTRAINTS, basic),
            critical(&NAME_CONSTRAINTS, name_constraints(profile)),
        ];
        let (key, asked) = remembering(public_key)?;
        params
            .serialize_request(&key)
            .map_err(|error| write_failed(&error))?;
        taken(&asked)
    }

    fn signed(&self, to_be_signed: &[u8], signature: &[u8]) -> Vec<u8> {
        let mut content = to_be_signed.to_vec();
        content.extend(tlv(0x30, &tlv(0x06, &ECDSA_WITH_SHA256)));
        let mut bits = vec![0];
        bits.extend_from_slice(signature);
        content.extend(tlv(0x03, &bits));
        tlv(0x30, &content)
    }

    fn read(&self, pem: &str) -> Result<CertificateFacts, DomainError> {
        let (_, block) = x509_parser::pem::parse_x509_pem(pem.trim().as_bytes())
            .map_err(|_| unsuitable("it is not a certificate in PEM"))?;
        if block.label != "CERTIFICATE" {
            return Err(unsuitable("it is not a certificate in PEM"));
        }
        let (rest, certificate) = X509Certificate::from_der(&block.contents)
            .map_err(|_| unsuitable("it is not a certificate"))?;
        if !rest.is_empty() {
            return Err(unsuitable("it is not a certificate"));
        }
        let validity = certificate.validity();
        let spki = certificate.public_key();
        let on_p256 = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.as_oid().ok())
            .is_some_and(|curve| curve == x509_parser::oid_registry::OID_EC_P256);
        let point = &spki.subject_public_key.data;
        let public_key =
            (on_p256 && point.len() == 65 && point[0] == 0x04).then(|| PublicKey::P256 {
                x: point[1..33].to_vec(),
                y: point[33..].to_vec(),
            });
        let twice = |_| unsuitable("an extension appears twice");
        let is_authority = certificate
            .basic_constraints()
            .map_err(twice)?
            .is_some_and(|basic| basic.value.ca);
        let signs_certificates = certificate
            .key_usage()
            .map_err(twice)?
            .is_some_and(|usage| usage.value.key_cert_sign());
        let name_constraints = certificate.name_constraints().map_err(twice)?.map(|found| {
            let mut read = FactsConstraints::default();
            for subtree in found.value.permitted_subtrees.iter().flatten() {
                match subtree.base {
                    GeneralName::URI(host) => read.permitted_uris.push(host.to_owned()),
                    GeneralName::DNSName(name) => read.permitted_dns_names.push(name.to_owned()),
                    _ => read.permitted_other += 1,
                }
            }
            read
        });
        Ok(CertificateFacts {
            serial_number: hexadecimal(certificate.raw_serial()),
            not_before: timestamp(validity.not_before)?,
            not_after: timestamp(validity.not_after)?,
            public_key,
            is_authority,
            signs_certificates,
            name_constraints,
            der: block.contents.clone(),
        })
    }
}

/// The URI subtrees of an authority's name constraints, which
/// `rustls-webpki` does not read, checked by Hodor itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UriConstraints {
    /// Permitted hosts: one beginning with `.` allows the subdomains of
    /// what follows, any other that host alone.
    pub permitted: Vec<String>,
    /// Excluded hosts, read the same way.
    pub excluded: Vec<String>,
}

/// The host of a URI with an authority part, lowercased, without a name
/// and password or a port. `None` for a URI without one, or whose host is
/// an address in brackets.
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

fn host_matches(host: &str, subtree: &str) -> bool {
    let subtree = subtree.to_ascii_lowercase();
    if subtree.starts_with('.') {
        host.ends_with(&subtree)
    } else {
        host == subtree
    }
}

impl UriConstraints {
    /// Whether there is any.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.permitted.is_empty() && self.excluded.is_empty()
    }

    /// Whether a URI is within them: it has a host, a permitted subtree
    /// allows it when there are any, and no excluded subtree names it.
    #[must_use]
    pub fn allows(&self, uri: &str) -> bool {
        if self.is_empty() {
            return true;
        }
        let Some(host) = uri_host(uri) else {
            return false;
        };
        (self.permitted.is_empty()
            || self
                .permitted
                .iter()
                .any(|subtree| host_matches(&host, subtree)))
            && !self
                .excluded
                .iter()
                .any(|subtree| host_matches(&host, subtree))
    }
}

/// Takes the URI subtrees out of the content of a `NameConstraints`
/// sequence, as `rustls-webpki` keeps it for a trust anchor. Answers what
/// is left and the URI subtrees.
fn without_uri_subtrees(content: &[u8]) -> Option<(Vec<u8>, UriConstraints)> {
    let mut kept = Vec::new();
    let mut uris = UriConstraints::default();
    let mut rest = content;
    while !rest.is_empty() {
        let (tag, subtrees, _, after) = read_tlv(rest)?;
        rest = after;
        let mut kept_subtrees = Vec::new();
        let mut inner = subtrees;
        while !inner.is_empty() {
            let (subtree_tag, subtree, whole, after) = read_tlv(inner)?;
            inner = after;
            if subtree_tag != 0x30 {
                return None;
            }
            let (name_tag, name, _, _) = read_tlv(subtree)?;
            if name_tag == 0x86 {
                let host = String::from_utf8(name.to_vec()).ok()?;
                match tag {
                    0xa0 => uris.permitted.push(host),
                    0xa1 => uris.excluded.push(host),
                    _ => return None,
                }
            } else {
                kept_subtrees.extend_from_slice(whole);
            }
        }
        if !kept_subtrees.is_empty() {
            kept.extend(tlv(tag, &kept_subtrees));
        }
    }
    Some((kept, uris))
}

fn path_refused(detail: String) -> DomainError {
    DomainError::invalid(
        "certificate.path_refused",
        "the certificate does not chain to a trusted authority within its constraints",
    )
    .with_detail(detail)
}

/// A trust anchor for `rustls-webpki` made of an authority's certificate,
/// without its URI subtrees, and those subtrees.
///
/// # Errors
///
/// Returns `certificate.path_refused` if the certificate does not read.
pub fn trust_anchor(
    certificate: &[u8],
) -> Result<(TrustAnchor<'static>, UriConstraints), DomainError> {
    let der = CertificateDer::from(certificate);
    let mut anchor = webpki::anchor_from_trusted_cert(&der)
        .map_err(|error| path_refused(format!("an anchor does not read: {error:?}")))?
        .to_owned();
    let Some(constraints) = anchor.name_constraints.take() else {
        return Ok((anchor, UriConstraints::default()));
    };
    let (kept, uris) = without_uri_subtrees(constraints.as_ref())
        .ok_or_else(|| path_refused("an anchor's name constraints do not read".to_owned()))?;
    anchor.name_constraints = (!kept.is_empty()).then(|| Der::from(kept));
    Ok((anchor, uris))
}

/// The URIs a certificate names.
fn uris(certificate: &[u8]) -> Result<Vec<String>, DomainError> {
    let (_, parsed) = X509Certificate::from_der(certificate)
        .map_err(|_| path_refused("a certificate does not read".to_owned()))?;
    let names = parsed
        .subject_alternative_name()
        .map_err(|_| path_refused("a certificate names its names twice".to_owned()))?;
    Ok(names
        .map(|names| {
            names
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::URI(uri) => Some((*uri).to_owned()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default())
}

/// Hodor's own chain checking of a certificate under authorities whose
/// name constraints may hold URIs. `rustls-webpki` builds and checks the
/// path from `leaf` through `intermediates` to one of `anchors` at `at`:
/// every signature, made with the algorithms of the forwarded certificate
/// check, every validity, the authorities and their path
/// lengths, the client authentication usage when the leaf names usages,
/// and the DNS and address constraints. The anchor's URI subtrees are
/// left out of what it is given, and every URI of the leaf and of the
/// path's intermediates is then checked against them. Answers which
/// anchor the path ends at.
///
/// A certificate below the anchor that constrains URIs itself is refused,
/// since `rustls-webpki` refuses every URI below it.
///
/// # Errors
///
/// Returns `certificate.path_refused`, with the reason as its detail.
pub fn check_path(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    at: Timestamp,
) -> Result<usize, DomainError> {
    let split = anchors
        .iter()
        .map(|anchor| trust_anchor(anchor))
        .collect::<Result<Vec<_>, _>>()?;
    let trusted: Vec<TrustAnchor<'static>> =
        split.iter().map(|(anchor, _)| anchor.clone()).collect();
    let leaf_der = CertificateDer::from(leaf);
    let end_entity = webpki::EndEntityCert::try_from(&leaf_der)
        .map_err(|error| path_refused(format!("the certificate does not read: {error:?}")))?;
    let intermediates: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|certificate| CertificateDer::from(certificate.as_slice()))
        .collect();
    let seconds = u64::try_from(at.unix_timestamp())
        .map_err(|_| path_refused("a time before 1970".to_owned()))?;
    let time = UnixTime::since_unix_epoch(std::time::Duration::from_secs(seconds));
    let path = end_entity
        .verify_for_usage(
            crate::certificate::ALGORITHMS,
            &trusted,
            &intermediates,
            time,
            webpki::KeyUsage::client_auth(),
            None,
            None,
        )
        .map_err(|error| path_refused(format!("{error:?}")))?;
    let anchor = path.anchor();
    let index = trusted
        .iter()
        .position(|candidate| {
            candidate.subject == anchor.subject
                && candidate.subject_public_key_info == anchor.subject_public_key_info
        })
        .ok_or_else(|| path_refused("the path ends at no anchor given".to_owned()))?;
    let constraints = &split[index].1;
    if !constraints.is_empty() {
        let mut below = vec![leaf.to_vec()];
        below.extend(
            path.intermediate_certificates()
                .map(|certificate| certificate.der().to_vec()),
        );
        for certificate in &below {
            if let Some(outside) = uris(certificate)?
                .into_iter()
                .find(|uri| !constraints.allows(uri))
            {
                return Err(path_refused(format!(
                    "`{outside}` is outside the anchor's URI constraints"
                )));
            }
        }
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_element_is_written_and_read_back() {
        let content = vec![7u8; 300];
        let written = tlv(0x30, &content);
        assert_eq!(&written[..4], &[0x30, 0x82, 0x01, 0x2c]);
        let (tag, read, whole, rest) = read_tlv(&written).expect("reads");
        assert_eq!(
            (tag, read, whole.len(), rest.len()),
            (0x30, &content[..], 304, 0)
        );
        assert!(read_tlv(&[0x30, 0x05, 0x00]).is_none());
    }

    #[test]
    fn uri_hosts_are_matched_exactly_or_as_subdomains_after_a_dot() {
        let constraints = UriConstraints {
            permitted: vec!["prod.example.com".to_owned(), ".mesh.example".to_owned()],
            excluded: vec!["bad.mesh.example".to_owned()],
        };
        for allowed in [
            "spiffe://prod.example.com/ns/a/sa/b",
            "spiffe://PROD.example.com/x",
            "spiffe://a.mesh.example/x",
            "https://user@prod.example.com:8443/x",
        ] {
            assert!(constraints.allows(allowed), "{allowed}");
        }
        for refused in [
            "spiffe://sub.prod.example.com/x",
            "spiffe://example.com/x",
            "spiffe://mesh.example/x",
            "spiffe://bad.mesh.example/x",
            "spiffe://prod.example.com.evil/x",
            "urn:prod.example.com",
            "spiffe://[::1]/x",
        ] {
            assert!(!constraints.allows(refused), "{refused}");
        }
        assert!(UriConstraints::default().allows("urn:anything"));
    }

    #[test]
    fn uri_subtrees_are_taken_out_and_the_rest_kept() {
        let profile = AuthorityProfile {
            common_name: "x".to_owned(),
            name_constraints: hodor_keys::api::NameConstraints {
                permitted_uris: vec!["a.example".to_owned()],
                permitted_dns_names: vec!["a.example".to_owned()],
                excluded_ip_ranges: Vec::new(),
            },
        };
        let written = name_constraints(&profile);
        let (_, content, _, _) = read_tlv(&written).expect("a sequence");
        let (kept, uris) = without_uri_subtrees(content).expect("reads");
        assert_eq!(uris.permitted, ["a.example"]);
        assert!(uris.excluded.is_empty());
        let mut expected = tlv(0xa0, &tlv(0x30, &tlv(0x82, b"a.example")));
        expected.extend(tlv(
            0xa1,
            &[
                tlv(0x30, &tlv(0x87, &[0; 8])),
                tlv(0x30, &tlv(0x87, &[0; 32])),
            ]
            .concat(),
        ));
        assert_eq!(kept, expected);
    }
}
