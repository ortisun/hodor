//! Certificate authorities and workload certificates for tests, made with
//! `rcgen`: what a mesh's authority would sign, and the SPIFFE bundle
//! elements that trust it. Never use outside tests.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

/// An authority on P-256 that signs certificates.
pub struct TestAuthority {
    key: KeyPair,
    certificate: rcgen::Certificate,
}

impl std::fmt::Debug for TestAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestAuthority").finish_non_exhaustive()
    }
}

/// What a workload's certificate holds.
#[derive(Debug, Clone, Default)]
pub struct Leaf {
    /// Its URIs, such as a SPIFFE identifier.
    pub uris: Vec<String>,
    /// Its DNS names, such as a Linkerd identity.
    pub dns_names: Vec<String>,
    /// Whether it expired yesterday.
    pub expired: bool,
    /// Whether it is an authority itself, which a workload's certificate
    /// must not be.
    pub authority: bool,
    /// Whether it names only `serverAuth` among its extended key usages.
    pub server_only: bool,
}

impl Leaf {
    /// A certificate with one URI, as an X509-SVID has.
    #[must_use]
    pub fn uri(uri: &str) -> Self {
        Self {
            uris: vec![uri.to_owned()],
            ..Self::default()
        }
    }

    /// A certificate with one DNS name, as a Linkerd workload's has.
    #[must_use]
    pub fn dns(name: &str) -> Self {
        Self {
            dns_names: vec![name.to_owned()],
            ..Self::default()
        }
    }
}

fn authority_parameters(name: &str) -> CertificateParams {
    let mut parameters = CertificateParams::default();
    parameters.distinguished_name.push(DnType::CommonName, name);
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    parameters
}

impl TestAuthority {
    /// A root authority, signing itself.
    ///
    /// # Panics
    ///
    /// If `rcgen` cannot make it.
    #[must_use]
    pub fn root(name: &str) -> Self {
        let key = KeyPair::generate().expect("a key");
        let certificate = authority_parameters(name)
            .self_signed(&key)
            .expect("a root");
        Self { key, certificate }
    }

    /// An authority this one signs.
    ///
    /// # Panics
    ///
    /// If `rcgen` cannot make it.
    #[must_use]
    pub fn intermediate(&self, name: &str) -> Self {
        let key = KeyPair::generate().expect("a key");
        let certificate = authority_parameters(name)
            .signed_by(&key, &self.certificate, &self.key)
            .expect("an intermediate");
        Self { key, certificate }
    }

    /// Its certificate, in DER.
    #[must_use]
    pub fn der(&self) -> Vec<u8> {
        self.certificate.der().to_vec()
    }

    /// Its certificate, in PEM.
    #[must_use]
    pub fn pem(&self) -> String {
        self.certificate.pem()
    }

    /// A certificate this authority signs, in DER.
    ///
    /// # Panics
    ///
    /// If a name is not ASCII, or `rcgen` cannot make it.
    #[must_use]
    pub fn issue(&self, leaf: &Leaf) -> Vec<u8> {
        self.issue_certificate(leaf).der().to_vec()
    }

    /// A certificate this authority signs, in PEM.
    ///
    /// # Panics
    ///
    /// If a name is not ASCII, or `rcgen` cannot make it.
    #[must_use]
    pub fn issue_pem(&self, leaf: &Leaf) -> String {
        self.issue_certificate(leaf).pem()
    }

    fn issue_certificate(&self, leaf: &Leaf) -> rcgen::Certificate {
        let key = KeyPair::generate().expect("a key");
        let mut parameters = CertificateParams::default();
        parameters
            .distinguished_name
            .push(DnType::CommonName, "workload");
        parameters.subject_alt_names = leaf
            .uris
            .iter()
            .map(|uri| SanType::URI(uri.as_str().try_into().expect("an ASCII URI")))
            .chain(
                leaf.dns_names
                    .iter()
                    .map(|name| SanType::DnsName(name.as_str().try_into().expect("ASCII"))),
            )
            .collect();
        parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        parameters.extended_key_usages = if leaf.server_only {
            vec![ExtendedKeyUsagePurpose::ServerAuth]
        } else {
            vec![
                ExtendedKeyUsagePurpose::ClientAuth,
                ExtendedKeyUsagePurpose::ServerAuth,
            ]
        };
        if leaf.authority {
            parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        if leaf.expired {
            let now = OffsetDateTime::now_utc();
            parameters.not_before = now - Duration::days(30);
            parameters.not_after = now - Duration::days(1);
        }
        parameters
            .signed_by(&key, &self.certificate, &self.key)
            .expect("a certificate")
    }

    /// The `x509-svid` element of a SPIFFE bundle that trusts this
    /// authority: its key, with its certificate in `x5c`.
    #[must_use]
    pub fn bundle_element(&self) -> Value {
        self.element_with(&self.key, &self.der())
    }

    /// An element that names this authority's certificate with `other`'s
    /// key, which the certificate does not hold.
    #[must_use]
    pub fn element_with_key_of(&self, other: &Self) -> Value {
        self.element_with(&other.key, &self.der())
    }

    fn element_with(&self, key: &KeyPair, certificate: &[u8]) -> Value {
        let point = key.public_key_raw();
        json!({
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
            "x5c": [STANDARD.encode(certificate)],
        })
    }
}

/// The element of a bundle for a certificate that is not an authority,
/// with its own key: what a careless bundle could hold.
///
/// # Panics
///
/// If `rcgen` cannot make it.
#[must_use]
pub fn not_an_authority_element(name: &str) -> Value {
    let key = KeyPair::generate().expect("a key");
    let mut parameters = CertificateParams::default();
    parameters.distinguished_name.push(DnType::CommonName, name);
    let certificate = parameters.self_signed(&key).expect("a certificate");
    let point = key.public_key_raw();
    json!({
        "use": "x509-svid",
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        "x5c": [STANDARD.encode(certificate.der())],
    })
}

/// A SPIFFE bundle of these elements.
#[must_use]
pub fn bundle(elements: &[Value]) -> Value {
    json!({ "keys": elements })
}
