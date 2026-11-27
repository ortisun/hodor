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

/// The public key of a certificate signing request, as `rcgen` signs a
/// certificate for it: the point of a P-256 key.
struct RequestedKey(Vec<u8>);

impl rcgen::PublicKeyData for RequestedKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
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

    /// Signs the certificate signing request of a tenant's intermediate
    /// authority, in PEM, as the tenant's own root outside Hodor would: an
    /// authority of path length one that signs certificates, for the key
    /// the request holds, permitting these DNS names and no address. Its
    /// name constraints hold no URI, which `rcgen` cannot write: an
    /// authority that constrains URIs refuses it. In DER.
    ///
    /// # Panics
    ///
    /// If the request does not read, its key is not on P-256, or `rcgen`
    /// cannot make the certificate.
    #[must_use]
    pub fn sign_authority_request(&self, request: &str, permitted_dns_names: &[&str]) -> Vec<u8> {
        use x509_parser::prelude::{FromDer as _, X509CertificationRequest};
        let body: String = request
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let der = STANDARD.decode(body).expect("base64");
        let (_, parsed) = X509CertificationRequest::from_der(&der).expect("a request");
        let key = RequestedKey(
            parsed
                .certification_request_info
                .subject_pki
                .subject_public_key
                .data
                .to_vec(),
        );
        let mut parameters = authority_parameters("Hodor authority signed outside");
        parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        parameters.name_constraints = Some(rcgen::NameConstraints {
            permitted_subtrees: permitted_dns_names
                .iter()
                .map(|name| rcgen::GeneralSubtree::DnsName((*name).to_owned()))
                .collect(),
            excluded_subtrees: vec![rcgen::GeneralSubtree::IpAddress(rcgen::CidrSubnet::V4(
                [0; 4], [0; 4],
            ))],
        });
        parameters
            .signed_by(&key, &self.certificate, &self.key)
            .expect("an authority")
            .der()
            .to_vec()
    }

    fn issue_certificate(&self, leaf: &Leaf) -> rcgen::Certificate {
        let (parameters, key) = leaf_parameters(leaf);
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

/// What a workload certificate of `leaf` is made of: its parameters and a
/// new key.
fn leaf_parameters(leaf: &Leaf) -> (CertificateParams, KeyPair) {
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
    (parameters, key)
}

/// A workload certificate under a tenant's certificate authority, in DER,
/// signed by the authority's key through `provider`, the provider that
/// made it: what a mesh below the authority would present.
///
/// # Panics
///
/// If a name is not ASCII, `rcgen` cannot make it, or the provider does
/// not sign.
pub async fn issue_under_authority(
    provider: &dyn hodor_keys::api::KeyProvider,
    tenant: &hodor_kernel::TenantContext,
    authority: &hodor_keys::api::CertificateAuthority,
    leaf: &Leaf,
) -> Vec<u8> {
    use hodor_keys::api::CertificateWriter as _;
    let (parameters, key) = leaf_parameters(leaf);
    let public_key = &authority.key().public_key;
    let mut issuer = CertificateParams::default();
    issuer.distinguished_name = crate::certificates::subject(&hodor_keys::api::AuthorityProfile {
        common_name: authority.snapshot().common_name.clone(),
        name_constraints: authority.name_constraints(),
    });
    issuer.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    let (issuer_key, _) = crate::certificates::remembering(public_key).expect("a key");
    let issuer = issuer.self_signed(&issuer_key).expect("the issuer");
    let (signing, asked) = crate::certificates::remembering(public_key).expect("a key");
    parameters
        .signed_by(&key, &issuer, &signing)
        .expect("a certificate");
    let to_be_signed = crate::certificates::taken(&asked).expect("asked");
    let signature = provider
        .sign(
            tenant,
            &authority.key().version(OffsetDateTime::now_utc()),
            &to_be_signed,
            hodor_keys::api::SignatureEncoding::Der,
        )
        .await
        .expect("signed by the authority's key");
    crate::X509Certificates.signed(&to_be_signed, &signature)
}

/// The kind of key a mesh's intermediate is made with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MeshKey {
    /// ECDSA on P-256.
    #[default]
    P256,
    /// ECDSA on P-384.
    P384,
    /// RSA of 2048 bits, too small for an intermediate.
    Rsa2048,
    /// RSA of 3072 bits.
    Rsa3072,
    /// Ed25519, which the authority does not sign.
    Ed25519,
}

/// What a mesh's certificate signing request for its intermediate asks
/// for, written as cert-manager or OpenSSL would.
#[derive(Debug, Clone)]
pub struct MeshRequest {
    /// The common name of its subject.
    pub common_name: String,
    /// The URIs of its subject alternative names.
    pub uris: Vec<String>,
    /// The DNS names of its subject alternative names.
    pub dns_names: Vec<String>,
    /// An IP address among its names.
    pub address: bool,
    /// What its basic constraints say of `cA`; `None` for no basic
    /// constraints.
    pub authority: Option<bool>,
    /// The path length it asks for.
    pub path_length: Option<u8>,
    /// The DNS names its name constraints permit.
    pub permitted_dns_names: Vec<String>,
    /// The DNS names its name constraints exclude.
    pub excluded_dns_names: Vec<String>,
    /// The URI hosts its name constraints permit.
    pub permitted_uris: Vec<String>,
    /// Whether its name constraints permit every IPv4 address.
    pub permitted_addresses: bool,
    /// Its key.
    pub key: MeshKey,
}

impl MeshRequest {
    /// A request for an authority, without a path length, as cert-manager
    /// writes one, with this common name and nothing else.
    #[must_use]
    pub fn authority(common_name: &str) -> Self {
        Self {
            common_name: common_name.to_owned(),
            uris: Vec::new(),
            dns_names: Vec::new(),
            address: false,
            authority: Some(true),
            path_length: None,
            permitted_dns_names: Vec::new(),
            excluded_dns_names: Vec::new(),
            permitted_uris: Vec::new(),
            permitted_addresses: false,
            key: MeshKey::P256,
        }
    }
}

/// A mesh's intermediate: its key and its certificate signing request,
/// and, once the tenant's authority signed it, what it issues to its
/// workloads.
pub struct MeshIntermediate {
    key: KeyPair,
    issuer: rcgen::Certificate,
    request: String,
}

impl std::fmt::Debug for MeshIntermediate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshIntermediate").finish_non_exhaustive()
    }
}

/// A DER element.
fn element(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(u8::try_from(length).expect("short"));
    } else if length < 0x100 {
        out.extend([0x81, u8::try_from(length).expect("one byte")]);
    } else {
        out.extend([0x82]);
        out.extend(u16::try_from(length).expect("two bytes").to_be_bytes());
    }
    out.extend_from_slice(content);
    out
}

fn mesh_key(kind: MeshKey) -> KeyPair {
    match kind {
        MeshKey::P256 => KeyPair::generate(),
        MeshKey::P384 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384),
        MeshKey::Rsa2048 => {
            KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
        }
        MeshKey::Rsa3072 => {
            KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_3072)
        }
        MeshKey::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519),
    }
    .expect("a key")
}

impl MeshIntermediate {
    /// A new key and the certificate signing request for it.
    ///
    /// # Panics
    ///
    /// If a name is not ASCII, or `rcgen` cannot make it.
    #[must_use]
    pub fn new(asked: &MeshRequest) -> Self {
        let key = mesh_key(asked.key);
        let mut parameters = CertificateParams::default();
        parameters
            .distinguished_name
            .push(DnType::CommonName, asked.common_name.as_str());
        parameters.subject_alt_names = asked
            .uris
            .iter()
            .map(|uri| SanType::URI(uri.as_str().try_into().expect("an ASCII URI")))
            .chain(
                asked
                    .dns_names
                    .iter()
                    .map(|name| SanType::DnsName(name.as_str().try_into().expect("ASCII"))),
            )
            .chain(
                asked
                    .address
                    .then(|| SanType::IpAddress(std::net::IpAddr::from([10, 0, 0, 1]))),
            )
            .collect();
        let mut extensions = Vec::new();
        if let Some(authority) = asked.authority {
            let mut content = Vec::new();
            if authority {
                content.extend([0x01, 0x01, 0xff]);
            }
            if let Some(length) = asked.path_length {
                content.extend([0x02, 0x01, length]);
            }
            let mut basic =
                rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 19], element(0x30, &content));
            basic.set_criticality(true);
            extensions.push(basic);
        }
        let mut permitted = Vec::new();
        for name in &asked.permitted_dns_names {
            permitted.extend(element(0x30, &element(0x82, name.as_bytes())));
        }
        for host in &asked.permitted_uris {
            permitted.extend(element(0x30, &element(0x86, host.as_bytes())));
        }
        if asked.permitted_addresses {
            permitted.extend(element(0x30, &element(0x87, &[0; 8])));
        }
        let mut excluded = Vec::new();
        for name in &asked.excluded_dns_names {
            excluded.extend(element(0x30, &element(0x82, name.as_bytes())));
        }
        if !permitted.is_empty() || !excluded.is_empty() {
            let mut content = Vec::new();
            if !permitted.is_empty() {
                content.extend(element(0xa0, &permitted));
            }
            if !excluded.is_empty() {
                content.extend(element(0xa1, &excluded));
            }
            let mut constraints =
                rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 30], element(0x30, &content));
            constraints.set_criticality(true);
            extensions.push(constraints);
        }
        parameters.custom_extensions = extensions;
        let request = parameters
            .serialize_request(&key)
            .expect("a request")
            .pem()
            .expect("PEM");
        // What the intermediate is as an issuer: its subject and its key.
        let mut issuer = CertificateParams::default();
        issuer
            .distinguished_name
            .push(DnType::CommonName, asked.common_name.as_str());
        issuer.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let issuer = issuer.self_signed(&key).expect("the issuer");
        Self {
            key,
            issuer,
            request,
        }
    }

    /// Its certificate signing request, in PEM.
    #[must_use]
    pub fn request(&self) -> &str {
        &self.request
    }

    /// A workload's certificate it issues, in DER.
    ///
    /// # Panics
    ///
    /// If a name is not ASCII, or `rcgen` cannot make it.
    #[must_use]
    pub fn issue(&self, leaf: &Leaf) -> Vec<u8> {
        let (parameters, key) = leaf_parameters(leaf);
        parameters
            .signed_by(&key, &self.issuer, &self.key)
            .expect("a certificate")
            .der()
            .to_vec()
    }
}
