//! Checking a forwarded certificate against the authorities of a trust
//! domain's bundle, for the OAuth context's [`CertificateCheck`] port.
//!
//! The path is checked by `rustls-webpki`, the validation `rustls` uses,
//! with the signature algorithms of `aws-lc-rs`; `x509-parser` reads a
//! certificate's names and an authority's key. See
//! `docs/architecture/contexts/oauth.md`, "An identity forwarded by a
//! proxy", and `docs/decisions/0056-forwarded-client-identity.md`.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hodor_kernel::Timestamp;
use hodor_oauth::api::{
    CertificateCheck, CertificateNames, MAX_FORWARDED_CERTIFICATE_BYTES, MAX_FORWARDED_CHAIN,
};
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use serde_json::Value;
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert, aws_lc_rs};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::{OID_EC_P256, OID_NIST_EC_P384, OID_NIST_EC_P521, Oid};
use x509_parser::prelude::FromDer as _;
use x509_parser::public_key::PublicKey;

/// The signatures a path may be made with, all made by `aws-lc-rs`.
static ALGORITHMS: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
    aws_lc_rs::ECDSA_P256_SHA256,
    aws_lc_rs::ECDSA_P256_SHA384,
    aws_lc_rs::ECDSA_P384_SHA256,
    aws_lc_rs::ECDSA_P384_SHA384,
    aws_lc_rs::ECDSA_P521_SHA256,
    aws_lc_rs::ECDSA_P521_SHA384,
    aws_lc_rs::ECDSA_P521_SHA512,
    aws_lc_rs::ED25519,
    aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
    aws_lc_rs::RSA_PKCS1_2048_8192_SHA384,
    aws_lc_rs::RSA_PKCS1_2048_8192_SHA512,
    aws_lc_rs::RSA_PKCS1_3072_8192_SHA384,
    aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];

/// [`CertificateCheck`] with `rustls-webpki` and `x509-parser`.
#[derive(Debug, Clone, Copy, Default)]
pub struct X509CertificateCheck;

/// Reads exactly one certificate, of an acceptable size.
fn read(der: &[u8]) -> Option<X509Certificate<'_>> {
    if der.is_empty() || der.len() > MAX_FORWARDED_CERTIFICATE_BYTES {
        return None;
    }
    match X509Certificate::from_der(der) {
        Ok(([], certificate)) => Some(certificate),
        _ => None,
    }
}

/// The certificate of a bundle's `x509-svid` element, if the element is
/// an authority that holds its own key: the certificate has the basic
/// constraint of an authority, and its public key is the element's.
fn authority_of(element: &str) -> Option<Vec<u8>> {
    let jwk: Value = serde_json::from_str(element).ok()?;
    let [certificate] = jwk.get("x5c")?.as_array()?.as_slice() else {
        return None;
    };
    let der = STANDARD.decode(certificate.as_str()?).ok()?;
    let parsed = read(&der)?;
    let is_authority = parsed
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|constraints| constraints.value.ca);
    (is_authority && holds_key(&parsed, &jwk)).then_some(der)
}

/// Whether the public key of `certificate` is the key `jwk` names.
fn holds_key(certificate: &X509Certificate<'_>, jwk: &Value) -> bool {
    let field = |name: &str| {
        jwk.get(name)
            .and_then(Value::as_str)
            .and_then(|text| URL_SAFE_NO_PAD.decode(text).ok())
    };
    let info = certificate.public_key();
    match (jwk.get("kty").and_then(Value::as_str), info.parsed()) {
        (Some("EC"), Ok(PublicKey::EC(point))) => {
            let curve: Option<Oid<'_>> = info
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.as_oid().ok());
            let expected = match jwk.get("crv").and_then(Value::as_str) {
                Some("P-256") => OID_EC_P256,
                Some("P-384") => OID_NIST_EC_P384,
                Some("P-521") => OID_NIST_EC_P521,
                _ => return false,
            };
            let (Some(x), Some(y)) = (field("x"), field("y")) else {
                return false;
            };
            let mut uncompressed = Vec::with_capacity(1 + x.len() + y.len());
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(&x);
            uncompressed.extend_from_slice(&y);
            curve.is_some_and(|curve| curve == expected) && point.data() == uncompressed.as_slice()
        }
        (Some("RSA"), Ok(PublicKey::RSA(key))) => {
            let (Some(modulus), Some(exponent)) = (field("n"), field("e")) else {
                return false;
            };
            without_leading_zeros(key.modulus) == without_leading_zeros(&modulus)
                && without_leading_zeros(key.exponent) == without_leading_zeros(&exponent)
        }
        _ => false,
    }
}

fn without_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len());
    &bytes[first..]
}

fn seconds_since_epoch(now: Timestamp) -> Option<UnixTime> {
    let seconds = u64::try_from(now.unix_timestamp()).ok()?;
    Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        seconds,
    )))
}

impl CertificateCheck for X509CertificateCheck {
    fn names(&self, certificate: &[u8]) -> Option<CertificateNames> {
        let parsed = read(certificate)?;
        let mut names = CertificateNames::default();
        // A certificate with two of these extensions does not read.
        let alternative = parsed.subject_alternative_name().ok()?;
        for name in alternative
            .iter()
            .flat_map(|extension| extension.value.general_names.iter())
        {
            match name {
                GeneralName::URI(uri) => names.uris.push((*uri).to_owned()),
                GeneralName::DNSName(dns) => names.dns_names.push((*dns).to_owned()),
                _ => {}
            }
        }
        Some(names)
    }

    fn chains_to(
        &self,
        certificate: &[u8],
        chain: &[Vec<u8>],
        authorities: &[&str],
        now: Timestamp,
    ) -> bool {
        if chain.len() > MAX_FORWARDED_CHAIN || read(certificate).is_none() {
            return false;
        }
        let Some(time) = seconds_since_epoch(now) else {
            return false;
        };
        let authorities: Vec<CertificateDer<'static>> = authorities
            .iter()
            .filter_map(|element| authority_of(element))
            .map(CertificateDer::from)
            .collect();
        let anchors: Vec<TrustAnchor<'_>> = authorities
            .iter()
            .filter_map(|authority| anchor_from_trusted_cert(authority).ok())
            .collect();
        if anchors.is_empty() {
            return false;
        }
        let intermediates: Vec<CertificateDer<'_>> = chain
            .iter()
            .filter(|der| der.len() <= MAX_FORWARDED_CERTIFICATE_BYTES)
            .map(|der| CertificateDer::from(der.as_slice()))
            .collect();
        let leaf = CertificateDer::from(certificate);
        let Ok(leaf) = EndEntityCert::try_from(&leaf) else {
            return false;
        };
        leaf.verify_for_usage(
            ALGORITHMS,
            &anchors,
            &intermediates,
            time,
            KeyUsage::client_auth(),
            None,
            None,
        )
        .is_ok()
    }
}
