//! The installation's key that signs bundles for Open Policy Agent.
//!
//! Specified in `docs/architecture/contexts/authorization.md`, "Signing":
//! an ECDSA P-256 key of the installation, kept by the operator in a file,
//! not a tenant's key.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_authorization_opa::api::BundleSigner;
use hodor_kernel::DomainError;

/// The start of the SubjectPublicKeyInfo of a P-256 key, before its
/// 65-byte uncompressed point: the algorithm `id-ecPublicKey` with the
/// curve `prime256v1`, then the bit string's header.
const P256_PUBLIC_KEY_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

fn unusable(detail: &'static str) -> DomainError {
    DomainError::invalid(
        "authorization.bundle_signing_key_invalid",
        "the key that signs bundles is not an ECDSA P-256 private key in PKCS #8",
    )
    .with_detail(detail)
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn from_pem(text: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin)? + begin.len();
    let stop = text[start..].find(&end)? + start;
    let body: String = text[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    STANDARD.decode(body).ok()
}

/// A key that signs bundles, with the name instances know it by.
pub struct BundleSigningKey {
    pair: EcdsaKeyPair,
    key_id: String,
}

impl std::fmt::Debug for BundleSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleSigningKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl BundleSigningKey {
    /// Reads a PKCS #8 private key in PEM, `-----BEGIN PRIVATE KEY-----`.
    ///
    /// # Errors
    ///
    /// Returns `authorization.bundle_signing_key_invalid` for anything
    /// that is not an ECDSA P-256 private key in that form, or a name that
    /// is empty.
    pub fn from_pem(text: &str, key_id: &str) -> Result<Self, DomainError> {
        if key_id.trim().is_empty() {
            return Err(unusable("the key's name is empty"));
        }
        let der = from_pem(text, "PRIVATE KEY").ok_or_else(|| unusable("no PKCS #8 PEM block"))?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der)
            .map_err(|_| unusable("not a P-256 key"))?;
        Ok(Self {
            pair,
            key_id: key_id.trim().to_owned(),
        })
    }

    /// A new key, as the private key in PEM and the public key in PEM.
    ///
    /// # Errors
    ///
    /// Returns an internal error if no key could be made.
    pub fn generate() -> Result<(String, String), DomainError> {
        let failed = || {
            DomainError::internal(
                "authorization.bundle_signing_key_failed",
                "a key could not be made",
            )
        };
        let pair =
            EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).map_err(|_| failed())?;
        let private = pair.to_pkcs8v1().map_err(|_| failed())?;
        let signing = Self {
            pair: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, private.as_ref())
                .map_err(|_| failed())?,
            key_id: "new".to_owned(),
        };
        Ok((
            pem("PRIVATE KEY", private.as_ref()),
            signing.public_key_pem(),
        ))
    }

    /// The public key in PEM, `-----BEGIN PUBLIC KEY-----`, as an
    /// instance's configuration takes it.
    #[must_use]
    pub fn public_key_pem(&self) -> String {
        let mut der = P256_PUBLIC_KEY_PREFIX.to_vec();
        der.extend_from_slice(self.pair.public_key().as_ref());
        pem("PUBLIC KEY", &der)
    }
}

impl BundleSigner for BundleSigningKey {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DomainError> {
        let signature = self
            .pair
            .sign(&SystemRandom::new(), message)
            .map_err(|_| unusable("the signature could not be made"))?;
        Ok(signature.as_ref().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AwsLcVerifier;
    use hodor_kernel::{PublicKey, SignatureAlgorithm, SignatureVerifier as _};

    #[test]
    fn a_new_key_signs_what_its_public_key_verifies() {
        let (private, public) = BundleSigningKey::generate().expect("key");
        assert!(private.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(public.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        let key = BundleSigningKey::from_pem(&private, "hodor").expect("read");
        assert_eq!(key.key_id(), "hodor");
        assert_eq!(key.public_key_pem(), public);

        let der = from_pem(&public, "PUBLIC KEY").expect("public");
        assert_eq!(der.len(), 91);
        assert_eq!(der[..26], P256_PUBLIC_KEY_PREFIX);
        let point = &der[26..];
        let verifying = PublicKey::P256 {
            x: point[1..33].to_vec(),
            y: point[33..65].to_vec(),
        };
        let signature = key.sign(b"message").expect("sign");
        assert_eq!(signature.len(), 64);
        let verifier = AwsLcVerifier;
        assert!(verifier.verify(
            SignatureAlgorithm::Es256,
            &verifying,
            b"message",
            &signature
        ));
        assert!(!verifier.verify(SignatureAlgorithm::Es256, &verifying, b"other", &signature));
    }

    #[test]
    fn anything_but_a_p256_private_key_is_refused() {
        let (private, public) = BundleSigningKey::generate().expect("key");
        for (text, name) in [
            (public.as_str(), "hodor"),
            ("not a key", "hodor"),
            (
                "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
                "hodor",
            ),
            (private.as_str(), " "),
        ] {
            assert_eq!(
                BundleSigningKey::from_pem(text, name)
                    .map(|_| ())
                    .map_err(|e| e.code().to_owned()),
                Err("authorization.bundle_signing_key_invalid".to_owned())
            );
        }
    }
}
