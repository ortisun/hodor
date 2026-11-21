//! The identity provider's key, from its certificate.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use x509_parser::oid_registry::OID_EC_P256;
use x509_parser::public_key::PublicKey;

/// The shortest RSA key accepted.
const SHORTEST_RSA_KEY_BITS: usize = 2048;

/// The kind of key, which decides the signature algorithms it may be used with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyKind {
    Rsa,
    EllipticCurveP256,
}

/// The key that every response of one identity provider is checked with.
///
/// It comes from the certificate an administrator copied from the identity
/// provider's metadata. Only the key is used: the certificate's dates and
/// issuer are not checked, because SAML uses a certificate as a way of
/// writing down a key. A key carried in a response is never used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProviderKey {
    subject_public_key_info: Vec<u8>,
    kind: KeyKind,
}

/// Why a certificate cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CertificateError {
    /// Not one certificate in PEM, base64 or DER.
    #[error("the certificate cannot be read")]
    Unreadable,
    /// An RSA key of fewer than 2048 bits.
    #[error("the certificate's RSA key is shorter than 2048 bits")]
    KeyTooShort,
    /// Neither RSA nor an elliptic curve key on P-256.
    #[error("the certificate's key is neither RSA nor an elliptic curve key on P-256")]
    KeyNotSupported,
}

impl CertificateError {
    /// The fixed name of the reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Unreadable => "certificate_unreadable",
            Self::KeyTooShort => "key_too_short",
            Self::KeyNotSupported => "key_not_supported",
        }
    }
}

impl IdentityProviderKey {
    /// Reads the key of a certificate given as PEM, or as the bare base64 that
    /// metadata carries in `X509Certificate`.
    ///
    /// # Errors
    ///
    /// [`CertificateError`] when the text is not exactly one certificate, or
    /// its key cannot be used.
    pub fn from_certificate(text: &str) -> Result<Self, CertificateError> {
        let text = text.trim();
        if text.starts_with("-----BEGIN") {
            let (rest, pem) = x509_parser::pem::parse_x509_pem(text.as_bytes())
                .map_err(|_| CertificateError::Unreadable)?;
            if pem.label != "CERTIFICATE" || !rest.iter().all(u8::is_ascii_whitespace) {
                return Err(CertificateError::Unreadable);
            }
            Self::from_der(&pem.contents)
        } else {
            let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            let der = STANDARD
                .decode(compact)
                .map_err(|_| CertificateError::Unreadable)?;
            Self::from_der(&der)
        }
    }

    /// Reads the key of a certificate in DER.
    ///
    /// # Errors
    ///
    /// [`CertificateError`] when the bytes are not exactly one certificate,
    /// or its key cannot be used.
    pub fn from_der(der: &[u8]) -> Result<Self, CertificateError> {
        let (rest, certificate) =
            x509_parser::parse_x509_certificate(der).map_err(|_| CertificateError::Unreadable)?;
        if !rest.is_empty() {
            return Err(CertificateError::Unreadable);
        }
        let info = &certificate.tbs_certificate.subject_pki;
        let kind = match info.parsed() {
            Ok(PublicKey::RSA(key)) if key.key_size() < SHORTEST_RSA_KEY_BITS => {
                return Err(CertificateError::KeyTooShort);
            }
            Ok(PublicKey::RSA(_)) => KeyKind::Rsa,
            Ok(PublicKey::EC(_))
                if info
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|parameters| parameters.as_oid().ok())
                    .is_some_and(|curve| curve == OID_EC_P256) =>
            {
                KeyKind::EllipticCurveP256
            }
            _ => return Err(CertificateError::KeyNotSupported),
        };
        Ok(Self {
            subject_public_key_info: info.raw.to_vec(),
            kind,
        })
    }

    pub(crate) fn subject_public_key_info(&self) -> &[u8] {
        &self.subject_public_key_info
    }

    pub(crate) const fn kind(&self) -> KeyKind {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_that_is_not_a_certificate_is_unreadable() {
        assert_eq!(
            IdentityProviderKey::from_certificate("not a certificate"),
            Err(CertificateError::Unreadable)
        );
        assert_eq!(
            IdentityProviderKey::from_certificate(
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
            ),
            Err(CertificateError::Unreadable)
        );
    }
}
