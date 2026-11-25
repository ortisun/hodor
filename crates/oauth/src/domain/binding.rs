//! Certificate-bound access tokens (RFC 8705): the thumbprint of the
//! certificate a request came with, the `cnf` claim that binds a token to
//! it, and the check of a bound token.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Certificate-bound
//! access tokens", and Decision 0057.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::Digest;
use serde_json::{Value, json};
use std::fmt;

/// The claim that binds a token to a key or a certificate (RFC 7800).
pub const CONFIRMATION_CLAIM: &str = "cnf";
/// The member of `cnf` that names a certificate by its SHA-256 (RFC 8705,
/// section 3.1).
pub const CERTIFICATE_THUMBPRINT_MEMBER: &str = "x5t#S256";

/// The SHA-256 of a certificate's DER encoding: what a bound token's
/// `x5t#S256` names.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertificateThumbprint([u8; 32]);

impl CertificateThumbprint {
    /// The thumbprint of a certificate, given in DER.
    #[must_use]
    pub fn of_certificate(der: &[u8], digest: &dyn Digest) -> Self {
        Self(digest.sha256(der))
    }

    /// A thumbprint as it was stored.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Reads Envoy's `Hash`: the SHA-256 of the certificate in
    /// hexadecimal, 64 digits of either case. Anything else reads as
    /// nothing.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        let digits = text.as_bytes();
        if digits.len() != 64 {
            return None;
        }
        let value = |digit: u8| char::from(digit).to_digit(16);
        let mut bytes = [0_u8; 32];
        let (pairs, _) = digits.as_chunks::<2>();
        for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
            let high = value(*high)?;
            let low = value(*low)?;
            *byte = u8::try_from(high * 16 + low).ok()?;
        }
        Some(Self(bytes))
    }

    /// Reads `x5t#S256`: 32 bytes in base64url without padding.
    #[must_use]
    pub fn from_x5t(text: &str) -> Option<Self> {
        if text.len() != 43 {
            return None;
        }
        let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
        <[u8; 32]>::try_from(bytes).ok().map(Self)
    }

    /// The bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// As `x5t#S256` writes it: base64url without padding.
    #[must_use]
    pub fn as_x5t(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// The `cnf` claim that binds a token to this certificate.
    #[must_use]
    pub fn confirmation(&self) -> Value {
        json!({ CERTIFICATE_THUMBPRINT_MEMBER: self.as_x5t() })
    }
}

impl fmt::Debug for CertificateThumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CertificateThumbprint")
            .field(&self.as_x5t())
            .finish()
    }
}

/// Whether a token whose `cnf` is `confirmation` may be used by a request
/// that came with the certificate of `presented`. A token without `cnf`
/// is bound to nothing and may always be; a bound one only with the same
/// certificate, compared byte for byte.
///
/// # Errors
///
/// The reason it may not, for Hodor's log.
pub fn check_confirmation(
    confirmation: Option<&Value>,
    presented: Option<&CertificateThumbprint>,
) -> Result<(), &'static str> {
    let Some(confirmation) = confirmation else {
        return Ok(());
    };
    let Some(bound) = confirmation
        .get(CERTIFICATE_THUMBPRINT_MEMBER)
        .and_then(Value::as_str)
        .and_then(CertificateThumbprint::from_x5t)
    else {
        return Err("the token is bound in a way that cannot be checked");
    };
    match presented {
        None => Err("the token is bound to a certificate and the request came with none"),
        Some(presented) if *presented == bound => Ok(()),
        Some(_) => Err("the token is bound to another certificate"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::random::testing::FakeDigest;

    #[test]
    fn a_thumbprint_is_written_as_base64url_and_read_back() {
        let thumbprint = CertificateThumbprint::of_certificate(b"a certificate", &FakeDigest);
        let written = thumbprint.as_x5t();
        assert_eq!(written.len(), 43);
        assert!(!written.contains('='));
        assert_eq!(CertificateThumbprint::from_x5t(&written), Some(thumbprint));
        assert_eq!(
            thumbprint.confirmation(),
            json!({ "x5t#S256": written.clone() })
        );
        for refused in ["", "AAAA", &format!("{written}="), &written[1..]] {
            assert_eq!(CertificateThumbprint::from_x5t(refused), None, "{refused}");
        }
    }

    #[test]
    fn envoy_s_hash_is_64_hexadecimal_digits() {
        let hex = "00ff10AbcdEF".to_owned() + &"0".repeat(52);
        let read = CertificateThumbprint::from_hex(&hex).expect("a hash");
        assert_eq!(&read.as_bytes()[..6], &[0x00, 0xff, 0x10, 0xab, 0xcd, 0xef]);
        for refused in [
            "",
            "abc",
            "0a1b",
            &"0".repeat(63),
            &"0".repeat(65),
            &("g".to_owned() + &"0".repeat(63)),
            &("+".to_owned() + &"0".repeat(63)),
        ] {
            assert_eq!(CertificateThumbprint::from_hex(refused), None, "{refused}");
        }
    }

    #[test]
    fn a_bound_token_needs_its_own_certificate() {
        let mine = CertificateThumbprint::from_bytes([7; 32]);
        let other = CertificateThumbprint::from_bytes([8; 32]);
        let bound = mine.confirmation();
        assert_eq!(check_confirmation(Some(&bound), Some(&mine)), Ok(()));
        assert!(check_confirmation(Some(&bound), None).is_err());
        assert!(check_confirmation(Some(&bound), Some(&other)).is_err());
        // A token bound to nothing goes with or without a certificate.
        assert_eq!(check_confirmation(None, None), Ok(()));
        assert_eq!(check_confirmation(None, Some(&other)), Ok(()));
        // A binding Hodor cannot read is never taken as no binding.
        for unreadable in [
            json!({}),
            json!({ "jkt": "abc" }),
            json!({ "x5t#S256": 7 }),
            json!({ "x5t#S256": "not a thumbprint" }),
        ] {
            assert!(
                check_confirmation(Some(&unreadable), Some(&mine)).is_err(),
                "{unreadable}"
            );
        }
    }
}
