//! Signature verification with `aws-lc-rs`.

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA256,
    RsaPublicKeyComponents, UnparsedPublicKey,
};
use hodor_kernel::{PublicKey, SignatureAlgorithm, SignatureVerifier};

/// [`SignatureVerifier`] on `aws-lc-rs`. RSA keys shorter than 2048 bits
/// are refused by the library's own parameters.
#[derive(Debug, Clone, Copy, Default)]
pub struct AwsLcVerifier;

impl SignatureVerifier for AwsLcVerifier {
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        match (algorithm, key) {
            (SignatureAlgorithm::Rs256, PublicKey::Rsa { modulus, exponent }) => {
                RsaPublicKeyComponents {
                    n: modulus,
                    e: exponent,
                }
                .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok()
            }
            (SignatureAlgorithm::Ps256, PublicKey::Rsa { modulus, exponent }) => {
                RsaPublicKeyComponents {
                    n: modulus,
                    e: exponent,
                }
                .verify(&RSA_PSS_2048_8192_SHA256, message, signature)
                .is_ok()
            }
            (SignatureAlgorithm::Es256, PublicKey::P256 { x, y }) => {
                if x.len() != 32 || y.len() != 32 {
                    return false;
                }
                // An uncompressed point: 0x04, then x, then y.
                let mut point = Vec::with_capacity(65);
                point.push(4);
                point.extend_from_slice(x);
                point.extend_from_slice(y);
                // The signature is r then s, 32 bytes each, as signed
                // statements carry it.
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                    .verify(message, signature)
                    .is_ok()
            }
            (SignatureAlgorithm::EdDsa, PublicKey::Ed25519 { x }) => {
                // The key's 32 bytes and a signature of 64, as RFC 8032
                // writes both; the message is signed as it is, not hashed
                // first.
                x.len() == 32
                    && UnparsedPublicKey::new(&ED25519, x)
                        .verify(message, signature)
                        .is_ok()
            }
            // A key that cannot have made a signature of this algorithm.
            (
                SignatureAlgorithm::Rs256 | SignatureAlgorithm::Ps256,
                PublicKey::P256 { .. } | PublicKey::Ed25519 { .. },
            )
            | (SignatureAlgorithm::Es256, PublicKey::Rsa { .. } | PublicKey::Ed25519 { .. })
            | (SignatureAlgorithm::EdDsa, PublicKey::Rsa { .. } | PublicKey::P256 { .. }) => false,
        }
    }
}
