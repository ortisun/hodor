//! Checking signatures made by others.
//!
//! A port, because Hodor implements no cryptography of its own. It lives
//! in the kernel because several contexts check statements signed by
//! someone else: federation today, tokens presented by clients later.

/// The signature algorithms Hodor accepts from others. There is no way to
/// name `none` or a shared-secret algorithm here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// RSA with PKCS#1 v1.5 padding and SHA-256.
    Rs256,
    /// RSA with PSS padding and SHA-256.
    Ps256,
    /// ECDSA on the P-256 curve with SHA-256.
    Es256,
}

impl SignatureAlgorithm {
    /// Reads the name used in a signed statement's header. Any other
    /// name is refused by not being one of these.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "RS256" => Some(Self::Rs256),
            "PS256" => Some(Self::Ps256),
            "ES256" => Some(Self::Es256),
            _ => None,
        }
    }

    /// Whether a key of this kind can have made a signature of this
    /// algorithm.
    #[must_use]
    pub const fn fits(self, key: &PublicKey) -> bool {
        matches!(
            (self, key),
            (Self::Rs256 | Self::Ps256, PublicKey::Rsa { .. })
                | (Self::Es256, PublicKey::P256 { .. })
        )
    }
}

/// A public key, as its numbers. Public: nothing here is secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// An RSA key.
    Rsa {
        /// The modulus, big-endian.
        modulus: Vec<u8>,
        /// The public exponent, big-endian.
        exponent: Vec<u8>,
    },
    /// A point on the P-256 curve.
    P256 {
        /// The x coordinate, 32 bytes.
        x: Vec<u8>,
        /// The y coordinate, 32 bytes.
        y: Vec<u8>,
    },
}

/// Checks signatures.
pub trait SignatureVerifier: Send + Sync {
    /// Whether `signature` is a signature of `message` by the holder of
    /// `key`, made with `algorithm`. Anything that is not exactly that is
    /// `false`: a key of the wrong kind, a key too weak to accept, a
    /// malformed signature.
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}
