//! SHA-256.

use hodor_kernel::Digest;
use sha2::{Digest as _, Sha256};

/// [`Digest`] on the RustCrypto implementation of SHA-2.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256Digest;

impl Digest for Sha256Digest {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The published test vectors of the standard.
    #[test]
    fn it_matches_the_published_test_vectors() {
        assert_eq!(
            hex(Sha256Digest.sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(Sha256Digest.sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
