//! Randomness as a port.
//!
//! Production implementations must draw from the operating system's cryptographically secure random number generator;
//! they live in the crypto adapter.

/// Source of cryptographically secure random bytes.
pub trait RandomSource: Send + Sync {
    /// Fills `buffer` with random bytes.
    fn fill(&self, buffer: &mut [u8]);
}

/// Computes cryptographic digests.
///
/// A port, because Hodor implements no cryptography of its own. It lives
/// in the kernel because every context that stores a token stores only its
/// digest.
pub trait Digest: Send + Sync {
    /// The SHA-256 digest of `data`.
    fn sha256(&self, data: &[u8]) -> [u8; 32];

    /// The SHA-512 digest of `data`: what the `at_hash` of an ID token
    /// signed with EdDSA on Ed25519 is taken from.
    fn sha512(&self, data: &[u8]) -> [u8; 64];
}

/// Deterministic random source for tests.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::{Digest, RandomSource};
    use std::sync::atomic::{AtomicU8, Ordering};

    /// A stand-in for SHA-256 in tests of use cases: deterministic and
    /// different for different inputs, but not a cryptographic hash. Never
    /// use outside tests.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct FakeDigest;

    impl Digest for FakeDigest {
        fn sha256(&self, data: &[u8]) -> [u8; 32] {
            let mut output = [0_u8; 32];
            for (chunk, seed) in output.chunks_mut(8).zip(1_u64..) {
                // FNV-1a with a different starting value per chunk.
                let mut hash = 0xcbf2_9ce4_8422_2325_u64.wrapping_mul(seed);
                for byte in data {
                    hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
                }
                chunk.copy_from_slice(&hash.to_be_bytes());
            }
            output
        }

        fn sha512(&self, data: &[u8]) -> [u8; 64] {
            // Two stand-ins for SHA-256, of the data and of the data
            // marked, one after the other.
            let mut output = [0_u8; 64];
            output[..32].copy_from_slice(&self.sha256(data));
            output[32..].copy_from_slice(&self.sha256(&[data, b"512"].concat()));
            output
        }
    }

    /// Produces the byte sequence 0, 1, 2, … wrapping at 255. Never use
    /// outside tests.
    #[derive(Debug, Default)]
    pub struct CountingRandom(AtomicU8);

    impl RandomSource for CountingRandom {
        fn fill(&self, buffer: &mut [u8]) {
            for byte in buffer {
                *byte = self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{CountingRandom, FakeDigest};
    use super::*;

    #[test]
    fn the_fake_digest_is_deterministic_and_separates_inputs() {
        assert_eq!(FakeDigest.sha256(b"token"), FakeDigest.sha256(b"token"));
        assert_ne!(FakeDigest.sha256(b"token"), FakeDigest.sha256(b"tokem"));
        assert_ne!(FakeDigest.sha256(b""), FakeDigest.sha256(b"\0"));
    }

    #[test]
    fn counting_random_is_deterministic() {
        let random = CountingRandom::default();
        let mut first = [0_u8; 4];
        let mut second = [0_u8; 4];
        random.fill(&mut first);
        random.fill(&mut second);
        assert_eq!(first, [0, 1, 2, 3]);
        assert_eq!(second, [4, 5, 6, 7]);
    }
}
