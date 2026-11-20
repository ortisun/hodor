//! Randomness as a port.
//!
//! Production implementations must draw from the operating system's CSPRNG;
//! they live in the crypto adapter.

/// Source of cryptographically secure random bytes.
pub trait RandomSource: Send + Sync {
    /// Fills `buffer` with random bytes.
    fn fill(&self, buffer: &mut [u8]);
}

/// Deterministic random source for tests.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::RandomSource;
    use std::sync::atomic::{AtomicU8, Ordering};

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
    use super::testing::CountingRandom;
    use super::*;

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
