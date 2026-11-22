//! The operating system's random source.

use hodor_kernel::RandomSource;

/// Random bytes from the operating system's cryptographically secure
/// generator. The only random source used in production.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    /// # Panics
    ///
    /// Panics if the operating system cannot provide random bytes. There is
    /// nothing safe to do without them: continuing with weak randomness
    /// would silently produce guessable salts, tokens and identifiers.
    fn fill(&self, buffer: &mut [u8]) {
        if let Err(error) = getrandom::fill(buffer) {
            panic!("the operating system's random source failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_draws_differ() {
        let (mut first, mut second) = ([0_u8; 32], [0_u8; 32]);
        OsRandom.fill(&mut first);
        OsRandom.fill(&mut second);
        assert_ne!(first, second);
        assert_ne!(first, [0_u8; 32]);
    }
}
