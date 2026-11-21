//! Cryptography adapter.
//!
//! Hodor implements no cryptography of its own. This crate connects the
//! ports that contexts define to audited libraries; replacing a library is
//! a change to this crate only. See `docs/decisions/0008-cryptography.md`.

mod digest;
mod password;
mod random;
mod sealing;
mod signature;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use digest::Sha256Digest;
pub use password::{Argon2Parameters, Argon2idHasher, HashingLimits};
pub use random::OsRandom;
pub use sealing::SecretKeys;
pub use signature::AwsLcVerifier;
