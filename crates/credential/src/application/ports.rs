//! What the credential context needs from the outside.

use crate::domain::password::PasswordHash;
use hodor_kernel::{DomainError, Secret};

/// The result of checking a password against a stored hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordVerification {
    /// Whether the password is the right one.
    pub matches: bool,
    /// Whether the stored hash was made with parameters other than the
    /// current ones and should be replaced by a fresh hash.
    pub needs_renewal: bool,
}

/// Hashes and verifies passwords.
///
/// Hashing is deliberately slow and memory-hungry, so implementations
/// bound how many run at once. When that bound and its queue are full,
/// every method fails with `ErrorKind::Unavailable` and the code
/// `credential.hashing_overloaded` instead of waiting.
#[async_trait::async_trait]
pub trait PasswordHasher: Send + Sync {
    /// Hashes a password with a fresh salt and the current parameters.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` when overloaded.
    async fn hash(&self, password: &Secret<String>) -> Result<PasswordHash, DomainError>;

    /// Checks a password against a stored hash, whatever parameters the
    /// hash was made with.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` when overloaded, and an internal error if the
    /// stored hash cannot be read.
    async fn verify(
        &self,
        password: &Secret<String>,
        hash: &PasswordHash,
    ) -> Result<PasswordVerification, DomainError>;

    /// Performs a computation that costs the same as a verification with
    /// the current parameters and discards the result.
    ///
    /// Used when there is no hash to check against, so that the time an
    /// answer takes does not reveal whether a user or a password exists.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` when overloaded.
    async fn verify_nothing(&self, password: &Secret<String>) -> Result<(), DomainError>;
}
