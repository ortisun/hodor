//! Secrets that must be read back, kept encrypted.
//!
//! A port, because Hodor implements no cryptography of its own. It lives
//! in the kernel because any context may have a secret to keep. See
//! `docs/security/secrets-at-rest.md`.

use crate::error::DomainError;
use crate::secret::Secret;
use crate::tenant::TenantContext;
use std::fmt;

/// A secret as it is stored: opaque bytes that only a [`SecretBox`] with
/// the right key, for the right tenant and purpose, turns back into the
/// secret.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedSecret(Vec<u8>);

impl SealedSecret {
    /// Wraps bytes read from storage. Whether they open is found out by
    /// opening them.
    #[must_use]
    pub const fn from_stored(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes to store.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedSecret({} bytes)", self.0.len())
    }
}

/// Keeps secrets encrypted at rest.
///
/// `purpose` is a fixed name chosen by the caller, such as
/// `federation.client_secret`. A secret sealed for one tenant and purpose
/// opens for no other.
pub trait SecretBox: Send + Sync {
    /// Encrypts `secret` for `tenant` and `purpose`.
    ///
    /// # Errors
    ///
    /// Returns an error if no key is configured or the purpose is not a
    /// usable name.
    fn seal(
        &self,
        tenant: &TenantContext,
        purpose: &str,
        secret: &Secret<Vec<u8>>,
    ) -> Result<SealedSecret, DomainError>;

    /// Decrypts `sealed`, which must have been sealed for `tenant` and
    /// `purpose`.
    ///
    /// # Errors
    ///
    /// Returns `secret.unreadable`, whatever the reason: changed bytes,
    /// another tenant or purpose, or a key that is not configured.
    fn open(
        &self,
        tenant: &TenantContext,
        purpose: &str,
        sealed: &SealedSecret,
    ) -> Result<Secret<Vec<u8>>, DomainError>;

    /// Whether `sealed` was made with a key that is no longer the one new
    /// secrets are sealed with.
    fn needs_resealing(&self, sealed: &SealedSecret) -> bool;
}

/// The error of a sealed secret that does not open. One code for every
/// reason; the reason goes to the log through `detail`.
#[must_use]
pub fn unreadable(detail: &str) -> DomainError {
    DomainError::internal("secret.unreadable", "a stored secret could not be read")
        .with_detail(detail)
}

/// A stand-in for tests of use cases.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::{SealedSecret, SecretBox, unreadable};
    use crate::error::DomainError;
    use crate::secret::Secret;
    use crate::tenant::TenantContext;

    /// Binds a secret to its tenant and purpose without hiding it: enough
    /// to test that callers pass the right ones, and nothing more. Never
    /// use outside tests.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct FakeSecretBox;

    fn label(tenant: &TenantContext, purpose: &str) -> Vec<u8> {
        format!("sealed|{}|{purpose}|", tenant.tenant_id()).into_bytes()
    }

    impl SecretBox for FakeSecretBox {
        fn seal(
            &self,
            tenant: &TenantContext,
            purpose: &str,
            secret: &Secret<Vec<u8>>,
        ) -> Result<SealedSecret, DomainError> {
            let mut bytes = label(tenant, purpose);
            // Reversed, so that a test searching storage for the secret
            // does not find it by accident.
            bytes.extend(secret.expose().iter().rev());
            Ok(SealedSecret::from_stored(bytes))
        }

        fn open(
            &self,
            tenant: &TenantContext,
            purpose: &str,
            sealed: &SealedSecret,
        ) -> Result<Secret<Vec<u8>>, DomainError> {
            let label = label(tenant, purpose);
            let rest = sealed
                .as_bytes()
                .strip_prefix(label.as_slice())
                .ok_or_else(|| unreadable("sealed for another tenant or purpose"))?;
            Ok(Secret::new(rest.iter().rev().copied().collect()))
        }

        fn needs_resealing(&self, _sealed: &SealedSecret) -> bool {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeSecretBox;
    use super::*;
    use crate::id::TenantId;

    #[test]
    fn a_sealed_secret_does_not_show_its_bytes_when_printed() {
        let sealed = SealedSecret::from_stored(b"something".to_vec());
        assert_eq!(format!("{sealed:?}"), "SealedSecret(9 bytes)");
    }

    #[test]
    fn the_fake_opens_only_for_the_tenant_and_purpose_it_sealed_for() {
        let tenant = TenantContext::assume(TenantId::generate());
        let other = TenantContext::assume(TenantId::generate());
        let secret = Secret::new(b"client secret".to_vec());

        let sealed = FakeSecretBox
            .seal(&tenant, "a.purpose", &secret)
            .expect("seal");
        let opened = FakeSecretBox
            .open(&tenant, "a.purpose", &sealed)
            .expect("open");
        assert_eq!(opened.expose(), secret.expose());

        for (tenant, purpose) in [(&other, "a.purpose"), (&tenant, "another.purpose")] {
            let error = FakeSecretBox
                .open(tenant, purpose, &sealed)
                .expect_err("must not open");
            assert_eq!(error.code(), "secret.unreadable");
        }
    }
}
