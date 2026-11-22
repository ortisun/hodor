//! What the keys context needs from storage and from a key provider.

use crate::domain::key::{GeneratedKey, KeyAlgorithm, KeyUse, KeyVersion, KeyVersionId};
use hodor_kernel::{DomainError, Secret, TenantContext, UnitOfWork};

/// Stores and loads key versions. Every method works inside the tenant
/// the unit of work is bound to.
#[async_trait::async_trait]
pub trait KeyStore: Send + Sync {
    /// Stores a new version.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        version: &KeyVersion,
    ) -> Result<(), DomainError>;

    /// Loads one version of the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: KeyVersionId,
    ) -> Result<Option<KeyVersion>, DomainError>;

    /// Loads every version of one use, in any order.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list_for_use(
        &self,
        uow: &mut dyn UnitOfWork,
        key_use: KeyUse,
    ) -> Result<Vec<KeyVersion>, DomainError>;

    /// Stores what can change in a version: its state, its times and its
    /// revocation reason. The key, its algorithm and its public key never
    /// change.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such version.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        version: &KeyVersion,
    ) -> Result<(), DomainError>;
}

/// Makes keys and uses them. The key itself never leaves the provider: it
/// hands back material only it can use, and is given it back for every
/// operation.
///
/// A provider must refuse material made for another tenant, version or
/// algorithm than the one it is told.
#[async_trait::async_trait]
pub trait KeyProvider: Send + Sync {
    /// The provider's name, stored with every version it makes, such as
    /// `local`.
    fn name(&self) -> &'static str;

    /// Makes a new key for `version` of `algorithm` in `tenant`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be made or kept.
    async fn generate(
        &self,
        tenant: &TenantContext,
        version: KeyVersionId,
        algorithm: KeyAlgorithm,
    ) -> Result<GeneratedKey, DomainError>;

    /// Signs `message` with a signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if the version is not a signing key or its material
    /// does not open for this tenant, version and algorithm.
    async fn sign(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        message: &[u8],
    ) -> Result<Vec<u8>, DomainError>;

    /// Encrypts `plaintext` with a data key. `associated` is authenticated
    /// with it and must be given again to decrypt.
    ///
    /// # Errors
    ///
    /// Returns an error if the version is not a data key or its material
    /// does not open for this tenant, version and algorithm.
    async fn encrypt(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        associated: &[u8],
        plaintext: &Secret<Vec<u8>>,
    ) -> Result<Vec<u8>, DomainError>;

    /// Decrypts what [`KeyProvider::encrypt`] made with the same version and
    /// associated data.
    ///
    /// # Errors
    ///
    /// Returns an error, one for every reason, if it does not decrypt.
    async fn decrypt(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        associated: &[u8],
        ciphertext: &[u8],
    ) -> Result<Secret<Vec<u8>>, DomainError>;
}
