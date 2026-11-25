//! What the keys context needs from storage and from a key provider.

use crate::domain::key::{GeneratedKey, KeyAlgorithm, KeyUse, KeyVersion, KeyVersionId};
use crate::domain::trust_domain::{TrustDomain, TrustDomainId};
use hodor_kernel::{
    DomainError, SealedSecret, Secret, TenantContext, TenantId, Timestamp, UnitOfWork,
};

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

/// Whether a tenant still opens secrets of the first format, the one
/// sealed directly with a root key. Works inside the tenant the unit of work
/// is bound to.
#[async_trait::async_trait]
pub trait SealingStateStore: Send + Sync {
    /// Whether the tenant refuses secrets of the first format.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn first_format_refused(&self, uow: &mut dyn UnitOfWork) -> Result<bool, DomainError>;

    /// Records that the tenant refuses secrets of the first format from
    /// `at` on. Recording it again changes nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn refuse_first_format(
        &self,
        uow: &mut dyn UnitOfWork,
        at: Timestamp,
    ) -> Result<(), DomainError>;
}

/// Secrets of the first format: sealed directly with a root key, as 0.1.0
/// did. See `docs/security/secrets-at-rest.md`, "The first format".
pub trait FirstFormatSecrets: Send + Sync {
    /// Whether `sealed` is laid out as the first format. Says nothing about
    /// whether it opens.
    fn is_first_format(&self, sealed: &SealedSecret) -> bool;

    /// Opens a secret of the first format sealed for `tenant` and
    /// `purpose`.
    ///
    /// # Errors
    ///
    /// Returns `secret.unreadable`, whatever the reason.
    fn open(
        &self,
        tenant: &TenantContext,
        purpose: &str,
        sealed: &SealedSecret,
    ) -> Result<Secret<Vec<u8>>, DomainError>;
}

/// Stores the trust domains of a tenant. Every method works inside the
/// tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait TrustDomainStore: Send + Sync {
    /// Stores a new trust domain.
    ///
    /// # Errors
    ///
    /// Returns `keys.trust_domain_name_taken` if the tenant has one of the
    /// same name.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        domain: &TrustDomain,
    ) -> Result<(), DomainError>;

    /// Reads a trust domain of the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TrustDomainId,
    ) -> Result<Option<TrustDomain>, DomainError>;

    /// The tenant's trust domain of a name.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find_by_name(
        &self,
        uow: &mut dyn UnitOfWork,
        name: &str,
    ) -> Result<Option<TrustDomain>, DomainError>;

    /// Up to `limit` trust domains of the tenant whose identifier comes
    /// after `after`, in the order of their identifiers.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<TrustDomainId>,
        limit: u32,
    ) -> Result<Vec<TrustDomain>, DomainError>;

    /// How many trust domains the tenant has. Until the unit of work ends,
    /// a second count of the same tenant waits, so that two additions count
    /// one after the other.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn count(&self, uow: &mut dyn UnitOfWork) -> Result<u32, DomainError>;

    /// Stores a changed trust domain if it still has the version it was
    /// read at, and increments its version.
    ///
    /// # Errors
    ///
    /// Returns `keys.trust_domain_changed` if it changed meanwhile, and
    /// `keys.trust_domain_not_found` if the tenant has no such trust
    /// domain.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        domain: &TrustDomain,
    ) -> Result<(), DomainError>;

    /// Removes a trust domain. Answers whether there was one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TrustDomainId,
    ) -> Result<bool, DomainError>;

    /// Takes a trust domain for a lease: holds it until the unit of work
    /// ends. Finds nothing if another unit of work holds it: it is skipped,
    /// not waited for.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TrustDomainId,
    ) -> Result<Option<TrustDomain>, DomainError>;

    /// Reads a trust domain and holds it until the unit of work ends,
    /// waiting for whoever holds it now.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TrustDomainId,
    ) -> Result<Option<TrustDomain>, DomainError>;
}

/// Finds the trust domains whose bundle is due to be fetched, across
/// tenants. Not bound to a tenant; only the worker is given it.
#[async_trait::async_trait]
pub trait DueRefreshes: Send + Sync {
    /// Up to `limit` trust domains of a bundle endpoint due at `now` and
    /// not leased past it, the longest waiting first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn due(
        &self,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<(TenantId, TrustDomainId)>, DomainError>;
}
