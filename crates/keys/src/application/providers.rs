//! Several key providers at once: one makes the signing keys, one makes
//! the data keys, and every version goes back to the provider that made
//! it. See `docs/architecture/contexts/keys.md`, "Choosing the provider".

use crate::application::ports::KeyProvider;
use crate::domain::key::{
    GeneratedKey, KeyAlgorithm, KeyUse, KeyVersion, KeyVersionId, SignatureEncoding,
};
use hodor_kernel::{DomainError, Secret, TenantContext};
use std::sync::Arc;

/// A [`KeyProvider`] made of others. New signing keys are made by one
/// provider and new data keys by another; a version is always used by
/// the provider whose name it was stored with, and by no other. A version
/// whose provider is not configured is refused: nothing ever falls back to
/// another provider, so a key stays where it was made.
#[derive(Clone)]
pub struct KeyProviders {
    signing: Arc<dyn KeyProvider>,
    data: Arc<dyn KeyProvider>,
    known: Vec<Arc<dyn KeyProvider>>,
}

impl std::fmt::Debug for KeyProviders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.known.iter().map(|provider| provider.name()).collect();
        f.debug_struct("KeyProviders")
            .field("signing", &self.signing.name())
            .field("data", &self.data.name())
            .field("known", &names)
            .finish()
    }
}

impl KeyProviders {
    /// `signing` makes the signing keys and `data` the data keys; both
    /// use the versions they made.
    #[must_use]
    pub fn new(signing: Arc<dyn KeyProvider>, data: Arc<dyn KeyProvider>) -> Self {
        let providers = Self {
            known: vec![signing.clone()],
            signing,
            data: data.clone(),
        };
        providers.also(data)
    }

    /// Also uses the versions `provider` made, without making new keys
    /// with it: for an installation that stopped making keys in a
    /// provider whose versions still sign. A provider of a name already
    /// known is ignored.
    #[must_use]
    pub fn also(mut self, provider: Arc<dyn KeyProvider>) -> Self {
        if !self
            .known
            .iter()
            .any(|known| known.name() == provider.name())
        {
            self.known.push(provider);
        }
        self
    }

    fn maker(&self, algorithm: KeyAlgorithm) -> &Arc<dyn KeyProvider> {
        match algorithm.key_use() {
            KeyUse::Data => &self.data,
            KeyUse::Signing | KeyUse::Encryption => &self.signing,
        }
    }

    /// The provider that made `version`, if it is configured.
    fn owner(&self, version: &KeyVersion) -> Result<&Arc<dyn KeyProvider>, DomainError> {
        let name = version.snapshot().provider.as_str();
        self.known
            .iter()
            .find(|provider| provider.name() == name)
            .ok_or_else(|| {
                DomainError::internal(
                    "keys.provider_not_configured",
                    "the key was made by a provider this installation does not use",
                )
                .with_detail(format!("provider `{name}`"))
            })
    }
}

#[async_trait::async_trait]
impl KeyProvider for KeyProviders {
    fn name(&self) -> &'static str {
        self.signing.name()
    }

    fn name_for(&self, algorithm: KeyAlgorithm) -> &'static str {
        self.maker(algorithm).name_for(algorithm)
    }

    async fn generate(
        &self,
        tenant: &TenantContext,
        version: KeyVersionId,
        algorithm: KeyAlgorithm,
    ) -> Result<GeneratedKey, DomainError> {
        self.maker(algorithm)
            .generate(tenant, version, algorithm)
            .await
    }

    async fn sign(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        message: &[u8],
        encoding: SignatureEncoding,
    ) -> Result<Vec<u8>, DomainError> {
        self.owner(version)?
            .sign(tenant, version, message, encoding)
            .await
    }

    async fn encrypt(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        associated: &[u8],
        plaintext: &Secret<Vec<u8>>,
    ) -> Result<Vec<u8>, DomainError> {
        self.owner(version)?
            .encrypt(tenant, version, associated, plaintext)
            .await
    }

    async fn decrypt(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        associated: &[u8],
        ciphertext: &[u8],
    ) -> Result<Secret<Vec<u8>>, DomainError> {
        self.owner(version)?
            .decrypt(tenant, version, associated, ciphertext)
            .await
    }
}
