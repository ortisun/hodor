//! The kernel's `SecretBox`, sealing under the tenant's data keys.
//!
//! See `docs/security/secrets-at-rest.md` for the format and
//! `docs/architecture/contexts/keys.md`, "Secrets under data keys", for the
//! rules.

use crate::application::ports::{FirstFormatSecrets, KeyProvider, KeyStore, SealingStateStore};
use crate::application::service::KeyService;
use crate::domain::key::{KeyAlgorithm, KeyState, KeyUse, KeyVersion, KeyVersionId};
use hodor_kernel::sealing::unreadable;
use hodor_kernel::{
    Caller, Clock, DomainError, SealedSecret, Secret, SecretBox, TenantContext, UnitOfWorkFactory,
};
use std::sync::Arc;

/// The first byte of a secret sealed under a data key.
pub const FORMAT: u8 = 2;
const VERSION_BYTES: usize = 16;
const MAX_PURPOSE: usize = 128;
/// Bound into every ciphertext, so that it is never mistaken for one made
/// for another use of the same data key.
const DOMAIN: &[u8] = b"hodor-secret-v2";
/// Why a data key that lost the race to be the tenant's first is revoked.
pub const LOST_RACE: &str = "lost the race to become the first data key";

/// [`SecretBox`] that seals every secret under the tenant's active data
/// key, making the first one when the tenant has none, and still opens the
/// first format until the tenant refuses it.
#[derive(Clone)]
pub struct TenantSecretBox {
    service: KeyService,
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    keys: Arc<dyn KeyStore>,
    provider: Arc<dyn KeyProvider>,
    states: Arc<dyn SealingStateStore>,
    first_format: Option<Arc<dyn FirstFormatSecrets>>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for TenantSecretBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantSecretBox").finish_non_exhaustive()
    }
}

impl TenantSecretBox {
    /// Wires the box to its ports. Without `first_format`, secrets of the
    /// first format never open.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        keys: Arc<dyn KeyStore>,
        provider: Arc<dyn KeyProvider>,
        states: Arc<dyn SealingStateStore>,
        first_format: Option<Arc<dyn FirstFormatSecrets>>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let service = KeyService::new(
            units_of_work.clone(),
            keys.clone(),
            provider.clone(),
            clock.clone(),
        );
        Self {
            service,
            units_of_work,
            keys,
            provider,
            states,
            first_format,
            clock,
        }
    }

    /// Whether `tenant` refuses secrets of the first format.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn first_format_refused(&self, tenant: &TenantContext) -> Result<bool, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let refused = self.states.first_format_refused(uow.as_mut()).await?;
        uow.commit().await?;
        Ok(refused)
    }

    /// Records that `tenant` refuses secrets of the first format from now
    /// on. Final; recording it again changes nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn refuse_first_format(&self, tenant: &TenantContext) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.states
            .refuse_first_format(uow.as_mut(), self.clock.now())
            .await?;
        uow.commit().await
    }

    /// The tenant's active data key, made and activated if it has none.
    async fn active_data_key(&self, tenant: &TenantContext) -> Result<KeyVersion, DomainError> {
        if let Some(active) = self.active(tenant).await? {
            return Ok(active);
        }
        let made = self
            .service
            .create_version(tenant, KeyAlgorithm::A256Gcm, Caller::system())
            .await?;
        // Another sealing may have made one meanwhile: use it, and give up
        // the version just made.
        if let Some(active) = self.active(tenant).await? {
            self.give_up(tenant, made.id()).await?;
            return Ok(active);
        }
        match self
            .service
            .activate_first(tenant, made.id(), Caller::system())
            .await
        {
            Ok(active) => Ok(active),
            Err(error)
                if matches!(
                    error.code(),
                    "keys.activation_conflict" | "keys.already_active"
                ) =>
            {
                self.give_up(tenant, made.id()).await?;
                self.active(tenant).await?.ok_or(error)
            }
            Err(error) => Err(error),
        }
    }

    async fn active(&self, tenant: &TenantContext) -> Result<Option<KeyVersion>, DomainError> {
        let set = self.service.key_set(tenant, KeyUse::Data).await?;
        Ok(set.active(KeyAlgorithm::A256Gcm).cloned())
    }

    async fn give_up(&self, tenant: &TenantContext, id: KeyVersionId) -> Result<(), DomainError> {
        self.service
            .revoke(tenant, id, LOST_RACE, Caller::system())
            .await
            .map(|_| ())
    }

    async fn version(
        &self,
        tenant: &TenantContext,
        id: KeyVersionId,
    ) -> Result<Option<KeyVersion>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let version = self.keys.get(uow.as_mut(), id).await?;
        uow.commit().await?;
        Ok(version.filter(|version| version.key_use() == KeyUse::Data))
    }

    fn open_first_format(
        &self,
        tenant: &TenantContext,
        purpose: &str,
        sealed: &SealedSecret,
        refused: bool,
    ) -> Result<Secret<Vec<u8>>, DomainError> {
        let first_format = self
            .first_format
            .as_ref()
            .ok_or_else(|| unreadable("the first format cannot be read here"))?;
        if refused {
            return Err(unreadable("the tenant refuses the first format"));
        }
        first_format.open(tenant, purpose, sealed)
    }

    fn is_first_format(&self, sealed: &SealedSecret) -> bool {
        self.first_format
            .as_ref()
            .is_some_and(|first_format| first_format.is_first_format(sealed))
    }
}

/// The data key version a sealed secret names, and what the provider made.
fn split(sealed: &[u8]) -> Option<(KeyVersionId, &[u8])> {
    let (&format, rest) = sealed.split_first()?;
    if format != FORMAT || rest.len() < VERSION_BYTES {
        return None;
    }
    let (version, ciphertext) = rest.split_at(VERSION_BYTES);
    let version: [u8; VERSION_BYTES] = version.try_into().ok()?;
    Some((
        KeyVersionId::from_uuid(uuid::Uuid::from_bytes(version)),
        ciphertext,
    ))
}

/// What is authenticated with a ciphertext without being stored.
fn associated_data(tenant: &TenantContext, purpose: &str, version: KeyVersionId) -> Vec<u8> {
    let tenant = tenant.tenant_id().to_string();
    let version = version.to_string();
    let mut data = Vec::with_capacity(DOMAIN.len() + tenant.len() + purpose.len() + 40);
    data.extend_from_slice(DOMAIN);
    data.push(0);
    data.extend_from_slice(tenant.as_bytes());
    data.push(0);
    data.extend_from_slice(purpose.as_bytes());
    data.push(0);
    data.extend_from_slice(version.as_bytes());
    data
}

fn check_purpose(purpose: &str) -> Result<(), DomainError> {
    let usable = (1..=MAX_PURPOSE).contains(&purpose.len())
        && purpose.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'_'
        });
    if usable {
        Ok(())
    } else {
        Err(DomainError::internal(
            "secret.purpose_invalid",
            "a stored secret could not be handled",
        )
        .with_detail("a purpose is lowercase letters, digits, dots and underscores"))
    }
}

/// Whether a data key in `state` opens what it sealed.
const fn opens(state: KeyState) -> bool {
    matches!(state, KeyState::Active | KeyState::Retiring)
}

#[async_trait::async_trait]
impl SecretBox for TenantSecretBox {
    async fn seal(
        &self,
        tenant: &TenantContext,
        purpose: &str,
        secret: &Secret<Vec<u8>>,
    ) -> Result<SealedSecret, DomainError> {
        check_purpose(purpose)?;
        let version = self.active_data_key(tenant).await?;
        let associated = associated_data(tenant, purpose, version.id());
        let ciphertext = self
            .provider
            .encrypt(tenant, &version, &associated, secret)
            .await?;
        let mut sealed = Vec::with_capacity(1 + VERSION_BYTES + ciphertext.len());
        sealed.push(FORMAT);
        sealed.extend_from_slice(version.id().as_uuid().as_bytes());
        sealed.extend_from_slice(&ciphertext);
        Ok(SealedSecret::from_stored(sealed))
    }

    async fn open(
        &self,
        tenant: &TenantContext,
        purpose: &str,
        sealed: &SealedSecret,
    ) -> Result<Secret<Vec<u8>>, DomainError> {
        check_purpose(purpose)?;
        if self.is_first_format(sealed) {
            let refused = self.first_format_refused(tenant).await?;
            return self.open_first_format(tenant, purpose, sealed, refused);
        }
        let (id, ciphertext) =
            split(sealed.as_bytes()).ok_or_else(|| unreadable("not a sealed secret"))?;
        let version = self
            .version(tenant, id)
            .await?
            .ok_or_else(|| unreadable("sealed under a data key the tenant does not have"))?;
        if !opens(version.state()) {
            return Err(unreadable("sealed under a data key that no longer opens"));
        }
        self.provider
            .decrypt(
                tenant,
                &version,
                &associated_data(tenant, purpose, id),
                ciphertext,
            )
            .await
            .map_err(|_| {
                unreadable("changed, or sealed for another tenant or purpose, or with another key")
            })
    }

    async fn needs_resealing(
        &self,
        tenant: &TenantContext,
        sealed: &SealedSecret,
    ) -> Result<bool, DomainError> {
        let Some((id, _)) = split(sealed.as_bytes()) else {
            // The first format, or bytes that are no sealed secret at all.
            return Ok(true);
        };
        let version = self.version(tenant, id).await?;
        Ok(version.is_none_or(|version| version.state() != KeyState::Active))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_read_back_from_where_it_was_written() {
        let id = KeyVersionId::generate();
        let mut bytes = vec![FORMAT];
        bytes.extend_from_slice(id.as_uuid().as_bytes());
        bytes.extend_from_slice(b"ciphertext");
        let (read, rest) = split(&bytes).expect("a sealed secret");
        assert_eq!(read, id);
        assert_eq!(rest, b"ciphertext");
    }

    #[test]
    fn what_is_not_the_second_format_is_not_split() {
        let id = KeyVersionId::generate();
        let mut other_format = vec![1];
        other_format.extend_from_slice(id.as_uuid().as_bytes());
        for bytes in [
            Vec::new(),
            vec![FORMAT],
            vec![FORMAT; VERSION_BYTES],
            other_format,
        ] {
            assert!(split(&bytes).is_none(), "{bytes:?}");
        }
    }

    #[test]
    fn the_associated_data_names_tenant_purpose_and_version() {
        let tenant = TenantContext::assume(hodor_kernel::TenantId::generate());
        let version = KeyVersionId::generate();
        let data = associated_data(&tenant, "a.purpose", version);
        let text = String::from_utf8(data).expect("text");
        assert!(text.starts_with("hodor-secret-v2\0"));
        assert!(text.contains(&tenant.tenant_id().to_string()));
        assert!(text.contains("\0a.purpose\0"));
        assert!(text.ends_with(&version.to_string()));
    }
}
