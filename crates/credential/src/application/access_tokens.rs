//! Access tokens: the port and the use cases.

use crate::domain::access_token::{
    AccessToken, AccessTokenEvent, AccessTokenHash, AccessTokenId, AccessTokenSecret,
};
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, EventEnvelope, EventMetadata, RandomSource, TenantContext,
    UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;
use time::Duration;

/// Stores access tokens. Every method works inside the tenant the unit of
/// work is bound to.
#[async_trait::async_trait]
pub trait AccessTokenStore: Send + Sync {
    /// Stores a new token.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &AccessToken,
    ) -> Result<(), DomainError>;

    /// Loads a token of the tenant by identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: AccessTokenId,
    ) -> Result<Option<AccessToken>, DomainError>;

    /// Loads the token of the tenant with the given hash.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find_by_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &AccessTokenHash,
    ) -> Result<Option<AccessToken>, DomainError>;

    /// Stores a token that was revoked.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such token.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &AccessToken,
    ) -> Result<(), DomainError>;
}

/// The use cases of access tokens.
#[derive(Clone)]
pub struct AccessTokenService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    tokens: Arc<dyn AccessTokenStore>,
    digest: Arc<dyn Digest>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for AccessTokenService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessTokenService").finish_non_exhaustive()
    }
}

impl AccessTokenService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        tokens: Arc<dyn AccessTokenStore>,
        digest: Arc<dyn Digest>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            tokens,
            digest,
            random,
            clock,
        }
    }

    /// Issues a token for a user. The token itself is returned once and is
    /// not available again.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the lifetime or the description is not
    /// acceptable; see [`AccessToken::issue`].
    pub async fn issue(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        description: &str,
        lifetime: Duration,
        caller: Caller,
    ) -> Result<(AccessToken, AccessTokenSecret), DomainError> {
        let (token, secret) = AccessToken::issue(
            user_id,
            description,
            lifetime,
            self.clock.now(),
            self.random.as_ref(),
            self.digest.as_ref(),
        )?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.tokens.insert(uow.as_mut(), &token).await?;
        self.record(uow.as_mut(), caller, &token.issued_event())?;
        uow.commit().await?;
        Ok((token, secret))
    }

    /// Says which token a presented value is, if it is one that works.
    ///
    /// A value that is malformed, unknown in this tenant, expired or
    /// revoked finds nothing; the four are not told apart. Whoever accepts
    /// the token must still ask whether its user may sign in and may do
    /// what is asked.
    ///
    /// # Errors
    ///
    /// Returns an error only if storage fails.
    pub async fn authenticate(
        &self,
        tenant: &TenantContext,
        presented: &str,
    ) -> Result<Option<AccessToken>, DomainError> {
        let Some(hash) = AccessTokenHash::of_presented(presented, self.digest.as_ref()) else {
            return Ok(None);
        };
        let now = self.clock.now();
        let mut uow = self.units_of_work.begin(tenant).await?;
        Ok(self
            .tokens
            .find_by_hash(uow.as_mut(), &hash)
            .await?
            .filter(|token| token.is_good_at(now)))
    }

    /// Ends a token. Ending one that is already revoked changes nothing.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such token.
    pub async fn revoke(
        &self,
        tenant: &TenantContext,
        id: AccessTokenId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut token = self.tokens.get(uow.as_mut(), id).await?.ok_or_else(|| {
            DomainError::not_found(
                "credential.access_token_not_found",
                "the access token does not exist",
            )
        })?;
        if let Some(event) = token.revoke(self.clock.now()) {
            self.tokens.update(uow.as_mut(), &token).await?;
            self.record(uow.as_mut(), caller, &event)?;
            uow.commit().await?;
        }
        Ok(())
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &AccessTokenEvent,
    ) -> Result<(), DomainError> {
        let metadata = EventMetadata::new(
            uow.tenant().tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }
}
