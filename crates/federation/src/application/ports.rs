//! What the federation context needs from storage.

use crate::domain::link::{ExternalIdentity, Subject};
use crate::domain::provider::{Alias, IdentityProvider, ProviderId};
use crate::domain::trip::Trip;
use hodor_authentication::api::TransactionId;
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};

/// Stores identity providers. Every method works inside the tenant the
/// unit of work is bound to.
#[async_trait::async_trait]
pub trait ProviderStore: Send + Sync {
    /// Stores a new provider.
    ///
    /// # Errors
    ///
    /// Returns `federation.alias_taken` if the tenant already has a
    /// provider with this alias.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        provider: &IdentityProvider,
    ) -> Result<(), DomainError>;

    /// Stores a changed provider, if nobody changed it since it was read:
    /// its stored version must be the one it was read with. The stored
    /// version becomes one more.
    ///
    /// # Errors
    ///
    /// Returns `federation.provider_modified_concurrently` otherwise.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        provider: &IdentityProvider,
    ) -> Result<(), DomainError>;

    /// The provider with this identifier, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ProviderId,
    ) -> Result<Option<IdentityProvider>, DomainError>;

    /// The provider with this alias, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find_by_alias(
        &self,
        uow: &mut dyn UnitOfWork,
        alias: &Alias,
    ) -> Result<Option<IdentityProvider>, DomainError>;

    /// The tenant's providers, ordered by alias.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<IdentityProvider>, DomainError>;
}

/// Stores links between external identities and users. Every method
/// works inside the tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait LinkStore: Send + Sync {
    /// Stores a new link. Returns `false`, storing nothing, if the
    /// provider's subject already belongs to a user.
    ///
    /// # Errors
    ///
    /// Returns `federation.provider_not_found` if the tenant has no such
    /// provider.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        link: &ExternalIdentity,
    ) -> Result<bool, DomainError>;

    /// The link of a provider's subject, if there is one. Found by these
    /// two and by nothing else.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        subject: &Subject,
    ) -> Result<Option<ExternalIdentity>, DomainError>;

    /// Records when a link last signed its user in. Returns whether there
    /// was such a link.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn mark_used(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        subject: &Subject,
        now: Timestamp,
    ) -> Result<bool, DomainError>;

    /// The external identities of a user, oldest link first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list_for_user(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Vec<ExternalIdentity>, DomainError>;

    /// Removes a link. Returns the user it belonged to, if there was one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        subject: &Subject,
    ) -> Result<Option<UserId>, DomainError>;
}

/// Stores the trip of a sign-in in progress. Every method works inside
/// the tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait TripStore: Send + Sync {
    /// Stores the trip of a sign-in, replacing the one it had.
    ///
    /// # Errors
    ///
    /// Returns `federation.provider_not_found` if the tenant has no such
    /// provider.
    async fn put(&self, uow: &mut dyn UnitOfWork, trip: &Trip) -> Result<(), DomainError>;

    /// Takes the trip of a sign-in away and returns it, if it had one.
    /// Of several callers at the same moment, one gets it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction_id: TransactionId,
    ) -> Result<Option<Trip>, DomainError>;
}
