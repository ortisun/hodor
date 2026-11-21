//! What the federation context needs from storage.

use crate::domain::link::{ExternalIdentity, Subject};
use crate::domain::pending_authorization::PendingAuthorization;
use crate::domain::provider::{Alias, IdentityProvider, ProviderId};
use hodor_authentication::api::{LockoutRules, TransactionId};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};
use hodor_kernel::{Secret, TenantContext};

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

/// Stores the pending authorization of a sign-in in progress. Every method works inside
/// the tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait PendingAuthorizationStore: Send + Sync {
    /// Stores the pending authorization of a sign-in, replacing the one it had.
    ///
    /// # Errors
    ///
    /// Returns `federation.provider_not_found` if the tenant has no such
    /// provider.
    async fn put(
        &self,
        uow: &mut dyn UnitOfWork,
        pending: &PendingAuthorization,
    ) -> Result<(), DomainError>;

    /// Takes the pending authorization of a sign-in away and returns it, if it had one.
    /// Of several callers at the same moment, one gets it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction_id: TransactionId,
    ) -> Result<Option<PendingAuthorization>, DomainError>;
}

/// What to ask a directory about one person.
#[derive(Debug)]
pub struct DirectoryQuery {
    /// The directory's address, such as `ldaps://ldap.example.com`.
    pub address: String,
    /// The name Hodor binds with to search.
    pub bind_name: String,
    /// The password of that name.
    pub bind_password: Secret<String>,
    /// Where people are searched for.
    pub base: String,
    /// The filter, with what the person typed already escaped and in
    /// its place.
    pub filter: String,
    /// The attributes to read from the entry that is found.
    pub attributes: Vec<String>,
}

/// One entry of a directory, as far as it was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// The entry's own name in the directory.
    pub name: String,
    /// Attribute names and their values. A value is bytes: not every
    /// directory's every attribute is text.
    pub attributes: Vec<(String, Vec<Vec<u8>>)>,
}

impl DirectoryEntry {
    /// The first value of an attribute, by its name in any case.
    #[must_use]
    pub fn first(&self, attribute: &str) -> Option<&[u8]> {
        self.attributes
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(attribute))
            .and_then(|(_, values)| values.first())
            .map(Vec::as_slice)
    }
}

/// What a directory said about a person and a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryAnswer {
    /// Exactly one entry was found, and the directory accepted the
    /// password for it.
    Verified(DirectoryEntry),
    /// Nobody is signed in. The reason is a fixed name, for the record:
    /// `not_found`, `ambiguous` or `wrong_password`.
    Refused(&'static str),
}

/// Asks a directory. Implemented by `hodor-adapters-ldap`.
#[async_trait::async_trait]
pub trait DirectoryClient: Send + Sync {
    /// Binds as Hodor, searches for the one entry the query's filter
    /// matches, and binds as that entry with `password`. The caller has
    /// already refused an empty password; an implementation refuses one
    /// as well.
    ///
    /// # Errors
    ///
    /// Returns `federation.provider_unavailable` if the directory cannot
    /// be reached or refuses Hodor's own name.
    async fn verify(
        &self,
        query: &DirectoryQuery,
        password: &Secret<String>,
    ) -> Result<DirectoryAnswer, DomainError>;
}

/// The tenant's rules for counting attempts. They belong to the tenant
/// context, which the composition root asks.
#[async_trait::async_trait]
pub trait LockoutPolicy: Send + Sync {
    /// The rules of this tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if they cannot be read.
    async fn rules(&self, tenant: &TenantContext) -> Result<LockoutRules, DomainError>;
}
