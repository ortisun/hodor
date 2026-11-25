//! What the OAuth context needs from storage. Every method works inside
//! the tenant the unit of work is bound to.

use crate::domain::application::{Application, ApplicationId};
use crate::domain::authorization::{
    AuthorizationCode, CodeHash, Grant, GrantId, PendingAuthorization, PendingAuthorizationId,
};
use crate::domain::client::{Client, ClientId};
use crate::domain::consent::{Consent, ConsentAnswer, ConsentHistoryEntry};
use crate::domain::introspection::AccessTokenRecord;
use crate::domain::refresh::{
    RefreshAsk, RefreshFamily, RefreshFamilyId, RefreshTokenHash, RefreshTokenRecord,
};
use crate::domain::resource_server::{Audience, ResourceServer, ResourceServerId};
use hodor_kernel::{
    DomainError, GroupId, OrganizationId, TenantContext, Timestamp, UnitOfWork, UserId,
};
use hodor_session::api::SessionId;

/// Stores applications.
#[async_trait::async_trait]
pub trait ApplicationStore: Send + Sync {
    /// Stores a new application.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        application: &Application,
    ) -> Result<(), DomainError>;

    /// Stores a changed application, if its stored version is the one it
    /// was read with. The stored version becomes one more.
    ///
    /// # Errors
    ///
    /// Returns `oauth.application_modified_concurrently` otherwise.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        application: &Application,
    ) -> Result<(), DomainError>;

    /// The application with this identifier, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ApplicationId,
    ) -> Result<Option<Application>, DomainError>;

    /// The tenant's applications, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<Application>, DomainError>;
}

/// Stores clients, with their secrets and keys.
#[async_trait::async_trait]
pub trait ClientStore: Send + Sync {
    /// Stores a new client of an application of the tenant.
    ///
    /// # Errors
    ///
    /// Returns `oauth.application_not_found` if the tenant has no such
    /// application.
    async fn insert(&self, uow: &mut dyn UnitOfWork, client: &Client) -> Result<(), DomainError>;

    /// Stores a changed client with its secrets and keys, if its stored
    /// version is the one it was read with. The stored version becomes one
    /// more.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_modified_concurrently` otherwise.
    async fn update(&self, uow: &mut dyn UnitOfWork, client: &Client) -> Result<(), DomainError>;

    /// The client with this identifier, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ClientId,
    ) -> Result<Option<Client>, DomainError>;

    /// The clients of an application, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list_for_application(
        &self,
        uow: &mut dyn UnitOfWork,
        application_id: ApplicationId,
    ) -> Result<Vec<Client>, DomainError>;
}

/// Stores resource servers.
#[async_trait::async_trait]
pub trait ResourceServerStore: Send + Sync {
    /// Stores a new resource server of an application of the tenant.
    ///
    /// # Errors
    ///
    /// Returns `oauth.audience_taken` if the tenant has a resource server
    /// with this audience, `oauth.application_has_resource_server` if the
    /// application has one, and `oauth.application_not_found` if the tenant
    /// has no such application.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        server: &ResourceServer,
    ) -> Result<(), DomainError>;

    /// Stores a changed resource server, if its stored version is the one
    /// it was read with. The stored version becomes one more.
    ///
    /// # Errors
    ///
    /// Returns `oauth.resource_server_modified_concurrently` otherwise.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        server: &ResourceServer,
    ) -> Result<(), DomainError>;

    /// The resource server with this identifier, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ResourceServerId,
    ) -> Result<Option<ResourceServer>, DomainError>;

    /// The resource server with this audience, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find_by_audience(
        &self,
        uow: &mut dyn UnitOfWork,
        audience: &Audience,
    ) -> Result<Option<ResourceServer>, DomainError>;

    /// The tenant's resource servers, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<ResourceServer>, DomainError>;
}

/// Stores the requests that wait for their person to sign in.
#[async_trait::async_trait]
pub trait AuthorizationRequestStore: Send + Sync {
    /// Stores a pending request.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_not_found` if the tenant has no such client.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        pending: &PendingAuthorization,
    ) -> Result<(), DomainError>;

    /// The pending request with this identifier, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: PendingAuthorizationId,
    ) -> Result<Option<PendingAuthorization>, DomainError>;

    /// Removes the pending request with this identifier. Returns whether
    /// this call removed it, so that of two resumptions at the same moment
    /// exactly one goes on.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        id: PendingAuthorizationId,
    ) -> Result<bool, DomainError>;

    /// Records the answer to a request that waits for consent. Returns
    /// whether this call recorded it: false when the request is gone, does
    /// not wait for consent, or was answered already, so that a request is
    /// answered once.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn answer(
        &self,
        uow: &mut dyn UnitOfWork,
        id: PendingAuthorizationId,
        answer: ConsentAnswer,
    ) -> Result<bool, DomainError>;
}

/// Stores grants.
#[async_trait::async_trait]
pub trait GrantStore: Send + Sync {
    /// Stores a new grant.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_not_found` if the tenant has no such client.
    async fn insert(&self, uow: &mut dyn UnitOfWork, grant: &Grant) -> Result<(), DomainError>;

    /// The grant with this identifier, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: GrantId,
    ) -> Result<Option<Grant>, DomainError>;

    /// Stores a grant's status, when it was revoked and why.
    ///
    /// # Errors
    ///
    /// Returns `oauth.grant_not_found` if the tenant has no such grant.
    async fn update(&self, uow: &mut dyn UnitOfWork, grant: &Grant) -> Result<(), DomainError>;

    /// The active grants of a person for a client.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list_active_for(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
        client: ClientId,
    ) -> Result<Vec<Grant>, DomainError>;

    /// The active grants of a person, for every client, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list_active_of(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
    ) -> Result<Vec<Grant>, DomainError>;
}

/// Stores consents and their history.
#[async_trait::async_trait]
pub trait ConsentStore: Send + Sync {
    /// The person's consent for the client, withdrawn or expired included.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
        client: ClientId,
    ) -> Result<Option<Consent>, DomainError>;

    /// Stores the consent, replacing the person's one for the client.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_not_found` if the tenant has no such client.
    async fn save(&self, uow: &mut dyn UnitOfWork, consent: &Consent) -> Result<(), DomainError>;

    /// The person's consents that stand at `now`, the most recently given
    /// first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list_standing(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
        now: Timestamp,
    ) -> Result<Vec<Consent>, DomainError>;

    /// Adds an entry to the history. Entries are never changed.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_not_found` if the tenant has no such client.
    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        entry: &ConsentHistoryEntry,
    ) -> Result<(), DomainError>;
}

/// Stores authorization codes, by the hash of the code.
#[async_trait::async_trait]
pub trait AuthorizationCodeStore: Send + Sync {
    /// Stores a new code.
    ///
    /// # Errors
    ///
    /// Returns `oauth.grant_not_found` if the tenant has no such grant.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        code: &AuthorizationCode,
    ) -> Result<(), DomainError>;

    /// The code with this hash, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &CodeHash,
    ) -> Result<Option<AuthorizationCode>, DomainError>;

    /// Marks the code redeemed at `at`, only if it was not redeemed
    /// before. Returns whether this call was the one that redeemed it, so
    /// that of two redemptions at the same moment exactly one wins.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn redeem(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &CodeHash,
        at: Timestamp,
    ) -> Result<bool, DomainError>;
}

/// Remembers the assertions clients proved who they are with, so that each
/// is used once.
#[async_trait::async_trait]
pub trait ClientAssertionStore: Send + Sync {
    /// Remembers the assertion `assertion_id` of `client` until
    /// `expires_at`. Returns whether this call was the first to remember
    /// it, so that of two requests with the same assertion at the same
    /// moment exactly one goes on.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_not_found` if the tenant has no such client.
    async fn remember(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
        assertion_id: &str,
        expires_at: Timestamp,
    ) -> Result<bool, DomainError>;
}

/// Stores refresh token families and every token they have had, by the
/// hash of the token.
#[async_trait::async_trait]
pub trait RefreshTokenStore: Send + Sync {
    /// Stores a new family with its first token.
    ///
    /// # Errors
    ///
    /// Returns `oauth.grant_not_found` if the tenant has no such grant.
    async fn start(
        &self,
        uow: &mut dyn UnitOfWork,
        family: &RefreshFamily,
    ) -> Result<(), DomainError>;

    /// The family of the token with this hash, and the token's record, if
    /// the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &RefreshTokenHash,
    ) -> Result<Option<(RefreshFamily, RefreshTokenRecord)>, DomainError>;

    /// Moves the family one generation, from `from_generation`, to the
    /// token `next`, for what `asked` asked, at `at`; only if it is still
    /// active and at that generation. Returns whether this call moved it,
    /// so that of two refreshes at the same moment exactly one does.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn advance(
        &self,
        uow: &mut dyn UnitOfWork,
        family: RefreshFamilyId,
        from_generation: i32,
        next: &RefreshTokenHash,
        asked: &RefreshAsk,
        at: Timestamp,
    ) -> Result<bool, DomainError>;

    /// Stores a family's revocation.
    ///
    /// # Errors
    ///
    /// Returns `oauth.refresh_token_family_not_found` if the tenant has no
    /// such family.
    async fn revoke(
        &self,
        uow: &mut dyn UnitOfWork,
        family: &RefreshFamily,
    ) -> Result<(), DomainError>;

    /// The family with this identifier, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: RefreshFamilyId,
    ) -> Result<Option<RefreshFamily>, DomainError>;
}

/// The register of access tokens: a record of every access token issued,
/// by its `jti`. Never the token.
#[async_trait::async_trait]
pub trait AccessTokenRecordStore: Send + Sync {
    /// Records a token just issued.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_not_found` if the tenant has no such client,
    /// and `oauth.grant_not_found` or
    /// `oauth.refresh_token_family_not_found` for a grant or family it does
    /// not have.
    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        record: &AccessTokenRecord,
    ) -> Result<(), DomainError>;

    /// The record of the token with this `jti`, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        token_id: &str,
    ) -> Result<Option<AccessTokenRecord>, DomainError>;

    /// Revokes the record of `token_id`, issued to `client`, at `at` for
    /// `reason`, unless it was revoked already. Returns whether this call
    /// revoked it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn revoke(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
        token_id: &str,
        at: Timestamp,
        reason: &str,
    ) -> Result<bool, DomainError>;

    /// Revokes, at `at` for `reason`, every record of a token issued for
    /// `principal` that is not revoked yet. Returns the client and the
    /// `jti` of each record this call revoked.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn revoke_for_principal(
        &self,
        uow: &mut dyn UnitOfWork,
        principal: UserId,
        at: Timestamp,
        reason: &str,
    ) -> Result<Vec<(ClientId, String)>, DomainError>;

    /// Removes up to `batch` records of tokens that had expired at `now`.
    /// Returns how many it removed.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn remove_expired(
        &self,
        uow: &mut dyn UnitOfWork,
        now: Timestamp,
        batch: u32,
    ) -> Result<u64, DomainError>;
}

/// What the OAuth context needs to know of a person, from the session and
/// identity contexts.
#[async_trait::async_trait]
pub trait PersonStanding: Send + Sync {
    /// Whether the session `session` of `user` is still active.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn session_is_active(
        &self,
        tenant: &TenantContext,
        user: UserId,
        session: SessionId,
    ) -> Result<bool, DomainError>;

    /// Whether `user` may still sign in.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn may_sign_in(&self, tenant: &TenantContext, user: UserId) -> Result<bool, DomainError>;

    /// The kind of `principal`, `service_account` or `agent`, if it is a
    /// workload of the tenant that may act: one that is active. None for a
    /// person, a workload that may not act, a user of another tenant and
    /// an identifier of nobody.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn workload_that_may_act(
        &self,
        tenant: &TenantContext,
        principal: UserId,
    ) -> Result<Option<&'static str>, DomainError>;
}

/// What the OAuth context needs to know of the groups and organizations of
/// a person, from the identity context.
#[async_trait::async_trait]
pub trait PersonMemberships: Send + Sync {
    /// Whether `user` is a member of `organization`. An organization the
    /// tenant does not have has no members.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn is_member(
        &self,
        tenant: &TenantContext,
        user: UserId,
        organization: OrganizationId,
    ) -> Result<bool, DomainError>;

    /// The effective groups of `user`: those they are in directly and those
    /// that hold one of them, sorted.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn effective_groups(
        &self,
        tenant: &TenantContext,
        user: UserId,
    ) -> Result<Vec<GroupId>, DomainError>;
}

/// Keeps a tenant's pairwise secret, sealed. A tenant has at most one, and
/// it is never replaced.
#[async_trait::async_trait]
pub trait PairwiseSecretStore: Send + Sync {
    /// The tenant's sealed pairwise secret, if it has one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<hodor_kernel::SealedSecret>, DomainError>;

    /// Stores `sealed` as the tenant's pairwise secret unless the tenant
    /// has one already, in which case nothing is changed. Of two calls at
    /// the same moment, exactly one stores its secret.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert_unless_present(
        &self,
        uow: &mut dyn UnitOfWork,
        sealed: &hodor_kernel::SealedSecret,
        created_at: Timestamp,
    ) -> Result<(), DomainError>;
}
