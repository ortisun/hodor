//! What the OAuth context needs from storage. Every method works inside
//! the tenant the unit of work is bound to.

use crate::domain::application::{Application, ApplicationId};
use crate::domain::authorization::{
    AuthorizationCode, CodeHash, Grant, GrantId, PendingAuthorization, PendingAuthorizationId,
};
use crate::domain::claim_mapper::{ClaimMapper, ClaimMapperId, PersonAttributes};
use crate::domain::client::{Client, ClientId};
use crate::domain::consent::{Consent, ConsentAnswer, ConsentHistoryEntry};
use crate::domain::forwarded::WorkloadIdentity;
use crate::domain::initial_access_token::{
    InitialAccessToken, InitialAccessTokenHash, InitialAccessTokenId,
};
use crate::domain::introspection::AccessTokenRecord;
use crate::domain::pushed::{PushedAuthorization, ReferenceHash};
use crate::domain::refresh::{
    RefreshAsk, RefreshFamily, RefreshFamilyId, RefreshTokenHash, RefreshTokenRecord,
};
use crate::domain::registration::ClientRegistration;
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
    /// application, and `oauth.client_spiffe_id_taken` or
    /// `oauth.client_linkerd_identity_taken` if a client of the tenant
    /// acting as another principal is bound to the client's identity: an
    /// identity binds the clients of one service account (Decision 0058).
    async fn insert(&self, uow: &mut dyn UnitOfWork, client: &Client) -> Result<(), DomainError>;

    /// Stores a changed client with its secrets and keys, if its stored
    /// version is the one it was read with. The stored version becomes one
    /// more.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_modified_concurrently` otherwise, and the
    /// errors of [`ClientStore::insert`] for its identity.
    async fn update(&self, uow: &mut dyn UnitOfWork, client: &Client) -> Result<(), DomainError>;

    /// The clients of the tenant bound to `identity`, oldest first. They
    /// all act as one service account.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn bound_to(
        &self,
        uow: &mut dyn UnitOfWork,
        identity: &WorkloadIdentity,
    ) -> Result<Vec<Client>, DomainError>;

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

    /// How many clients an application holds, whoever made them.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn count_for_application(
        &self,
        uow: &mut dyn UnitOfWork,
        application_id: ApplicationId,
    ) -> Result<usize, DomainError>;

    /// How many clients registered themselves in the tenant at `since` or
    /// later from the address whose SHA-256 is `address_hash`, or, with
    /// `None`, from an address that was not known.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn count_registered_since(
        &self,
        uow: &mut dyn UnitOfWork,
        address_hash: Option<&[u8; 32]>,
        since: Timestamp,
    ) -> Result<usize, DomainError>;

    /// The client with this identifier, if the tenant has it, with its row
    /// locked until the unit of work ends: what a change of a registration
    /// reads before it stores, so that two changes at once are made one
    /// after the other.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ClientId,
    ) -> Result<Option<Client>, DomainError>;

    /// Deletes the client, with its secrets and keys and everything else
    /// stored that names it. Answers whether the tenant had it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn delete(&self, uow: &mut dyn UnitOfWork, id: ClientId) -> Result<bool, DomainError>;
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

    /// The resource server of this application, if it has one: an
    /// application has at most one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find_by_application(
        &self,
        uow: &mut dyn UnitOfWork,
        application_id: ApplicationId,
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

    /// Stores a pushed request. The oldest pushed requests of its client
    /// are removed first, so that at most `keep` wait, this one included;
    /// two pushes of one client at the same moment keep the bound too.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_not_found` if the tenant has no such client.
    async fn push(
        &self,
        uow: &mut dyn UnitOfWork,
        pushed: &PushedAuthorization,
        keep: usize,
    ) -> Result<(), DomainError>;

    /// Takes the pushed request of `client` whose reference has this hash:
    /// removes it and answers it, only if this call removed it, so that of
    /// two uses at the same moment exactly one has it. An expired one is
    /// taken too. A request of another client stays where it is.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn take_pushed(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
        hash: &ReferenceHash,
    ) -> Result<Option<PushedAuthorization>, DomainError>;
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

/// Stores the claim mappers of clients.
#[async_trait::async_trait]
pub trait ClaimMapperStore: Send + Sync {
    /// Locks the client's row until the unit of work ends, so that the
    /// mappers of one client are changed one change at a time. Answers
    /// whether the tenant has the client.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn lock_client(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: ClientId,
    ) -> Result<bool, DomainError>;

    /// Stores a new mapper of a client of the tenant.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_not_found` if the tenant has no such client,
    /// and `oauth.claim_mapper_name_taken` if the client has a mapper of
    /// the claim, without regard to case.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        mapper: &ClaimMapper,
    ) -> Result<(), DomainError>;

    /// Stores a replaced mapper, if its stored version is the one it was
    /// read with. The stored version becomes one more.
    ///
    /// # Errors
    ///
    /// Returns `oauth.claim_mapper_modified_concurrently` otherwise, and
    /// `oauth.claim_mapper_name_taken` as for `insert`.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        mapper: &ClaimMapper,
    ) -> Result<(), DomainError>;

    /// Deletes a mapper. Answers whether there was one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn delete(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: ClientId,
        id: ClaimMapperId,
    ) -> Result<bool, DomainError>;

    /// The mapper of the client with this identifier, if there is one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: ClientId,
        id: ClaimMapperId,
    ) -> Result<Option<ClaimMapper>, DomainError>;

    /// Every mapper of the client, by claim name.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list_for_client(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: ClientId,
    ) -> Result<Vec<ClaimMapper>, DomainError>;
}

/// What the claim mappers read of a person and an organization, from the
/// identity context.
#[async_trait::async_trait]
pub trait PersonClaimSources: Send + Sync {
    /// The attributes of `user`; none of them for a user the tenant does
    /// not have.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn attributes(
        &self,
        tenant: &TenantContext,
        user: UserId,
    ) -> Result<PersonAttributes, DomainError>;

    /// The name of `organization`, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn organization_name(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
    ) -> Result<Option<String>, DomainError>;
}

/// Reads the certificates a proxy forwards, and checks one against the
/// authorities of a trust domain's bundle. The cryptography adapter
/// implements it; the OAuth context holds no X.509 library.
pub trait CertificateCheck: Send + Sync {
    /// The URIs and DNS names of `certificate`, in DER, from its subject
    /// alternative names; `None` when it does not read as a certificate.
    fn names(&self, certificate: &[u8]) -> Option<crate::domain::forwarded::CertificateNames>;

    /// Whether `certificate`, in DER, has a path to one of `authorities`
    /// at `now`, through any of `chain`, for a TLS client. `authorities`
    /// are the `x509-svid` elements of a bundle, each a JSON Web Key with
    /// its certificate in `x5c`; an element whose certificate is not an
    /// authority holding the element's key is passed over. No certificate
    /// between `certificate` and the authority may hold a key of
    /// `withdrawn`, each the SHA-256 of a subject public key info in
    /// lowercase hexadecimal: the keys of the intermediates the tenant's
    /// certificate authority signed and an administrator withdrew. Anything
    /// that does not read is `false`.
    fn chains_to(
        &self,
        certificate: &[u8],
        chain: &[Vec<u8>],
        authorities: &[&str],
        withdrawn: &[String],
        now: Timestamp,
    ) -> bool;
}

/// Stores the client registration settings of a tenant: none, or one.
#[async_trait::async_trait]
pub trait ClientRegistrationStore: Send + Sync {
    /// The tenant's settings, if it set them.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<ClientRegistration>, DomainError>;

    /// The tenant's settings, if it set them, with their row locked until
    /// the unit of work ends, so that what is decided from them holds
    /// until it is stored.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<ClientRegistration>, DomainError>;

    /// Stores the tenant's first settings.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_registration_modified_concurrently` if the
    /// tenant has settings already, and `oauth.client_registration_application_invalid`
    /// for an application that is not one of the tenant's.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        registration: &ClientRegistration,
    ) -> Result<(), DomainError>;

    /// Stores replaced settings, if their stored version is the one they
    /// were read with. The stored version becomes one more.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_registration_modified_concurrently` otherwise,
    /// and `oauth.client_registration_application_invalid` for an
    /// application that is not one of the tenant's.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        registration: &ClientRegistration,
    ) -> Result<(), DomainError>;
}

/// Stores the initial access tokens of a tenant.
#[async_trait::async_trait]
pub trait InitialAccessTokenStore: Send + Sync {
    /// Stores a new token.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &InitialAccessToken,
    ) -> Result<(), DomainError>;

    /// A token of the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: InitialAccessTokenId,
    ) -> Result<Option<InitialAccessToken>, DomainError>;

    /// The token of the tenant with this hash, with its row locked until
    /// the unit of work ends, so that it is spent one registration at a
    /// time.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn lock_by_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &InitialAccessTokenHash,
    ) -> Result<Option<InitialAccessToken>, DomainError>;

    /// Every token of the tenant, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<InitialAccessToken>, DomainError>;

    /// How many tokens of the tenant are active at `now`: neither revoked,
    /// expired nor used up.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn count_active(
        &self,
        uow: &mut dyn UnitOfWork,
        now: Timestamp,
    ) -> Result<usize, DomainError>;

    /// Stores how many registrations a token has allowed and when it last
    /// allowed one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn record_use(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &InitialAccessToken,
    ) -> Result<(), DomainError>;

    /// Stores that a token was revoked, unless it already was. Answers
    /// whether it was revoked now.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn revoke(
        &self,
        uow: &mut dyn UnitOfWork,
        id: InitialAccessTokenId,
        at: Timestamp,
    ) -> Result<bool, DomainError>;
}
