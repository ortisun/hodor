//! In-memory stores and the contract every store of the OAuth context
//! passes.

use crate::api::{
    Application, ApplicationId, ApplicationSettings, ApplicationSnapshot, ApplicationStore,
    Audience, Client, ClientId, ClientKey, ClientSecret, ClientSettings, ClientSnapshot,
    ClientStore, ClientType, GrantType, ResourceServer, ResourceServerId, ResourceServerSettings,
    ResourceServerSnapshot, ResourceServerStore, ScopeDefinition, Status, WorkloadIdentity,
};
use hodor_kernel::{
    DomainError, RandomSource, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use time::Duration;

mod authorization;
mod backchannel;
mod claim_mapper;
mod consent;
mod pairwise;
mod refresh;
mod register;
mod registration;
mod request_uri;
mod token;
pub use authorization::{
    AuthorizationStorePorts, InMemoryAuthorizationCodes, InMemoryAuthorizationRequests,
    InMemoryGrants, run_authorization_contract,
};
pub use backchannel::{
    ClientAnswer, FakeDestinations, FixedIssuer, InMemoryLogoutDeliveries, InMemorySessionClients,
    LogoutDeliveryStorePorts, RecordingClients, run_logout_delivery_contract,
};
pub use claim_mapper::{
    ClaimMapperStorePorts, ClaimSourcesOf, InMemoryClaimMappers, run_claim_mapper_contract,
};
pub use consent::{ConsentStorePorts, InMemoryConsents, consent_service, run_consent_contract};
pub use pairwise::{
    FakeHmac, InMemoryPairwiseSecrets, PairwiseSecretStorePorts, SectorDocuments,
    pairwise_subjects, run_pairwise_secret_contract,
};
pub use refresh::{
    InMemoryRefreshTokens, MembershipsOf, RefreshStorePorts, StandingOf, run_refresh_token_contract,
};
pub use register::{
    AccessTokenRecordStorePorts, InMemoryAccessTokenRecords, run_access_token_record_contract,
};
pub use registration::{
    ClientRegistrationStorePorts, InMemoryClientRegistrations, InMemoryInitialAccessTokens,
    client_registration_service, run_client_registration_contract,
};
pub use request_uri::{AddressAnswer, RequestObjectAddresses};
pub use token::{
    AssertionStorePorts, FakeVerifier, InMemoryClientAssertions, fake_signature,
    run_assertion_contract,
};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn modified(code: &'static str) -> DomainError {
    DomainError::conflict(code, "it was changed by someone else; read it again")
}

/// Applications kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryApplications {
    rows: Arc<Mutex<BTreeMap<(TenantId, ApplicationId), Application>>>,
}

impl InMemoryApplications {
    fn exists(&self, tenant: TenantId, id: ApplicationId) -> bool {
        lock(&self.rows).contains_key(&(tenant, id))
    }
}

#[async_trait::async_trait]
impl ApplicationStore for InMemoryApplications {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        application: &Application,
    ) -> Result<(), DomainError> {
        lock(&self.rows).insert(
            (uow.tenant().tenant_id(), application.id()),
            application.clone(),
        );
        Ok(())
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        application: &Application,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), application.id());
        let mut rows = lock(&self.rows);
        let version = application.snapshot().version;
        match rows.get(&key) {
            Some(stored) if stored.snapshot().version == version => {
                rows.insert(
                    key,
                    Application::from_snapshot(ApplicationSnapshot {
                        version: version + 1,
                        ..application.snapshot().clone()
                    }),
                );
                Ok(())
            }
            _ => Err(modified("oauth.application_modified_concurrently")),
        }
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ApplicationId,
    ) -> Result<Option<Application>, DomainError> {
        Ok(lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), id))
            .cloned())
    }

    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<Application>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut found: Vec<Application> = lock(&self.rows)
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, application)| application.clone())
            .collect();
        found.sort_by_key(|a| (a.snapshot().created_at, a.id()));
        Ok(found)
    }
}

/// Clients kept in memory. They know the applications they are stored
/// against, as the database knows its references.
#[derive(Debug, Clone)]
pub struct InMemoryClients {
    applications: InMemoryApplications,
    rows: Arc<Mutex<BTreeMap<(TenantId, ClientId), Client>>>,
}

impl InMemoryClients {
    /// Clients of the applications in `applications`.
    #[must_use]
    pub fn new(applications: &InMemoryApplications) -> Self {
        Self {
            applications: applications.clone(),
            rows: Arc::default(),
        }
    }

    fn exists(&self, tenant: TenantId, id: ClientId) -> bool {
        lock(&self.rows).contains_key(&(tenant, id))
    }
}

/// Whether a client of `tenant` acting as another principal than `client`
/// is bound to its SPIFFE identifier, as the store's check under its lock
/// finds it: an identity binds the clients of one service account.
fn spiffe_id_taken(
    rows: &BTreeMap<(TenantId, ClientId), Client>,
    tenant: TenantId,
    client: &Client,
) -> bool {
    let Some(bound) = &client.snapshot().settings.spiffe_id else {
        return false;
    };
    rows.iter().any(|((owner, id), other)| {
        *owner == tenant
            && *id != client.id()
            && other.snapshot().settings.spiffe_id.as_ref() == Some(bound)
            && other.principal() != client.principal()
    })
}

/// Whether a client of `tenant` acting as another principal than `client`
/// is bound to its Linkerd identity.
fn linkerd_identity_taken(
    rows: &BTreeMap<(TenantId, ClientId), Client>,
    tenant: TenantId,
    client: &Client,
) -> bool {
    let Some(bound) = &client.snapshot().settings.linkerd_identity else {
        return false;
    };
    rows.iter().any(|((owner, id), other)| {
        *owner == tenant
            && *id != client.id()
            && other.snapshot().settings.linkerd_identity.as_ref() == Some(bound)
            && other.principal() != client.principal()
    })
}

fn linkerd_identity_conflict() -> DomainError {
    DomainError::conflict(
        "oauth.client_linkerd_identity_taken",
        "a client of the tenant acting as another principal is bound to this Linkerd identity",
    )
}

fn spiffe_id_conflict() -> DomainError {
    DomainError::conflict(
        "oauth.client_spiffe_id_taken",
        "a client of the tenant acting as another principal is bound to this SPIFFE identifier",
    )
}

#[async_trait::async_trait]
impl ClientStore for InMemoryClients {
    async fn insert(&self, uow: &mut dyn UnitOfWork, client: &Client) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self.applications.exists(tenant, client.application_id()) {
            return Err(DomainError::not_found(
                "oauth.application_not_found",
                "there is no such application",
            ));
        }
        let mut rows = lock(&self.rows);
        if spiffe_id_taken(&rows, tenant, client) {
            return Err(spiffe_id_conflict());
        }
        if linkerd_identity_taken(&rows, tenant, client) {
            return Err(linkerd_identity_conflict());
        }
        rows.insert((tenant, client.id()), client.clone());
        Ok(())
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, client: &Client) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), client.id());
        let mut rows = lock(&self.rows);
        let version = client.snapshot().version;
        match rows.get(&key) {
            Some(stored) if stored.snapshot().version == version => {
                if spiffe_id_taken(&rows, key.0, client) {
                    return Err(spiffe_id_conflict());
                }
                if linkerd_identity_taken(&rows, key.0, client) {
                    return Err(linkerd_identity_conflict());
                }
                rows.insert(
                    key,
                    Client::from_snapshot(ClientSnapshot {
                        version: version + 1,
                        ..client.snapshot().clone()
                    }),
                );
                Ok(())
            }
            _ => Err(modified("oauth.client_modified_concurrently")),
        }
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ClientId,
    ) -> Result<Option<Client>, DomainError> {
        Ok(lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), id))
            .cloned())
    }

    async fn bound_to(
        &self,
        uow: &mut dyn UnitOfWork,
        identity: &WorkloadIdentity,
    ) -> Result<Vec<Client>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut found: Vec<Client> = lock(&self.rows)
            .iter()
            .filter(|((owner, _), client)| {
                *owner == tenant
                    && client.snapshot().settings.workload_identity().as_ref() == Some(identity)
            })
            .map(|(_, client)| client.clone())
            .collect();
        found.sort_by_key(|client| (client.snapshot().created_at, client.id()));
        Ok(found)
    }

    async fn list_for_application(
        &self,
        uow: &mut dyn UnitOfWork,
        application_id: ApplicationId,
    ) -> Result<Vec<Client>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut found: Vec<Client> = lock(&self.rows)
            .iter()
            .filter(|((owner, _), client)| {
                *owner == tenant && client.application_id() == application_id
            })
            .map(|(_, client)| client.clone())
            .collect();
        found.sort_by_key(|c| (c.snapshot().created_at, c.id()));
        Ok(found)
    }

    async fn count_for_application(
        &self,
        uow: &mut dyn UnitOfWork,
        application_id: ApplicationId,
    ) -> Result<usize, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows)
            .iter()
            .filter(|((owner, _), client)| {
                *owner == tenant && client.application_id() == application_id
            })
            .count())
    }

    async fn count_registered_since(
        &self,
        uow: &mut dyn UnitOfWork,
        address_hash: Option<&[u8; 32]>,
        since: hodor_kernel::Timestamp,
    ) -> Result<usize, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows)
            .iter()
            .filter(|((owner, _), client)| {
                let state = client.snapshot();
                *owner == tenant
                    && state.created_at >= since
                    && state
                        .self_registration
                        .is_some_and(|registered| registered.address_hash.as_ref() == address_hash)
            })
            .count())
    }

    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ClientId,
    ) -> Result<Option<Client>, DomainError> {
        // Every change here is made at once, under the mutex.
        self.get(uow, id).await
    }

    async fn delete(&self, uow: &mut dyn UnitOfWork, id: ClientId) -> Result<bool, DomainError> {
        Ok(lock(&self.rows)
            .remove(&(uow.tenant().tenant_id(), id))
            .is_some())
    }
}

/// Resource servers kept in memory.
#[derive(Debug, Clone)]
pub struct InMemoryResourceServers {
    applications: InMemoryApplications,
    rows: Arc<Mutex<BTreeMap<(TenantId, ResourceServerId), ResourceServer>>>,
}

impl InMemoryResourceServers {
    /// Resource servers of the applications in `applications`.
    #[must_use]
    pub fn new(applications: &InMemoryApplications) -> Self {
        Self {
            applications: applications.clone(),
            rows: Arc::default(),
        }
    }
}

#[async_trait::async_trait]
impl ResourceServerStore for InMemoryResourceServers {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        server: &ResourceServer,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = server.snapshot();
        if !self.applications.exists(tenant, state.application_id) {
            return Err(DomainError::not_found(
                "oauth.application_not_found",
                "there is no such application",
            ));
        }
        let mut rows = lock(&self.rows);
        let mine = rows.iter().filter(|((owner, _), _)| *owner == tenant);
        for (_, other) in mine {
            if other.audience() == server.audience() {
                return Err(DomainError::conflict(
                    "oauth.audience_taken",
                    "this tenant already has a resource server with this audience",
                ));
            }
            if other.snapshot().application_id == state.application_id {
                return Err(DomainError::conflict(
                    "oauth.application_has_resource_server",
                    "this application already has a resource server",
                ));
            }
        }
        rows.insert((tenant, server.id()), server.clone());
        Ok(())
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        server: &ResourceServer,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), server.id());
        let mut rows = lock(&self.rows);
        let version = server.snapshot().version;
        match rows.get(&key) {
            Some(stored) if stored.snapshot().version == version => {
                rows.insert(
                    key,
                    ResourceServer::from_snapshot(ResourceServerSnapshot {
                        version: version + 1,
                        ..server.snapshot().clone()
                    }),
                );
                Ok(())
            }
            _ => Err(modified("oauth.resource_server_modified_concurrently")),
        }
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ResourceServerId,
    ) -> Result<Option<ResourceServer>, DomainError> {
        Ok(lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), id))
            .cloned())
    }

    async fn find_by_audience(
        &self,
        uow: &mut dyn UnitOfWork,
        audience: &Audience,
    ) -> Result<Option<ResourceServer>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows)
            .iter()
            .find(|((owner, _), server)| *owner == tenant && server.audience() == audience)
            .map(|(_, server)| server.clone()))
    }

    async fn find_by_application(
        &self,
        uow: &mut dyn UnitOfWork,
        application_id: ApplicationId,
    ) -> Result<Option<ResourceServer>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows)
            .iter()
            .find(|((owner, _), server)| {
                *owner == tenant && server.snapshot().application_id == application_id
            })
            .map(|(_, server)| server.clone()))
    }

    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<ResourceServer>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut found: Vec<ResourceServer> = lock(&self.rows)
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, server)| server.clone())
            .collect();
        found.sort_by_key(|s| (s.snapshot().created_at, s.id()));
        Ok(found)
    }
}

/// The three in-memory stores, wired to each other.
#[derive(Debug, Clone)]
pub struct InMemoryStores {
    /// The applications.
    pub applications: InMemoryApplications,
    /// The clients.
    pub clients: InMemoryClients,
    /// The resource servers.
    pub resource_servers: InMemoryResourceServers,
}

impl Default for InMemoryStores {
    fn default() -> Self {
        let applications = InMemoryApplications::default();
        Self {
            clients: InMemoryClients::new(&applications),
            resource_servers: InMemoryResourceServers::new(&applications),
            applications,
        }
    }
}

/// The ports under test.
#[derive(Clone, Copy)]
pub struct Ports<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The application store under test.
    pub applications: &'a dyn ApplicationStore,
    /// The client store under test.
    pub clients: &'a dyn ClientStore,
    /// The resource server store under test.
    pub resource_servers: &'a dyn ResourceServerStore,
}

impl std::fmt::Debug for Ports<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

/// A random source whose every call gives different bytes, so that every
/// secret made with it is different, across runs that share a database.
#[derive(Debug, Clone, Copy, Default)]
pub struct DistinctRandom;

impl RandomSource for DistinctRandom {
    fn fill(&self, buffer: &mut [u8]) {
        let unique = ClientId::generate().as_uuid();
        for (byte, source) in buffer
            .iter_mut()
            .zip(unique.as_bytes().iter().rev().cycle())
        {
            *byte = *source;
        }
    }
}

const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

fn application(name: &str, at: Timestamp) -> Application {
    Application::create(
        ApplicationSettings {
            name: name.to_owned(),
            first_party: false,
        },
        at,
    )
    .expect("valid application")
}

/// A confidential client with a secret, of `application_id`.
fn client(application_id: ApplicationId, at: Timestamp) -> Client {
    use hodor_kernel::random::testing::FakeDigest;
    let mut settings = ClientSettings::new(
        "Payroll web",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        vec![
            "https://payroll.example.com/callback".to_owned(),
            "http://127.0.0.1:8080/callback".to_owned(),
        ],
    );
    settings.post_logout_redirect_uris = vec!["https://payroll.example.com/signed-out".to_owned()];
    settings.backchannel_logout_uri = Some("https://payroll.example.com/backchannel".to_owned());
    settings.backchannel_logout_session_required = true;
    settings.allowed_scopes = vec!["openid".to_owned(), "payroll:read".to_owned()];
    // Stored and read back as every other setting.
    settings.certificate_bound_access_tokens = true;
    Client::create(
        application_id,
        ClientType::Confidential,
        settings,
        ClientSecret::DEFAULT_LIFETIME,
        at,
        &DistinctRandom,
        &FakeDigest,
    )
    .expect("valid client")
    .0
}

fn server(application_id: ApplicationId, audience: &str) -> ResourceServer {
    ResourceServer::create(
        application_id,
        Audience::parse(audience).expect("valid audience"),
        ResourceServerSettings {
            name: "Payroll interface".to_owned(),
            scopes: ["write", "read", "approve"]
                .into_iter()
                .map(|name| ScopeDefinition {
                    name: name.to_owned(),
                    description: format!("lets a client {name}"),
                })
                .collect(),
        },
        MOMENT,
    )
    .expect("valid resource server")
}

async fn store_application(ports: Ports<'_>, tenant: &TenantContext, application: &Application) {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .applications
        .insert(uow.as_mut(), application)
        .await
        .expect("insert application");
    uow.commit().await.expect("commit");
}

async fn store_client(ports: Ports<'_>, tenant: &TenantContext, client: &Client) {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .clients
        .insert(uow.as_mut(), client)
        .await
        .expect("insert client");
    uow.commit().await.expect("commit");
}

async fn load_client(ports: Ports<'_>, tenant: &TenantContext, id: ClientId) -> Option<Client> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.clients.get(uow.as_mut(), id).await.expect("get")
}

/// Runs every rule a store of the OAuth context must obey. Each case uses
/// tenants of its own, so runs can share one database.
///
/// # Panics
///
/// Panics when an implementation breaks a rule.
pub async fn run_contract(ports: Ports<'_>) {
    applications_are_stored_and_listed_in_their_tenant(ports).await;
    a_stale_application_is_not_stored(ports).await;
    a_client_is_stored_with_its_secrets_and_keys(ports).await;
    a_client_change_replaces_its_secrets_and_keys(ports).await;
    a_client_belongs_to_an_application_of_its_tenant(ports).await;
    a_stale_client_is_not_stored(ports).await;
    a_client_is_locked_and_deleted_in_its_tenant_only(ports).await;
    a_spiffe_identifier_is_bound_to_one_service_account_of_its_tenant(ports).await;
    a_linkerd_identity_is_bound_to_one_service_account_of_its_tenant(ports).await;
    an_identity_binds_the_clients_of_one_service_account(ports).await;
    resource_servers_are_found_by_exact_audience(ports).await;
    an_audience_and_an_application_have_one_resource_server(ports).await;
}

async fn applications_are_stored_and_listed_in_their_tenant(ports: Ports<'_>) {
    let tenant = tenant();
    let first = application("Payroll", MOMENT);
    let second = application("Expenses", MOMENT + Duration::minutes(1));
    store_application(ports, &tenant, &second).await;
    store_application(ports, &tenant, &first).await;

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .applications
            .get(uow.as_mut(), first.id())
            .await
            .expect("get"),
        Some(first.clone())
    );
    assert_eq!(
        ports.applications.list(uow.as_mut()).await.expect("list"),
        vec![first.clone(), second.clone()],
        "oldest first"
    );
    drop(uow);

    let elsewhere = self::tenant();
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .applications
            .get(uow.as_mut(), first.id())
            .await
            .expect("get"),
        None
    );
    assert!(
        ports
            .applications
            .list(uow.as_mut())
            .await
            .expect("list")
            .is_empty()
    );
    let mut changed = first.clone();
    changed.set_status(Status::Disabled, MOMENT);
    assert_eq!(
        ports
            .applications
            .update(uow.as_mut(), &changed)
            .await
            .expect_err("another tenant's application")
            .code(),
        "oauth.application_modified_concurrently"
    );
}

async fn a_stale_application_is_not_stored(ports: Ports<'_>) {
    let tenant = tenant();
    let original = application("Payroll", MOMENT);
    store_application(ports, &tenant, &original).await;

    let mut changed = original.clone();
    changed.set_status(Status::Disabled, MOMENT + Duration::minutes(1));
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .applications
        .update(uow.as_mut(), &changed)
        .await
        .expect("update");
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let stored = ports
        .applications
        .get(uow.as_mut(), original.id())
        .await
        .expect("get")
        .expect("stored");
    assert_eq!(stored.snapshot().version, 1);
    assert!(!stored.is_enabled());
    let error = ports
        .applications
        .update(uow.as_mut(), &changed)
        .await
        .expect_err("stale");
    assert_eq!(error.code(), "oauth.application_modified_concurrently");
}

async fn a_client_is_stored_with_its_secrets_and_keys(ports: Ports<'_>) {
    let tenant = tenant();
    let owner = application("Payroll", MOMENT);
    let other = application("Expenses", MOMENT);
    store_application(ports, &tenant, &owner).await;
    store_application(ports, &tenant, &other).await;
    let first = client(owner.id(), MOMENT);
    let second = client(owner.id(), MOMENT + Duration::minutes(1));
    let elsewhere_in_tenant = client(other.id(), MOMENT);
    store_client(ports, &tenant, &second).await;
    store_client(ports, &tenant, &first).await;
    store_client(ports, &tenant, &elsewhere_in_tenant).await;

    assert_eq!(
        load_client(ports, &tenant, first.id()).await,
        Some(first.clone())
    );
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .clients
            .list_for_application(uow.as_mut(), owner.id())
            .await
            .expect("list"),
        vec![first.clone(), second],
        "an application's clients, oldest first"
    );
    drop(uow);

    let elsewhere = self::tenant();
    assert_eq!(load_client(ports, &elsewhere, first.id()).await, None);
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert!(
        ports
            .clients
            .list_for_application(uow.as_mut(), owner.id())
            .await
            .expect("list")
            .is_empty()
    );
    let mut changed = first.clone();
    changed.set_status(Status::Disabled, MOMENT);
    assert_eq!(
        ports
            .clients
            .update(uow.as_mut(), &changed)
            .await
            .expect_err("another tenant's client")
            .code(),
        "oauth.client_modified_concurrently"
    );
}

async fn a_client_change_replaces_its_secrets_and_keys(ports: Ports<'_>) {
    use crate::api::AuthenticationMethod;
    use hodor_kernel::random::testing::FakeDigest;
    let tenant = tenant();
    let owner = application("Payroll", MOMENT);
    store_application(ports, &tenant, &owner).await;
    let original = client(owner.id(), MOMENT);
    store_client(ports, &tenant, &original).await;

    // A rotation adds a secret and keeps the previous one for a while.
    let mut rotated = original.clone();
    let later = MOMENT + Duration::days(1);
    rotated
        .rotate_secret(
            ClientSecret::DEFAULT_LIFETIME,
            Duration::days(7),
            later,
            &DistinctRandom,
            &FakeDigest,
        )
        .expect("rotated");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .clients
        .update(uow.as_mut(), &rotated)
        .await
        .expect("update");
    uow.commit().await.expect("commit");
    let stored = load_client(ports, &tenant, original.id())
        .await
        .expect("stored");
    assert_eq!(stored.snapshot().secrets, rotated.snapshot().secrets);
    assert_eq!(stored.snapshot().secrets.len(), 2);
    assert_eq!(stored.snapshot().version, 1);

    // A switch to keys drops the secrets; the keys are kept in order.
    let mut keyed = stored.clone();
    let mut settings = keyed.snapshot().settings.clone();
    settings.authentication_method = AuthenticationMethod::PrivateKeyJwt;
    // And its ID tokens are now signed with RS256, and its UserInfo answers
    // with EdDSA, both kept too.
    settings.id_token_algorithm = crate::api::IdTokenAlgorithm::Rs256;
    settings.userinfo_algorithm = Some(crate::api::IdTokenAlgorithm::EdDsa);
    // And it signs its request objects with PS256 only, which is kept.
    settings.request_object_algorithm = Some(crate::api::RequestObjectAlgorithm::Ps256);
    // And it must push its requests, which is kept.
    settings.require_pushed_requests = true;
    // And it keeps request objects at two addresses, kept in their order.
    settings.request_uris = vec![
        "https://requests.example.org/web/".to_owned(),
        "https://requests.example.org/".to_owned(),
    ];
    // And it becomes pairwise, its redirect addresses of two hosts put in
    // one sector by its sector identifier address, both kept.
    settings.subject_type = crate::api::SubjectType::Pairwise;
    settings.sector_identifier_uri = Some("https://sector.example.org/uris.json".to_owned());
    // And it has defaults for a sign-in, kept in order.
    settings.default_max_age = Some(600);
    settings.default_acr_values = vec![
        "urn:hodor:acr:mfa".to_owned(),
        "urn:hodor:acr:single-factor".to_owned(),
    ];
    settings.require_auth_time = true;
    keyed.change(settings, later).expect("changed");
    for kid in ["second", "first"] {
        let key = ClientKey::parse(
            &format!(
                r#"{{"kty":"OKP","crv":"Ed25519","kid":"{kid}","x":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}}"#
            ),
            later,
        )
        .expect("key");
        keyed.add_key(key, later).expect("added");
    }
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .clients
        .update(uow.as_mut(), &keyed)
        .await
        .expect("update");
    uow.commit().await.expect("commit");
    let stored = load_client(ports, &tenant, original.id())
        .await
        .expect("stored");
    assert!(stored.snapshot().secrets.is_empty());
    assert_eq!(stored.snapshot().keys, keyed.snapshot().keys);
    assert_eq!(stored.snapshot().settings, keyed.snapshot().settings);
    assert_eq!(
        stored.snapshot().settings.id_token_algorithm,
        crate::api::IdTokenAlgorithm::Rs256
    );
    assert_eq!(
        stored.snapshot().settings.request_object_algorithm,
        Some(crate::api::RequestObjectAlgorithm::Ps256)
    );
    assert_eq!(
        stored.snapshot().settings.userinfo_algorithm,
        Some(crate::api::IdTokenAlgorithm::EdDsa)
    );
    assert!(stored.snapshot().settings.require_pushed_requests);
    assert_eq!(
        stored.snapshot().settings.request_uris,
        [
            "https://requests.example.org/web/",
            "https://requests.example.org/"
        ]
    );
    assert_eq!(stored.subject_type(), crate::api::SubjectType::Pairwise);
    assert_eq!(stored.sector().as_deref(), Some("sector.example.org"));
    assert_eq!(stored.default_max_age(), Some(600));
    assert_eq!(
        stored.default_acr_values().as_deref(),
        Some("urn:hodor:acr:mfa urn:hodor:acr:single-factor")
    );
    assert!(stored.snapshot().settings.require_auth_time);
    assert_eq!(stored.snapshot().version, 2);

    // None chosen again is kept as none.
    let mut cleared = stored.clone();
    let mut settings = cleared.snapshot().settings.clone();
    settings.request_object_algorithm = None;
    settings.userinfo_algorithm = None;
    settings.id_token_algorithm = crate::api::IdTokenAlgorithm::Ps256;
    cleared.change(settings, later).expect("changed");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .clients
        .update(uow.as_mut(), &cleared)
        .await
        .expect("update");
    uow.commit().await.expect("commit");
    let stored = load_client(ports, &tenant, original.id())
        .await
        .expect("stored");
    assert_eq!(stored.snapshot().settings.request_object_algorithm, None);
    assert_eq!(stored.snapshot().settings.userinfo_algorithm, None);
    assert_eq!(
        stored.snapshot().settings.id_token_algorithm,
        crate::api::IdTokenAlgorithm::Ps256
    );
}

async fn a_client_belongs_to_an_application_of_its_tenant(ports: Ports<'_>) {
    let tenant = tenant();
    let elsewhere = self::tenant();
    let owner = application("Payroll", MOMENT);
    store_application(ports, &elsewhere, &owner).await;
    let orphan = client(owner.id(), MOMENT);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let error = ports
        .clients
        .insert(uow.as_mut(), &orphan)
        .await
        .expect_err("an application of another tenant");
    assert_eq!(error.code(), "oauth.application_not_found");
}

async fn a_stale_client_is_not_stored(ports: Ports<'_>) {
    let tenant = tenant();
    let owner = application("Payroll", MOMENT);
    store_application(ports, &tenant, &owner).await;
    let original = client(owner.id(), MOMENT);
    store_client(ports, &tenant, &original).await;
    let mut first = original.clone();
    first.set_status(Status::Disabled, MOMENT);
    let mut second = original.clone();
    let mut settings = second.snapshot().settings.clone();
    settings.name = "Renamed".to_owned();
    second.change(settings, MOMENT).expect("changed");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .clients
        .update(uow.as_mut(), &first)
        .await
        .expect("first");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let error = ports
        .clients
        .update(uow.as_mut(), &second)
        .await
        .expect_err("stale");
    assert_eq!(error.code(), "oauth.client_modified_concurrently");
    drop(uow);
    let stored = load_client(ports, &tenant, original.id())
        .await
        .expect("stored");
    assert_eq!(stored.snapshot().settings.name, "Payroll web");
    assert!(!stored.is_enabled());
}

async fn a_client_is_locked_and_deleted_in_its_tenant_only(ports: Ports<'_>) {
    let tenant = tenant();
    let owner = application("Payroll", MOMENT);
    store_application(ports, &tenant, &owner).await;
    let kept = client(owner.id(), MOMENT);
    let gone = client(owner.id(), MOMENT);
    store_client(ports, &tenant, &kept).await;
    store_client(ports, &tenant, &gone).await;

    let elsewhere = self::tenant();
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .clients
            .lock(uow.as_mut(), gone.id())
            .await
            .expect("lock"),
        None
    );
    assert!(
        !ports
            .clients
            .delete(uow.as_mut(), gone.id())
            .await
            .expect("delete"),
        "another tenant's client"
    );
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .clients
            .lock(uow.as_mut(), gone.id())
            .await
            .expect("lock"),
        Some(gone.clone())
    );
    assert!(
        ports
            .clients
            .delete(uow.as_mut(), gone.id())
            .await
            .expect("delete")
    );
    uow.commit().await.expect("commit");
    assert_eq!(load_client(ports, &tenant, gone.id()).await, None);
    assert_eq!(
        load_client(ports, &tenant, kept.id()).await,
        Some(kept.clone())
    );
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        !ports
            .clients
            .delete(uow.as_mut(), gone.id())
            .await
            .expect("delete"),
        "gone already"
    );
}

/// A client of a service account bound to `spiffe_id`, of `application_id`.
fn workload_client(application_id: ApplicationId, spiffe_id: &str) -> Client {
    use crate::api::{AuthenticationMethod, SpiffeId};
    use hodor_kernel::UserId;
    use hodor_kernel::random::testing::FakeDigest;
    let mut settings = ClientSettings::new(
        "Nightly export",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    settings.authentication_method = AuthenticationMethod::SpiffeJwt;
    settings.principal = Some(UserId::generate());
    settings.spiffe_id = Some(SpiffeId::parse(spiffe_id).expect("identifier"));
    Client::create(
        application_id,
        ClientType::Confidential,
        settings,
        ClientSecret::DEFAULT_LIFETIME,
        MOMENT,
        &DistinctRandom,
        &FakeDigest,
    )
    .expect("valid client")
    .0
}

async fn a_spiffe_identifier_is_bound_to_one_service_account_of_its_tenant(ports: Ports<'_>) {
    use crate::api::{AuthenticationMethod, SpiffeId};
    const EXPORT: &str = "spiffe://cluster.local/ns/payroll/sa/export";
    let tenant = tenant();
    let owner = application("Payroll", MOMENT);
    store_application(ports, &tenant, &owner).await;
    let export = workload_client(owner.id(), EXPORT);
    store_client(ports, &tenant, &export).await;
    let stored = load_client(ports, &tenant, export.id())
        .await
        .expect("stored");
    assert_eq!(stored, export, "kept with its SPIFFE identifier");

    // A client of another service account may not take the identifier.
    let twin = workload_client(owner.id(), EXPORT);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .clients
            .insert(uow.as_mut(), &twin)
            .await
            .expect_err("taken")
            .code(),
        "oauth.client_spiffe_id_taken"
    );
    drop(uow);

    // Nor by a change.
    let mut other = workload_client(owner.id(), "spiffe://cluster.local/ns/payroll/sa/import");
    store_client(ports, &tenant, &other).await;
    let mut settings = other.snapshot().settings.clone();
    settings.spiffe_id = Some(SpiffeId::parse(EXPORT).expect("identifier"));
    other.change(settings, MOMENT).expect("changed");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .clients
            .update(uow.as_mut(), &other)
            .await
            .expect_err("taken")
            .code(),
        "oauth.client_spiffe_id_taken"
    );
    drop(uow);

    // Once the first client lets it go, the identifier is free.
    let mut released = stored.clone();
    let mut settings = released.snapshot().settings.clone();
    settings.authentication_method = AuthenticationMethod::PrivateKeyJwt;
    settings.spiffe_id = None;
    released.change(settings, MOMENT).expect("changed");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .clients
        .update(uow.as_mut(), &released)
        .await
        .expect("released");
    uow.commit().await.expect("commit");
    let stale = load_client(ports, &tenant, other.id())
        .await
        .expect("other");
    let mut settings = stale.snapshot().settings.clone();
    settings.spiffe_id = Some(SpiffeId::parse(EXPORT).expect("identifier"));
    let mut taking = stale.clone();
    taking.change(settings, MOMENT).expect("changed");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .clients
        .update(uow.as_mut(), &taking)
        .await
        .expect("free now");
    uow.commit().await.expect("commit");

    // Another tenant binds the same identifier to a client of its own.
    let elsewhere = self::tenant();
    let theirs = application("Payroll", MOMENT);
    store_application(ports, &elsewhere, &theirs).await;
    let same = workload_client(theirs.id(), EXPORT);
    store_client(ports, &elsewhere, &same).await;
    assert_eq!(
        load_client(ports, &elsewhere, same.id())
            .await
            .expect("stored")
            .snapshot()
            .settings
            .spiffe_id,
        same.snapshot().settings.spiffe_id
    );
}

/// A client of a service account using `method`, bound to `spiffe_id` or
/// `linkerd_identity`, of `application_id`.
fn forwarded_client(
    application_id: ApplicationId,
    method: crate::api::AuthenticationMethod,
    spiffe_id: Option<&str>,
    linkerd_identity: Option<&str>,
) -> Client {
    use crate::api::{LinkerdIdentity, SpiffeId};
    use hodor_kernel::UserId;
    use hodor_kernel::random::testing::FakeDigest;
    let mut settings = ClientSettings::new(
        "Shop web",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    settings.authentication_method = method;
    settings.principal = Some(UserId::generate());
    settings.spiffe_id = spiffe_id.map(|id| SpiffeId::parse(id).expect("identifier"));
    settings.linkerd_identity =
        linkerd_identity.map(|id| LinkerdIdentity::parse(id).expect("identity"));
    Client::create(
        application_id,
        ClientType::Confidential,
        settings,
        ClientSecret::DEFAULT_LIFETIME,
        MOMENT,
        &DistinctRandom,
        &FakeDigest,
    )
    .expect("valid client")
    .0
}

async fn a_linkerd_identity_is_bound_to_one_service_account_of_its_tenant(ports: Ports<'_>) {
    use crate::api::AuthenticationMethod;
    const WEB: &str = "web.shop.serviceaccount.identity.linkerd.cluster.local";
    let tenant = tenant();
    let owner = application("Shop", MOMENT);
    store_application(ports, &tenant, &owner).await;
    // Each method of a forwarded identity is kept with its identity.
    for client in [
        forwarded_client(
            owner.id(),
            AuthenticationMethod::LinkerdIdentity,
            None,
            Some(WEB),
        ),
        forwarded_client(
            owner.id(),
            AuthenticationMethod::SpiffeX509,
            Some("spiffe://cluster.local/ns/shop/sa/web"),
            None,
        ),
        forwarded_client(
            owner.id(),
            AuthenticationMethod::TlsClientAuth,
            Some("spiffe://cluster.local/ns/shop/sa/api"),
            None,
        ),
    ] {
        store_client(ports, &tenant, &client).await;
        assert_eq!(
            load_client(ports, &tenant, client.id())
                .await
                .expect("stored"),
            client,
            "kept with its identity"
        );
    }
    // A client of another service account may not take the Linkerd
    // identity.
    let twin = forwarded_client(
        owner.id(),
        AuthenticationMethod::TlsClientAuth,
        None,
        Some(WEB),
    );
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .clients
            .insert(uow.as_mut(), &twin)
            .await
            .expect_err("taken")
            .code(),
        "oauth.client_linkerd_identity_taken"
    );
    drop(uow);
    // Another tenant binds the same identity to a client of its own.
    let elsewhere = self::tenant();
    let theirs = application("Shop", MOMENT);
    store_application(ports, &elsewhere, &theirs).await;
    let same = forwarded_client(
        theirs.id(),
        AuthenticationMethod::LinkerdIdentity,
        None,
        Some(WEB),
    );
    store_client(ports, &elsewhere, &same).await;
}

/// The clients of the tenant bound to `identity`, as the store finds them.
async fn bound(
    ports: Ports<'_>,
    tenant: &TenantContext,
    identity: &WorkloadIdentity,
) -> Vec<ClientId> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .clients
        .bound_to(uow.as_mut(), identity)
        .await
        .expect("bound")
        .iter()
        .map(Client::id)
        .collect()
}

async fn an_identity_binds_the_clients_of_one_service_account(ports: Ports<'_>) {
    use crate::api::{AuthenticationMethod, LinkerdIdentity, SpiffeId};
    const ADAPTER: &str = "spiffe://cluster.local/ns/hodor/sa/hodor-ext-authz";
    const LINKERD_ADAPTER: &str =
        "hodor-ext-authz.hodor.serviceaccount.identity.linkerd.cluster.local";
    let tenant = tenant();
    let orders = application("Orders", MOMENT);
    let invoices = application("Invoices", MOMENT);
    store_application(ports, &tenant, &orders).await;
    store_application(ports, &tenant, &invoices).await;
    let identity = WorkloadIdentity::Spiffe(SpiffeId::parse(ADAPTER).expect("identifier"));
    let linkerd =
        WorkloadIdentity::Linkerd(LinkerdIdentity::parse(LINKERD_ADAPTER).expect("identity"));
    assert!(bound(ports, &tenant, &identity).await.is_empty());

    // One service account holds a client in each application, all bound
    // to its one identity, whichever method each uses.
    let first = forwarded_client(
        orders.id(),
        AuthenticationMethod::SpiffeX509,
        Some(ADAPTER),
        None,
    );
    let mut settings = first.snapshot().settings.clone();
    settings.authentication_method = AuthenticationMethod::TlsClientAuth;
    let second = Client::create(
        invoices.id(),
        ClientType::Confidential,
        settings,
        ClientSecret::DEFAULT_LIFETIME,
        MOMENT,
        &DistinctRandom,
        &hodor_kernel::random::testing::FakeDigest,
    )
    .expect("valid client")
    .0;
    store_client(ports, &tenant, &first).await;
    store_client(ports, &tenant, &second).await;
    let found = bound(ports, &tenant, &identity).await;
    assert_eq!(found.len(), 2, "both clients are bound");
    assert!(found.contains(&first.id()) && found.contains(&second.id()));
    assert!(
        bound(ports, &tenant, &linkerd).await.is_empty(),
        "a Linkerd identity is another identity"
    );

    // A client of another service account may not join them, by creation
    // or by a change.
    let intruder = forwarded_client(
        invoices.id(),
        AuthenticationMethod::SpiffeX509,
        Some(ADAPTER),
        None,
    );
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .clients
            .insert(uow.as_mut(), &intruder)
            .await
            .expect_err("another service account")
            .code(),
        "oauth.client_spiffe_id_taken"
    );
    drop(uow);
    let mut moved = load_client(ports, &tenant, second.id())
        .await
        .expect("stored");
    let mut settings = moved.snapshot().settings.clone();
    settings.principal = Some(hodor_kernel::UserId::generate());
    moved.change(settings, MOMENT).expect("changed");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .clients
            .update(uow.as_mut(), &moved)
            .await
            .expect_err("another service account")
            .code(),
        "oauth.client_spiffe_id_taken"
    );
    drop(uow);

    // Another tenant sees none of them.
    let elsewhere = self::tenant();
    assert!(bound(ports, &elsewhere, &identity).await.is_empty());
}

async fn resource_servers_are_found_by_exact_audience(ports: Ports<'_>) {
    let tenant = tenant();
    let owner = application("Payroll", MOMENT);
    store_application(ports, &tenant, &owner).await;
    let without = application("Expenses", MOMENT);
    store_application(ports, &tenant, &without).await;
    let audience = format!("https://api-{}.example.com/payroll", owner.id());
    let payroll = server(owner.id(), &audience);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .resource_servers
        .insert(uow.as_mut(), &payroll)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .resource_servers
            .get(uow.as_mut(), payroll.id())
            .await
            .expect("get"),
        Some(payroll.clone()),
        "scopes come back in their order"
    );
    assert_eq!(
        ports
            .resource_servers
            .find_by_audience(uow.as_mut(), payroll.audience())
            .await
            .expect("find"),
        Some(payroll.clone())
    );
    assert_eq!(
        ports
            .resource_servers
            .find_by_application(uow.as_mut(), owner.id())
            .await
            .expect("find"),
        Some(payroll.clone()),
        "found by its application, with its scopes"
    );
    assert_eq!(
        ports
            .resource_servers
            .find_by_application(uow.as_mut(), without.id())
            .await
            .expect("find"),
        None,
        "an application without a resource server"
    );
    for near in [
        format!("{audience}/"),
        audience.replace("payroll", "Payroll"),
    ] {
        let near = Audience::parse(&near).expect("an audience");
        assert_eq!(
            ports
                .resource_servers
                .find_by_audience(uow.as_mut(), &near)
                .await
                .expect("find"),
            None,
            "{near:?}"
        );
    }
    assert_eq!(
        ports
            .resource_servers
            .list(uow.as_mut())
            .await
            .expect("list"),
        vec![payroll.clone()]
    );

    // A change of scopes is stored in its new order.
    let mut changed = payroll.clone();
    changed
        .change(
            ResourceServerSettings {
                name: "Payroll".to_owned(),
                scopes: vec![ScopeDefinition {
                    name: "read".to_owned(),
                    description: String::new(),
                }],
            },
            MOMENT,
        )
        .expect("changed");
    ports
        .resource_servers
        .update(uow.as_mut(), &changed)
        .await
        .expect("update");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let stored = ports
        .resource_servers
        .get(uow.as_mut(), payroll.id())
        .await
        .expect("get")
        .expect("stored");
    assert_eq!(stored.snapshot().settings, changed.snapshot().settings);
    assert_eq!(stored.snapshot().version, 1);
    assert_eq!(
        ports
            .resource_servers
            .update(uow.as_mut(), &changed)
            .await
            .expect_err("stale")
            .code(),
        "oauth.resource_server_modified_concurrently"
    );
    drop(uow);

    let elsewhere = self::tenant();
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .resource_servers
            .find_by_audience(uow.as_mut(), payroll.audience())
            .await
            .expect("find"),
        None
    );
    assert_eq!(
        ports
            .resource_servers
            .find_by_application(uow.as_mut(), owner.id())
            .await
            .expect("find"),
        None
    );
    assert_eq!(
        ports
            .resource_servers
            .get(uow.as_mut(), payroll.id())
            .await
            .expect("get"),
        None
    );
}

async fn an_audience_and_an_application_have_one_resource_server(ports: Ports<'_>) {
    let tenant = tenant();
    let first = application("Payroll", MOMENT);
    let second = application("Expenses", MOMENT);
    store_application(ports, &tenant, &first).await;
    store_application(ports, &tenant, &second).await;
    let audience = format!("urn:example:{}", first.id());
    let insert = async |tenant: &TenantContext, server: &ResourceServer| {
        let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
        let result = ports.resource_servers.insert(uow.as_mut(), server).await;
        if result.is_ok() {
            uow.commit().await.expect("commit");
        }
        result
    };
    insert(&tenant, &server(first.id(), &audience))
        .await
        .expect("first");
    assert_eq!(
        insert(&tenant, &server(second.id(), &audience))
            .await
            .expect_err("same audience")
            .code(),
        "oauth.audience_taken"
    );
    assert_eq!(
        insert(&tenant, &server(first.id(), &format!("{audience}:other")))
            .await
            .expect_err("same application")
            .code(),
        "oauth.application_has_resource_server"
    );
    assert_eq!(
        insert(
            &tenant,
            &server(ApplicationId::generate(), &format!("{audience}:x"))
        )
        .await
        .expect_err("no such application")
        .code(),
        "oauth.application_not_found"
    );
    // Another tenant may use the same audience for its own application.
    let elsewhere = self::tenant();
    let theirs = application("Payroll", MOMENT);
    store_application(ports, &elsewhere, &theirs).await;
    insert(&elsewhere, &server(theirs.id(), &audience))
        .await
        .expect("another tenant");
}
