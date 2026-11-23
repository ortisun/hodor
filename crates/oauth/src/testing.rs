//! In-memory stores and the contract every store of the OAuth context
//! passes.

use crate::api::{
    Application, ApplicationId, ApplicationSettings, ApplicationSnapshot, ApplicationStore,
    Audience, Client, ClientId, ClientKey, ClientSecret, ClientSettings, ClientSnapshot,
    ClientStore, ClientType, GrantType, ResourceServer, ResourceServerId, ResourceServerSettings,
    ResourceServerSnapshot, ResourceServerStore, ScopeDefinition, Status,
};
use hodor_kernel::{
    DomainError, RandomSource, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use time::Duration;

mod authorization;
mod token;
pub use authorization::{
    AuthorizationStorePorts, InMemoryAuthorizationCodes, InMemoryAuthorizationRequests,
    InMemoryGrants, run_authorization_contract,
};
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
        lock(&self.rows).insert((tenant, client.id()), client.clone());
        Ok(())
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, client: &Client) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), client.id());
        let mut rows = lock(&self.rows);
        let version = client.snapshot().version;
        match rows.get(&key) {
            Some(stored) if stored.snapshot().version == version => {
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
    settings.allowed_scopes = vec!["openid".to_owned(), "payroll:read".to_owned()];
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
    assert_eq!(stored.snapshot().version, 2);
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

async fn resource_servers_are_found_by_exact_audience(ports: Ports<'_>) {
    let tenant = tenant();
    let owner = application("Payroll", MOMENT);
    store_application(ports, &tenant, &owner).await;
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
