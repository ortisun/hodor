//! In-memory stores of back-channel logout, fakes of what it calls, and the
//! contract every store of logout deliveries passes.

use super::{InMemoryClients, InMemoryGrants, lock};
use crate::api::{
    Application, ApplicationSettings, ApplicationStore, Client, ClientId, ClientSecret,
    ClientSettings, ClientStore, ClientType, DueLogoutDeliveries, Grant, GrantId, GrantStatus,
    GrantStore, LogoutDelivery, LogoutDeliveryId, LogoutDeliveryStatus, LogoutDeliveryStore,
    LogoutRetryPolicy, OPENID_SCOPE, SessionClients, TenantIssuer,
};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    DestinationCheck, DomainError, ErrorKind, HttpClient, HttpRequest, HttpResponse, TenantContext,
    TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use hodor_session::api::SessionId;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use time::Duration;

/// The clients of a session, read from the grants of an
/// [`InMemoryGrants`].
#[derive(Debug, Clone)]
pub struct InMemorySessionClients {
    grants: InMemoryGrants,
}

impl InMemorySessionClients {
    /// The clients of the sessions of `grants`.
    #[must_use]
    pub fn new(grants: &InMemoryGrants) -> Self {
        Self {
            grants: grants.clone(),
        }
    }
}

#[async_trait::async_trait]
impl SessionClients for InMemorySessionClients {
    async fn clients_of(
        &self,
        uow: &mut dyn UnitOfWork,
        session: SessionId,
    ) -> Result<Vec<ClientId>, DomainError> {
        let mut clients: Vec<ClientId> = self
            .grants
            .all(uow.tenant().tenant_id())
            .into_iter()
            .filter(|grant| {
                grant.session_id == session && grant.scopes.iter().any(|s| s == OPENID_SCOPE)
            })
            .map(|grant| grant.client_id)
            .collect();
        clients.sort();
        clients.dedup();
        Ok(clients)
    }
}

/// Logout deliveries kept in memory, across tenants. They know the clients
/// they are stored against, as the database knows its references.
#[derive(Debug, Clone)]
pub struct InMemoryLogoutDeliveries {
    clients: InMemoryClients,
    rows: Arc<Mutex<BTreeMap<(TenantId, LogoutDeliveryId), LogoutDelivery>>>,
}

impl InMemoryLogoutDeliveries {
    /// Deliveries to the clients in `clients`.
    #[must_use]
    pub fn new(clients: &InMemoryClients) -> Self {
        Self {
            clients: clients.clone(),
            rows: Arc::default(),
        }
    }

    /// Every delivery of `tenant`, for tests that look behind the use
    /// cases.
    #[must_use]
    pub fn all(&self, tenant: TenantId) -> Vec<LogoutDelivery> {
        lock(&self.rows)
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, delivery)| delivery.clone())
            .collect()
    }

    fn read(&self, uow: &dyn UnitOfWork, id: LogoutDeliveryId) -> Option<LogoutDelivery> {
        lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), id))
            .cloned()
    }
}

#[async_trait::async_trait]
impl LogoutDeliveryStore for InMemoryLogoutDeliveries {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        delivery: &LogoutDelivery,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = delivery.snapshot();
        if !self.clients.exists(tenant, state.client_id) {
            return Err(DomainError::not_found(
                "oauth.client_not_found",
                "there is no such client",
            ));
        }
        let mut rows = lock(&self.rows);
        let taken = rows.iter().any(|((owner, _), kept)| {
            *owner == tenant
                && kept.snapshot().client_id == state.client_id
                && kept.snapshot().session_id == state.session_id
        });
        if taken {
            return Ok(false);
        }
        rows.insert((tenant, delivery.id()), delivery.clone());
        Ok(true)
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: LogoutDeliveryId,
    ) -> Result<Option<LogoutDelivery>, DomainError> {
        Ok(self.read(uow, id))
    }

    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        id: LogoutDeliveryId,
    ) -> Result<Option<LogoutDelivery>, DomainError> {
        Ok(self.read(uow, id))
    }

    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: LogoutDeliveryId,
    ) -> Result<Option<LogoutDelivery>, DomainError> {
        Ok(self.read(uow, id))
    }

    async fn hold_client(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
    ) -> Result<bool, DomainError> {
        Ok(self.clients.exists(uow.tenant().tenant_id(), client))
    }

    async fn leased(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
        now: Timestamp,
    ) -> Result<u32, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let count = lock(&self.rows)
            .iter()
            .filter(|((owner, _), delivery)| {
                *owner == tenant
                    && delivery.snapshot().client_id == client
                    && delivery.is_leased(now)
            })
            .count();
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        delivery: &LogoutDelivery,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), delivery.id());
        let mut rows = lock(&self.rows);
        let Some(kept) = rows.get_mut(&key) else {
            return Err(DomainError::not_found(
                "oauth.logout_delivery_not_found",
                "there is no such logout delivery",
            ));
        };
        *kept = delivery.clone();
        Ok(())
    }
}

#[async_trait::async_trait]
impl DueLogoutDeliveries for InMemoryLogoutDeliveries {
    async fn due(
        &self,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<(TenantId, LogoutDeliveryId)>, DomainError> {
        let mut due: Vec<(Timestamp, LogoutDeliveryId, TenantId)> = lock(&self.rows)
            .iter()
            .filter(|(_, delivery)| delivery.is_due(now))
            .map(|((tenant, id), delivery)| (delivery.snapshot().next_attempt_at, *id, *tenant))
            .collect();
        due.sort();
        Ok(due
            .into_iter()
            .take(limit as usize)
            .map(|(_, id, tenant)| (tenant, id))
            .collect())
    }
}

/// The issuer of every tenant, `https://login.example.com/t/` and the
/// tenant's identifier.
#[derive(Debug, Clone, Copy, Default)]
pub struct FixedIssuer;

impl FixedIssuer {
    /// The issuer this names `tenant` by.
    #[must_use]
    pub fn of(tenant: &TenantContext) -> String {
        format!("https://login.example.com/t/{}", tenant.tenant_id())
    }
}

#[async_trait::async_trait]
impl TenantIssuer for FixedIssuer {
    async fn issuer(&self, tenant: &TenantContext) -> Result<String, DomainError> {
        Ok(Self::of(tenant))
    }
}

/// A destination check without a resolver: `https://` or `http://`, and
/// these hosts are what names resolve to. `localhost`, `internal.example`
/// and addresses of private ranges may not be called, nor may anything
/// over plain HTTP; `nowhere.example` resolves to nothing; every other
/// host is public.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeDestinations;

#[async_trait::async_trait]
impl DestinationCheck for FakeDestinations {
    async fn check(&self, url: &str) -> Result<(), DomainError> {
        let Some(rest) = url.strip_prefix("https://") else {
            return Err(DomainError::invalid(
                "http.url_invalid",
                "the address cannot be called",
            ));
        };
        let authority = rest.split(['/', '?']).next().unwrap_or_default();
        let host = authority
            .rsplit_once(':')
            .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()))
            .map_or(authority, |(host, _)| host);
        if host == "localhost"
            || host == "internal.example"
            || ["127.", "10.", "169.254.", "192.168."]
                .iter()
                .any(|start| host.starts_with(start))
        {
            return Err(DomainError::new(
                ErrorKind::Forbidden,
                "http.destination_forbidden",
                "the address may not be called",
            ));
        }
        if host == "nowhere.example" {
            return Err(DomainError::new(
                ErrorKind::Unavailable,
                "http.unreachable",
                "the address did not answer",
            ));
        }
        Ok(())
    }
}

/// How a [`RecordingClients`] answers an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAnswer {
    /// With this status and no body.
    Status(u16),
    /// With this error of the outbound client, such as `http.timed_out`.
    Failure(&'static str),
}

/// An outbound client for tests: keeps every request and answers each
/// address as it was told, `200` unless told otherwise.
#[derive(Debug, Clone, Default)]
pub struct RecordingClients {
    requests: Arc<Mutex<Vec<HttpRequest>>>,
    answers: Arc<Mutex<BTreeMap<String, ClientAnswer>>>,
}

impl RecordingClients {
    /// From now on, answer `url` with `answer`.
    pub fn answer(&self, url: &str, answer: ClientAnswer) {
        lock(&self.answers).insert(url.to_owned(), answer);
    }

    /// Every request sent so far, oldest first.
    #[must_use]
    pub fn requests(&self) -> Vec<HttpRequest> {
        lock(&self.requests).clone()
    }

    /// The logout tokens sent to `url`, oldest first.
    #[must_use]
    pub fn tokens_to(&self, url: &str) -> Vec<String> {
        self.requests()
            .into_iter()
            .filter(|request| request.url == url)
            .filter_map(|request| {
                let body = String::from_utf8(request.body?).ok()?;
                body.strip_prefix("logout_token=").map(str::to_owned)
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl HttpClient for RecordingClients {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
        let answer = lock(&self.answers)
            .get(&request.url)
            .cloned()
            .unwrap_or(ClientAnswer::Status(200));
        lock(&self.requests).push(request);
        match answer {
            ClientAnswer::Status(status) => Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: Vec::new(),
            }),
            ClientAnswer::Failure(code) => Err(DomainError::new(
                ErrorKind::Unavailable,
                code,
                "the address did not answer",
            )),
        }
    }
}

/// The ports of the contract of logout deliveries.
#[derive(Clone, Copy)]
pub struct LogoutDeliveryStorePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// Where the applications of the clients are stored.
    pub applications: &'a dyn ApplicationStore,
    /// Where the clients the rows reference are stored.
    pub clients: &'a dyn ClientStore,
    /// Where the grants the sessions are read from are stored.
    pub grants: &'a dyn GrantStore,
    /// The clients of a session, under test.
    pub sessions: &'a dyn SessionClients,
    /// The delivery store under test.
    pub deliveries: &'a dyn LogoutDeliveryStore,
    /// The search across tenants, under test.
    pub due: &'a dyn DueLogoutDeliveries,
}

impl std::fmt::Debug for LogoutDeliveryStorePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogoutDeliveryStorePorts")
            .finish_non_exhaustive()
    }
}

/// A moment whole to the microsecond, as PostgreSQL keeps it.
fn moment() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

async fn a_client(ports: LogoutDeliveryStorePorts<'_>, tenant: &TenantContext) -> Client {
    let application = Application::create(
        ApplicationSettings {
            name: "Billing".to_owned(),
            first_party: true,
        },
        moment(),
    )
    .expect("application");
    let mut settings = ClientSettings::new(
        "Billing web",
        ClientType::Public,
        vec![crate::api::GrantType::AuthorizationCode],
        vec!["https://billing.example.com/callback".to_owned()],
    );
    settings.backchannel_logout_uri = Some("https://billing.example.com/logout".to_owned());
    let client = Client::create(
        application.id(),
        ClientType::Public,
        settings,
        ClientSecret::DEFAULT_LIFETIME,
        moment(),
        &super::DistinctRandom,
        &FakeDigest,
    )
    .expect("client")
    .0;
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .applications
        .insert(uow.as_mut(), &application)
        .await
        .expect("application");
    ports
        .clients
        .insert(uow.as_mut(), &client)
        .await
        .expect("client");
    uow.commit().await.expect("commit");
    client
}

async fn a_grant(
    ports: LogoutDeliveryStorePorts<'_>,
    tenant: &TenantContext,
    client: ClientId,
    session: SessionId,
    scopes: &[&str],
) {
    let grant = Grant {
        id: GrantId::generate(),
        client_id: client,
        user_id: UserId::generate(),
        session_id: session,
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        audiences: Vec::new(),
        organization: None,
        status: GrantStatus::Active,
        created_at: moment(),
        revoked_at: None,
        revocation_reason: None,
    };
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .grants
        .insert(uow.as_mut(), &grant)
        .await
        .expect("grant");
    uow.commit().await.expect("commit");
}

async fn insert(
    ports: LogoutDeliveryStorePorts<'_>,
    tenant: &TenantContext,
    delivery: &LogoutDelivery,
) -> Result<bool, DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let stored = ports.deliveries.insert(uow.as_mut(), delivery).await?;
    uow.commit().await.expect("commit");
    Ok(stored)
}

async fn update(
    ports: LogoutDeliveryStorePorts<'_>,
    tenant: &TenantContext,
    delivery: &LogoutDelivery,
) {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .deliveries
        .update(uow.as_mut(), delivery)
        .await
        .expect("update");
    uow.commit().await.expect("commit");
}

async fn read(
    ports: LogoutDeliveryStorePorts<'_>,
    tenant: &TenantContext,
    id: LogoutDeliveryId,
) -> Option<LogoutDelivery> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.deliveries.get(uow.as_mut(), id).await.expect("get")
}

/// Runs every rule a store of logout deliveries, and the clients of a
/// session, must obey. Each case uses tenants of its own, so runs can
/// share one database.
///
/// # Panics
///
/// Panics when an implementation breaks a rule.
pub async fn run_logout_delivery_contract(ports: LogoutDeliveryStorePorts<'_>) {
    the_clients_of_a_session_are_those_with_an_openid_grant_in_it(ports).await;
    a_delivery_is_stored_whole_once_per_client_and_session(ports).await;
    a_delivery_names_a_client_of_its_own_tenant(ports).await;
    what_an_attempt_did_is_stored_and_leases_are_counted(ports).await;
    due_deliveries_are_found_across_tenants_longest_waiting_first(ports).await;
}

async fn the_clients_of_a_session_are_those_with_an_openid_grant_in_it(
    ports: LogoutDeliveryStorePorts<'_>,
) {
    let (home, other) = (tenant(), tenant());
    let (first, second, without) = (
        a_client(ports, &home).await,
        a_client(ports, &home).await,
        a_client(ports, &home).await,
    );
    let elsewhere = a_client(ports, &other).await;
    let session = SessionId::generate();
    a_grant(ports, &home, first.id(), session, &["openid", "email"]).await;
    a_grant(ports, &home, first.id(), session, &["openid"]).await;
    a_grant(ports, &home, second.id(), session, &["profile", "openid"]).await;
    a_grant(ports, &home, without.id(), session, &["invoices:read"]).await;
    a_grant(
        ports,
        &home,
        without.id(),
        SessionId::generate(),
        &["openid"],
    )
    .await;
    a_grant(ports, &other, elsewhere.id(), session, &["openid"]).await;

    let mut uow = ports.units_of_work.begin(&home).await.expect("begin");
    let mut found = ports
        .sessions
        .clients_of(uow.as_mut(), session)
        .await
        .expect("clients");
    found.sort();
    let mut expected = vec![first.id(), second.id()];
    expected.sort();
    assert_eq!(found, expected, "each client once, and only with `openid`");
    let mut uow = ports.units_of_work.begin(&other).await.expect("begin");
    assert_eq!(
        ports
            .sessions
            .clients_of(uow.as_mut(), session)
            .await
            .expect("clients"),
        [elsewhere.id()],
        "a tenant sees its own grants only"
    );
}

async fn a_delivery_is_stored_whole_once_per_client_and_session(
    ports: LogoutDeliveryStorePorts<'_>,
) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let session = SessionId::generate();
    let delivery = LogoutDelivery::make(client.id(), session, UserId::generate(), moment());
    assert!(insert(ports, &tenant, &delivery).await.expect("stored"));
    assert_eq!(
        read(ports, &tenant, delivery.id()).await.as_ref(),
        Some(&delivery)
    );
    let again = LogoutDelivery::make(client.id(), session, UserId::generate(), moment());
    assert!(
        !insert(ports, &tenant, &again).await.expect("ignored"),
        "a client gets one delivery per session"
    );
    assert!(read(ports, &tenant, again.id()).await.is_none());
    let another = LogoutDelivery::make(
        client.id(),
        SessionId::generate(),
        UserId::generate(),
        moment(),
    );
    assert!(insert(ports, &tenant, &another).await.expect("stored"));

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        ports
            .deliveries
            .take(uow.as_mut(), delivery.id())
            .await
            .expect("take")
            .is_some()
    );
    assert!(
        ports
            .deliveries
            .lock(uow.as_mut(), another.id())
            .await
            .expect("lock")
            .is_some()
    );
}

async fn a_delivery_names_a_client_of_its_own_tenant(ports: LogoutDeliveryStorePorts<'_>) {
    let (home, other) = (tenant(), tenant());
    let client = a_client(ports, &home).await;
    let delivery = LogoutDelivery::make(
        client.id(),
        SessionId::generate(),
        UserId::generate(),
        moment(),
    );
    let mut uow = ports.units_of_work.begin(&other).await.expect("begin");
    let error = ports
        .deliveries
        .insert(uow.as_mut(), &delivery)
        .await
        .expect_err("another tenant's client");
    assert_eq!(error.code(), "oauth.client_not_found");
    drop(uow);
    let mut uow = ports.units_of_work.begin(&other).await.expect("begin");
    assert!(
        !ports
            .deliveries
            .hold_client(uow.as_mut(), client.id())
            .await
            .expect("hold")
    );
    drop(uow);
    insert(ports, &home, &delivery).await.expect("stored");
    assert!(
        read(ports, &other, delivery.id()).await.is_none(),
        "another tenant does not see it"
    );
    let mut uow = ports.units_of_work.begin(&other).await.expect("begin");
    assert_eq!(
        ports
            .deliveries
            .update(uow.as_mut(), &delivery)
            .await
            .expect_err("not there")
            .code(),
        "oauth.logout_delivery_not_found"
    );
}

async fn what_an_attempt_did_is_stored_and_leases_are_counted(ports: LogoutDeliveryStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let at = |seconds: i64| moment() + Duration::seconds(seconds);
    let mut made: Vec<LogoutDelivery> = Vec::new();
    for _ in 0..3 {
        let delivery = LogoutDelivery::make(
            client.id(),
            SessionId::generate(),
            UserId::generate(),
            at(0),
        );
        insert(ports, &tenant, &delivery).await.expect("stored");
        made.push(delivery);
    }
    made[0].lease(at(0), at(70)).expect("due");
    update(ports, &tenant, &made[0]).await;
    made[1].lease(at(0), at(70)).expect("due");
    made[1].record_failure(
        at(5),
        Some(503),
        "the client answered 503",
        &LogoutRetryPolicy::DEFAULT,
    );
    update(ports, &tenant, &made[1]).await;
    made[2].lease(at(0), at(10)).expect("due");
    made[2].record_success(at(6), 204);
    update(ports, &tenant, &made[2]).await;

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        ports
            .deliveries
            .hold_client(uow.as_mut(), client.id())
            .await
            .expect("hold")
    );
    assert_eq!(
        ports
            .deliveries
            .leased(uow.as_mut(), client.id(), at(30))
            .await
            .expect("leased"),
        1
    );
    assert_eq!(
        ports
            .deliveries
            .leased(uow.as_mut(), client.id(), at(70))
            .await
            .expect("leased"),
        0,
        "a lease that ran out counts no more"
    );
    drop(uow);
    for delivery in &made {
        assert_eq!(
            read(ports, &tenant, delivery.id()).await.as_ref(),
            Some(delivery)
        );
    }
    let failed = read(ports, &tenant, made[1].id()).await.expect("kept");
    assert_eq!(failed.snapshot().last_response_status, Some(503));
    assert_eq!(failed.snapshot().attempts, 1);
    assert_eq!(failed.status(), LogoutDeliveryStatus::Pending);
    let delivered = read(ports, &tenant, made[2].id()).await.expect("kept");
    assert_eq!(delivered.status(), LogoutDeliveryStatus::Delivered);
    assert_eq!(delivered.snapshot().finished_at, Some(at(6)));
}

async fn due_deliveries_are_found_across_tenants_longest_waiting_first(
    ports: LogoutDeliveryStorePorts<'_>,
) {
    // Far from every other case's moments, so that only these are due.
    let base = moment() - Duration::days(3_650);
    let (first, second) = (tenant(), tenant());
    let (a, b) = (
        a_client(ports, &first).await,
        a_client(ports, &second).await,
    );
    let make = |client: ClientId, at: Timestamp| {
        LogoutDelivery::make(client, SessionId::generate(), UserId::generate(), at)
    };
    let oldest = make(a.id(), base);
    let newer = make(b.id(), base + Duration::seconds(5));
    let mut leased = make(a.id(), base);
    let mut set_aside = make(b.id(), base);
    for (tenant, delivery) in [
        (&first, &oldest),
        (&second, &newer),
        (&first, &leased),
        (&second, &set_aside),
    ] {
        insert(ports, tenant, delivery).await.expect("stored");
    }
    leased
        .lease(base, base + Duration::seconds(60))
        .expect("due");
    update(ports, &first, &leased).await;
    set_aside.set_aside(base, "the client has no back-channel logout address");
    update(ports, &second, &set_aside).await;

    let now = base + Duration::seconds(10);
    assert_eq!(
        ports.due.due(now, 100).await.expect("due"),
        [
            (first.tenant_id(), oldest.id()),
            (second.tenant_id(), newer.id())
        ]
    );
    assert_eq!(ports.due.due(now, 1).await.expect("due").len(), 1);
    assert!(
        ports
            .due
            .due(base + Duration::seconds(60), 100)
            .await
            .expect("due")
            .contains(&(first.tenant_id(), leased.id()))
    );
}
