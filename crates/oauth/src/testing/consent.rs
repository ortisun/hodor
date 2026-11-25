//! In-memory store of consents, and the contract every store of consents
//! passes.

use super::{InMemoryClients, lock};
use crate::api::{
    Application, ApplicationSettings, ApplicationStore, AuthorizationRequest, Client, ClientId,
    ClientSecret, ClientSettings, ClientStore, ClientType, Consent, ConsentAction, ConsentActor,
    ConsentHistoryEntry, ConsentPorts, ConsentService, ConsentStore, DEFAULT_CONSENT_LIFETIME,
    GrantType,
};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use time::Duration;

fn client_not_found() -> DomainError {
    DomainError::not_found("oauth.client_not_found", "there is no such client")
}

/// The consents of every tenant, by tenant, person and client.
type ConsentRows = BTreeMap<(TenantId, UserId, ClientId), Consent>;

/// Consents and their history kept in memory. They know the clients they
/// are stored against, as the database knows its references.
#[derive(Debug, Clone)]
pub struct InMemoryConsents {
    clients: InMemoryClients,
    rows: Arc<Mutex<ConsentRows>>,
    history: Arc<Mutex<Vec<(TenantId, ConsentHistoryEntry)>>>,
}

impl InMemoryConsents {
    /// Consents to the clients in `clients`.
    #[must_use]
    pub fn new(clients: &InMemoryClients) -> Self {
        Self {
            clients: clients.clone(),
            rows: Arc::default(),
            history: Arc::default(),
        }
    }

    /// The history of `tenant`, in the order it was written, for tests that
    /// look behind the use cases.
    #[must_use]
    pub fn history(&self, tenant: TenantId) -> Vec<ConsentHistoryEntry> {
        lock(&self.history)
            .iter()
            .filter(|(owner, _)| *owner == tenant)
            .map(|(_, entry)| entry.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl ConsentStore for InMemoryConsents {
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
        client: ClientId,
    ) -> Result<Option<Consent>, DomainError> {
        Ok(lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), user, client))
            .cloned())
    }

    async fn save(&self, uow: &mut dyn UnitOfWork, consent: &Consent) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self.clients.exists(tenant, consent.client_id) {
            return Err(client_not_found());
        }
        lock(&self.rows).insert(
            (tenant, consent.user_id, consent.client_id),
            consent.clone(),
        );
        Ok(())
    }

    async fn list_standing(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
        now: Timestamp,
    ) -> Result<Vec<Consent>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut standing: Vec<Consent> = lock(&self.rows)
            .iter()
            .filter(|((owner, whose, _), consent)| {
                *owner == tenant && *whose == user && consent.stands_at(now)
            })
            .map(|(_, consent)| consent.clone())
            .collect();
        standing.sort_by_key(|consent| std::cmp::Reverse(consent.given_at));
        Ok(standing)
    }

    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        entry: &ConsentHistoryEntry,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self.clients.exists(tenant, entry.client_id) {
            return Err(client_not_found());
        }
        lock(&self.history).push((tenant, entry.clone()));
        Ok(())
    }
}

/// A [`ConsentService`] on in-memory stores, against the clients of
/// `stores`, for tests of the layers above.
#[must_use]
pub fn consent_service(
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    stores: &super::InMemoryStores,
    clock: Arc<dyn hodor_kernel::Clock>,
) -> ConsentService {
    ConsentService::new(ConsentPorts {
        units_of_work,
        consents: Arc::new(InMemoryConsents::new(&stores.clients)),
        requests: Arc::new(super::InMemoryAuthorizationRequests::new(&stores.clients)),
        grants: Arc::new(super::InMemoryGrants::new(&stores.clients)),
        clients: Arc::new(stores.clients.clone()),
        applications: Arc::new(stores.applications.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        digest: Arc::new(FakeDigest),
        random: Arc::new(super::DistinctRandom),
        clock,
    })
}

/// The ports of the consent contract.
#[derive(Clone, Copy)]
pub struct ConsentStorePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// Where the applications of the clients are stored.
    pub applications: &'a dyn ApplicationStore,
    /// Where the clients the rows reference are stored.
    pub clients: &'a dyn ClientStore,
    /// The consent store under test.
    pub consents: &'a dyn ConsentStore,
}

impl std::fmt::Debug for ConsentStorePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentStorePorts").finish_non_exhaustive()
    }
}

/// A moment whole to the microsecond, as PostgreSQL keeps it.
fn moment() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

async fn a_client(ports: ConsentStorePorts<'_>, tenant: &TenantContext) -> Client {
    let application = Application::create(
        ApplicationSettings {
            name: "Billing".to_owned(),
            first_party: false,
        },
        moment(),
    )
    .expect("application");
    let client = Client::create(
        application.id(),
        ClientType::Public,
        ClientSettings::new(
            "Billing web",
            ClientType::Public,
            vec![GrantType::AuthorizationCode],
            vec!["https://billing.example.com/callback".to_owned()],
        ),
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

fn asked(client: ClientId) -> AuthorizationRequest {
    AuthorizationRequest {
        client_id: client,
        redirect_uri: "https://billing.example.com/callback".to_owned(),
        scopes: vec!["openid".to_owned(), "invoices:read".to_owned()],
        audiences: vec!["https://api.billing.example.com".to_owned()],
        code_challenge: None,
        state: None,
        nonce: None,
        prompt: Vec::new(),
        max_age: None,
        login_hint: None,
        ui_locales: None,
        acr_values: None,
        first_party: false,
        organization: None,
        response_mode: crate::domain::response::ResponseMode::Query,
        id_token_hint: None,
        given_hint: None,
        claims: crate::api::ClaimsRequest::default(),
        claims_locales: None,
    }
}

fn consent_at(user: UserId, client: ClientId, at: Timestamp) -> Consent {
    Consent::give(None, user, &asked(client), DEFAULT_CONSENT_LIFETIME, at)
}

/// Runs every rule a store of consents must obey. Each case uses tenants
/// of its own, so runs can share one database.
///
/// # Panics
///
/// Panics when an implementation breaks a rule.
pub async fn run_consent_contract(ports: ConsentStorePorts<'_>) {
    a_consent_is_stored_whole_and_replaced(ports).await;
    only_standing_consents_are_listed_newest_first(ports).await;
    the_history_keeps_what_happened(ports).await;
    rows_reference_their_own_tenant(ports).await;
}

async fn a_consent_is_stored_whole_and_replaced(ports: ConsentStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let user = UserId::generate();
    let consent = consent_at(user, client.id(), moment());
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .consents
        .save(uow.as_mut(), &consent)
        .await
        .expect("save");
    uow.commit().await.expect("commit");

    let mut withdrawn = consent.clone();
    withdrawn.withdraw(ConsentActor::Person, moment() + Duration::seconds(5));
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .consents
            .get(uow.as_mut(), user, client.id())
            .await
            .expect("get"),
        Some(consent),
        "stored whole"
    );
    ports
        .consents
        .save(uow.as_mut(), &withdrawn)
        .await
        .expect("replace");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .consents
            .get(uow.as_mut(), user, client.id())
            .await
            .expect("get"),
        Some(withdrawn),
        "replaced, with who withdrew it"
    );
    assert_eq!(
        ports
            .consents
            .get(uow.as_mut(), UserId::generate(), client.id())
            .await
            .expect("get"),
        None,
        "another person has none"
    );
}

async fn only_standing_consents_are_listed_newest_first(ports: ConsentStorePorts<'_>) {
    let tenant = tenant();
    let first = a_client(ports, &tenant).await;
    let second = a_client(ports, &tenant).await;
    let expired = a_client(ports, &tenant).await;
    let withdrawn = a_client(ports, &tenant).await;
    let user = UserId::generate();
    let now = moment() + Duration::days(400);
    let older = consent_at(user, first.id(), now - Duration::days(10));
    let newer = consent_at(user, second.id(), now - Duration::days(1));
    let gone = consent_at(user, expired.id(), moment());
    let mut ended = consent_at(user, withdrawn.id(), now - Duration::days(2));
    ended.withdraw(ConsentActor::Administrator, now - Duration::days(1));
    let someone_else = consent_at(UserId::generate(), first.id(), now);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    for consent in [&older, &newer, &gone, &ended, &someone_else] {
        ports
            .consents
            .save(uow.as_mut(), consent)
            .await
            .expect("save");
    }
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .consents
            .list_standing(uow.as_mut(), user, now)
            .await
            .expect("list"),
        vec![newer, older]
    );
}

async fn the_history_keeps_what_happened(ports: ConsentStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let entry = ConsentHistoryEntry {
        user_id: UserId::generate(),
        client_id: client.id(),
        action: ConsentAction::Refused,
        scopes: vec!["openid".to_owned()],
        audiences: Vec::new(),
        by: ConsentActor::Person,
        at: moment(),
    };
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .consents
        .record(uow.as_mut(), &entry)
        .await
        .expect("record");
    ports
        .consents
        .record(uow.as_mut(), &entry)
        .await
        .expect("the same thing may happen twice");
    uow.commit().await.expect("commit");
}

async fn rows_reference_their_own_tenant(ports: ConsentStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let user = UserId::generate();
    let consent = consent_at(user, client.id(), moment());
    let elsewhere = self::tenant();
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .consents
            .save(uow.as_mut(), &consent)
            .await
            .expect_err("another tenant's client")
            .code(),
        "oauth.client_not_found"
    );
    drop(uow);

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .consents
        .save(uow.as_mut(), &consent)
        .await
        .expect("save");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .consents
            .get(uow.as_mut(), user, client.id())
            .await
            .expect("get"),
        None,
        "another tenant cannot read it"
    );
    assert!(
        ports
            .consents
            .list_standing(uow.as_mut(), user, moment())
            .await
            .expect("list")
            .is_empty()
    );
}
