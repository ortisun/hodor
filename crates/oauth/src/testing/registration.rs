//! The client registration settings and initial access tokens of tenants,
//! kept in memory, and the contract every store of them passes.

use super::{InMemoryApplications, lock, modified};
use crate::api::{
    Application, ApplicationId, ApplicationSettings, ApplicationStore, ClientRegistration,
    ClientRegistrationSnapshot, ClientRegistrationStore, InitialAccessToken,
    InitialAccessTokenHash, InitialAccessTokenId, InitialAccessTokenSnapshot,
    InitialAccessTokenStore, NewInitialAccessToken, RegistrationPolicy, RegistrationSettings,
    RegistrationWay,
};
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use time::Duration;

fn settings_modified() -> DomainError {
    modified("oauth.client_registration_modified_concurrently")
}

fn unknown_application() -> DomainError {
    DomainError::invalid(
        "oauth.client_registration_application_invalid",
        "registered clients belong to one application of the tenant",
    )
}

/// The registration settings of every tenant, kept in memory. They know
/// the applications they name, as the database knows its references.
#[derive(Debug, Clone)]
pub struct InMemoryClientRegistrations {
    applications: InMemoryApplications,
    rows: Arc<Mutex<BTreeMap<TenantId, ClientRegistration>>>,
}

impl InMemoryClientRegistrations {
    /// The settings of tenants whose applications are in `applications`.
    #[must_use]
    pub fn new(applications: &InMemoryApplications) -> Self {
        Self {
            applications: applications.clone(),
            rows: Arc::default(),
        }
    }

    fn names_known(&self, tenant: TenantId, registration: &ClientRegistration) -> bool {
        registration
            .settings()
            .application_id
            .is_none_or(|id| self.applications.exists(tenant, id))
    }
}

#[async_trait::async_trait]
impl ClientRegistrationStore for InMemoryClientRegistrations {
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<ClientRegistration>, DomainError> {
        Ok(lock(&self.rows).get(&uow.tenant().tenant_id()).cloned())
    }

    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<ClientRegistration>, DomainError> {
        self.get(uow).await
    }

    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        registration: &ClientRegistration,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self.names_known(tenant, registration) {
            return Err(unknown_application());
        }
        let mut rows = lock(&self.rows);
        if rows.contains_key(&tenant) {
            return Err(settings_modified());
        }
        rows.insert(tenant, registration.clone());
        Ok(())
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        registration: &ClientRegistration,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self.names_known(tenant, registration) {
            return Err(unknown_application());
        }
        let mut rows = lock(&self.rows);
        let version = registration.snapshot().version;
        match rows.get(&tenant) {
            Some(stored) if stored.snapshot().version == version => {
                rows.insert(
                    tenant,
                    ClientRegistration::from_snapshot(ClientRegistrationSnapshot {
                        version: version + 1,
                        ..registration.snapshot().clone()
                    }),
                );
                Ok(())
            }
            _ => Err(settings_modified()),
        }
    }
}

/// The initial access tokens of every tenant, kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryInitialAccessTokens {
    rows: Arc<Mutex<BTreeMap<(TenantId, InitialAccessTokenId), InitialAccessToken>>>,
}

#[async_trait::async_trait]
impl InitialAccessTokenStore for InMemoryInitialAccessTokens {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &InitialAccessToken,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = lock(&self.rows);
        if rows.iter().any(|((owner, _), other)| {
            *owner == tenant && other.snapshot().token_hash == token.snapshot().token_hash
        }) {
            return Err(DomainError::internal(
                "oauth.initial_access_token_hash_taken",
                "two tokens of a tenant have one hash",
            ));
        }
        rows.insert((tenant, token.id()), token.clone());
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: InitialAccessTokenId,
    ) -> Result<Option<InitialAccessToken>, DomainError> {
        Ok(lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), id))
            .cloned())
    }

    async fn lock_by_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &InitialAccessTokenHash,
    ) -> Result<Option<InitialAccessToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows)
            .iter()
            .find(|((owner, _), token)| *owner == tenant && token.snapshot().token_hash == *hash)
            .map(|(_, token)| token.clone()))
    }

    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<InitialAccessToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut found: Vec<InitialAccessToken> = lock(&self.rows)
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, token)| token.clone())
            .collect();
        found.sort_by_key(|token| std::cmp::Reverse((token.snapshot().created_at, token.id())));
        Ok(found)
    }

    async fn count_active(
        &self,
        uow: &mut dyn UnitOfWork,
        now: Timestamp,
    ) -> Result<usize, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows)
            .iter()
            .filter(|((owner, _), token)| *owner == tenant && token.is_active(now))
            .count())
    }

    async fn record_use(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &InitialAccessToken,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), token.id());
        let mut rows = lock(&self.rows);
        if let Some(stored) = rows.get(&key) {
            let state = stored.snapshot().clone();
            rows.insert(
                key,
                InitialAccessToken::from_snapshot(InitialAccessTokenSnapshot {
                    registrations: token.snapshot().registrations,
                    last_used_at: token.snapshot().last_used_at,
                    ..state
                }),
            );
        }
        Ok(())
    }

    async fn revoke(
        &self,
        uow: &mut dyn UnitOfWork,
        id: InitialAccessTokenId,
        at: Timestamp,
    ) -> Result<bool, DomainError> {
        let key = (uow.tenant().tenant_id(), id);
        let mut rows = lock(&self.rows);
        let Some(stored) = rows.get(&key) else {
            return Ok(false);
        };
        if stored.snapshot().revoked_at.is_some() {
            return Ok(false);
        }
        let state = stored.snapshot().clone();
        rows.insert(
            key,
            InitialAccessToken::from_snapshot(InitialAccessTokenSnapshot {
                revoked_at: Some(at),
                ..state
            }),
        );
        Ok(true)
    }
}

/// The use cases of client registration on in-memory stores, over the
/// applications of `stores`.
#[must_use]
pub fn client_registration_service(
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    stores: &super::InMemoryStores,
    clock: Arc<dyn hodor_kernel::Clock>,
) -> crate::api::ClientRegistrationService {
    crate::api::ClientRegistrationService::new(crate::api::ClientRegistrationPorts {
        units_of_work,
        registrations: Arc::new(InMemoryClientRegistrations::new(&stores.applications)),
        tokens: Arc::new(InMemoryInitialAccessTokens::default()),
        applications: Arc::new(stores.applications.clone()),
        digest: Arc::new(hodor_kernel::random::testing::FakeDigest),
        random: Arc::new(super::DistinctRandom),
        clock,
    })
}

/// The ports under test.
#[derive(Clone, Copy)]
pub struct ClientRegistrationStorePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// Stores the applications the settings name.
    pub applications: &'a dyn ApplicationStore,
    /// The settings store under test.
    pub registrations: &'a dyn ClientRegistrationStore,
    /// The token store under test.
    pub tokens: &'a dyn InitialAccessTokenStore,
}

impl std::fmt::Debug for ClientRegistrationStorePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRegistrationStorePorts")
            .finish_non_exhaustive()
    }
}

fn moment() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

async fn an_application(
    ports: ClientRegistrationStorePorts<'_>,
    tenant: &TenantContext,
) -> ApplicationId {
    let application = Application::create(
        ApplicationSettings {
            name: "Partners".to_owned(),
            first_party: false,
        },
        moment(),
    )
    .expect("valid");
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .applications
        .insert(uow.as_mut(), &application)
        .await
        .expect("application");
    uow.commit().await.expect("commit");
    application.id()
}

fn settings_on(application: ApplicationId) -> RegistrationSettings {
    RegistrationSettings {
        enabled: true,
        application_id: Some(application),
        ways: vec![RegistrationWay::Open, RegistrationWay::InitialAccessToken],
        max_clients: 250,
        policy: RegistrationPolicy {
            hosts: Some(vec!["app.example.com".to_owned(), "[::1]".to_owned()]),
            ..RegistrationPolicy::default()
        },
    }
}

async fn stored(
    ports: ClientRegistrationStorePorts<'_>,
    tenant: &TenantContext,
) -> Option<ClientRegistration> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.registrations.get(uow.as_mut()).await.expect("get")
}

async fn store_token(
    ports: ClientRegistrationStorePorts<'_>,
    tenant: &TenantContext,
    token: &InitialAccessToken,
) {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .tokens
        .insert(uow.as_mut(), token)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
}

fn a_token(name: &str, at: Timestamp, max_registrations: u32) -> InitialAccessToken {
    InitialAccessToken::create(
        NewInitialAccessToken {
            name: name.to_owned(),
            lifetime: Duration::days(7),
            max_registrations,
        },
        at,
        &super::DistinctRandom,
        &hodor_kernel::random::testing::FakeDigest,
    )
    .expect("valid")
    .0
}

/// Runs every rule a store of registration settings and initial access
/// tokens must obey. Each case uses tenants of its own, so runs can share
/// one database.
///
/// # Panics
///
/// Panics when an implementation breaks a rule.
pub async fn run_client_registration_contract(ports: ClientRegistrationStorePorts<'_>) {
    settings_are_stored_once_per_tenant_and_read_back(ports).await;
    stale_settings_are_not_stored(ports).await;
    settings_name_only_an_application_of_their_tenant(ports).await;
    a_token_is_stored_and_found_by_its_hash(ports).await;
    a_tokens_use_and_revocation_are_stored(ports).await;
    another_tenant_sees_no_setting_and_no_token(ports).await;
}

async fn settings_are_stored_once_per_tenant_and_read_back(
    ports: ClientRegistrationStorePorts<'_>,
) {
    let tenant = TenantContext::assume(TenantId::generate());
    assert_eq!(stored(ports, &tenant).await, None, "none until set");
    let application = an_application(ports, &tenant).await;
    let (registration, _) =
        ClientRegistration::create(settings_on(application), moment()).expect("valid");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .registrations
        .insert(uow.as_mut(), &registration)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
    assert_eq!(stored(ports, &tenant).await, Some(registration.clone()));
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports.registrations.lock(uow.as_mut()).await.expect("lock"),
        Some(registration.clone())
    );
    drop(uow);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .registrations
            .insert(uow.as_mut(), &registration)
            .await
            .expect_err("once per tenant")
            .code(),
        "oauth.client_registration_modified_concurrently"
    );
}

async fn stale_settings_are_not_stored(ports: ClientRegistrationStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let application = an_application(ports, &tenant).await;
    let (registration, _) =
        ClientRegistration::create(settings_on(application), moment()).expect("valid");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .registrations
        .insert(uow.as_mut(), &registration)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
    let mut off = registration.clone();
    off.replace(
        RegistrationSettings {
            enabled: false,
            application_id: None,
            ways: Vec::new(),
            ..registration.settings().clone()
        },
        moment() + Duration::hours(1),
    )
    .expect("valid");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .registrations
        .update(uow.as_mut(), &off)
        .await
        .expect("update");
    uow.commit().await.expect("commit");
    let read = stored(ports, &tenant).await.expect("stored");
    assert_eq!(read.settings(), off.settings());
    assert_eq!(read.snapshot().version, 1);
    assert_eq!(read.snapshot().created_at, moment());
    assert_eq!(read.snapshot().updated_at, moment() + Duration::hours(1));
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .registrations
            .update(uow.as_mut(), &off)
            .await
            .expect_err("stale")
            .code(),
        "oauth.client_registration_modified_concurrently"
    );
}

async fn settings_name_only_an_application_of_their_tenant(
    ports: ClientRegistrationStorePorts<'_>,
) {
    let tenant = TenantContext::assume(TenantId::generate());
    let other = TenantContext::assume(TenantId::generate());
    let theirs = an_application(ports, &other).await;
    for application in [theirs, ApplicationId::generate()] {
        let (registration, _) =
            ClientRegistration::create(settings_on(application), moment()).expect("valid");
        let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
        assert_eq!(
            ports
                .registrations
                .insert(uow.as_mut(), &registration)
                .await
                .expect_err("refused")
                .code(),
            "oauth.client_registration_application_invalid"
        );
    }
    assert_eq!(stored(ports, &tenant).await, None);
}

async fn a_token_is_stored_and_found_by_its_hash(ports: ClientRegistrationStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let older = a_token("Older", moment(), 1);
    let newer = a_token("Newer", moment() + Duration::minutes(1), 3);
    store_token(ports, &tenant, &older).await;
    store_token(ports, &tenant, &newer).await;
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports.tokens.list(uow.as_mut()).await.expect("list"),
        [newer.clone(), older.clone()],
        "newest first"
    );
    assert_eq!(
        ports
            .tokens
            .get(uow.as_mut(), older.id())
            .await
            .expect("get"),
        Some(older.clone())
    );
    assert_eq!(
        ports
            .tokens
            .get(uow.as_mut(), InitialAccessTokenId::generate())
            .await
            .expect("get"),
        None
    );
    assert_eq!(
        ports
            .tokens
            .lock_by_hash(uow.as_mut(), &newer.snapshot().token_hash)
            .await
            .expect("found"),
        Some(newer.clone())
    );
    assert_eq!(
        ports
            .tokens
            .lock_by_hash(uow.as_mut(), &InitialAccessTokenHash::from_stored([7; 32]))
            .await
            .expect("found"),
        None
    );
    assert_eq!(
        ports
            .tokens
            .count_active(uow.as_mut(), moment() + Duration::minutes(1))
            .await
            .expect("count"),
        2
    );
    assert_eq!(
        ports
            .tokens
            .count_active(uow.as_mut(), moment() + Duration::days(7))
            .await
            .expect("count"),
        1,
        "the older one expired"
    );
}

async fn a_tokens_use_and_revocation_are_stored(ports: ClientRegistrationStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let mut token = a_token("Once", moment(), 1);
    store_token(ports, &tenant, &token).await;
    let used_at = moment() + Duration::hours(2);
    token.spend(used_at).expect("active");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let locked = ports
        .tokens
        .lock_by_hash(uow.as_mut(), &token.snapshot().token_hash)
        .await
        .expect("found");
    assert!(locked.is_some());
    ports
        .tokens
        .record_use(uow.as_mut(), &token)
        .await
        .expect("record");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let read = ports
        .tokens
        .get(uow.as_mut(), token.id())
        .await
        .expect("get")
        .expect("stored");
    assert_eq!(read.snapshot().registrations, 1);
    assert_eq!(read.snapshot().last_used_at, Some(used_at));
    assert_eq!(
        ports
            .tokens
            .count_active(uow.as_mut(), used_at)
            .await
            .expect("count"),
        0,
        "used up"
    );
    drop(uow);

    let other = a_token("Revoked", moment(), 5);
    store_token(ports, &tenant, &other).await;
    let revoked_at = moment() + Duration::hours(3);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        ports
            .tokens
            .revoke(uow.as_mut(), other.id(), revoked_at)
            .await
            .expect("revoke")
    );
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        !ports
            .tokens
            .revoke(uow.as_mut(), other.id(), revoked_at + Duration::hours(1))
            .await
            .expect("revoke"),
        "revoked once"
    );
    assert!(
        !ports
            .tokens
            .revoke(uow.as_mut(), InitialAccessTokenId::generate(), revoked_at)
            .await
            .expect("revoke"),
        "nothing to revoke"
    );
    let read = ports
        .tokens
        .get(uow.as_mut(), other.id())
        .await
        .expect("get")
        .expect("stored");
    assert_eq!(read.snapshot().revoked_at, Some(revoked_at));
    assert_eq!(read.snapshot().registrations, 0);
}

async fn another_tenant_sees_no_setting_and_no_token(ports: ClientRegistrationStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let other = TenantContext::assume(TenantId::generate());
    let application = an_application(ports, &tenant).await;
    let (registration, _) =
        ClientRegistration::create(settings_on(application), moment()).expect("valid");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .registrations
        .insert(uow.as_mut(), &registration)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
    let token = a_token("Mine", moment(), 1);
    store_token(ports, &tenant, &token).await;

    assert_eq!(stored(ports, &other).await, None);
    let mut uow = ports.units_of_work.begin(&other).await.expect("begin");
    assert_eq!(
        ports.registrations.lock(uow.as_mut()).await.expect("lock"),
        None
    );
    assert!(
        ports
            .tokens
            .list(uow.as_mut())
            .await
            .expect("list")
            .is_empty()
    );
    assert_eq!(
        ports
            .tokens
            .get(uow.as_mut(), token.id())
            .await
            .expect("get"),
        None
    );
    assert_eq!(
        ports
            .tokens
            .lock_by_hash(uow.as_mut(), &token.snapshot().token_hash)
            .await
            .expect("lock"),
        None
    );
    assert_eq!(
        ports
            .tokens
            .count_active(uow.as_mut(), moment())
            .await
            .expect("count"),
        0
    );
    assert!(
        !ports
            .tokens
            .revoke(uow.as_mut(), token.id(), moment())
            .await
            .expect("revoke")
    );
    // The same token, or one with the same hash, may be another tenant's.
    ports
        .tokens
        .insert(uow.as_mut(), &token)
        .await
        .expect("each tenant its own");
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let read = ports
        .tokens
        .get(uow.as_mut(), token.id())
        .await
        .expect("get")
        .expect("still there");
    assert_eq!(read.snapshot().revoked_at, None);
}
