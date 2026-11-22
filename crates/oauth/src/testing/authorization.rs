//! In-memory stores of the authorization endpoint, and the contract every
//! store of pending requests, grants and codes passes.

use super::{InMemoryClients, lock};
use crate::api::{
    Application, ApplicationSettings, ApplicationStore, AuthorizationCode, AuthorizationCodeStore,
    AuthorizationRequest, AuthorizationRequestStore, Client, ClientId, ClientSecret,
    ClientSettings, ClientStore, ClientType, CodeHash, Grant, GrantId, GrantStatus, GrantStore,
    GrantType, PendingAuthorization, PendingAuthorizationId, SignedInPerson,
};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use hodor_session::api::SessionId;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use time::Duration;

fn client_not_found() -> DomainError {
    DomainError::not_found("oauth.client_not_found", "there is no such client")
}

fn grant_not_found() -> DomainError {
    DomainError::not_found("oauth.grant_not_found", "there is no such grant")
}

/// Pending requests kept in memory. They know the clients they are stored
/// against, as the database knows its references.
#[derive(Debug, Clone)]
pub struct InMemoryAuthorizationRequests {
    clients: InMemoryClients,
    rows: Arc<Mutex<BTreeMap<(TenantId, PendingAuthorizationId), PendingAuthorization>>>,
}

impl InMemoryAuthorizationRequests {
    /// Pending requests of the clients in `clients`.
    #[must_use]
    pub fn new(clients: &InMemoryClients) -> Self {
        Self {
            clients: clients.clone(),
            rows: Arc::default(),
        }
    }
}

#[async_trait::async_trait]
impl AuthorizationRequestStore for InMemoryAuthorizationRequests {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        pending: &PendingAuthorization,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self.clients.exists(tenant, pending.request.client_id) {
            return Err(client_not_found());
        }
        lock(&self.rows).insert((tenant, pending.id), pending.clone());
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: PendingAuthorizationId,
    ) -> Result<Option<PendingAuthorization>, DomainError> {
        Ok(lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), id))
            .cloned())
    }

    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        id: PendingAuthorizationId,
    ) -> Result<bool, DomainError> {
        Ok(lock(&self.rows)
            .remove(&(uow.tenant().tenant_id(), id))
            .is_some())
    }
}

/// Grants kept in memory.
#[derive(Debug, Clone)]
pub struct InMemoryGrants {
    clients: InMemoryClients,
    rows: Arc<Mutex<BTreeMap<(TenantId, GrantId), Grant>>>,
}

impl InMemoryGrants {
    /// Grants of the clients in `clients`.
    #[must_use]
    pub fn new(clients: &InMemoryClients) -> Self {
        Self {
            clients: clients.clone(),
            rows: Arc::default(),
        }
    }

    fn exists(&self, tenant: TenantId, id: GrantId) -> bool {
        lock(&self.rows).contains_key(&(tenant, id))
    }
}

#[async_trait::async_trait]
impl GrantStore for InMemoryGrants {
    async fn insert(&self, uow: &mut dyn UnitOfWork, grant: &Grant) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self.clients.exists(tenant, grant.client_id) {
            return Err(client_not_found());
        }
        lock(&self.rows).insert((tenant, grant.id), grant.clone());
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: GrantId,
    ) -> Result<Option<Grant>, DomainError> {
        Ok(lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), id))
            .cloned())
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, grant: &Grant) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), grant.id);
        let mut rows = lock(&self.rows);
        match rows.get_mut(&key) {
            Some(stored) => {
                stored.status = grant.status;
                stored.revoked_at = grant.revoked_at;
                stored
                    .revocation_reason
                    .clone_from(&grant.revocation_reason);
                Ok(())
            }
            None => Err(grant_not_found()),
        }
    }
}

/// Codes kept in memory, by tenant and hash.
#[derive(Debug, Clone)]
pub struct InMemoryAuthorizationCodes {
    grants: InMemoryGrants,
    rows: Arc<Mutex<BTreeMap<(TenantId, [u8; 32]), AuthorizationCode>>>,
}

impl InMemoryAuthorizationCodes {
    /// Codes of the grants in `grants`.
    #[must_use]
    pub fn new(grants: &InMemoryGrants) -> Self {
        Self {
            grants: grants.clone(),
            rows: Arc::default(),
        }
    }
}

#[async_trait::async_trait]
impl AuthorizationCodeStore for InMemoryAuthorizationCodes {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        code: &AuthorizationCode,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self.grants.exists(tenant, code.grant_id) {
            return Err(grant_not_found());
        }
        lock(&self.rows).insert((tenant, *code.hash.as_bytes()), code.clone());
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &CodeHash,
    ) -> Result<Option<AuthorizationCode>, DomainError> {
        Ok(lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), *hash.as_bytes()))
            .cloned())
    }

    async fn redeem(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &CodeHash,
        at: Timestamp,
    ) -> Result<bool, DomainError> {
        let mut rows = lock(&self.rows);
        match rows.get_mut(&(uow.tenant().tenant_id(), *hash.as_bytes())) {
            Some(code) if code.redeemed_at.is_none() => {
                code.redeemed_at = Some(at);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// The ports of the authorization contract.
#[derive(Clone, Copy)]
pub struct AuthorizationStorePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// Where the clients the rows reference are stored.
    pub applications: &'a dyn ApplicationStore,
    /// Where the clients the rows reference are stored.
    pub clients: &'a dyn ClientStore,
    /// The pending request store under test.
    pub requests: &'a dyn AuthorizationRequestStore,
    /// The grant store under test.
    pub grants: &'a dyn GrantStore,
    /// The code store under test.
    pub codes: &'a dyn AuthorizationCodeStore,
}

impl std::fmt::Debug for AuthorizationStorePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationStorePorts")
            .finish_non_exhaustive()
    }
}

/// A moment whole to the microsecond, as PostgreSQL keeps it.
fn moment() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

async fn a_client(ports: AuthorizationStorePorts<'_>, tenant: &TenantContext) -> Client {
    let application = Application::create(
        ApplicationSettings {
            name: "Payroll".to_owned(),
            first_party: true,
        },
        moment(),
    )
    .expect("application");
    let client = Client::create(
        application.id(),
        ClientType::Public,
        ClientSettings::new(
            "Payroll mobile",
            ClientType::Public,
            vec![GrantType::AuthorizationCode],
            vec!["com.example.payroll:/callback".to_owned()],
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

fn request_for(client_id: ClientId) -> AuthorizationRequest {
    AuthorizationRequest {
        client_id,
        redirect_uri: "com.example.payroll:/callback".to_owned(),
        scopes: vec!["openid".to_owned(), "payroll:read".to_owned()],
        audiences: vec!["https://api.payroll.example.com".to_owned()],
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
        state: Some("state with spaces & signs".to_owned()),
        nonce: Some("n-0S6_WzA2Mj".to_owned()),
        prompt: vec!["login".to_owned()],
        max_age: Some(300),
        login_hint: Some("ana@example.com".to_owned()),
        ui_locales: Some("pt-BR en".to_owned()),
        acr_values: Some("urn:hodor:mfa".to_owned()),
    }
}

fn person() -> SignedInPerson {
    SignedInPerson {
        user_id: UserId::generate(),
        session_id: SessionId::generate(),
        signed_in_at: moment(),
        methods: vec!["password".to_owned(), "otp".to_owned()],
    }
}

/// Runs every rule a store of pending requests, grants and codes must
/// obey. Each case uses tenants of its own, so runs can share one
/// database.
///
/// # Panics
///
/// Panics when an implementation breaks a rule.
pub async fn run_authorization_contract(ports: AuthorizationStorePorts<'_>) {
    a_pending_request_is_stored_whole_and_removed_once(ports).await;
    a_grant_is_stored_and_its_revocation_kept(ports).await;
    a_code_is_found_by_its_hash_and_redeemed_once(ports).await;
    rows_reference_their_own_tenant(ports).await;
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

async fn a_pending_request_is_stored_whole_and_removed_once(ports: AuthorizationStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let (pending, _) = PendingAuthorization::hold(
        request_for(client.id()),
        moment(),
        &super::DistinctRandom,
        &FakeDigest,
    );
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .requests
        .insert(uow.as_mut(), &pending)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .requests
            .get(uow.as_mut(), pending.id)
            .await
            .expect("get"),
        Some(pending.clone()),
        "stored whole"
    );
    drop(uow);

    let elsewhere = self::tenant();
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .requests
            .get(uow.as_mut(), pending.id)
            .await
            .expect("get"),
        None
    );
    assert!(
        !ports
            .requests
            .remove(uow.as_mut(), pending.id)
            .await
            .expect("remove"),
        "another tenant cannot remove it"
    );
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        ports
            .requests
            .remove(uow.as_mut(), pending.id)
            .await
            .expect("remove")
    );
    assert!(
        !ports
            .requests
            .remove(uow.as_mut(), pending.id)
            .await
            .expect("remove"),
        "removed once"
    );
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .requests
            .get(uow.as_mut(), pending.id)
            .await
            .expect("get"),
        None
    );
}

async fn a_grant_is_stored_and_its_revocation_kept(ports: AuthorizationStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let grant = Grant::make(&request_for(client.id()), &person(), moment());
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .grants
        .insert(uow.as_mut(), &grant)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");

    let mut revoked = grant.clone();
    revoked
        .revoke("code_reused", moment() + Duration::seconds(5))
        .expect("event");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .grants
        .update(uow.as_mut(), &revoked)
        .await
        .expect("update");
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let stored = ports
        .grants
        .get(uow.as_mut(), grant.id)
        .await
        .expect("get")
        .expect("found");
    assert_eq!(stored, revoked);
    assert_eq!(stored.status, GrantStatus::Revoked);
    drop(uow);

    let elsewhere = self::tenant();
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports.grants.get(uow.as_mut(), grant.id).await.expect("get"),
        None
    );
    assert_eq!(
        ports
            .grants
            .update(uow.as_mut(), &revoked)
            .await
            .expect_err("another tenant's grant")
            .code(),
        "oauth.grant_not_found"
    );
}

async fn a_code_is_found_by_its_hash_and_redeemed_once(ports: AuthorizationStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let request = request_for(client.id());
    let person = person();
    let grant = Grant::make(&request, &person, moment());
    let (code, value) = AuthorizationCode::issue(
        &grant,
        &request,
        &person,
        moment(),
        &super::DistinctRandom,
        &FakeDigest,
    );
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .grants
        .insert(uow.as_mut(), &grant)
        .await
        .expect("grant");
    ports.codes.insert(uow.as_mut(), &code).await.expect("code");
    uow.commit().await.expect("commit");

    let hash = CodeHash::of_presented(value.expose(), &FakeDigest).expect("shaped");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports.codes.find(uow.as_mut(), &hash).await.expect("find"),
        Some(code.clone()),
        "stored whole"
    );
    drop(uow);

    let elsewhere = self::tenant();
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports.codes.find(uow.as_mut(), &hash).await.expect("find"),
        None
    );
    assert!(
        !ports
            .codes
            .redeem(uow.as_mut(), &hash, moment())
            .await
            .expect("redeem"),
        "another tenant cannot redeem it"
    );
    uow.commit().await.expect("commit");

    let at = moment() + Duration::seconds(3);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        ports
            .codes
            .redeem(uow.as_mut(), &hash, at)
            .await
            .expect("redeem")
    );
    assert!(
        !ports
            .codes
            .redeem(uow.as_mut(), &hash, at)
            .await
            .expect("redeem"),
        "redeemed once"
    );
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let stored = ports
        .codes
        .find(uow.as_mut(), &hash)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(stored.redeemed_at, Some(at));
}

async fn rows_reference_their_own_tenant(ports: AuthorizationStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let elsewhere = self::tenant();
    let request = request_for(client.id());
    let (pending, _) = PendingAuthorization::hold(
        request.clone(),
        moment(),
        &super::DistinctRandom,
        &FakeDigest,
    );
    let grant = Grant::make(&request, &person(), moment());

    // The client is of `tenant`: another tenant cannot point at it.
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .requests
            .insert(uow.as_mut(), &pending)
            .await
            .expect_err("another tenant's client")
            .code(),
        "oauth.client_not_found"
    );
    drop(uow);
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .grants
            .insert(uow.as_mut(), &grant)
            .await
            .expect_err("another tenant's client")
            .code(),
        "oauth.client_not_found"
    );
    drop(uow);

    // A code needs a grant of its own tenant.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .grants
        .insert(uow.as_mut(), &grant)
        .await
        .expect("grant");
    uow.commit().await.expect("commit");
    let (code, _) = AuthorizationCode::issue(
        &grant,
        &request,
        &person(),
        moment(),
        &super::DistinctRandom,
        &FakeDigest,
    );
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .codes
            .insert(uow.as_mut(), &code)
            .await
            .expect_err("another tenant's grant")
            .code(),
        "oauth.grant_not_found"
    );
}
