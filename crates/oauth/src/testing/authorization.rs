//! In-memory stores of the authorization endpoint, and the contract every
//! store of pending requests, grants and codes passes.

use super::{InMemoryClients, lock};
use crate::api::{
    Application, ApplicationSettings, ApplicationStore, AuthorizationCode, AuthorizationCodeStore,
    AuthorizationRequest, AuthorizationRequestStore, Client, ClientId, ClientSecret,
    ClientSettings, ClientStore, ClientType, CodeHash, ConsentAnswer, Grant, GrantId, GrantStatus,
    GrantStore, GrantType, PendingAuthorization, PendingAuthorizationId, PushedAuthorization,
    ReferenceHash, SignedInPerson,
};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    DomainError, OrganizationId, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
    UserId,
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
    pushed: Arc<Mutex<BTreeMap<(TenantId, ReferenceHash), PushedAuthorization>>>,
}

impl InMemoryAuthorizationRequests {
    /// Pending requests of the clients in `clients`.
    #[must_use]
    pub fn new(clients: &InMemoryClients) -> Self {
        Self {
            clients: clients.clone(),
            rows: Arc::default(),
            pushed: Arc::default(),
        }
    }

    /// The pushed requests of `tenant` that wait, for tests that look
    /// behind the use cases.
    #[must_use]
    pub fn pushed(&self, tenant: TenantId) -> Vec<PushedAuthorization> {
        lock(&self.pushed)
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, pushed)| pushed.clone())
            .collect()
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

    async fn answer(
        &self,
        uow: &mut dyn UnitOfWork,
        id: PendingAuthorizationId,
        answer: ConsentAnswer,
    ) -> Result<bool, DomainError> {
        let mut rows = lock(&self.rows);
        match rows
            .get_mut(&(uow.tenant().tenant_id(), id))
            .and_then(|pending| pending.consent.as_mut())
        {
            Some(wait) if wait.answer.is_none() => {
                wait.answer = Some(answer);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn push(
        &self,
        uow: &mut dyn UnitOfWork,
        pushed: &PushedAuthorization,
        keep: usize,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let client = pushed.request.client_id;
        if !self.clients.exists(tenant, client) {
            return Err(client_not_found());
        }
        let mut rows = lock(&self.pushed);
        let mut waiting: Vec<(Timestamp, ReferenceHash)> = rows
            .iter()
            .filter(|((owner, _), row)| *owner == tenant && row.request.client_id == client)
            .map(|((_, hash), row)| (row.received_at, *hash))
            .collect();
        waiting.sort();
        let beyond = (waiting.len() + 1).saturating_sub(keep);
        for (_, hash) in waiting.into_iter().take(beyond) {
            rows.remove(&(tenant, hash));
        }
        rows.insert((tenant, pushed.reference_hash), pushed.clone());
        Ok(())
    }

    async fn take_pushed(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
        hash: &ReferenceHash,
    ) -> Result<Option<PushedAuthorization>, DomainError> {
        let key = (uow.tenant().tenant_id(), *hash);
        let mut rows = lock(&self.pushed);
        if rows
            .get(&key)
            .is_some_and(|pushed| pushed.request.client_id == client)
        {
            Ok(rows.remove(&key))
        } else {
            Ok(None)
        }
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

    pub(super) fn exists(&self, tenant: TenantId, id: GrantId) -> bool {
        lock(&self.rows).contains_key(&(tenant, id))
    }

    /// Every grant of `tenant`, for tests that look behind the use cases.
    #[must_use]
    pub fn all(&self, tenant: TenantId) -> Vec<Grant> {
        lock(&self.rows)
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, grant)| grant.clone())
            .collect()
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

    async fn list_active_for(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
        client: ClientId,
    ) -> Result<Vec<Grant>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows)
            .iter()
            .filter(|((owner, _), grant)| {
                *owner == tenant
                    && grant.user_id == user
                    && grant.client_id == client
                    && grant.status == GrantStatus::Active
            })
            .map(|(_, grant)| grant.clone())
            .collect())
    }

    async fn list_active_of(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
    ) -> Result<Vec<Grant>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut found: Vec<Grant> = lock(&self.rows)
            .iter()
            .filter(|((owner, _), grant)| {
                *owner == tenant && grant.user_id == user && grant.status == GrantStatus::Active
            })
            .map(|(_, grant)| grant.clone())
            .collect();
        found.sort_by_key(|grant| (grant.created_at, grant.id));
        Ok(found)
    }
}

/// The codes of every tenant, by tenant and hash.
type CodeRows = BTreeMap<(TenantId, [u8; 32]), AuthorizationCode>;

/// Codes kept in memory, by tenant and hash.
#[derive(Debug, Clone)]
pub struct InMemoryAuthorizationCodes {
    grants: InMemoryGrants,
    rows: Arc<Mutex<CodeRows>>,
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
        first_party: true,
        organization: None,
        id_token_hint: None,
        given_hint: None,
        claims: crate::api::ClaimsRequest::default(),
        claims_locales: None,
        // Kept and read back: a hybrid request answered as a form, so that
        // both the type and the mode are kept.
        response_type: crate::api::ResponseType::CodeIdToken,
        response_mode: crate::api::ResponseMode::FormPost,
    }
}

fn person() -> SignedInPerson {
    SignedInPerson {
        user_id: UserId::generate(),
        session_id: SessionId::generate(),
        signed_in_at: moment(),
        methods: vec!["password".to_owned(), "otp".to_owned()],
        acr: Some("urn:hodor:acr:mfa".to_owned()),
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
    a_pushed_request_is_taken_once_by_its_client(ports).await;
    a_client_keeps_only_its_newest_pushed_requests(ports).await;
    a_request_waiting_for_consent_is_answered_once(ports).await;
    a_grant_is_stored_and_its_revocation_kept(ports).await;
    the_active_grants_of_a_person_for_a_client_are_listed(ports).await;
    a_code_is_found_by_its_hash_and_redeemed_once(ports).await;
    rows_reference_their_own_tenant(ports).await;
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

async fn a_pending_request_is_stored_whole_and_removed_once(ports: AuthorizationStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let mut request = request_for(client.id());
    request.claims = crate::api::ClaimsRequest {
        id_token: vec!["email".to_owned()],
        userinfo: vec!["name".to_owned()],
        subject: Some("someone".to_owned()),
    };
    request.claims_locales = Some("fr-CA".to_owned());
    let (pending, _) =
        PendingAuthorization::hold(request, moment(), &super::DistinctRandom, &FakeDigest);
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

fn pushed_for(client_id: ClientId, received_at: Timestamp) -> PushedAuthorization {
    PushedAuthorization::push(
        request_for(client_id),
        Duration::seconds(60),
        received_at,
        &super::DistinctRandom,
        &FakeDigest,
    )
    .0
}

async fn take(
    ports: AuthorizationStorePorts<'_>,
    tenant: &TenantContext,
    client: ClientId,
    hash: &ReferenceHash,
) -> Option<PushedAuthorization> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let taken = ports
        .requests
        .take_pushed(uow.as_mut(), client, hash)
        .await
        .expect("take");
    uow.commit().await.expect("commit");
    taken
}

async fn a_pushed_request_is_taken_once_by_its_client(ports: AuthorizationStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let other_client = a_client(ports, &tenant).await;
    let pushed = pushed_for(client.id(), moment());
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .requests
        .push(uow.as_mut(), &pushed, 5)
        .await
        .expect("push");
    uow.commit().await.expect("commit");

    // It is no browser's: it cannot be read or removed as one.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .requests
            .get(uow.as_mut(), pushed.id)
            .await
            .expect("get"),
        None
    );
    assert!(
        !ports
            .requests
            .remove(uow.as_mut(), pushed.id)
            .await
            .expect("remove")
    );
    uow.commit().await.expect("commit");

    // Another client and another tenant do not find it, and leave it.
    assert_eq!(
        take(ports, &tenant, other_client.id(), &pushed.reference_hash).await,
        None,
        "another client's reference is unknown"
    );
    let elsewhere = self::tenant();
    assert_eq!(
        take(ports, &elsewhere, client.id(), &pushed.reference_hash).await,
        None,
        "another tenant's reference is unknown"
    );

    assert_eq!(
        take(ports, &tenant, client.id(), &pushed.reference_hash).await,
        Some(pushed.clone()),
        "taken whole by its client"
    );
    assert_eq!(
        take(ports, &tenant, client.id(), &pushed.reference_hash).await,
        None,
        "taken once"
    );

    // A pushed request of a client that does not exist is refused.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let error = ports
        .requests
        .push(uow.as_mut(), &pushed_for(ClientId::generate(), moment()), 5)
        .await
        .expect_err("no such client");
    assert_eq!(error.code(), "oauth.client_not_found");
}

async fn a_client_keeps_only_its_newest_pushed_requests(ports: AuthorizationStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let other_client = a_client(ports, &tenant).await;
    // The other client's waiting request is not one of this client's.
    let others = pushed_for(other_client.id(), moment());
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .requests
        .push(uow.as_mut(), &others, 5)
        .await
        .expect("push");
    uow.commit().await.expect("commit");
    let mut kept = Vec::new();
    for second in 0..7 {
        let pushed = pushed_for(client.id(), moment() + Duration::seconds(second));
        let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
        ports
            .requests
            .push(uow.as_mut(), &pushed, 5)
            .await
            .expect("push");
        uow.commit().await.expect("commit");
        kept.push(pushed);
    }
    for (index, pushed) in kept.iter().enumerate() {
        let taken = take(ports, &tenant, client.id(), &pushed.reference_hash).await;
        assert_eq!(
            taken.is_some(),
            index >= 2,
            "the two oldest went, the newest five wait: {index}"
        );
    }
    assert!(
        take(ports, &tenant, other_client.id(), &others.reference_hash)
            .await
            .is_some(),
        "another client's request stays"
    );
}

async fn a_request_waiting_for_consent_is_answered_once(ports: AuthorizationStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let asked = person();
    let (pending, _) = PendingAuthorization::hold_for_consent(
        request_for(client.id()),
        &asked,
        moment(),
        &super::DistinctRandom,
        &FakeDigest,
    );
    let (signing_in, _) = PendingAuthorization::hold(
        request_for(client.id()),
        moment(),
        &super::DistinctRandom,
        &FakeDigest,
    );
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    for kept in [&pending, &signing_in] {
        ports
            .requests
            .insert(uow.as_mut(), kept)
            .await
            .expect("insert");
    }
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .requests
            .get(uow.as_mut(), pending.id)
            .await
            .expect("get"),
        Some(pending.clone()),
        "stored whole, with whom it waits for"
    );
    assert!(
        !ports
            .requests
            .answer(uow.as_mut(), signing_in.id, ConsentAnswer::Agreed)
            .await
            .expect("answer"),
        "a request that waits for a sign-in has no answer to record"
    );
    drop(uow);

    let elsewhere = self::tenant();
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert!(
        !ports
            .requests
            .answer(uow.as_mut(), pending.id, ConsentAnswer::Agreed)
            .await
            .expect("answer"),
        "another tenant cannot answer it"
    );
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        ports
            .requests
            .answer(uow.as_mut(), pending.id, ConsentAnswer::Refused)
            .await
            .expect("answer")
    );
    assert!(
        !ports
            .requests
            .answer(uow.as_mut(), pending.id, ConsentAnswer::Agreed)
            .await
            .expect("answer"),
        "answered once"
    );
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let stored = ports
        .requests
        .get(uow.as_mut(), pending.id)
        .await
        .expect("get")
        .expect("found");
    assert_eq!(
        stored.consent.and_then(|wait| wait.answer),
        Some(ConsentAnswer::Refused)
    );
}

async fn the_active_grants_of_a_person_for_a_client_are_listed(ports: AuthorizationStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let other_client = a_client(ports, &tenant).await;
    let someone = person();
    let request = request_for(client.id());
    let first = Grant::make(&request, &someone, moment());
    let mut second = Grant::make(&request, &someone, moment());
    second.organization = Some(OrganizationId::generate());
    let mut revoked = Grant::make(&request, &someone, moment());
    revoked.revoke("code_reused", moment());
    let another_person = Grant::make(&request, &person(), moment());
    let another_client = Grant::make(&request_for(other_client.id()), &someone, moment());
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    for grant in [&first, &second, &revoked, &another_person, &another_client] {
        ports
            .grants
            .insert(uow.as_mut(), grant)
            .await
            .expect("insert");
    }
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .grants
            .get(uow.as_mut(), second.id)
            .await
            .expect("get")
            .as_ref(),
        Some(&second),
        "a grant reads back as it was stored, its organization included"
    );
    let mut listed: Vec<GrantId> = ports
        .grants
        .list_active_for(uow.as_mut(), someone.user_id, client.id())
        .await
        .expect("list")
        .into_iter()
        .map(|grant| grant.id)
        .collect();
    listed.sort();
    let mut expected = vec![first.id, second.id];
    expected.sort();
    assert_eq!(listed, expected);
    let mut of_person: Vec<GrantId> = ports
        .grants
        .list_active_of(uow.as_mut(), someone.user_id)
        .await
        .expect("list")
        .into_iter()
        .map(|grant| grant.id)
        .collect();
    of_person.sort();
    let mut expected = vec![first.id, second.id, another_client.id];
    expected.sort();
    assert_eq!(
        of_person, expected,
        "every client's active grants of the person"
    );
    drop(uow);

    let elsewhere = self::tenant();
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert!(
        ports
            .grants
            .list_active_for(uow.as_mut(), someone.user_id, client.id())
            .await
            .expect("list")
            .is_empty(),
        "another tenant sees none"
    );
    assert!(
        ports
            .grants
            .list_active_of(uow.as_mut(), someone.user_id)
            .await
            .expect("list")
            .is_empty(),
        "another tenant sees none of the person's grants"
    );
}

async fn a_grant_is_stored_and_its_revocation_kept(ports: AuthorizationStorePorts<'_>) {
    let tenant = tenant();
    let client = a_client(ports, &tenant).await;
    let mut grant = Grant::make(&request_for(client.id()), &person(), moment());
    // What it gives through the `claims` parameter is kept, in order.
    grant.claims = crate::api::GrantClaims {
        id_token: vec!["name".to_owned(), "email".to_owned()],
        userinfo: vec!["phone_number".to_owned()],
    };
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
