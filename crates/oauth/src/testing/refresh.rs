//! Refresh token families kept in memory, a stand-in for the standing of
//! people, and the contract every store of refresh tokens passes.

use super::{InMemoryGrants, lock};
use crate::api::{
    Application, ApplicationSettings, ApplicationStore, AuthorizationCode, Client, ClientId,
    ClientSecret, ClientSettings, ClientStore, ClientType, CodeHash, FamilyStatus, Grant, GrantId,
    GrantStatus, GrantStore, GrantType, PersonMemberships, PersonStanding, RefreshAsk,
    RefreshFamily, RefreshFamilyId, RefreshTokenHash, RefreshTokenRecord, RefreshTokenStore,
    TokenPolicy,
};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    DomainError, GroupId, OrganizationId, SealedSecret, TenantContext, TenantId, Timestamp,
    UnitOfWork, UnitOfWorkFactory, UserId,
};
use hodor_session::api::SessionId;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use time::Duration;

fn grant_not_found() -> DomainError {
    DomainError::not_found("oauth.grant_not_found", "there is no such grant")
}

fn family_not_found() -> DomainError {
    DomainError::not_found(
        "oauth.refresh_token_family_not_found",
        "there is no such refresh token family",
    )
}

#[derive(Debug, Default)]
struct Rows {
    families: BTreeMap<(TenantId, RefreshFamilyId), RefreshFamily>,
    tokens: BTreeMap<(TenantId, [u8; 32]), RefreshTokenRecord>,
}

/// Refresh token families and their tokens kept in memory. They know the
/// grants they are stored against, as the database knows its references.
#[derive(Debug, Clone)]
pub struct InMemoryRefreshTokens {
    grants: InMemoryGrants,
    rows: Arc<Mutex<Rows>>,
}

impl InMemoryRefreshTokens {
    /// Families of the grants in `grants`.
    #[must_use]
    pub fn new(grants: &InMemoryGrants) -> Self {
        Self {
            grants: grants.clone(),
            rows: Arc::default(),
        }
    }

    /// Every family of `tenant`, for tests that look behind the use cases.
    #[must_use]
    pub fn all(&self, tenant: TenantId) -> Vec<RefreshFamily> {
        lock(&self.rows)
            .families
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, family)| family.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl RefreshTokenStore for InMemoryRefreshTokens {
    async fn start(
        &self,
        uow: &mut dyn UnitOfWork,
        family: &RefreshFamily,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self.grants.exists(tenant, family.grant_id) {
            return Err(grant_not_found());
        }
        let mut rows = lock(&self.rows);
        rows.families.insert((tenant, family.id), family.clone());
        let record = family.first_record();
        rows.tokens
            .insert((tenant, *record.hash.as_bytes()), record);
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &RefreshTokenHash,
    ) -> Result<Option<(RefreshFamily, RefreshTokenRecord)>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows = lock(&self.rows);
        Ok(rows
            .tokens
            .get(&(tenant, *hash.as_bytes()))
            .and_then(|record| {
                rows.families
                    .get(&(tenant, record.family_id))
                    .map(|family| (family.clone(), *record))
            }))
    }

    async fn advance(
        &self,
        uow: &mut dyn UnitOfWork,
        family: RefreshFamilyId,
        from_generation: i32,
        next: &RefreshTokenHash,
        asked: &RefreshAsk,
        at: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = lock(&self.rows);
        let Some(stored) = rows.families.get_mut(&(tenant, family)) else {
            return Ok(false);
        };
        if stored.status != FamilyStatus::Active || stored.generation != from_generation {
            return Ok(false);
        }
        stored.generation = from_generation + 1;
        stored.current_hash = *next;
        stored.moved_at = Some(at);
        stored.moved_for = asked.clone();
        stored.last_used_at = at;
        let record = RefreshTokenRecord {
            hash: *next,
            family_id: family,
            generation: from_generation + 1,
            issued_at: at,
        };
        rows.tokens.insert((tenant, *next.as_bytes()), record);
        Ok(true)
    }

    async fn revoke(
        &self,
        uow: &mut dyn UnitOfWork,
        family: &RefreshFamily,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), family.id);
        let mut rows = lock(&self.rows);
        let stored = rows.families.get_mut(&key).ok_or_else(family_not_found)?;
        stored.status = family.status;
        stored.revoked_at = family.revoked_at;
        stored
            .revocation_reason
            .clone_from(&family.revocation_reason);
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: RefreshFamilyId,
    ) -> Result<Option<RefreshFamily>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows).families.get(&(tenant, id)).cloned())
    }
}

/// A stand-in for the session and identity contexts: every person may sign
/// in and every session is active, except those the test ends; only the
/// workloads the test names may act, until it bars them.
#[derive(Debug, Clone, Default)]
pub struct StandingOf {
    ended_sessions: Arc<Mutex<BTreeSet<SessionId>>>,
    barred_users: Arc<Mutex<BTreeSet<UserId>>>,
    workloads: Arc<Mutex<std::collections::BTreeMap<UserId, &'static str>>>,
}

impl StandingOf {
    /// Ends `session`.
    pub fn end_session(&self, session: SessionId) {
        lock(&self.ended_sessions).insert(session);
    }

    /// Bars `user` from signing in, or from acting if it is a workload.
    pub fn bar(&self, user: UserId) {
        lock(&self.barred_users).insert(user);
    }

    /// Makes `principal` a workload of `kind`, `service_account` or
    /// `agent`, that may act.
    pub fn workload(&self, principal: UserId, kind: &'static str) {
        lock(&self.workloads).insert(principal, kind);
    }
}

#[async_trait::async_trait]
impl PersonStanding for StandingOf {
    async fn session_is_active(
        &self,
        _tenant: &TenantContext,
        _user: UserId,
        session: SessionId,
    ) -> Result<bool, DomainError> {
        Ok(!lock(&self.ended_sessions).contains(&session))
    }

    async fn may_sign_in(
        &self,
        _tenant: &TenantContext,
        user: UserId,
    ) -> Result<bool, DomainError> {
        Ok(!lock(&self.barred_users).contains(&user) && !lock(&self.workloads).contains_key(&user))
    }

    async fn workload_that_may_act(
        &self,
        _tenant: &TenantContext,
        principal: UserId,
    ) -> Result<Option<&'static str>, DomainError> {
        if lock(&self.barred_users).contains(&principal) {
            return Ok(None);
        }
        Ok(lock(&self.workloads).get(&principal).copied())
    }
}

/// [`PersonMemberships`] answered from what a test sets: nobody is a
/// member of anything, and in no group, until a test says so.
#[derive(Debug, Clone, Default)]
pub struct MembershipsOf {
    members: Arc<Mutex<BTreeSet<(UserId, OrganizationId)>>>,
    groups: Arc<Mutex<BTreeMap<UserId, Vec<GroupId>>>>,
}

impl MembershipsOf {
    /// Makes `user` a member of `organization`.
    pub fn join(&self, user: UserId, organization: OrganizationId) {
        lock(&self.members).insert((user, organization));
    }

    /// Takes `user` out of `organization`.
    pub fn leave(&self, user: UserId, organization: OrganizationId) {
        lock(&self.members).remove(&(user, organization));
    }

    /// Sets the effective groups of `user`.
    pub fn set_groups(&self, user: UserId, groups: Vec<GroupId>) {
        lock(&self.groups).insert(user, groups);
    }
}

#[async_trait::async_trait]
impl PersonMemberships for MembershipsOf {
    async fn is_member(
        &self,
        _tenant: &TenantContext,
        user: UserId,
        organization: OrganizationId,
    ) -> Result<bool, DomainError> {
        Ok(lock(&self.members).contains(&(user, organization)))
    }

    async fn effective_groups(
        &self,
        _tenant: &TenantContext,
        user: UserId,
    ) -> Result<Vec<GroupId>, DomainError> {
        Ok(lock(&self.groups).get(&user).cloned().unwrap_or_default())
    }
}

/// The ports of the refresh token contract.
#[derive(Clone, Copy)]
pub struct RefreshStorePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// Where the applications of the clients are stored.
    pub applications: &'a dyn ApplicationStore,
    /// Where the clients of the grants are stored.
    pub clients: &'a dyn ClientStore,
    /// Where the grants the families reference are stored.
    pub grants: &'a dyn GrantStore,
    /// The store under test.
    pub refresh_tokens: &'a dyn RefreshTokenStore,
}

impl std::fmt::Debug for RefreshStorePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshStorePorts").finish_non_exhaustive()
    }
}

/// A moment whole to the microsecond, as PostgreSQL keeps it.
fn moment() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

/// A grant of a new client of `tenant`, stored.
async fn a_grant(ports: RefreshStorePorts<'_>, tenant: &TenantContext) -> Grant {
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
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            vec!["com.example.payroll:/callback".to_owned()],
        ),
        ClientSecret::DEFAULT_LIFETIME,
        moment(),
        &super::DistinctRandom,
        &FakeDigest,
    )
    .expect("client")
    .0;
    let grant = Grant {
        id: GrantId::generate(),
        client_id: client.id(),
        user_id: UserId::generate(),
        session_id: SessionId::generate(),
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        audiences: vec!["https://api.payroll.example.com".to_owned()],
        organization: None,
        status: GrantStatus::Active,
        created_at: moment(),
        revoked_at: None,
        revocation_reason: None,
    };
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
    ports
        .grants
        .insert(uow.as_mut(), &grant)
        .await
        .expect("grant");
    uow.commit().await.expect("commit");
    grant
}

/// A family for `grant`, not stored.
fn family_of(grant: &Grant, client: ClientId) -> (RefreshFamily, RefreshTokenHash) {
    let code = AuthorizationCode {
        hash: CodeHash::from_stored([4; 32]),
        grant_id: grant.id,
        client_id: client,
        redirect_uri: "com.example.payroll:/callback".to_owned(),
        scopes: grant.scopes.clone(),
        audiences: grant.audiences.clone(),
        code_challenge: None,
        nonce: None,
        session_id: grant.session_id,
        user_id: grant.user_id,
        signed_in_at: moment() - Duration::minutes(3),
        methods: vec!["password".to_owned(), "totp".to_owned()],
        acr: Some("urn:hodor:acr:mfa".to_owned()),
        issued_at: moment(),
        expires_at: moment() + Duration::seconds(60),
        redeemed_at: Some(moment()),
    };
    let (family, _) = RefreshFamily::start(
        &code,
        &TokenPolicy::default(),
        SealedSecret::from_stored(vec![5; 60]),
        moment(),
        &super::DistinctRandom,
        &FakeDigest,
    );
    let hash = family.current_hash;
    (family, hash)
}

/// Runs every rule a store of refresh tokens must obey. Each case uses
/// tenants of its own, so runs can share one database.
///
/// # Panics
///
/// Panics when an implementation breaks a rule.
pub async fn run_refresh_token_contract(ports: RefreshStorePorts<'_>) {
    a_family_is_stored_whole_and_found_by_its_token(ports).await;
    a_family_moves_once_from_a_generation_and_keeps_its_tokens(ports).await;
    a_revocation_is_kept_and_stops_moving(ports).await;
    families_belong_to_their_own_tenant(ports).await;
    a_family_is_found_by_its_identifier(ports).await;
}

async fn a_family_is_found_by_its_identifier(ports: RefreshStorePorts<'_>) {
    let tenant = tenant();
    let grant = a_grant(ports, &tenant).await;
    let (family, _) = family_of(&grant, grant.client_id);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .refresh_tokens
        .start(uow.as_mut(), &family)
        .await
        .expect("start");
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let found = ports
        .refresh_tokens
        .get(uow.as_mut(), family.id)
        .await
        .expect("get")
        .expect("found");
    assert_eq!(found, family, "found whole");
    assert!(
        ports
            .refresh_tokens
            .get(uow.as_mut(), RefreshFamilyId::generate())
            .await
            .expect("get")
            .is_none()
    );
    drop(uow);

    let elsewhere = self::tenant();
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert!(
        ports
            .refresh_tokens
            .get(uow.as_mut(), family.id)
            .await
            .expect("get")
            .is_none(),
        "another tenant does not see the family"
    );
}

async fn a_family_is_stored_whole_and_found_by_its_token(ports: RefreshStorePorts<'_>) {
    let tenant = tenant();
    let grant = a_grant(ports, &tenant).await;
    let (family, hash) = family_of(&grant, grant.client_id);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .refresh_tokens
        .start(uow.as_mut(), &family)
        .await
        .expect("start");
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let (found, record) = ports
        .refresh_tokens
        .find(uow.as_mut(), &hash)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(found, family, "stored whole");
    assert_eq!(record, family.first_record());
    assert!(
        ports
            .refresh_tokens
            .find(uow.as_mut(), &RefreshTokenHash::from_stored([0; 32]))
            .await
            .expect("find")
            .is_none(),
        "an unknown token finds nothing"
    );
}

async fn a_family_moves_once_from_a_generation_and_keeps_its_tokens(ports: RefreshStorePorts<'_>) {
    let tenant = tenant();
    let grant = a_grant(ports, &tenant).await;
    let (family, first) = family_of(&grant, grant.client_id);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .refresh_tokens
        .start(uow.as_mut(), &family)
        .await
        .expect("start");
    uow.commit().await.expect("commit");

    let second = RefreshTokenHash::from_stored([2; 32]);
    let asked = RefreshAsk {
        scopes: vec!["openid".to_owned()],
        resource: Some("https://api.payroll.example.com".to_owned()),
    };
    let at = moment() + Duration::minutes(10);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        ports
            .refresh_tokens
            .advance(uow.as_mut(), family.id, 1, &second, &asked, at)
            .await
            .expect("advance"),
        "the first move from generation 1 moves"
    );
    assert!(
        !ports
            .refresh_tokens
            .advance(
                uow.as_mut(),
                family.id,
                1,
                &RefreshTokenHash::from_stored([3; 32]),
                &asked,
                at
            )
            .await
            .expect("advance"),
        "a second move from generation 1 does not"
    );
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let (moved, record) = ports
        .refresh_tokens
        .find(uow.as_mut(), &second)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(record.generation, 2);
    assert_eq!(moved.generation, 2);
    assert_eq!(moved.current_hash, second);
    assert_eq!(moved.moved_at, Some(at));
    assert_eq!(moved.moved_for, asked);
    assert_eq!(moved.last_used_at, at);
    let (_, old) = ports
        .refresh_tokens
        .find(uow.as_mut(), &first)
        .await
        .expect("find")
        .expect("an earlier token is still known");
    assert_eq!(old.generation, 1, "known as one generation old");
    assert!(
        ports
            .refresh_tokens
            .find(uow.as_mut(), &RefreshTokenHash::from_stored([3; 32]))
            .await
            .expect("find")
            .is_none(),
        "the losing move left nothing"
    );
}

async fn a_revocation_is_kept_and_stops_moving(ports: RefreshStorePorts<'_>) {
    let tenant = tenant();
    let grant = a_grant(ports, &tenant).await;
    let (mut family, hash) = family_of(&grant, grant.client_id);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .refresh_tokens
        .start(uow.as_mut(), &family)
        .await
        .expect("start");
    family
        .revoke("refresh_token_reused", moment())
        .expect("revoked");
    ports
        .refresh_tokens
        .revoke(uow.as_mut(), &family)
        .await
        .expect("revoke");
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let (found, _) = ports
        .refresh_tokens
        .find(uow.as_mut(), &hash)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(found.status, FamilyStatus::Revoked);
    assert_eq!(found.revoked_at, Some(moment()));
    assert_eq!(
        found.revocation_reason.as_deref(),
        Some("refresh_token_reused")
    );
    assert!(
        !ports
            .refresh_tokens
            .advance(
                uow.as_mut(),
                family.id,
                1,
                &RefreshTokenHash::from_stored([8; 32]),
                &RefreshAsk::default(),
                moment()
            )
            .await
            .expect("advance"),
        "a revoked family does not move"
    );
}

async fn families_belong_to_their_own_tenant(ports: RefreshStorePorts<'_>) {
    let acme = tenant();
    let globex = tenant();
    let grant = a_grant(ports, &acme).await;
    let (family, hash) = family_of(&grant, grant.client_id);

    let mut uow = ports.units_of_work.begin(&globex).await.expect("begin");
    let error = ports
        .refresh_tokens
        .start(uow.as_mut(), &family)
        .await
        .expect_err("a grant of another tenant");
    assert_eq!(error.code(), "oauth.grant_not_found");
    drop(uow);

    let mut uow = ports.units_of_work.begin(&acme).await.expect("begin");
    ports
        .refresh_tokens
        .start(uow.as_mut(), &family)
        .await
        .expect("start");
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&globex).await.expect("begin");
    assert!(
        ports
            .refresh_tokens
            .find(uow.as_mut(), &hash)
            .await
            .expect("find")
            .is_none(),
        "another tenant finds nothing"
    );
    assert!(
        !ports
            .refresh_tokens
            .advance(
                uow.as_mut(),
                family.id,
                1,
                &RefreshTokenHash::from_stored([6; 32]),
                &RefreshAsk::default(),
                moment()
            )
            .await
            .expect("advance"),
        "another tenant moves nothing"
    );
}
