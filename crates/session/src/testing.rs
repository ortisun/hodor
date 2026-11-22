//! In-memory store and the contract every session store passes.

use crate::api::{
    Assurance, ClientInfo, Session, SessionId, SessionStore, SessionTimeouts, SessionToken,
    TokenHash,
};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    DomainError, RandomSource, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
    UserId,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use time::Duration;

/// Sessions kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemorySessions {
    rows: Arc<Mutex<BTreeMap<(TenantId, SessionId), Session>>>,
}

impl InMemorySessions {
    fn rows(&self) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, SessionId), Session>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl SessionStore for InMemorySessions {
    async fn insert(&self, uow: &mut dyn UnitOfWork, session: &Session) -> Result<(), DomainError> {
        self.rows()
            .insert((uow.tenant().tenant_id(), session.id()), session.clone());
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: SessionId,
    ) -> Result<Option<Session>, DomainError> {
        Ok(self.rows().get(&(uow.tenant().tenant_id(), id)).cloned())
    }

    async fn find_by_token_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &TokenHash,
    ) -> Result<Option<Session>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .iter()
            .find(|((owner, _), session)| {
                *owner == tenant && &session.snapshot().token_hash == hash
            })
            .map(|(_, session)| session.clone()))
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, session: &Session) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), session.id());
        let mut rows = self.rows();
        if !rows.contains_key(&key) {
            return Err(DomainError::not_found(
                "session.not_found",
                "the session does not exist",
            ));
        }
        rows.insert(key, session.clone());
        Ok(())
    }

    async fn list_for_user(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        now: Timestamp,
    ) -> Result<Vec<Session>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut found: Vec<Session> = self
            .rows()
            .iter()
            .filter(|((owner, _), session)| {
                let state = session.snapshot();
                *owner == tenant
                    && state.user_id == user_id
                    && state.revoked_at.is_none()
                    && state.absolute_expires_at > now
            })
            .map(|(_, session)| session.clone())
            .collect();
        found.sort_by(|a, b| {
            (b.snapshot().started_at, b.id()).cmp(&(a.snapshot().started_at, a.id()))
        });
        Ok(found)
    }
}

/// A random source for tests that never repeats: tokens made with it are
/// all different, and predictable. Never use outside tests.
#[derive(Debug)]
pub struct SequentialRandom(AtomicU64);

impl Default for SequentialRandom {
    /// Starts at a value whose hexadecimal form has letters, so that tokens
    /// made from it are affected by letter case, as real ones are.
    fn default() -> Self {
        Self(AtomicU64::new(0x0a1b_2c3d_4e5f_6a7b))
    }
}

impl RandomSource for SequentialRandom {
    fn fill(&self, buffer: &mut [u8]) {
        let value = self.0.fetch_add(1, Ordering::SeqCst).to_be_bytes();
        for (byte, source) in buffer.iter_mut().zip(value.iter().cycle()) {
            *byte = *source;
        }
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct Ports<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub sessions: &'a dyn SessionStore,
}

impl std::fmt::Debug for Ports<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

/// A fixed, whole-second moment, so that stored timestamps compare equal
/// after a round trip through any storage.
const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;
const TIMEOUTS: SessionTimeouts = SessionTimeouts {
    idle: Duration::minutes(30),
    absolute: Duration::hours(12),
};

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

fn new_session(
    random: &SequentialRandom,
    user_id: UserId,
    at: Timestamp,
) -> (Session, SessionToken) {
    let client = ClientInfo {
        address: Some("203.0.113.9".to_owned()),
        description: Some("Example Browser 1.0".to_owned()),
    };
    let (session, token, _) = Session::start(
        user_id,
        Assurance::SingleFactor,
        vec!["password".to_owned()],
        TIMEOUTS,
        client,
        at,
        random,
        &FakeDigest,
    )
    .expect("valid session");
    (session, token)
}

async fn insert(ports: &Ports<'_>, tenant: &TenantContext, session: &Session) {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .sessions
        .insert(uow.as_mut(), session)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
}

async fn update(
    ports: &Ports<'_>,
    tenant: &TenantContext,
    session: &Session,
) -> Result<(), DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await?;
    ports.sessions.update(uow.as_mut(), session).await?;
    uow.commit().await
}

async fn get(ports: &Ports<'_>, tenant: &TenantContext, id: SessionId) -> Option<Session> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.sessions.get(uow.as_mut(), id).await.expect("get")
}

async fn find(ports: &Ports<'_>, tenant: &TenantContext, token: &SessionToken) -> Option<Session> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .sessions
        .find_by_token_hash(uow.as_mut(), &token.hash(&FakeDigest))
        .await
        .expect("find")
}

async fn list(
    ports: &Ports<'_>,
    tenant: &TenantContext,
    user_id: UserId,
    now: Timestamp,
) -> Vec<SessionId> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .sessions
        .list_for_user(uow.as_mut(), user_id, now)
        .await
        .expect("list")
        .iter()
        .map(Session::id)
        .collect()
}

/// Runs the whole contract. Each case uses tenants of its own, so runs can
/// share one database.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_contract(ports: Ports<'_>) {
    let random = SequentialRandom::default();
    a_stored_session_is_loaded_unchanged(&ports, &random).await;
    a_session_is_found_by_its_token_within_its_tenant_only(&ports, &random).await;
    changes_are_stored(&ports, &random).await;
    an_update_cannot_reach_another_tenant(&ports, &random).await;
    a_users_sessions_are_listed_newest_first_without_ended_ones(&ports, &random).await;
}

async fn a_stored_session_is_loaded_unchanged(ports: &Ports<'_>, random: &SequentialRandom) {
    let tenant = tenant();
    let (session, _) = new_session(random, UserId::generate(), MOMENT);
    insert(ports, &tenant, &session).await;
    assert_eq!(get(ports, &tenant, session.id()).await, Some(session));
    assert_eq!(get(ports, &tenant, SessionId::generate()).await, None);
}

async fn a_session_is_found_by_its_token_within_its_tenant_only(
    ports: &Ports<'_>,
    random: &SequentialRandom,
) {
    let (home, elsewhere) = (tenant(), tenant());
    let (session, token) = new_session(random, UserId::generate(), MOMENT);
    let (_, unknown) = new_session(random, UserId::generate(), MOMENT);
    insert(ports, &home, &session).await;

    assert_eq!(
        find(ports, &home, &token).await.map(|s| s.id()),
        Some(session.id())
    );
    assert_eq!(find(ports, &home, &unknown).await, None);
    assert_eq!(find(ports, &elsewhere, &token).await, None);
    assert_eq!(get(ports, &elsewhere, session.id()).await, None);
}

async fn changes_are_stored(ports: &Ports<'_>, random: &SequentialRandom) {
    let tenant = tenant();
    let (session, old_token) = new_session(random, UserId::generate(), MOMENT);
    insert(ports, &tenant, &session).await;

    let mut loaded = get(ports, &tenant, session.id()).await.expect("exists");
    let later = MOMENT + Duration::minutes(5);
    assert!(loaded.record_activity(later));
    let new_token = loaded
        .replace_token(later, random, &FakeDigest)
        .expect("replace");
    update(ports, &tenant, &loaded).await.expect("update");

    let stored = get(ports, &tenant, session.id()).await.expect("exists");
    assert_eq!(stored, loaded);
    assert_eq!(stored.snapshot().last_activity_at, later);
    assert_eq!(
        find(ports, &tenant, &old_token).await,
        None,
        "the old token is useless"
    );
    assert_eq!(
        find(ports, &tenant, &new_token).await.map(|s| s.id()),
        Some(session.id())
    );

    let mut ending = stored;
    ending.revoke("signed out", later);
    update(ports, &tenant, &ending).await.expect("update");
    let ended = get(ports, &tenant, session.id())
        .await
        .expect("the row remains");
    assert_eq!(ended.snapshot().revoked_at, Some(later));
    assert_eq!(
        ended.snapshot().revocation_reason.as_deref(),
        Some("signed out")
    );
}

async fn an_update_cannot_reach_another_tenant(ports: &Ports<'_>, random: &SequentialRandom) {
    let (home, elsewhere) = (tenant(), tenant());
    let (session, _) = new_session(random, UserId::generate(), MOMENT);
    insert(ports, &home, &session).await;

    let mut tampered = session.clone();
    tampered.revoke("tampering", MOMENT);
    let error = update(ports, &elsewhere, &tampered)
        .await
        .expect_err("cross-tenant");
    assert_eq!(error.code(), "session.not_found");
    assert_eq!(get(ports, &home, session.id()).await, Some(session));
}

async fn a_users_sessions_are_listed_newest_first_without_ended_ones(
    ports: &Ports<'_>,
    random: &SequentialRandom,
) {
    let tenant = tenant();
    let (user, other_user) = (UserId::generate(), UserId::generate());
    let (first, _) = new_session(random, user, MOMENT);
    let (second, _) = new_session(random, user, MOMENT + Duration::hours(1));
    let (mut revoked, _) = new_session(random, user, MOMENT + Duration::hours(2));
    revoked.revoke("signed out", MOMENT + Duration::hours(2));
    let (theirs, _) = new_session(random, other_user, MOMENT);
    for session in [&first, &second, &revoked, &theirs] {
        insert(ports, &tenant, session).await;
    }

    // Soon after: both live sessions, newest first; never the revoked one
    // or another user's.
    let soon = MOMENT + Duration::hours(3);
    assert_eq!(
        list(ports, &tenant, user, soon).await,
        [second.id(), first.id()]
    );
    // After the first one's absolute expiry, only the second.
    let later = MOMENT + Duration::hours(12) + Duration::minutes(1);
    assert_eq!(list(ports, &tenant, user, later).await, [second.id()]);
    // In another tenant the user has none.
    assert!(list(ports, &self::tenant(), user, soon).await.is_empty());
}
