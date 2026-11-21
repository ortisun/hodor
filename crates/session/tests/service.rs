//! The session use cases, run against the in-memory store.

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp, UserId};
use hodor_session::api::{
    Assurance, ClientInfo, Session, SessionId, SessionService, SessionTimeouts, SessionToken,
    StartSession,
};
use hodor_session::testing::{InMemorySessions, Ports, SequentialRandom, run_contract};
use std::sync::Arc;
use time::Duration;

struct World {
    service: SessionService,
    clock: Arc<FixedClock>,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
    user: UserId,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let service = SessionService::new(
        Arc::new(units_of_work.clone()),
        Arc::new(InMemorySessions::default()),
        Arc::new(FakeDigest),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    );
    World {
        service,
        clock,
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
        user: UserId::generate(),
    }
}

impl World {
    async fn start(&self) -> (Session, SessionToken) {
        let command = StartSession {
            user_id: self.user,
            assurance: Assurance::SingleFactor,
            methods: vec!["password".to_owned()],
            timeouts: SessionTimeouts {
                idle: Duration::minutes(30),
                absolute: Duration::hours(12),
            },
            client: ClientInfo::default(),
        };
        self.service
            .start(&self.tenant, command, Caller::system())
            .await
            .expect("start")
    }

    async fn find(&self, token: &str) -> Option<SessionId> {
        self.service
            .find_by_token(&self.tenant, token)
            .await
            .expect("find")
            .map(|session| session.id())
    }
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let sessions = InMemorySessions::default();
    run_contract(Ports {
        units_of_work: &units_of_work,
        sessions: &sessions,
    })
    .await;
}

#[tokio::test]
async fn a_started_session_is_found_by_its_token_and_by_nothing_else() {
    let world = world();
    let (session, token) = world.start().await;

    assert_eq!(world.find(token.expose()).await, Some(session.id()));
    let upper = token.expose().to_uppercase();
    let identifier = session.id().to_string();
    for other in ["", "not a token", &upper, &identifier, &"f".repeat(64)] {
        assert_eq!(world.find(other).await, None, "{other}");
    }
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["session.started"]
    );
}

#[tokio::test]
async fn neither_the_token_nor_its_hash_reaches_an_event() {
    let world = world();
    let (_, token) = world.start().await;
    let published = format!("{:?}", world.units_of_work.committed_events());
    assert!(!published.contains(token.expose()), "{published}");
}

#[tokio::test]
async fn a_token_of_one_tenant_finds_nothing_in_another() {
    let world = world();
    let (_, token) = world.start().await;
    let elsewhere = TenantContext::assume(TenantId::generate());
    let found = world
        .service
        .find_by_token(&elsewhere, token.expose())
        .await
        .expect("find");
    assert_eq!(found, None);
}

#[tokio::test]
async fn an_idle_session_expires_and_use_keeps_it_alive_only_until_the_absolute_expiry() {
    let world = world();
    let (session, token) = world.start().await;

    // Used every 20 minutes, it stays alive well past the idle timeout...
    for _ in 0..35 {
        world.clock.advance(Duration::minutes(20));
        assert_eq!(world.find(token.expose()).await, Some(session.id()));
    }
    // ...until the absolute expiry, twelve hours after the start.
    world.clock.advance(Duration::minutes(20));
    assert_eq!(world.find(token.expose()).await, None);

    // A second session left alone expires after the idle timeout.
    let (_, idle_token) = world.start().await;
    world.clock.advance(Duration::minutes(30));
    assert_eq!(world.find(idle_token.expose()).await, None);
}

#[tokio::test]
async fn a_revoked_session_is_not_found_and_revoking_is_announced_once() {
    let world = world();
    let (session, token) = world.start().await;

    for _ in 0..2 {
        world
            .service
            .revoke(&world.tenant, session.id(), "signed out", Caller::system())
            .await
            .expect("revoke");
    }

    assert_eq!(world.find(token.expose()).await, None);
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["session.started", "session.revoked"]
    );
    let missing = world
        .service
        .revoke(&world.tenant, SessionId::generate(), "x", Caller::system())
        .await
        .expect_err("unknown");
    assert_eq!(missing.code(), "session.not_found");
}

#[tokio::test]
async fn a_password_change_ends_every_other_session_of_the_user() {
    let world = world();
    let (current, current_token) = world.start().await;
    let (_, other_token) = world.start().await;
    let (_, third_token) = world.start().await;
    let someone_else = World {
        user: UserId::generate(),
        ..world
    };
    let (_, their_token) = someone_else.start().await;

    let ended = someone_else
        .service
        .revoke_all_for_user(
            &someone_else.tenant,
            current.user_id(),
            Some(current.id()),
            "password changed",
            Caller::system(),
        )
        .await
        .expect("revoke all");

    assert_eq!(ended, 2);
    assert_eq!(
        someone_else.find(current_token.expose()).await,
        Some(current.id())
    );
    assert_eq!(someone_else.find(other_token.expose()).await, None);
    assert_eq!(someone_else.find(third_token.expose()).await, None);
    assert!(
        someone_else.find(their_token.expose()).await.is_some(),
        "another user is untouched"
    );
}

#[tokio::test]
async fn only_active_sessions_are_listed() {
    let world = world();
    let (first, _) = world.start().await;
    world.clock.advance(Duration::minutes(40));
    let (second, _) = world.start().await;
    let (third, _) = world.start().await;
    world
        .service
        .revoke(&world.tenant, third.id(), "signed out", Caller::system())
        .await
        .expect("revoke");

    let listed: Vec<SessionId> = world
        .service
        .list_for_user(&world.tenant, world.user)
        .await
        .expect("list")
        .iter()
        .map(Session::id)
        .collect();

    // The first has been idle for too long; the third was revoked.
    assert_eq!(listed, [second.id()]);
    assert_ne!(first.id(), second.id());
}

#[tokio::test]
async fn replacing_the_token_keeps_the_session_and_retires_the_old_token() {
    let world = world();
    let (session, old) = world.start().await;

    let new = world
        .service
        .replace_token(&world.tenant, session.id())
        .await
        .expect("replace");

    assert_eq!(world.find(old.expose()).await, None);
    assert_eq!(world.find(new.expose()).await, Some(session.id()));
}

#[tokio::test]
async fn a_person_can_end_only_their_own_active_sessions() {
    let world = world();
    let (session, token) = world.start().await;
    let (other, other_token) = world.start().await;
    let stranger = UserId::generate();
    let end = |user: UserId, id: SessionId| {
        let world = &world;
        async move {
            world
                .service
                .revoke_for_user(&world.tenant, user, id, "sign_out", Caller::system())
                .await
        }
    };

    // Someone else's session, and one that does not exist, look the same.
    for (user, id) in [
        (stranger, session.id()),
        (world.user, SessionId::generate()),
    ] {
        let error = end(user, id).await.expect_err("refused");
        assert_eq!(error.code(), "session.not_found");
    }
    assert!(world.find(token.expose()).await.is_some());

    end(world.user, session.id()).await.expect("ended");
    assert!(world.find(token.expose()).await.is_none());
    assert!(world.find(other_token.expose()).await.is_some());
    assert_eq!(
        world
            .units_of_work
            .committed_event_types()
            .last()
            .map(String::as_str),
        Some("session.revoked")
    );

    // A session that has already ended is not found either, whether it
    // was ended on purpose or expired.
    let error = end(world.user, session.id())
        .await
        .expect_err("already ended");
    assert_eq!(error.code(), "session.not_found");
    world.clock.advance(Duration::hours(13));
    let error = end(world.user, other.id()).await.expect_err("expired");
    assert_eq!(error.code(), "session.not_found");
}
