//! The session store on PostgreSQL.

use hodor_adapters_postgres::PgSessionStore;
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp, UserId};
use hodor_session::api::{Assurance, ClientInfo, SessionService, SessionTimeouts, StartSession};
use hodor_session::testing::{Ports, SequentialRandom, run_contract};
use std::sync::Arc;
use time::Duration;

#[tokio::test]
async fn the_postgres_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_contract(Ports {
        units_of_work: database.app(),
        sessions: &PgSessionStore,
    })
    .await;
}

#[tokio::test]
async fn the_use_cases_work_end_to_end_and_store_no_usable_token() {
    let database = TestDatabase::start().await;
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let service = SessionService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgSessionStore),
        Arc::new(FakeDigest),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    );
    let tenant = TenantContext::assume(TenantId::generate());
    let command = StartSession {
        user_id: UserId::generate(),
        assurance: Assurance::SingleFactor,
        methods: vec!["password".to_owned()],
        timeouts: SessionTimeouts {
            idle: Duration::minutes(30),
            absolute: Duration::hours(12),
        },
        client: ClientInfo {
            address: Some("203.0.113.9".to_owned()),
            description: Some("Example Browser".to_owned()),
        },
    };

    let (session, token) = service
        .start(&tenant, command, Caller::system())
        .await
        .expect("start");

    // Nothing in the row or in the event contains the token.
    let everything: String = sqlx::query_scalar(
        "SELECT (SELECT string_agg(to_jsonb(s)::text, '') FROM session.session s)
             || (SELECT string_agg(to_jsonb(o)::text, '') FROM platform.outbox o)",
    )
    .fetch_one(database.owner())
    .await
    .expect("dump");
    assert!(
        !everything.contains(token.expose()),
        "the token must not be stored"
    );

    // Activity is written back, at most once a minute.
    clock.advance(Duration::seconds(30));
    service
        .find_by_token(&tenant, token.expose())
        .await
        .expect("find");
    clock.advance(Duration::seconds(45));
    let found = service
        .find_by_token(&tenant, token.expose())
        .await
        .expect("find")
        .expect("active");
    assert_eq!(found.id(), session.id());
    let last_activity: Timestamp =
        sqlx::query_scalar("SELECT last_activity_at FROM session.session")
            .fetch_one(database.owner())
            .await
            .expect("last activity");
    assert_eq!(last_activity, Timestamp::UNIX_EPOCH + Duration::seconds(75));

    service
        .revoke(&tenant, session.id(), "signed out", Caller::system())
        .await
        .expect("revoke");
    assert_eq!(
        service
            .find_by_token(&tenant, token.expose())
            .await
            .expect("find"),
        None
    );
}

#[tokio::test]
async fn the_database_refuses_a_token_hash_of_the_wrong_size() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let mut tx = database.app().begin(&tenant).await.expect("begin");
    let short = sqlx::query(
        "INSERT INTO session.session
             (tenant_id, id, user_id, token_hash, signed_in_at, assurance, methods, started_at,
              last_activity_at, idle_timeout_seconds, absolute_expires_at)
         VALUES ($1, gen_random_uuid(), gen_random_uuid(), '\\x00', now(), 'single_factor',
                 '{password}', now(), now(), 60, now())",
    )
    .bind(tenant.tenant_id().as_uuid())
    .execute(tx.connection())
    .await;
    assert!(short.is_err());
}
