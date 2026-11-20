//! The attempt store on PostgreSQL.

use hodor_adapters_postgres::PgAttemptStore;
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_authentication::api::{AttemptGuard, LockoutRules};
use hodor_authentication::testing::{AttemptPorts, run_attempt_contract};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp};
use std::sync::Arc;
use time::Duration;

const RULES: LockoutRules = LockoutRules {
    max_failures: 5,
    window: Duration::minutes(15),
    first_lockout: Duration::minutes(1),
    longest_lockout: Duration::hours(1),
};

fn guard(database: &TestDatabase) -> AttemptGuard {
    AttemptGuard::new(
        Arc::new(database.app().clone()),
        Arc::new(PgAttemptStore),
        Arc::new(FakeDigest),
        Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
    )
}

#[tokio::test]
async fn the_postgres_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_attempt_contract(AttemptPorts {
        units_of_work: database.app(),
        attempts: &PgAttemptStore,
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_attempts_admits_exactly_the_limit() {
    let database = TestDatabase::start().await;
    let guard = guard(&database);
    let tenant = TenantContext::assume(TenantId::generate());

    // Forty attempts against one identifier arrive at once, each from its
    // own address so that only the identifier's limit is in play.
    let attempts: Vec<_> = (0..40)
        .map(|n| {
            let (guard, tenant) = (guard.clone(), tenant.clone());
            tokio::spawn(async move {
                let address = format!("198.51.100.{n}");
                guard
                    .admit(&tenant, &RULES, [3; 32], Some(&address), Caller::system())
                    .await
            })
        })
        .collect();
    let (mut admitted, mut refused) = (0, 0);
    for attempt in attempts {
        match attempt.await.expect("task") {
            Ok(()) => admitted += 1,
            Err(error) => {
                assert_eq!(error.code(), "authentication.too_many_attempts");
                assert_eq!(error.retry_after_seconds(), Some(60));
                refused += 1;
            }
        }
    }

    assert_eq!(
        (admitted, refused),
        (5, 35),
        "no more guesses than the limit get through"
    );
    let lockouts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM platform.outbox WHERE event_type = 'authentication.locked_out'",
    )
    .fetch_one(database.owner())
    .await
    .expect("events");
    assert_eq!(lockouts, 1, "the lockout is announced once");
}

#[tokio::test]
async fn a_refused_attempt_counts_nothing_and_a_success_clears_the_identifier_only() {
    let database = TestDatabase::start().await;
    let guard = guard(&database);
    let tenant = TenantContext::assume(TenantId::generate());
    let admit = async || {
        guard
            .admit(
                &tenant,
                &RULES,
                [3; 32],
                Some("203.0.113.9"),
                Caller::system(),
            )
            .await
    };
    for _ in 0..5 {
        admit().await.expect("admitted");
    }
    admit().await.expect_err("locked out");

    let counters = async || -> Vec<(String, i32, i32)> {
        sqlx::query_as(
            "SELECT subject_kind, failures, lockouts FROM authentication.attempt_counter
             ORDER BY subject_kind",
        )
        .fetch_all(database.owner())
        .await
        .expect("counters")
    };
    // Five attempts were counted against the address; the refused sixth
    // was not.
    assert_eq!(
        counters().await,
        [
            ("address".to_owned(), 5, 0),
            ("identifier".to_owned(), 0, 1)
        ]
    );

    guard.succeeded(&tenant, [3; 32]).await.expect("success");
    assert_eq!(counters().await, [("address".to_owned(), 5, 0)]);
}

#[tokio::test]
async fn nothing_stored_reveals_the_identifier_or_the_address() {
    let database = TestDatabase::start().await;
    let guard = guard(&database);
    let tenant = TenantContext::assume(TenantId::generate());
    guard
        .admit(
            &tenant,
            &RULES,
            [3; 32],
            Some("203.0.113.77"),
            Caller::system(),
        )
        .await
        .expect("admitted");

    let stored: String = sqlx::query_scalar(
        "SELECT string_agg(to_jsonb(c)::text, '') FROM authentication.attempt_counter c",
    )
    .fetch_one(database.owner())
    .await
    .expect("dump");
    assert!(!stored.contains("203.0.113.77"), "{stored}");
}
