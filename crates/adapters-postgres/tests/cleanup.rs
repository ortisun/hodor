//! The cleanup of rows that stopped being useful, on PostgreSQL. See
//! `docs/operations/deployment.md`, under "Cleanup".

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{ExpiredKind, ExpiredRowCleanup};
use hodor_kernel::{TenantContext, TenantId, Timestamp};
use sqlx::types::Uuid;
use time::Duration;

/// A moment far from the epoch, so that "long ago" is still a valid time.
fn now() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

fn job(database: &TestDatabase, kind: ExpiredKind) -> ExpiredRowCleanup {
    ExpiredRowCleanup::new(
        kind,
        kind.default_retention_days(),
        database.platform().clone(),
        database.app().clone(),
    )
}

/// A 32-byte value that differs for every `seed`.
fn hash(seed: u128) -> Vec<u8> {
    let mut bytes = seed.to_be_bytes().to_vec();
    bytes.extend_from_slice(&seed.to_le_bytes());
    bytes
}

/// Inserts a session that started at `started`, was last active at
/// `active` with an idle timeout of one hour, expires absolutely at
/// `absolute`, and was revoked at `revoked` if given.
async fn session(
    database: &TestDatabase,
    tenant: &TenantContext,
    seed: u128,
    started: Timestamp,
    active: Timestamp,
    absolute: Timestamp,
    revoked: Option<Timestamp>,
) -> Uuid {
    let id = Uuid::now_v7();
    let mut transaction = database.app().begin(tenant).await.expect("begin");
    sqlx::query(
        "INSERT INTO session.session (tenant_id, id, user_id, token_hash, signed_in_at,
             assurance, methods, started_at, last_activity_at, idle_timeout_seconds,
             absolute_expires_at, revoked_at, revocation_reason)
         VALUES ($1, $2, $3, $4, $5, 'single_factor', '{password}', $5, $6, 3600, $7, $8,
             CASE WHEN $8::timestamptz IS NULL THEN NULL ELSE 'signed_out' END)",
    )
    .bind(tenant.tenant_id().as_uuid())
    .bind(id)
    .bind(Uuid::now_v7())
    .bind(hash(seed))
    .bind(started)
    .bind(active)
    .bind(absolute)
    .bind(revoked)
    .execute(transaction.connection())
    .await
    .expect("a session");
    transaction.commit().await.expect("commit");
    id
}

async fn sessions_left(database: &TestDatabase, tenant: &TenantContext) -> Vec<Uuid> {
    let mut transaction = database.app().begin(tenant).await.expect("begin");
    let rows: Vec<(Uuid,)> = sqlx::query_as("SELECT id FROM session.session ORDER BY id")
        .fetch_all(transaction.connection())
        .await
        .expect("sessions");
    rows.into_iter().map(|(id,)| id).collect()
}

#[tokio::test]
async fn every_kind_of_row_can_be_looked_for_and_removed() {
    let database = TestDatabase::start().await;
    // Every query is run against the real schema: a condition that names a
    // column that does not exist fails here.
    for kind in ExpiredKind::ALL {
        let report = job(&database, kind)
            .run(now(), 10)
            .await
            .unwrap_or_else(|error| panic!("{kind}: {error:?}"));
        assert_eq!(report.removed, 0, "{kind}");
    }
}

#[tokio::test]
async fn sessions_are_removed_a_retention_after_they_ended_in_every_tenant() {
    let database = TestDatabase::start().await;
    let now = now();
    let long_ago = now - Duration::days(30);
    let lately = now - Duration::days(2);
    let mut kept = Vec::new();
    let mut tenants = Vec::new();
    for tenant_seed in 0..2_u128 {
        let tenant = TenantContext::assume(TenantId::generate());
        let seed = tenant_seed * 100;
        // Ended long ago, three ways: revoked, idle, absolute.
        session(
            &database,
            &tenant,
            seed + 1,
            long_ago,
            long_ago,
            now,
            Some(long_ago),
        )
        .await;
        session(
            &database,
            &tenant,
            seed + 2,
            long_ago,
            long_ago,
            now + Duration::days(1),
            None,
        )
        .await;
        session(
            &database,
            &tenant,
            seed + 3,
            long_ago - Duration::days(1),
            long_ago + Duration::days(29),
            long_ago,
            None,
        )
        .await;
        // Ended within the retention, and still in use.
        let recent = session(
            &database,
            &tenant,
            seed + 4,
            lately,
            lately,
            now,
            Some(lately),
        )
        .await;
        let live = session(
            &database,
            &tenant,
            seed + 5,
            now - Duration::minutes(5),
            now - Duration::minutes(5),
            now + Duration::days(1),
            None,
        )
        .await;
        let mut expected = vec![recent, live];
        expected.sort();
        kept.push(expected);
        tenants.push(tenant);
    }

    let report = job(&database, ExpiredKind::Sessions)
        .run(now, 100)
        .await
        .expect("a pass");
    assert_eq!(report.tenants, 2);
    assert_eq!(report.removed, 6);
    for (tenant, kept) in tenants.iter().zip(kept) {
        assert_eq!(sessions_left(&database, tenant).await, kept);
    }
}

#[tokio::test]
async fn two_workers_remove_each_row_once() {
    let database = TestDatabase::start().await;
    let now = now();
    let long_ago = now - Duration::days(30);
    let tenant = TenantContext::assume(TenantId::generate());
    for seed in 0..40 {
        session(
            &database,
            &tenant,
            seed,
            long_ago,
            long_ago,
            now,
            Some(long_ago),
        )
        .await;
    }

    let one = job(&database, ExpiredKind::Sessions);
    let two = job(&database, ExpiredKind::Sessions);
    let mut removed = 0;
    // Batches smaller than the rows, so that the two passes overlap.
    for _ in 0..10 {
        let (first, second) = tokio::join!(one.run(now, 5), two.run(now, 5));
        removed += first.expect("first").removed + second.expect("second").removed;
    }
    assert_eq!(removed, 40, "every row removed, none twice");
    assert!(sessions_left(&database, &tenant).await.is_empty());
}

#[tokio::test]
async fn a_batch_is_the_most_removed_in_one_tenant() {
    let database = TestDatabase::start().await;
    let now = now();
    let long_ago = now - Duration::days(30);
    let tenant = TenantContext::assume(TenantId::generate());
    for seed in 0..7 {
        session(
            &database,
            &tenant,
            seed,
            long_ago,
            long_ago,
            now,
            Some(long_ago),
        )
        .await;
    }
    let cleanup = job(&database, ExpiredKind::Sessions);
    assert_eq!(cleanup.run(now, 5).await.expect("a pass").removed, 5);
    assert_eq!(cleanup.run(now, 5).await.expect("a pass").removed, 2);
    assert_eq!(cleanup.run(now, 5).await.expect("a pass").tenants, 0);
}

#[tokio::test]
async fn a_retention_set_by_the_operator_keeps_rows_longer() {
    let database = TestDatabase::start().await;
    let now = now();
    let tenant = TenantContext::assume(TenantId::generate());
    let ended = now - Duration::days(10);
    session(&database, &tenant, 1, ended, ended, now, Some(ended)).await;

    let longer = ExpiredRowCleanup::new(
        ExpiredKind::Sessions,
        30,
        database.platform().clone(),
        database.app().clone(),
    );
    assert_eq!(longer.run(now, 10).await.expect("a pass").removed, 0);
    assert_eq!(
        job(&database, ExpiredKind::Sessions)
            .run(now, 10)
            .await
            .expect("a pass")
            .removed,
        1,
        "past the default of seven days"
    );
}

#[tokio::test]
async fn messages_are_removed_once_done_and_never_while_pending() {
    let database = TestDatabase::start().await;
    let now = now();
    let long_ago = now - Duration::days(60);
    let tenant = TenantContext::assume(TenantId::generate());
    let mut transaction = database.app().begin(&tenant).await.expect("begin");
    for (status, sent) in [
        ("sent", Some(long_ago)),
        ("failed", None),
        ("expired", None),
        ("pending", None),
    ] {
        sqlx::query(
            "INSERT INTO notification.message (tenant_id, id, recipient, template, locale,
                 variables, status, attempts, next_attempt_at, expires_at, created_at, sent_at)
             VALUES ($1, $2, 'ana@example.com', 'registration', 'en', '{}', $3, 1, $4, $4, $4, $5)",
        )
        .bind(tenant.tenant_id().as_uuid())
        .bind(Uuid::now_v7())
        .bind(status)
        .bind(long_ago)
        .bind(sent)
        .execute(transaction.connection())
        .await
        .expect("a message");
    }
    transaction.commit().await.expect("commit");

    let report = job(&database, ExpiredKind::Messages)
        .run(now, 10)
        .await
        .expect("a pass");
    assert_eq!(report.removed, 3);
    let mut transaction = database.app().begin(&tenant).await.expect("begin");
    let left: Vec<(String,)> = sqlx::query_as("SELECT status FROM notification.message")
        .fetch_all(transaction.connection())
        .await
        .expect("messages");
    assert_eq!(left, [("pending".to_owned(),)]);
}

#[tokio::test]
async fn links_are_removed_a_retention_after_they_were_used_replaced_or_expired() {
    let database = TestDatabase::start().await;
    let now = now();
    let long_ago = now - Duration::days(30);
    let tenant = TenantContext::assume(TenantId::generate());
    let mut transaction = database.app().begin(&tenant).await.expect("begin");
    let insert = "INSERT INTO authentication.verification_token (tenant_id, id, purpose,
                      token_hash, email, locale, created_at, expires_at, used_at, replaced_at)
                  VALUES ($1, $2, 'registration', $3, 'ana@example.com', 'en', $4, $5, $6, $7)";
    let rows: [(Timestamp, Option<Timestamp>, Option<Timestamp>); 4] = [
        (long_ago + Duration::hours(1), Some(long_ago), None),
        (now + Duration::hours(1), None, Some(long_ago)),
        (long_ago, None, None),
        // Still good: not used, not replaced, not expired.
        (now + Duration::hours(1), None, None),
    ];
    for (seed, (expires, used, replaced)) in (0_u128..).zip(rows) {
        sqlx::query(insert)
            .bind(tenant.tenant_id().as_uuid())
            .bind(Uuid::now_v7())
            .bind(hash(seed))
            .bind(long_ago - Duration::hours(1))
            .bind(expires)
            .bind(used)
            .bind(replaced)
            .execute(transaction.connection())
            .await
            .expect("a link");
    }
    transaction.commit().await.expect("commit");

    let report = job(&database, ExpiredKind::VerificationTokens)
        .run(now, 10)
        .await
        .expect("a pass");
    assert_eq!(report.removed, 3, "the link still good is kept");
}

#[test]
fn kinds_are_named_once_each() {
    let mut names: Vec<&str> = ExpiredKind::ALL.iter().map(|kind| kind.name()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), ExpiredKind::ALL.len());
    for kind in ExpiredKind::ALL {
        assert_eq!(kind.name().parse::<ExpiredKind>(), Ok(kind));
    }
    assert!("audit_records".parse::<ExpiredKind>().is_err());
}
