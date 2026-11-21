//! The message queue on PostgreSQL.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgMessageQueue, PgPendingMessages};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory};
use hodor_notification::api::{DeliveryService, MessageQueue, PendingMessages};
use hodor_notification::testing::{Ports, RecordingSender, run_contract, verification_message};
use std::sync::Arc;
use time::Duration;

const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;

async fn begin(database: &TestDatabase, tenant: &TenantContext) -> Box<dyn UnitOfWork> {
    UnitOfWorkFactory::begin(database.app(), tenant)
        .await
        .expect("begin")
}

#[tokio::test]
async fn the_postgres_queue_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_contract(Ports {
        units_of_work: database.app(),
        queue: &PgMessageQueue,
        pending: &PgPendingMessages::new(database.platform().clone()),
    })
    .await;
}

#[tokio::test]
async fn a_message_is_stored_only_if_the_change_that_caused_it_is_committed() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let pending = PgPendingMessages::new(database.platform().clone());

    let mut abandoned = begin(&database, &tenant).await;
    PgMessageQueue
        .insert(
            abandoned.as_mut(),
            &verification_message("lost@example.com", MOMENT),
        )
        .await
        .expect("insert");
    drop(abandoned);

    assert!(pending.due(MOMENT, 10).await.expect("due").is_empty());
}

#[tokio::test]
async fn a_message_being_delivered_is_skipped_by_other_workers() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let message = verification_message("person@example.com", MOMENT);
    let mut uow = begin(&database, &tenant).await;
    PgMessageQueue
        .insert(uow.as_mut(), &message)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");

    let mut first = begin(&database, &tenant).await;
    let mut second = begin(&database, &tenant).await;
    let taken = PgMessageQueue
        .take(first.as_mut(), message.id())
        .await
        .expect("take");
    assert!(taken.is_some());
    // The second worker does not wait for the first: it finds nothing.
    let skipped = PgMessageQueue
        .take(second.as_mut(), message.id())
        .await
        .expect("take");
    assert_eq!(skipped, None);

    // The first worker ends its unit of work without changing the message.
    first.commit().await.expect("commit");
    let retaken = PgMessageQueue
        .take(second.as_mut(), message.id())
        .await
        .expect("take");
    assert!(retaken.is_some());
}

#[tokio::test]
async fn delivery_sends_once_erases_the_contents_and_records_the_event() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let message = verification_message("person@example.com", MOMENT);
    let mut uow = begin(&database, &tenant).await;
    PgMessageQueue
        .insert(uow.as_mut(), &message)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");

    let sender = Arc::new(RecordingSender::default());
    let delivery = DeliveryService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgMessageQueue),
        Arc::new(PgPendingMessages::new(database.platform().clone())),
        sender.clone(),
        Arc::new(FixedClock::at(MOMENT + Duration::seconds(5))),
    );

    // Two workers at once: the message is still sent exactly once.
    let (first, second) = tokio::join!(delivery.deliver_pending(10), delivery.deliver_pending(10));
    let (first, second) = (first.expect("deliver"), second.expect("deliver"));
    assert_eq!(first.sent + second.sent, 1);
    assert_eq!(sender.sent().len(), 1);
    assert!(sender.sent()[0].body.contains("token=0a1b2c"));
    assert_eq!(
        delivery
            .deliver_pending(10)
            .await
            .expect("deliver")
            .handled(),
        0
    );

    // The link is nowhere in the database once the message is sent.
    let everything: String = sqlx::query_scalar(
        "SELECT (SELECT string_agg(to_jsonb(m)::text, '') FROM notification.message m)
             || (SELECT string_agg(to_jsonb(o)::text, '') FROM platform.outbox o)",
    )
    .fetch_one(database.owner())
    .await
    .expect("read");
    assert!(!everything.contains("0a1b2c"), "{everything}");
    assert!(everything.contains("notification.message_sent"));
    let (status, variables): (String, String) =
        sqlx::query_as("SELECT status, variables::text FROM notification.message WHERE id = $1")
            .bind(message.id().as_uuid())
            .fetch_one(database.owner())
            .await
            .expect("read");
    assert_eq!((status.as_str(), variables.as_str()), ("sent", "{}"));
}

#[tokio::test]
async fn the_database_refuses_contents_on_a_message_that_is_no_longer_pending() {
    let database = TestDatabase::start().await;
    let result = sqlx::query(
        "INSERT INTO notification.message
             (tenant_id, id, recipient, template, locale, variables, status, attempts,
              next_attempt_at, expires_at, created_at, sent_at)
         VALUES (gen_random_uuid(), gen_random_uuid(), 'person@example.com',
                 'email_verification', 'en', '{\"link\": \"secret\"}', 'sent', 1,
                 now(), now(), now(), now())",
    )
    .execute(database.owner())
    .await;
    assert!(result.is_err());
}
