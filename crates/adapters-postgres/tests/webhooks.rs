//! The webhooks stores on PostgreSQL: the contract, the fan-out through the
//! real outbox dispatcher, and what only a real database can show: leases
//! and registrations made at once.

use hodor_adapters_crypto::Sha256Digest;
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    OutboxDispatcher, PgAuditLog, PgDeliveryStore, PgDueDeliveries, PgEndpointStore,
};
use hodor_audit::api::{AuditHandler, AuditService};
use hodor_kernel::random::testing::CountingRandom;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::{
    Actor, Caller, CorrelationId, EventEnvelope, EventMetadata, SystemClock, TenantContext,
    TenantId, UnitOfWorkFactory,
};
use hodor_webhooks::api::{
    AttemptOutcome, DeliverySettings, RegisterEndpoint, SenderPorts, WebhookFanOut, WebhookSender,
    WebhookService,
};
use hodor_webhooks::testing::{
    FakeDestinations, FakeHmac, Ports, RecordingEndpoints, run_contract,
};
use std::sync::Arc;

#[tokio::test]
async fn the_postgres_stores_pass_the_contract() {
    let database = TestDatabase::start().await;
    run_contract(Ports {
        units_of_work: database.app(),
        endpoints: &PgEndpointStore,
        deliveries: &PgDeliveryStore,
        due: &PgDueDeliveries::new(database.platform().clone()),
    })
    .await;
}

fn service(database: &TestDatabase) -> WebhookService {
    WebhookService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgEndpointStore),
        Arc::new(PgDeliveryStore),
        Arc::new(FakeSecretBox),
        Arc::new(FakeDestinations),
        Arc::new(CountingRandom::default()),
        Arc::new(SystemClock),
    )
}

fn sender(database: &TestDatabase, http: &RecordingEndpoints, in_flight: u32) -> WebhookSender {
    WebhookSender::new(
        SenderPorts {
            units_of_work: Arc::new(database.app().clone()),
            endpoints: Arc::new(PgEndpointStore),
            deliveries: Arc::new(PgDeliveryStore),
            due: Arc::new(PgDueDeliveries::new(database.platform().clone())),
            secrets: Arc::new(FakeSecretBox),
            http: Arc::new(http.clone()),
            hmac: Arc::new(FakeHmac),
            clock: Arc::new(SystemClock),
        },
        DeliverySettings {
            in_flight_per_endpoint: in_flight,
            ..DeliverySettings::default()
        },
    )
}

fn registration(url: &str) -> RegisterEndpoint {
    RegisterEndpoint {
        url: url.to_owned(),
        description: None,
        event_types: vec!["session.started".to_owned()],
    }
}

/// Records events in the outbox, as a context does with its change.
async fn record(database: &TestDatabase, tenant: &TenantContext, event_type: &str, count: usize) {
    let mut uow = UnitOfWorkFactory::begin(database.app(), tenant)
        .await
        .expect("begin");
    for _ in 0..count {
        uow.record_event(EventEnvelope {
            metadata: EventMetadata::new(
                tenant.tenant_id(),
                Actor::System,
                CorrelationId::generate(),
                &SystemClock,
            ),
            event_type: event_type.to_owned(),
            payload: serde_json::json!({ "session_id": "s" }),
        });
    }
    uow.commit().await.expect("commit");
}

fn dispatcher(database: &TestDatabase) -> OutboxDispatcher {
    let audit = AuditService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgAuditLog),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
    );
    OutboxDispatcher::new(
        database.platform().clone(),
        database.app().clone(),
        vec![
            Arc::new(AuditHandler::new(audit)),
            Arc::new(WebhookFanOut::new(
                Arc::new(PgEndpointStore),
                Arc::new(PgDeliveryStore),
                Arc::new(SystemClock),
            )),
        ],
    )
}

async fn count(database: &TestDatabase, statement: &'static str) -> i64 {
    sqlx::query_scalar(statement)
        .fetch_one(database.owner())
        .await
        .expect("count")
}

#[tokio::test]
async fn the_outbox_makes_deliveries_in_the_events_tenant_with_its_audit_record() {
    let database = TestDatabase::start().await;
    let service = service(&database);
    let (acme, globex) = (
        TenantContext::assume(TenantId::generate()),
        TenantContext::assume(TenantId::generate()),
    );
    for tenant in [&acme, &globex] {
        service
            .register(
                tenant,
                registration("https://hooks.example.com/"),
                Caller::system(),
            )
            .await
            .expect("registered");
    }
    record(&database, &acme, "session.started", 3).await;
    record(&database, &acme, "authentication.succeeded", 1).await;

    let report = dispatcher(&database)
        .dispatch_batch(100)
        .await
        .expect("dispatch");
    assert_eq!(report.failed, 0);
    let per_tenant: Vec<(String, i64)> = sqlx::query_as(
        "SELECT tenant_id::text, count(*) FROM webhooks.delivery GROUP BY tenant_id",
    )
    .fetch_all(database.owner())
    .await
    .expect("deliveries");
    assert_eq!(
        per_tenant,
        [(acme.tenant_id().to_string(), 3)],
        "only Acme's subscribed events, only to Acme's endpoint"
    );
    // Every event, the registrations' among them, is also in the audit log.
    assert_eq!(
        count(&database, "SELECT count(*) FROM audit.record").await,
        2 + 4
    );
}

#[tokio::test]
async fn leases_made_at_once_never_pass_the_bound_of_an_endpoint() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    service(&database)
        .register(
            &tenant,
            registration("https://slow.example.com/"),
            Caller::system(),
        )
        .await
        .expect("registered");
    record(&database, &tenant, "session.started", 12).await;
    dispatcher(&database)
        .dispatch_batch(100)
        .await
        .expect("dispatch");

    let http = RecordingEndpoints::default();
    let mut workers = Vec::new();
    for _ in 0..6 {
        let sender = sender(&database, &http, 3);
        workers.push(tokio::spawn(async move { sender.lease_due(10).await }));
    }
    let mut leased = 0;
    for worker in workers {
        leased += worker.await.expect("joined").expect("leased").len();
    }
    assert_eq!(leased, 3, "six workers at once lease three, the bound");
    assert_eq!(
        count(
            &database,
            "SELECT count(*) FROM webhooks.delivery WHERE leased_until IS NOT NULL"
        )
        .await,
        3
    );
}

#[tokio::test]
async fn a_lease_sent_and_recorded_leaves_room_for_the_next() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    service(&database)
        .register(
            &tenant,
            registration("https://hooks.example.com/"),
            Caller::system(),
        )
        .await
        .expect("registered");
    record(&database, &tenant, "session.started", 2).await;
    dispatcher(&database)
        .dispatch_batch(100)
        .await
        .expect("dispatch");

    let http = RecordingEndpoints::default();
    let sender = sender(&database, &http, 1);
    let first = sender.lease_due(10).await.expect("lease");
    assert_eq!(first.len(), 1);
    assert!(sender.lease_due(10).await.expect("lease").is_empty());
    for lease in first {
        assert_eq!(
            sender.send(lease).await.expect("send"),
            AttemptOutcome::Delivered
        );
    }
    let second = sender.lease_due(10).await.expect("lease");
    assert_eq!(second.len(), 1);
    for lease in second {
        sender.send(lease).await.expect("send");
    }
    assert_eq!(
        count(
            &database,
            "SELECT count(*) FROM webhooks.delivery WHERE status = 'delivered' AND leased_until IS NULL"
        )
        .await,
        2
    );
    assert_eq!(http.requests().len(), 2);
}

#[tokio::test]
async fn registrations_made_at_once_stop_at_twenty() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let mut attempts = Vec::new();
    for number in 0..26 {
        let service = service(&database);
        let tenant = tenant.clone();
        attempts.push(tokio::spawn(async move {
            service
                .register(
                    &tenant,
                    registration(&format!("https://hooks.example.com/{number}")),
                    Caller::system(),
                )
                .await
        }));
    }
    let mut registered = 0;
    let mut refused = 0;
    for attempt in attempts {
        match attempt.await.expect("joined") {
            Ok(_) => registered += 1,
            Err(error) => {
                assert_eq!(error.code(), "webhooks.too_many_endpoints");
                refused += 1;
            }
        }
    }
    assert_eq!((registered, refused), (20, 6));
}
