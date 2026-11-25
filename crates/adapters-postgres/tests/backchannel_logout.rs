//! Back-channel logout on PostgreSQL: the contract of its stores, the
//! fan-out through the real outbox dispatcher, and what only a real
//! database can show: the rules it keeps itself, leases taken at once, and
//! the cleanup of finished deliveries.

use hodor_adapters_crypto::Sha256Digest;
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    Database, ExpiredKind, ExpiredRowCleanup, OutboxDispatcher, PgApplicationStore, PgAuditLog,
    PgClientStore, PgDueLogoutDeliveries, PgGrantStore, PgKeyStore, PgLogoutDeliveryStore,
    PgResourceServerStore, PgSessionClients,
};
use hodor_audit::api::{AuditHandler, AuditService};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    Actor, Caller, Clock as _, CorrelationId, EventEnvelope, EventMetadata, SystemClock,
    TenantContext, TenantId, UnitOfWorkFactory, UserId,
};
use hodor_keys::api::KeyService;
use hodor_keys::testing::FakeKeyProvider;
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, BackChannelLogoutFanOut,
    BackChannelLogoutSender, Client, ClientSettings, ClientType, CreateClient, Grant, GrantId,
    GrantStatus, GrantStore as _, GrantType, LogoutDeliverySettings, LogoutSenderPorts,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeDestinations, FixedIssuer, LogoutDeliveryStorePorts, RecordingClients,
    run_logout_delivery_contract,
};
use hodor_session::api::SessionId;
use std::sync::Arc;
use time::Duration;

#[tokio::test]
async fn the_postgres_stores_pass_the_contract() {
    let database = TestDatabase::start().await;
    run_logout_delivery_contract(LogoutDeliveryStorePorts {
        units_of_work: database.app(),
        applications: &PgApplicationStore,
        clients: &PgClientStore,
        grants: &PgGrantStore,
        sessions: &PgSessionClients,
        deliveries: &PgLogoutDeliveryStore,
        due: &PgDueLogoutDeliveries::new(database.platform().clone()),
    })
    .await;
}

fn applications(database: &Database) -> ApplicationService {
    ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(database.clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: Arc::new(SystemClock),
    })
    .with_destinations(Arc::new(FakeDestinations))
}

/// A client of a new application with a back-channel logout address.
async fn client(database: &TestDatabase, tenant: &TenantContext) -> Client {
    let service = applications(database.app());
    let application = service
        .create_application(
            tenant,
            ApplicationSettings {
                name: "Payroll".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    let mut settings = ClientSettings::new(
        "Payroll web",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec!["https://payroll.example.com/callback".to_owned()],
    );
    settings.backchannel_logout_uri = Some("https://payroll.example.com/logout".to_owned());
    service
        .create_client(
            tenant,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client")
        .0
}

/// A code was issued to `client` in `session` with `openid`.
async fn signed_in(
    database: &TestDatabase,
    tenant: &TenantContext,
    client: &Client,
    user: UserId,
    session: SessionId,
) {
    let mut uow = UnitOfWorkFactory::begin(database.app(), tenant)
        .await
        .expect("begin");
    PgGrantStore
        .insert(
            uow.as_mut(),
            &Grant {
                id: GrantId::generate(),
                client_id: client.id(),
                user_id: user,
                session_id: session,
                scopes: vec!["openid".to_owned()],
                audiences: Vec::new(),
                organization: None,
                status: GrantStatus::Active,
                created_at: SystemClock.now(),
                revoked_at: None,
                revocation_reason: None,
            },
        )
        .await
        .expect("grant");
    uow.commit().await.expect("commit");
}

/// `session.revoked` in the outbox of `tenant`.
async fn session_ended(
    database: &TestDatabase,
    tenant: &TenantContext,
    user: UserId,
    session: SessionId,
) {
    let mut uow = UnitOfWorkFactory::begin(database.app(), tenant)
        .await
        .expect("begin");
    uow.record_event(EventEnvelope {
        metadata: EventMetadata::new(
            tenant.tenant_id(),
            Actor::User(user),
            CorrelationId::generate(),
            &SystemClock,
        ),
        event_type: "session.revoked".to_owned(),
        payload: serde_json::json!({
            "session_id": session.to_string(),
            "user_id": user.to_string(),
            "reason": "sign_out",
        }),
    });
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
            Arc::new(BackChannelLogoutFanOut::new(
                Arc::new(PgSessionClients),
                Arc::new(PgClientStore),
                Arc::new(PgApplicationStore),
                Arc::new(PgLogoutDeliveryStore),
                Arc::new(SystemClock),
            )),
        ],
    )
}

fn sender(database: &TestDatabase, in_flight: u32) -> BackChannelLogoutSender {
    BackChannelLogoutSender::new(
        LogoutSenderPorts {
            units_of_work: Arc::new(database.app().clone()),
            clients: Arc::new(PgClientStore),
            deliveries: Arc::new(PgLogoutDeliveryStore),
            due: Arc::new(PgDueLogoutDeliveries::new(database.platform().clone())),
            issuers: Arc::new(FixedIssuer),
            keys: KeyService::new(
                Arc::new(database.app().clone()),
                Arc::new(PgKeyStore),
                Arc::new(FakeKeyProvider),
                Arc::new(SystemClock),
            ),
            http: Arc::new(RecordingClients::default()),
            random: Arc::new(DistinctRandom),
            clock: Arc::new(SystemClock),
        },
        LogoutDeliverySettings {
            in_flight_per_client: in_flight,
            ..LogoutDeliverySettings::default()
        },
    )
}

async fn count(database: &TestDatabase, statement: &'static str) -> i64 {
    sqlx::query_scalar(statement)
        .fetch_one(database.owner())
        .await
        .expect("count")
}

#[tokio::test]
async fn the_outbox_makes_deliveries_in_the_sessions_tenant_only() {
    let database = TestDatabase::start().await;
    let (acme, globex) = (
        TenantContext::assume(TenantId::generate()),
        TenantContext::assume(TenantId::generate()),
    );
    let (ana, session) = (UserId::generate(), SessionId::generate());
    let ours = client(&database, &acme).await;
    let theirs = client(&database, &globex).await;
    signed_in(&database, &acme, &ours, ana, session).await;
    // The same identifiers in another tenant: nothing a sign-out in Acme
    // does may reach it.
    signed_in(&database, &globex, &theirs, ana, session).await;
    session_ended(&database, &acme, ana, session).await;

    let report = dispatcher(&database)
        .dispatch_batch(100)
        .await
        .expect("dispatch");
    assert_eq!(report.failed, 0);
    let made: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT tenant_id::text, client_id::text, status FROM oauth.logout_delivery",
    )
    .fetch_all(database.owner())
    .await
    .expect("deliveries");
    assert_eq!(
        made,
        [(
            acme.tenant_id().to_string(),
            ours.id().to_string(),
            "pending".to_owned()
        )]
    );
    // Dispatched once: the event is in the audit log, and handling it
    // again would find the delivery made.
    assert_eq!(
        count(
            &database,
            "SELECT count(*) FROM audit.record WHERE action = 'session.revoked'"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn leases_taken_at_once_never_pass_the_bound_of_a_client() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let payroll = client(&database, &tenant).await;
    let ana = UserId::generate();
    for _ in 0..10 {
        let session = SessionId::generate();
        signed_in(&database, &tenant, &payroll, ana, session).await;
        session_ended(&database, &tenant, ana, session).await;
    }
    dispatcher(&database)
        .dispatch_batch(100)
        .await
        .expect("dispatch");

    let mut workers = Vec::new();
    for _ in 0..6 {
        let sender = sender(&database, 3);
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
            "SELECT count(*) FROM oauth.logout_delivery WHERE leased_until IS NOT NULL"
        )
        .await,
        3
    );
}

#[tokio::test]
async fn the_database_keeps_the_rules_of_an_address_and_of_a_delivery() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let payroll = client(&database, &tenant).await;
    for (change, constraint) in [
        (
            "UPDATE oauth.client SET grant_types = ARRAY['client_credentials'] WHERE id = $1",
            "client_backchannel_logout_needs_code",
        ),
        (
            "UPDATE oauth.client SET backchannel_logout_uri = 'ftp://payroll.example.com' WHERE id = $1",
            "client_backchannel_logout_uri_form",
        ),
        (
            "UPDATE oauth.client SET backchannel_logout_uri = NULL,
                 backchannel_logout_session_required = true WHERE id = $1",
            "client_backchannel_logout_session_needs_uri",
        ),
    ] {
        let error = sqlx::query(change)
            .bind(payroll.id().as_uuid())
            .execute(database.owner())
            .await
            .expect_err(constraint);
        assert!(
            error.to_string().contains(constraint),
            "{constraint}: {error}"
        );
    }
    let session = SessionId::generate().as_uuid();
    let insert = "INSERT INTO oauth.logout_delivery
         (tenant_id, id, client_id, session_id, user_id, status, attempts, next_attempt_at,
          created_at, finished_at)
         VALUES ($1, gen_random_uuid(), $2, $3, gen_random_uuid(), $4, 0, now(), now(), $5)";
    for (status, finished, constraint) in [
        ("pending", true, "logout_delivery_finished_when_not_pending"),
        (
            "delivered",
            false,
            "logout_delivery_finished_when_not_pending",
        ),
        ("lost", true, "logout_delivery_status_known"),
    ] {
        let error = sqlx::query(insert)
            .bind(tenant.tenant_id().as_uuid())
            .bind(payroll.id().as_uuid())
            .bind(session)
            .bind(status)
            .bind(finished.then(|| SystemClock.now()))
            .execute(database.owner())
            .await
            .expect_err(constraint);
        assert!(
            error.to_string().contains(constraint),
            "{constraint}: {error}"
        );
    }
}

#[tokio::test]
async fn finished_deliveries_are_removed_a_retention_after_and_pending_ones_never() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let payroll = client(&database, &tenant).await;
    let now = SystemClock.now();
    let insert = "INSERT INTO oauth.logout_delivery
         (tenant_id, id, client_id, session_id, user_id, status, attempts, next_attempt_at,
          created_at, finished_at)
         VALUES ($1, gen_random_uuid(), $2, gen_random_uuid(), gen_random_uuid(), $3, 1, $4, $4,
                 $5)";
    for (status, at, finished) in [
        ("delivered", now - Duration::days(40), true),
        ("set_aside", now - Duration::days(31), true),
        ("delivered", now - Duration::days(2), true),
        ("pending", now - Duration::days(90), false),
    ] {
        sqlx::query(insert)
            .bind(tenant.tenant_id().as_uuid())
            .bind(payroll.id().as_uuid())
            .bind(status)
            .bind(at)
            .bind(finished.then_some(at))
            .execute(database.owner())
            .await
            .expect("delivery");
    }
    let report = ExpiredRowCleanup::new(
        ExpiredKind::LogoutDeliveries,
        ExpiredKind::LogoutDeliveries.default_retention_days(),
        database.platform().clone(),
        database.app().clone(),
    )
    .run(now, 100)
    .await
    .expect("cleanup");
    assert_eq!(report.removed, 2);
    let left: Vec<(String,)> =
        sqlx::query_as("SELECT status FROM oauth.logout_delivery ORDER BY status")
            .fetch_all(database.owner())
            .await
            .expect("left");
    assert_eq!(left, [("delivered".to_owned(),), ("pending".to_owned(),)]);
    assert_eq!(ExpiredKind::LogoutDeliveries.name(), "logout_deliveries");
}
