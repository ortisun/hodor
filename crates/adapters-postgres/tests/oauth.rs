//! The stores of the OAuth context on PostgreSQL.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgApplicationStore, PgClientStore, PgResourceServerStore};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, ClientSettings, ClientType,
    CreateClient, GrantType, RotateSecret,
};
use hodor_oauth::testing::{DistinctRandom, Ports, run_contract};
use std::sync::Arc;
use time::Duration;

#[tokio::test]
async fn the_postgres_stores_pass_the_contract() {
    let database = TestDatabase::start().await;
    run_contract(Ports {
        units_of_work: database.app(),
        applications: &PgApplicationStore,
        clients: &PgClientStore,
        resource_servers: &PgResourceServerStore,
    })
    .await;
}

#[tokio::test]
async fn a_client_and_its_rotated_secret_work_end_to_end_on_postgres() {
    let database = TestDatabase::start().await;
    let now = Timestamp::UNIX_EPOCH + Duration::days(20_000);
    let clock = Arc::new(FixedClock::at(now));
    let service = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(database.app().clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let tenant = TenantContext::assume(TenantId::generate());
    let application = service
        .create_application(
            &tenant,
            ApplicationSettings {
                name: "Payroll".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("created");
    let (client, first) = service
        .create_client(
            &tenant,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Confidential,
                settings: ClientSettings::new(
                    "Payroll web",
                    ClientType::Confidential,
                    vec![GrantType::AuthorizationCode],
                    vec!["https://payroll.example.com/callback".to_owned()],
                ),
                secret_lifetime: Some(Duration::days(90)),
            },
            Caller::system(),
        )
        .await
        .expect("created");
    let first = first.expect("secret");
    clock.advance(Duration::days(1));
    let second = service
        .rotate_client_secret(
            &tenant,
            client.id(),
            RotateSecret {
                lifetime: Duration::days(90),
                keep_previous_for: Duration::hours(1),
            },
            Caller::system(),
        )
        .await
        .expect("rotated");
    let stored = service.client(&tenant, client.id()).await.expect("stored");
    let today = now + Duration::days(1);
    assert!(stored.accepts_secret(first.expose(), &FakeDigest, today));
    assert!(stored.accepts_secret(second.expose(), &FakeDigest, today));
    assert!(!stored.accepts_secret(first.expose(), &FakeDigest, today + Duration::hours(1)));

    // The table holds hashes only, and the outbox no trace of a secret.
    let rows: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT secret_hash FROM oauth.client_secret WHERE client_id = $1")
            .bind(client.id().as_uuid())
            .fetch_all(database.owner())
            .await
            .expect("secrets");
    assert_eq!(rows.len(), 2);
    let payloads: Vec<(String,)> = sqlx::query_as("SELECT payload::text FROM platform.outbox")
        .fetch_all(database.owner())
        .await
        .expect("outbox");
    for (payload,) in payloads {
        assert!(!payload.contains(&first.expose()[9..]), "{payload}");
        assert!(!payload.contains(&second.expose()[9..]), "{payload}");
    }
}

#[tokio::test]
async fn the_database_refuses_a_public_client_with_a_method_or_without_pkce() {
    let database = TestDatabase::start().await;
    let tenant = sqlx::types::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth.application VALUES ($1, $1, 'Payroll', false, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("application");
    for (method, pkce) in [("client_secret_basic", true), ("none", false)] {
        let refused = sqlx::query(
            "INSERT INTO oauth.client VALUES ($1, gen_random_uuid(), $1, 'Mobile', 'public', $2,
                 ARRAY['authorization_code'], ARRAY['com.example.app:/callback'], ARRAY[]::text[],
                 $3, 300, 300, 2592000, 604800, 'enabled', now(), now(), 0)",
        )
        .bind(tenant)
        .bind(method)
        .bind(pkce)
        .execute(database.owner())
        .await;
        assert!(refused.is_err(), "{method} {pkce}");
    }
    let private_key = sqlx::query(
        "INSERT INTO oauth.client VALUES ($1, $1, $1, 'Server', 'confidential', 'private_key_jwt',
             ARRAY['client_credentials'], ARRAY[]::text[], ARRAY[]::text[],
             true, 300, 300, 2592000, 604800, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await;
    assert!(private_key.is_ok(), "{private_key:?}");
    let leaked = sqlx::query(
        "INSERT INTO oauth.client_key VALUES ($1, $1, 'leak', '{\"kty\":\"OKP\",\"d\":\"x\"}', 0, now())",
    )
    .bind(tenant)
    .execute(database.owner())
    .await;
    assert!(
        leaked.is_err(),
        "a private key is refused by the database too"
    );
}
