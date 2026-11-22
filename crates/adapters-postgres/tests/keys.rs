//! The key store on PostgreSQL.

use hodor_adapters_crypto::{AwsLcVerifier, LocalKeyProvider, OsRandom, SecretKeys};
use hodor_adapters_postgres::PgKeyStore;
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{
    Caller, Secret, SignatureAlgorithm, SignatureVerifier, TenantContext, TenantId, Timestamp,
};
use hodor_keys::api::{KeyAlgorithm, KeyService, KeyState, KeyUse};
use hodor_keys::testing::{Ports, run_contract};
use std::sync::Arc;
use time::Duration;

#[tokio::test]
async fn the_postgres_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_contract(Ports {
        units_of_work: database.app(),
        keys: &PgKeyStore,
    })
    .await;
}

fn local_provider() -> LocalKeyProvider {
    let setting = Secret::new(format!("root:{}", SecretKeys::generate(&OsRandom).expose()));
    LocalKeyProvider::new(Arc::new(SecretKeys::parse(&setting).expect("root keys")))
}

#[tokio::test]
async fn keys_are_made_rotated_and_used_end_to_end_without_leaving_material_in_events() {
    let database = TestDatabase::start().await;
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let service = KeyService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgKeyStore),
        Arc::new(local_provider()),
        clock.clone(),
    );
    let tenant = TenantContext::assume(TenantId::generate());

    let first = service
        .create_version(&tenant, KeyAlgorithm::Es256, Caller::system())
        .await
        .expect("create");
    service
        .activate(&tenant, first.id(), Duration::ZERO, Caller::system())
        .await
        .expect("activate");
    let second = service
        .create_version(&tenant, KeyAlgorithm::Es256, Caller::system())
        .await
        .expect("create");
    service
        .activate(&tenant, second.id(), Duration::minutes(5), Caller::system())
        .await
        .expect("rotate");

    let signature = service
        .sign(&tenant, KeyAlgorithm::Es256, b"a token")
        .await
        .expect("sign");
    assert_eq!(signature.key_version_id, second.id());
    let set = service
        .key_set(&tenant, KeyUse::Signing)
        .await
        .expect("set");
    let signer = set.version(second.id()).expect("in the set");
    assert!(AwsLcVerifier.verify(
        SignatureAlgorithm::Es256,
        signer.public_key().expect("public"),
        b"a token",
        &signature.bytes
    ));
    assert_eq!(
        set.version(first.id())
            .map(hodor_keys::api::KeyVersion::state),
        Some(KeyState::Retiring)
    );

    clock.advance(Duration::minutes(5));
    service
        .retire(&tenant, first.id(), Caller::system())
        .await
        .expect("retire");

    let outbox: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(payload::text, ''), '') FROM platform.outbox",
    )
    .fetch_one(database.owner())
    .await
    .expect("outbox");
    let material: Vec<u8> =
        sqlx::query_scalar("SELECT key_material FROM keys.key_version WHERE id = $1")
            .bind(second.id().as_uuid())
            .fetch_one(database.owner())
            .await
            .expect("material");
    assert_eq!(material, second.material().as_bytes());
    let hex: String = material.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(!outbox.contains(&hex), "events carry no key material");
    let types: Vec<String> =
        sqlx::query_scalar("SELECT event_type FROM platform.outbox ORDER BY created_at, id")
            .fetch_all(database.owner())
            .await
            .expect("event types");
    assert_eq!(
        types,
        vec![
            "keys.version_created",
            "keys.version_activated",
            "keys.version_created",
            "keys.version_activated",
            "keys.version_retired",
        ]
    );
}

async fn insert_raw(
    database: &TestDatabase,
    tenant: &TenantContext,
    values: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = database.app().begin(tenant).await.expect("begin");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO keys.key_version
             (tenant_id, id, key_use, algorithm, state, provider, key_material,
              public_p256_x, public_p256_y, public_rsa_modulus, public_rsa_exponent,
              created_at, activated_at, retiring_at, retire_after, retired_at, revoked_at,
              revocation_reason)
         VALUES ($1, gen_random_uuid(), {values})"
    )))
    .bind(tenant.tenant_id().as_uuid())
    .execute(tx.connection())
    .await?;
    tx.commit().await
}

const P256: &str =
    "'\\x01', decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), NULL, NULL";

#[tokio::test]
async fn the_database_allows_one_active_version_per_algorithm() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let other = TenantContext::assume(TenantId::generate());
    let active = format!(
        "'sig', 'ES256', 'active', 'local', {P256}, now(), now(), NULL, NULL, NULL, NULL, NULL"
    );
    insert_raw(&database, &tenant, &active)
        .await
        .expect("the first active version");
    assert!(
        insert_raw(&database, &tenant, &active).await.is_err(),
        "a second active ES256 version"
    );
    insert_raw(&database, &other, &active)
        .await
        .expect("another tenant has its own");
    let pending = format!(
        "'sig', 'ES256', 'pending', 'local', {P256}, now(), NULL, NULL, NULL, NULL, NULL, NULL"
    );
    insert_raw(&database, &tenant, &pending)
        .await
        .expect("pending versions beside it");
}

#[tokio::test]
async fn the_database_refuses_rows_that_break_the_rules() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let no_times = "now(), NULL, NULL, NULL, NULL, NULL, NULL";
    let cases = [
        (
            "a signing algorithm in the data key set",
            format!("'data', 'ES256', 'pending', 'local', {P256}, {no_times}"),
        ),
        (
            "an encryption key, for which no algorithm is offered",
            format!(
                "'enc', 'A256GCM', 'pending', 'local', '\\x01', NULL, NULL, NULL, NULL, {no_times}"
            ),
        ),
        (
            "the public key of another kind",
            format!("'sig', 'RS256', 'pending', 'local', {P256}, {no_times}"),
        ),
        (
            "a data key with a public key",
            format!("'data', 'A256GCM', 'pending', 'local', {P256}, {no_times}"),
        ),
        (
            "no key material",
            format!(
                "'sig', 'ES256', 'pending', 'local', '\\x', decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), NULL, NULL, {no_times}"
            ),
        ),
        (
            "an active version without its activation time",
            format!("'sig', 'ES256', 'active', 'local', {P256}, {no_times}"),
        ),
        (
            "a retiring version without the moment it may retire",
            format!(
                "'sig', 'ES256', 'retiring', 'local', {P256}, now(), now(), now(), NULL, NULL, NULL, NULL"
            ),
        ),
        (
            "a revoked version without a reason",
            format!(
                "'sig', 'ES256', 'revoked', 'local', {P256}, now(), NULL, NULL, NULL, NULL, now(), NULL"
            ),
        ),
        (
            "an unknown state",
            format!("'sig', 'ES256', 'expired', 'local', {P256}, {no_times}"),
        ),
    ];
    for (case, values) in cases {
        assert!(
            insert_raw(&database, &tenant, &values).await.is_err(),
            "{case} must be refused"
        );
    }
}

#[tokio::test]
async fn the_application_cannot_delete_a_version() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let pending = format!(
        "'sig', 'ES256', 'pending', 'local', {P256}, now(), NULL, NULL, NULL, NULL, NULL, NULL"
    );
    insert_raw(&database, &tenant, &pending)
        .await
        .expect("insert");
    let mut tx = database.app().begin(&tenant).await.expect("begin");
    let deleted = sqlx::query("DELETE FROM keys.key_version")
        .execute(tx.connection())
        .await;
    assert!(deleted.is_err(), "the application role may not delete");
}
