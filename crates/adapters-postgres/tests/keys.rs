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

/// A pending signing version with its public key given as the five
/// columns: P-256 x and y, RSA modulus and exponent, and Ed25519.
async fn insert_signing(
    database: &TestDatabase,
    tenant: &TenantContext,
    algorithm: &str,
    public_key: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = database.app().begin(tenant).await.expect("begin");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO keys.key_version
             (tenant_id, id, key_use, algorithm, state, provider, key_material,
              public_p256_x, public_p256_y, public_rsa_modulus, public_rsa_exponent,
              public_ed25519, created_at)
         VALUES ($1, gen_random_uuid(), 'sig', '{algorithm}', 'pending', 'local', '\\x01',
                 {public_key}, now())"
    )))
    .bind(tenant.tenant_id().as_uuid())
    .execute(tx.connection())
    .await?;
    tx.commit().await
}

#[tokio::test]
async fn an_eddsa_version_holds_its_ed25519_key_and_nothing_else() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let ed25519 = "NULL, NULL, NULL, NULL, decode(repeat('03', 32), 'hex')";
    insert_signing(&database, &tenant, "EdDSA", ed25519)
        .await
        .expect("an Ed25519 key of 32 bytes");
    let p256 = "decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), NULL, NULL";
    let rsa = "NULL, NULL, decode(repeat('01', 256), 'hex'), '\\x010001'";
    let extra = "decode(repeat('03', 32), 'hex')";
    let cases: [(&str, String, &str); 8] = [
        (
            "EdDSA",
            "NULL, NULL, NULL, NULL, decode(repeat('03', 31), 'hex')".to_owned(),
            "31 bytes",
        ),
        ("EdDSA", "NULL, NULL, NULL, NULL, NULL".to_owned(), "no key"),
        ("EdDSA", format!("{p256}, NULL"), "a P-256 key"),
        ("EdDSA", format!("{p256}, {extra}"), "a P-256 key besides"),
        ("ES256", ed25519.to_owned(), "an Ed25519 key for ES256"),
        (
            "ES256",
            format!("{p256}, {extra}"),
            "an Ed25519 key besides a P-256 one",
        ),
        (
            "RS256",
            format!("{rsa}, {extra}"),
            "an Ed25519 key besides an RSA one",
        ),
        (
            "Ed25519",
            ed25519.to_owned(),
            "an algorithm by another name",
        ),
    ];
    for (algorithm, public_key, case) in cases {
        assert!(
            insert_signing(&database, &tenant, algorithm, &public_key)
                .await
                .is_err(),
            "{case} must be refused"
        );
    }
    // And no Ed25519 key in the data key set.
    let mut tx = database.app().begin(&tenant).await.expect("begin");
    let refused = sqlx::query(
        "INSERT INTO keys.key_version
             (tenant_id, id, key_use, algorithm, state, provider, key_material,
              public_ed25519, created_at)
         VALUES ($1, gen_random_uuid(), 'data', 'EdDSA', 'pending', 'local', '\\x01',
                 decode(repeat('03', 32), 'hex'), now())",
    )
    .bind(tenant.tenant_id().as_uuid())
    .execute(tx.connection())
    .await;
    assert!(refused.is_err(), "EdDSA in the data key set");
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

mod rotation {
    use super::local_provider;
    use hodor_adapters_postgres::testing::TestDatabase;
    use hodor_adapters_postgres::{
        KeyRotationJob, PgKeyStore, PgTenantDirectory, PgTenantRepository,
    };
    use hodor_kernel::clock::testing::FixedClock;
    use hodor_kernel::{Actor, Clock as _, CorrelationId, TenantContext, Timestamp};
    use hodor_keys::api::{KeyService, KeyState, KeyUse, RotationPolicy};
    use hodor_tenant::api::{Caller, CreateTenant, TenantService};
    use std::sync::Arc;

    struct World {
        database: TestDatabase,
        clock: Arc<FixedClock>,
        keys: KeyService,
        tenants: TenantService,
    }

    async fn world() -> World {
        let database = TestDatabase::start().await;
        let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
        let keys = KeyService::new(
            Arc::new(database.app().clone()),
            Arc::new(PgKeyStore),
            Arc::new(local_provider()),
            clock.clone(),
        );
        let tenants = TenantService::new(
            Arc::new(database.app().clone()),
            Arc::new(PgTenantRepository),
            Arc::new(PgTenantDirectory::new(database.app().clone())),
            clock.clone(),
        );
        World {
            database,
            clock,
            keys,
            tenants,
        }
    }

    fn caller() -> Caller {
        Caller {
            actor: Actor::System,
            correlation_id: CorrelationId::generate(),
        }
    }

    impl World {
        fn job(&self) -> KeyRotationJob {
            KeyRotationJob::new(
                self.database.platform().clone(),
                self.keys.clone(),
                RotationPolicy::DEFAULT,
            )
        }

        async fn tenant(&self, slug: &str) -> TenantContext {
            let tenant = self
                .tenants
                .create(
                    CreateTenant {
                        slug: slug.to_owned(),
                        display_name: slug.to_owned(),
                        open_registration: false,
                        system: false,
                    },
                    caller(),
                )
                .await
                .expect("tenant");
            TenantContext::assume(tenant.id())
        }

        async fn states(&self, tenant: &TenantContext) -> Vec<KeyState> {
            let set = self
                .keys
                .key_set(tenant, KeyUse::Signing)
                .await
                .expect("set");
            set.versions()
                .iter()
                .map(|version| version.state())
                .collect()
        }
    }

    #[tokio::test]
    async fn every_active_tenant_gets_a_key_and_a_suspended_one_does_not() {
        let world = world().await;
        let acme = world.tenant("acme").await;
        let globex = world.tenant("globex").await;
        let initech = world.tenant("initech").await;
        world
            .tenants
            .suspend(&initech, "unpaid", caller())
            .await
            .expect("suspend");

        let pass = world.job().run(world.clock.now()).await.expect("pass");
        assert!(!pass.skipped);
        assert_eq!(pass.tenants, 2);
        assert!(pass.failures.is_empty());
        assert_eq!((pass.changes.created, pass.changes.activated), (2, 2));
        assert_eq!(world.states(&acme).await, vec![KeyState::Active]);
        assert_eq!(world.states(&globex).await, vec![KeyState::Active]);
        assert!(world.states(&initech).await.is_empty());

        let again = world.job().run(world.clock.now()).await.expect("pass");
        assert_eq!(again.tenants, 0, "nothing is due, so no tenant is visited");
    }

    #[tokio::test]
    async fn a_tenant_is_visited_only_when_a_change_is_due() {
        let world = world().await;
        let acme = world.tenant("acme").await;
        let policy = RotationPolicy::DEFAULT;
        world.job().run(world.clock.now()).await.expect("first key");

        // Just before the next key is due: nothing.
        world
            .clock
            .advance(policy.period() - policy.publication() - time::Duration::seconds(1));
        assert_eq!(
            world
                .job()
                .run(world.clock.now())
                .await
                .expect("pass")
                .tenants,
            0
        );

        // The next key is made, then nothing until it may sign.
        world.clock.advance(time::Duration::seconds(1));
        let prepared = world.job().run(world.clock.now()).await.expect("pass");
        assert_eq!((prepared.tenants, prepared.changes.created), (1, 1));
        world.clock.advance(time::Duration::hours(1));
        assert_eq!(
            world
                .job()
                .run(world.clock.now())
                .await
                .expect("pass")
                .tenants,
            0
        );

        // It signs at the end of the period; the old one retires after the
        // overlap.
        world
            .clock
            .advance(policy.publication() - time::Duration::hours(1));
        let activated = world.job().run(world.clock.now()).await.expect("pass");
        assert_eq!(activated.changes.activated, 1);
        assert_eq!(
            world.states(&acme).await,
            vec![KeyState::Active, KeyState::Retiring]
        );
        world.clock.advance(policy.overlap());
        let retired = world.job().run(world.clock.now()).await.expect("pass");
        assert_eq!(retired.changes.retired, 1);
        assert_eq!(
            world.states(&acme).await,
            vec![KeyState::Active, KeyState::Retired]
        );
        assert_eq!(
            world
                .job()
                .run(world.clock.now())
                .await
                .expect("pass")
                .tenants,
            0
        );
    }

    #[tokio::test]
    async fn two_workers_at_once_rotate_once() {
        let world = world().await;
        let mut tenants = Vec::new();
        for slug in ["acme", "globex", "initech", "umbrella"] {
            tenants.push(world.tenant(slug).await);
        }
        let (first, second) = (world.job(), world.job());
        let now = world.clock.now();
        let (a, b) = tokio::join!(first.run(now), second.run(now));
        let (a, b) = (a.expect("first"), b.expect("second"));
        assert_eq!(
            a.changes.activated + b.changes.activated,
            4,
            "one key for each tenant, whichever worker made it"
        );
        for tenant in &tenants {
            assert_eq!(world.states(tenant).await, vec![KeyState::Active]);
        }
    }

    #[tokio::test]
    async fn a_pass_is_skipped_while_another_holds_the_lock() {
        let world = world().await;
        let acme = world.tenant("acme").await;
        let mut other = world.database.platform().begin().await.expect("begin");
        let (held,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_xact_lock($1)")
            .bind(0x686f_646f_726b_6579_i64)
            .fetch_one(&mut *other)
            .await
            .expect("lock");
        assert!(held);

        let pass = world.job().run(world.clock.now()).await.expect("pass");
        assert!(pass.skipped);
        assert!(world.states(&acme).await.is_empty());

        other.rollback().await.expect("release");
        let pass = world.job().run(world.clock.now()).await.expect("pass");
        assert!(!pass.skipped);
        assert_eq!(world.states(&acme).await, vec![KeyState::Active]);
    }
}

#[tokio::test]
async fn requests_that_make_the_first_key_of_an_algorithm_at_once_end_with_one() {
    let database = TestDatabase::start().await;
    let service = KeyService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgKeyStore),
        Arc::new(local_provider()),
        Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
    );
    let tenant = TenantContext::assume(TenantId::generate());
    let ensure = || service.ensure_active(&tenant, KeyAlgorithm::Rs256, Caller::system());
    let (first, second, third, fourth) = tokio::join!(ensure(), ensure(), ensure(), ensure());
    let made = [first, second, third, fourth];
    let winners: std::collections::BTreeSet<_> = made
        .into_iter()
        .map(|answer| answer.expect("every request signs").id())
        .collect();
    assert_eq!(winners.len(), 1, "every request got the same key");

    let set = service
        .key_set(&tenant, KeyUse::Signing)
        .await
        .expect("set");
    let rsa: Vec<_> = set
        .versions()
        .iter()
        .filter(|version| version.algorithm() == KeyAlgorithm::Rs256)
        .collect();
    assert_eq!(
        rsa.iter().filter(|v| v.state() == KeyState::Active).count(),
        1
    );
    for loser in rsa.iter().filter(|v| v.state() != KeyState::Active) {
        assert_eq!(loser.state(), KeyState::Revoked);
        assert_eq!(
            loser.snapshot().revocation_reason.as_deref(),
            Some(hodor_keys::api::LOST_FIRST_RACE)
        );
    }
}
