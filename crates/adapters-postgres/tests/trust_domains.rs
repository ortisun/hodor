//! Trust domains on PostgreSQL: the contract, the database's own checks,
//! and what only a real database can show: leases taken by several workers
//! at once, and a trust domain one worker holds skipped by another.

use hodor_adapters_crypto::Sha256Digest;
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgDueRefreshes, PgTrustDomainStore};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp, UnitOfWorkFactory};
use hodor_keys::api::{
    BundleRefresher, RefreshOutcome, TrustDomainPorts, TrustDomainService, TrustDomainStore,
    TrustSourceRequest,
};
use hodor_keys::testing::{
    FakeBundleEndpoints, TrustDomainContract, run_trust_domain_contract, sample_bundle,
};
use std::collections::BTreeSet;
use std::sync::Arc;
use time::Duration;

#[tokio::test]
async fn the_postgres_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_trust_domain_contract(TrustDomainContract {
        units_of_work: database.app(),
        store: &PgTrustDomainStore,
        due: &PgDueRefreshes::new(database.platform().clone()),
    })
    .await;
}

fn service(
    database: &TestDatabase,
    endpoints: &FakeBundleEndpoints,
    clock: &Arc<FixedClock>,
) -> TrustDomainService {
    TrustDomainService::new(TrustDomainPorts {
        units_of_work: Arc::new(database.app().clone()),
        store: Arc::new(PgTrustDomainStore),
        destinations: Arc::new(endpoints.clone()),
        http: Arc::new(endpoints.clone()),
        digest: Arc::new(Sha256Digest),
        clock: clock.clone(),
    })
}

/// A moment far from every other test's, so that the search across
/// tenants of this database finds this test's trust domains first.
fn moment() -> Timestamp {
    Timestamp::UNIX_EPOCH - Duration::days(3650)
}

#[tokio::test]
async fn six_workers_leasing_at_once_never_take_one_trust_domain_twice() {
    let database = TestDatabase::start().await;
    let endpoints = FakeBundleEndpoints::default();
    let clock = Arc::new(FixedClock::at(moment()));
    let service = service(&database, &endpoints, &clock);
    let mut ids = BTreeSet::new();
    for index in 0..10 {
        let tenant = TenantContext::assume(TenantId::generate());
        let url = format!("https://spire{index}.example/bundle");
        endpoints.serve(&url, &sample_bundle(Some(1), &["one"]));
        let added = service
            .add(
                &tenant,
                "cluster.local",
                TrustSourceRequest::BundleEndpoint { url },
                Caller::system(),
            )
            .await
            .expect("added");
        ids.insert(added.id());
    }
    clock.advance(Duration::minutes(5));
    let refresher = BundleRefresher::new(
        service.clone(),
        Arc::new(PgDueRefreshes::new(database.platform().clone())),
    );
    let mut workers = Vec::new();
    for _ in 0..6 {
        let refresher = refresher.clone();
        workers.push(tokio::spawn(async move {
            refresher.lease_due(8).await.expect("leased")
        }));
    }
    let mut leased = Vec::new();
    for worker in workers {
        leased.extend(worker.await.expect("worker"));
    }
    let taken: BTreeSet<_> = leased.iter().map(|lease| lease.id).collect();
    assert_eq!(taken.len(), leased.len(), "no trust domain leased twice");
    assert_eq!(taken, ids, "every due trust domain leased");
    for lease in leased {
        assert_eq!(
            refresher.refresh(lease).await.expect("refreshed"),
            RefreshOutcome::Unchanged
        );
    }
    assert!(refresher.lease_due(8).await.expect("leased").is_empty());
}

#[tokio::test]
async fn a_trust_domain_one_worker_holds_is_skipped_by_another() {
    let database = TestDatabase::start().await;
    let endpoints = FakeBundleEndpoints::default();
    let clock = Arc::new(FixedClock::at(moment()));
    let tenant = TenantContext::assume(TenantId::generate());
    let url = "https://spire.example/bundle";
    endpoints.serve(url, &sample_bundle(Some(1), &["one"]));
    let added = service(&database, &endpoints, &clock)
        .add(
            &tenant,
            "spire.example",
            TrustSourceRequest::BundleEndpoint {
                url: url.to_owned(),
            },
            Caller::system(),
        )
        .await
        .expect("added");
    let mut holding = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    assert!(
        PgTrustDomainStore
            .take(holding.as_mut(), added.id())
            .await
            .expect("take")
            .is_some()
    );
    let mut other = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    assert!(
        PgTrustDomainStore
            .take(other.as_mut(), added.id())
            .await
            .expect("take")
            .is_none(),
        "skipped, not waited for"
    );
}

#[tokio::test]
async fn the_database_holds_the_rules_of_a_trust_domain() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let bundle = "'{\"keys\":[]}'";
    for (case, values) in [
        (
            "a name with an uppercase letter",
            format!("'Prod', 'uploaded', NULL, {bundle}, now(), NULL"),
        ),
        (
            "a source that is not one of the three",
            format!("'prod', 'other', NULL, {bundle}, now(), NULL"),
        ),
        (
            "a trust domain of the mesh with a bundle",
            format!("'prod', 'mesh', NULL, {bundle}, now(), NULL"),
        ),
        (
            "an uploaded trust domain without a bundle",
            "'prod', 'uploaded', NULL, NULL, NULL, NULL".to_owned(),
        ),
        (
            "a bundle endpoint without an address",
            format!("'prod', 'bundle_endpoint', NULL, {bundle}, now(), now()"),
        ),
        (
            "a bundle endpoint never due",
            format!("'prod', 'bundle_endpoint', 'https://e.example/b', {bundle}, now(), NULL"),
        ),
        (
            "an address beside an uploaded bundle",
            format!("'prod', 'uploaded', 'https://e.example/b', {bundle}, now(), NULL"),
        ),
    ] {
        let mut tx = database.app().begin(&tenant).await.expect("begin");
        let inserted = sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO keys.trust_domain
                 (tenant_id, id, name, source, bundle_endpoint_url, bundle, bundle_changed_at,
                  next_refresh_at, created_at, updated_at)
             VALUES ($1, gen_random_uuid(), {values}, now(), now())"
        )))
        .bind(tenant.tenant_id().as_uuid())
        .execute(tx.connection())
        .await;
        assert!(inserted.is_err(), "{case} is refused by the database");
    }
}
