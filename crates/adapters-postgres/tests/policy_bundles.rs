//! The stores of the bundles of Open Policy Agent, on PostgreSQL.

use hodor_adapters_postgres::testing::{TestDatabase, schema_violations};
use hodor_adapters_postgres::{
    PgBundleStore, PgInstanceStatusStore, PgInstanceStore, PgUploadedDecisionStore,
};
use hodor_authorization_opa::testing::{BundlePorts, run_bundle_contract};

#[tokio::test]
async fn the_postgres_stores_of_the_bundles_pass_the_contract() {
    let database = TestDatabase::start().await;
    let instances = PgInstanceStore::new(database.app().clone());
    run_bundle_contract(BundlePorts {
        units_of_work: database.app(),
        instances: &instances,
        bundles: &PgBundleStore,
        statuses: &PgInstanceStatusStore,
        decisions: &PgUploadedDecisionStore,
    })
    .await;
    assert_eq!(
        schema_violations(database.owner()).await,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn a_published_bundle_is_never_changed_or_removed_by_the_application() {
    let database = TestDatabase::start().await;
    let pool = hodor_adapters_postgres::connect_pool(
        &hodor_kernel::Secret::from(database.app_url().to_owned()),
        1,
    )
    .await
    .expect("pool");
    for statement in [
        "UPDATE \"authorization\".policy_bundle SET written_by = 'operator'",
        "DELETE FROM \"authorization\".policy_bundle",
        "DELETE FROM platform.policy_agent_instance",
    ] {
        let refused = sqlx::query(statement).execute(&pool).await;
        assert!(refused.is_err(), "{statement}");
    }
}
