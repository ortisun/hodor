//! The stores behind the administration interface, on PostgreSQL.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgAccessTokenStore, PgRoleAssignmentStore};
use hodor_authorization::testing::{Ports, run_contract};
use hodor_credential::testing::{AccessTokenPorts, run_access_token_contract};

#[tokio::test]
async fn the_postgres_role_assignment_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_contract(Ports {
        units_of_work: database.app(),
        assignments: &PgRoleAssignmentStore,
    })
    .await;
}

#[tokio::test]
async fn the_postgres_access_token_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_access_token_contract(AccessTokenPorts {
        units_of_work: database.app(),
        tokens: &PgAccessTokenStore,
    })
    .await;
}

#[tokio::test]
async fn the_database_refuses_a_role_that_does_not_exist() {
    let database = TestDatabase::start().await;
    let result = sqlx::query(
        "INSERT INTO \"authorization\".role_assignment (tenant_id, user_id, role, assigned_at)
         VALUES (gen_random_uuid(), gen_random_uuid(), 'owner', now())",
    )
    .execute(database.owner())
    .await;
    assert!(result.is_err());
}
