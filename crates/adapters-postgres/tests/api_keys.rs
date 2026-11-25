//! API keys on PostgreSQL.

use hodor_adapters_postgres::PgApiKeyStore;
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_credential::testing::{ApiKeyPorts, run_api_key_contract};

#[tokio::test]
async fn the_postgres_api_key_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_api_key_contract(ApiKeyPorts {
        units_of_work: database.app(),
        keys: &PgApiKeyStore,
    })
    .await;
}
