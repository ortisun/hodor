//! The intermediates of a tenant's certificate authority kept in memory:
//! the contract every intermediate store passes.

use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_keys::testing::{InMemoryIntermediates, run_intermediate_contract};

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    run_intermediate_contract(
        &InMemoryUnitOfWorkFactory::default(),
        &InMemoryIntermediates::default(),
    )
    .await;
}
