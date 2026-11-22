//! The stores behind the administration interface, on PostgreSQL.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgAccessTokenStore, PgEngineBindingStore, PgRoleAssignmentStore, PgWebAuthnStore,
};
use hodor_authorization::testing::{BindingPorts, Ports, run_binding_contract, run_contract};
use hodor_credential::testing::{
    AccessTokenPorts, WebAuthnPorts, run_access_token_contract, run_webauthn_contract,
};

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
async fn the_postgres_binding_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_binding_contract(BindingPorts {
        units_of_work: database.app(),
        bindings: &PgEngineBindingStore,
    })
    .await;
}

#[tokio::test]
async fn the_database_refuses_a_binding_that_breaks_its_rules() {
    let database = TestDatabase::start().await;
    let insert = |namespace: &'static str,
                  timeout: i32,
                  sensitive: bool,
                  actions: &'static [&'static str]| {
        let owner = database.owner().clone();
        async move {
            sqlx::query(
                "INSERT INTO \"authorization\".engine_binding (tenant_id, namespace, engine,
                     timeout_milliseconds, sensitive, fail_open_actions, trust_asserted,
                     created_at, updated_at)
                 VALUES (gen_random_uuid(), $1, 'native', $2, $3, $4, false, now(), now())",
            )
            .bind(namespace)
            .bind(timeout)
            .bind(sensitive)
            .bind(actions)
            .execute(&owner)
            .await
        }
    };
    assert!(
        insert("https://documents.example.com", 200, false, &["read"])
            .await
            .is_ok()
    );
    for refused in [
        insert("hodor:admin", 200, true, &[]).await,
        insert("documents", 200, false, &[]).await,
        insert("https://documents.example.com", 0, false, &[]).await,
        insert("https://documents.example.com", 5001, false, &[]).await,
        insert("https://documents.example.com", 200, true, &["read"]).await,
    ] {
        assert!(refused.is_err());
    }
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
async fn the_postgres_webauthn_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_webauthn_contract(WebAuthnPorts {
        units_of_work: database.app(),
        store: &PgWebAuthnStore,
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
