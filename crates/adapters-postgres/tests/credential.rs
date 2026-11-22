//! The password store on PostgreSQL.

use hodor_adapters_postgres::PgPasswordStore;
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_credential::api::{CredentialService, NewPassword, PasswordCheck, PasswordRules};
use hodor_credential::testing::{FakeHasher, Ports, run_contract};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{Caller, Secret, TenantContext, TenantId, Timestamp, UserId};
use std::sync::Arc;

const RULES: PasswordRules = PasswordRules {
    min_length: 12,
    max_length: 128,
    history_depth: 2,
};

fn secret(value: &str) -> Secret<String> {
    Secret::from(value.to_owned())
}

#[tokio::test]
async fn the_postgres_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_contract(Ports {
        units_of_work: database.app(),
        passwords: &PgPasswordStore,
    })
    .await;
}

#[tokio::test]
async fn the_use_cases_work_end_to_end_on_postgres() {
    let database = TestDatabase::start().await;
    let hasher = Arc::new(FakeHasher::default());
    let service = CredentialService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgPasswordStore),
        hasher.clone(),
        Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
    );
    let tenant = TenantContext::assume(TenantId::generate());
    let user = UserId::generate();
    let set = async |password: &str| {
        let password = secret(password);
        let new = NewPassword {
            password: &password,
            rules: RULES,
            own_names: &[],
        };
        service
            .set_password(&tenant, user, new, false, Caller::system())
            .await
    };

    set("password number 1").await.expect("first");
    set("password number 2").await.expect("second");
    set("password number 3").await.expect("third");
    assert_eq!(
        set("password number 1").await.expect_err("reuse").code(),
        "credential.password_reused"
    );

    // Renewal after the parameters are raised is written back.
    hasher.raise_parameters();
    let check = service
        .verify_password(&tenant, Some(user), &secret("password number 3"))
        .await
        .expect("verify");
    assert_eq!(check, PasswordCheck::Verified { must_change: false });

    let (stored, history, events): (String, i64, i64) = sqlx::query_as(
        "SELECT (SELECT password_hash FROM credential.password),
                (SELECT count(*) FROM credential.password_history),
                (SELECT count(*) FROM platform.outbox)",
    )
    .fetch_one(database.owner())
    .await
    .expect("state");
    assert_eq!(
        stored, "fake$1$password number 3",
        "the renewed hash was stored"
    );
    assert_eq!(history, 2, "trimmed to the history depth");
    assert_eq!(
        events, 3,
        "one event per password set, none for the renewal"
    );

    service
        .remove_password(&tenant, user, Caller::system())
        .await
        .expect("remove");
    let left: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM credential.password),
                (SELECT count(*) FROM credential.password_history)",
    )
    .fetch_one(database.owner())
    .await
    .expect("state");
    assert_eq!(left, (0, 0), "the history goes with the password");
}
