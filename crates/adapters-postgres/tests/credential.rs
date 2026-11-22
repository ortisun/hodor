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

#[tokio::test]
async fn the_postgres_store_of_authenticator_applications_passes_the_contract() {
    use hodor_adapters_postgres::PgTotpStore;
    use hodor_credential::testing::{TotpPorts, run_totp_contract};
    let database = TestDatabase::start().await;
    run_totp_contract(TotpPorts {
        units_of_work: database.app(),
        totps: &PgTotpStore,
    })
    .await;
}

#[tokio::test]
async fn a_code_presented_twice_at_once_is_accepted_once_on_postgres() {
    use hodor_adapters_postgres::PgTotpStore;
    use hodor_credential::api::{STEP_SECONDS, TotpCheck, TotpService, totp_code_at};
    use hodor_credential::testing::{FakeHmacSha1, base32_secret};
    use hodor_kernel::Clock;
    use hodor_kernel::random::testing::CountingRandom;
    use hodor_kernel::sealing::testing::FakeSecretBox;

    let database = TestDatabase::start().await;
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + time::Duration::seconds(STEP_SECONDS * 60_000_000),
    ));
    let service = TotpService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgTotpStore),
        Arc::new(FakeSecretBox),
        Arc::new(FakeHmacSha1),
        Arc::new(CountingRandom::default()),
        clock.clone(),
    );
    let tenant = TenantContext::assume(TenantId::generate());
    let user = UserId::generate();
    let enrollment = service
        .begin_enrollment(&tenant, user, "Acme", "ana@example.com")
        .await
        .expect("begin");
    let secret = base32_secret(enrollment.secret());
    let phone = |moment| secret_code(totp_code_at(&FakeHmacSha1, &secret, moment));
    service
        .confirm_enrollment(&tenant, user, &phone(clock.now()), Caller::system())
        .await
        .expect("confirm");
    clock.advance(time::Duration::seconds(STEP_SECONDS));

    let code = phone(clock.now());
    let (first, second) = tokio::join!(
        service.verify(&tenant, Some(user), &code),
        service.verify(&tenant, Some(user), &code),
    );
    let answers = [first, second];
    let verified = answers
        .iter()
        .filter(|answer| matches!(answer, Ok(TotpCheck::Verified)))
        .count();
    assert_eq!(verified, 1, "{answers:?}");

    // Only the sealed secret is stored, and the events name no secret.
    let (stored, events): (Vec<u8>, String) = sqlx::query_as(
        "SELECT (SELECT sealed_secret FROM credential.totp),
                (SELECT string_agg(payload::text, ' ') FROM platform.outbox)",
    )
    .fetch_one(database.owner())
    .await
    .expect("state");
    assert!(
        !stored
            .windows(secret.len())
            .any(|window| window == secret.as_slice())
    );
    assert!(!events.contains(enrollment.secret()), "{events}");
}

fn secret_code(value: String) -> Secret<String> {
    Secret::from(value)
}
