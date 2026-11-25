//! The intermediates of a tenant's certificate authority on PostgreSQL:
//! the contract of intermediate stores, under row-level security, and the
//! database's own rules.

use hodor_adapters_postgres::PgIntermediateStore;
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_kernel::{TenantContext, TenantId, UnitOfWorkFactory};
use hodor_keys::api::{AuthorityId, IntermediateStore as _};
use hodor_keys::testing::{run_intermediate_contract, sample_intermediate};

#[tokio::test]
async fn the_postgres_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_intermediate_contract(database.app(), &PgIntermediateStore).await;
}

#[tokio::test]
async fn the_database_refuses_an_intermediate_that_breaks_its_rules_and_never_deletes_one() {
    let database = TestDatabase::start().await;
    let insert = |state: &str, withdrawn: bool, permitted: &str, key: &str| {
        format!(
            "INSERT INTO keys.intermediate
                 (tenant_id, id, authority_id, serial_number, subject, permitted_dns_names,
                  certificate, certificate_sha256, public_key_sha256, request_sha256,
                  not_before, not_after, signed_at, state, withdrawn_at, withdrawal_reason)
             VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
                     substr(md5(random()::text), 1, 16), 'CN=issuer', {permitted}, '\\x30',
                     repeat('a', 64), {key}, repeat('c', 64), now(), now() + interval '1 day',
                     now(), '{state}', {at}, {reason})",
            at = if withdrawn { "now()" } else { "NULL" },
            reason = if withdrawn { "'leaked'" } else { "NULL" },
        )
    };
    let fine = "ARRAY['cluster.local']";
    let key = "repeat('b', 64)";
    for statement in [
        insert("active", false, fine, key),
        insert("withdrawn", true, fine, key),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(database.owner())
            .await
            .expect("accepted");
    }
    // Withdrawn without a time, a time without being withdrawn, nothing
    // permitted, a key that is not a SHA-256, an unknown state.
    for statement in [
        insert("withdrawn", false, fine, key),
        insert("active", true, fine, key),
        insert("active", false, "ARRAY[]::text[]", key),
        insert("active", false, fine, "'not-a-hash'"),
        insert("revoked", false, fine, key),
    ] {
        assert!(
            sqlx::query(sqlx::AssertSqlSafe(statement.clone()))
                .execute(database.owner())
                .await
                .is_err(),
            "{statement}"
        );
    }

    // The application keeps what it signed: it may not delete it.
    let tenant = TenantContext::assume(TenantId::generate());
    let row = sample_intermediate(
        AuthorityId::generate(),
        "dd",
        hodor_kernel::Timestamp::now_utc(),
    );
    let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("uow");
    PgIntermediateStore
        .insert(uow.as_mut(), &row)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
    let mut tx = database.app().begin(&tenant).await.expect("begin");
    let deleted = sqlx::query("DELETE FROM keys.intermediate")
        .execute(tx.connection())
        .await;
    assert!(deleted.is_err(), "the application may not delete");
}
