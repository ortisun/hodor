//! The certificate authority of a tenant on PostgreSQL: the contract of
//! authority stores, under row-level security, and the database's own
//! rules.

use hodor_adapters_postgres::PgAuthorityStore;
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_keys::testing::run_authority_contract;

#[tokio::test]
async fn the_postgres_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_authority_contract(database.app(), &PgAuthorityStore).await;
}

#[tokio::test]
async fn the_database_refuses_an_authority_that_breaks_its_rules() {
    let database = TestDatabase::start().await;
    let insert = |kind: &str, state: &str, certificate: bool, lifetime: Option<i32>| {
        format!(
            "INSERT INTO keys.certificate_authority
                 (tenant_id, id, kind, state, trust_domains, common_name, lifetime_days,
                  intermediate_lifetime_days, for_development, key_id, provider, key_material,
                  public_p256_x, public_p256_y, certificate_signing_request, certificate,
                  serial_number, not_before, not_after, certificate_sha256, created_at,
                  activated_at, updated_at)
             VALUES (gen_random_uuid(), gen_random_uuid(), '{kind}', '{state}',
                     ARRAY['a.example'], 'x', {lifetime}, 30, false, gen_random_uuid(),
                     'openbao', '\\x01', decode(repeat('01', 32), 'hex'),
                     decode(repeat('02', 32), 'hex'), {request}, {certificate}, {serial},
                     {at}, {at}, {sha}, now(), {at}, now())",
            lifetime = lifetime.map_or("NULL".to_owned(), |days| days.to_string()),
            request = if kind == "intermediate" {
                "'\\x30'"
            } else {
                "NULL"
            },
            certificate = if certificate { "'\\x30'" } else { "NULL" },
            serial = if certificate { "'0a'" } else { "NULL" },
            at = if certificate { "now()" } else { "NULL" },
            sha = if certificate { "'ab'" } else { "NULL" },
        )
    };
    // What the application writes is accepted.
    for statement in [
        insert("root", "active", true, Some(1826)),
        insert("intermediate", "awaiting_certificate", false, None),
        insert("intermediate", "active", true, None),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(database.owner())
            .await
            .expect("accepted");
    }
    // A root awaiting, a root without a lifetime, an intermediate with
    // one, an active authority without its certificate.
    for statement in [
        insert("root", "awaiting_certificate", false, Some(1826)),
        insert("root", "active", true, None),
        insert("intermediate", "awaiting_certificate", false, Some(30)),
        insert("root", "active", false, Some(1826)),
        insert("root", "active", true, Some(3651)),
    ] {
        assert!(
            sqlx::query(sqlx::AssertSqlSafe(statement.clone()))
                .execute(database.owner())
                .await
                .is_err(),
            "{statement}"
        );
    }
    // A trust domain may hold an authority's bundle.
    sqlx::query(
        "INSERT INTO keys.trust_domain
             (tenant_id, id, name, source, bundle, bundle_changed_at, created_at, updated_at)
         VALUES (gen_random_uuid(), gen_random_uuid(), 'a.example', 'authority', '{}', now(),
                 now(), now())",
    )
    .execute(database.owner())
    .await
    .expect("the source `authority` is known");
}
