//! Every table must be a tenant table unless it is on the platform list.

use holdor_adapters_postgres::testing::{TestDatabase, schema_violations};

async fn run(database: &TestDatabase, statements: &[&'static str]) {
    for statement in statements {
        sqlx::query(*statement)
            .execute(database.owner())
            .await
            .expect("test schema setup");
    }
}

#[tokio::test]
async fn the_migrated_schema_follows_the_rules() {
    let database = TestDatabase::start().await;
    let found = schema_violations(database.owner()).await;
    assert!(
        found.is_empty(),
        "schema rules violated:\n{}",
        found.join("\n")
    );
}

#[tokio::test]
async fn a_conforming_tenant_table_passes() {
    let database = TestDatabase::start().await;
    run(
        &database,
        &[
            "CREATE TABLE platform.parent (
                 tenant_id uuid NOT NULL,
                 id uuid NOT NULL,
                 PRIMARY KEY (tenant_id, id)
             )",
            "SELECT platform.enable_tenant_rls('platform.parent')",
            "CREATE TABLE platform.child (
                 tenant_id uuid NOT NULL,
                 id uuid NOT NULL,
                 parent_id uuid NOT NULL,
                 PRIMARY KEY (tenant_id, id),
                 FOREIGN KEY (tenant_id, parent_id) REFERENCES platform.parent (tenant_id, id)
             )",
            "SELECT platform.enable_tenant_rls('platform.child')",
        ],
    )
    .await;

    assert_eq!(
        schema_violations(database.owner()).await,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn each_kind_of_violation_is_reported() {
    let database = TestDatabase::start().await;
    run(
        &database,
        &[
            // No tenant column at all.
            "CREATE TABLE platform.no_tenant (id uuid PRIMARY KEY)",
            // Tenant column present, but nothing else.
            "CREATE TABLE platform.no_rls (
                 tenant_id uuid NOT NULL,
                 id uuid NOT NULL,
                 PRIMARY KEY (id, tenant_id)
             )",
            // Row-level security enabled but not forced, and no policy.
            "CREATE TABLE platform.not_forced (
                 tenant_id uuid NOT NULL,
                 id uuid NOT NULL,
                 PRIMARY KEY (tenant_id, id)
             )",
            "ALTER TABLE platform.not_forced ENABLE ROW LEVEL SECURITY",
            // Otherwise correct, but its foreign key ignores the tenant.
            "CREATE TABLE platform.target (
                 tenant_id uuid NOT NULL,
                 id uuid NOT NULL UNIQUE,
                 PRIMARY KEY (tenant_id, id)
             )",
            "SELECT platform.enable_tenant_rls('platform.target')",
            "CREATE TABLE platform.loose_reference (
                 tenant_id uuid NOT NULL,
                 id uuid NOT NULL,
                 target_id uuid NOT NULL REFERENCES platform.target (id),
                 PRIMARY KEY (tenant_id, id)
             )",
            "SELECT platform.enable_tenant_rls('platform.loose_reference')",
        ],
    )
    .await;

    let found = schema_violations(database.owner()).await;
    let expected = [
        "platform.loose_reference has a foreign key that does not include `tenant_id`",
        "platform.no_rls does not have row-level security enabled and forced",
        "platform.no_rls has no `tenant_isolation` policy",
        "platform.no_rls has no primary key starting with `tenant_id`",
        "platform.no_tenant has no `tenant_id uuid NOT NULL` column",
        "platform.no_tenant does not have row-level security enabled and forced",
        "platform.no_tenant has no `tenant_isolation` policy",
        "platform.no_tenant has no primary key starting with `tenant_id`",
        "platform.not_forced does not have row-level security enabled and forced",
        "platform.not_forced has no `tenant_isolation` policy",
    ];
    assert_eq!(found, expected);
}
