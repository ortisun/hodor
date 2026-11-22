//! Row-level security as the application role experiences it.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_kernel::{TenantContext, TenantId};

async fn database_with_probe_table() -> TestDatabase {
    let database = TestDatabase::start().await;
    for statement in [
        "CREATE TABLE platform.rls_probe (
             tenant_id uuid NOT NULL,
             id integer NOT NULL,
             note text NOT NULL,
             PRIMARY KEY (tenant_id, id)
         )",
        "SELECT platform.enable_tenant_rls('platform.rls_probe')",
    ] {
        sqlx::query(statement)
            .execute(database.owner())
            .await
            .expect("probe table setup");
    }
    database
}

async fn insert(
    database: &TestDatabase,
    context: &TenantContext,
    row_tenant: TenantId,
    id: i32,
) -> Result<(), sqlx::Error> {
    let mut tx = database.app().begin(context).await?;
    sqlx::query("INSERT INTO platform.rls_probe (tenant_id, id, note) VALUES ($1, $2, 'x')")
        .bind(row_tenant.as_uuid())
        .bind(id)
        .execute(tx.connection())
        .await?;
    tx.commit().await
}

async fn count(database: &TestDatabase, context: &TenantContext) -> i64 {
    let mut tx = database.app().begin(context).await.expect("begin");
    sqlx::query_scalar("SELECT count(*) FROM platform.rls_probe")
        .fetch_one(tx.connection())
        .await
        .expect("count")
}

#[tokio::test]
async fn a_tenant_sees_only_its_own_rows() {
    let database = database_with_probe_table().await;
    let a = TenantContext::assume(TenantId::generate());
    let b = TenantContext::assume(TenantId::generate());

    insert(&database, &a, a.tenant_id(), 1)
        .await
        .expect("insert a");
    insert(&database, &a, a.tenant_id(), 2)
        .await
        .expect("insert a");
    insert(&database, &b, b.tenant_id(), 1)
        .await
        .expect("insert b");

    // The queries carry no tenant filter on purpose: the policy alone must
    // keep the tenants apart.
    assert_eq!(count(&database, &a).await, 2);
    assert_eq!(count(&database, &b).await, 1);
}

#[tokio::test]
async fn a_tenant_cannot_write_rows_of_another_tenant() {
    let database = database_with_probe_table().await;
    let a = TenantContext::assume(TenantId::generate());
    let b = TenantContext::assume(TenantId::generate());
    insert(&database, &a, a.tenant_id(), 1)
        .await
        .expect("insert a");

    // Inserting a row labelled with another tenant is rejected.
    let forged = insert(&database, &b, a.tenant_id(), 2).await;
    assert!(forged.is_err(), "forged insert must be rejected");

    // Updates and deletes do not reach the other tenant's rows.
    let mut tx = database.app().begin(&b).await.expect("begin");
    let updated = sqlx::query("UPDATE platform.rls_probe SET note = 'changed'")
        .execute(tx.connection())
        .await
        .expect("update")
        .rows_affected();
    let deleted = sqlx::query("DELETE FROM platform.rls_probe")
        .execute(tx.connection())
        .await
        .expect("delete")
        .rows_affected();
    tx.commit().await.expect("commit");

    assert_eq!((updated, deleted), (0, 0));
    assert_eq!(count(&database, &a).await, 1);
}

#[tokio::test]
async fn without_a_tenant_nothing_is_visible_or_writable() {
    let database = database_with_probe_table().await;
    let a = TenantContext::assume(TenantId::generate());
    insert(&database, &a, a.tenant_id(), 1)
        .await
        .expect("insert a");

    let pool = database.app().pool();
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM platform.rls_probe")
        .fetch_one(pool)
        .await
        .expect("count");
    assert_eq!(visible, 0);

    let insert =
        sqlx::query("INSERT INTO platform.rls_probe (tenant_id, id, note) VALUES ($1, 9, 'x')")
            .bind(a.tenant_id().as_uuid())
            .execute(pool)
            .await;
    assert!(insert.is_err(), "insert without a tenant must be rejected");
}

#[tokio::test]
async fn the_tenant_does_not_leak_to_the_next_transaction() {
    let database = database_with_probe_table().await;
    let a = TenantContext::assume(TenantId::generate());
    insert(&database, &a, a.tenant_id(), 1)
        .await
        .expect("insert a");

    // Run many tenant-less queries so that every pooled connection,
    // including the one tenant A just used, is exercised.
    for _ in 0..20 {
        let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM platform.rls_probe")
            .fetch_one(database.app().pool())
            .await
            .expect("count");
        assert_eq!(visible, 0);
    }
}

#[tokio::test]
async fn a_rolled_back_transaction_leaves_nothing_behind() {
    let database = database_with_probe_table().await;
    let a = TenantContext::assume(TenantId::generate());

    let mut tx = database.app().begin(&a).await.expect("begin");
    sqlx::query("INSERT INTO platform.rls_probe (tenant_id, id, note) VALUES ($1, 1, 'x')")
        .bind(a.tenant_id().as_uuid())
        .execute(tx.connection())
        .await
        .expect("insert");
    drop(tx);

    assert_eq!(count(&database, &a).await, 0);
}

#[tokio::test]
async fn the_platform_role_sees_every_tenant() {
    let database = database_with_probe_table().await;
    let a = TenantContext::assume(TenantId::generate());
    let b = TenantContext::assume(TenantId::generate());
    insert(&database, &a, a.tenant_id(), 1)
        .await
        .expect("insert a");
    insert(&database, &b, b.tenant_id(), 1)
        .await
        .expect("insert b");

    let mut connection = database.owner().acquire().await.expect("connection");
    sqlx::query("SET ROLE hodor_platform")
        .execute(&mut *connection)
        .await
        .expect("set role");
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM platform.rls_probe")
        .fetch_one(&mut *connection)
        .await
        .expect("count");
    sqlx::query("RESET ROLE")
        .execute(&mut *connection)
        .await
        .expect("reset role");

    assert_eq!(visible, 2);
}
