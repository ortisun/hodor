//! Disposable PostgreSQL for integration tests.

use crate::{Database, migrate};
use hodor_kernel::Secret;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use testcontainers::runners::AsyncRunner as _;
use testcontainers::{ContainerAsync, ImageExt as _};
use testcontainers_modules::postgres::Postgres;

const IMAGE_TAG: &str = "17-alpine";
const APP_LOGIN: &str = "hodor_app_login";
const APP_PASSWORD: &str = "app";

/// A PostgreSQL container with the schema migrated and two connections: one
/// as the schema owner and one as the application role.
///
/// The container is removed when this value is dropped.
#[derive(Debug)]
pub struct TestDatabase {
    owner: PgPool,
    app: Database,
    _container: ContainerAsync<Postgres>,
}

impl TestDatabase {
    /// Starts a container, applies the migrations and connects.
    ///
    /// # Panics
    ///
    /// Panics if Docker is unavailable or the database cannot be prepared;
    /// a test cannot continue without it.
    pub async fn start() -> Self {
        let container = Postgres::default()
            .with_tag(IMAGE_TAG)
            .start()
            .await
            .expect("PostgreSQL container should start; is Docker running?");
        let host = container.get_host().await.expect("container host");
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("container port");

        let owner_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let owner = PgPoolOptions::new()
            .max_connections(2)
            .connect(&owner_url)
            .await
            .expect("owner connection");
        migrate(&owner).await.expect("migrations should apply");

        // A login role that is a member of the application group role, the
        // way an operator would provision it.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {APP_LOGIN} LOGIN PASSWORD '{APP_PASSWORD}' IN ROLE hodor_app"
        )))
        .execute(&owner)
        .await
        .expect("application login role");

        let app_url = Secret::from(format!(
            "postgres://{APP_LOGIN}:{APP_PASSWORD}@{host}:{port}/postgres"
        ));
        let app = Database::connect(&app_url, 5)
            .await
            .expect("application connection");

        Self {
            owner,
            app,
            _container: container,
        }
    }

    /// Connection as the schema owner, for test setup.
    #[must_use]
    pub const fn owner(&self) -> &PgPool {
        &self.owner
    }

    /// The database as the application sees it.
    #[must_use]
    pub const fn app(&self) -> &Database {
        &self.app
    }
}

/// Tables that are deliberately not tenant tables.
///
/// Keep this list short: every entry is a table without tenant isolation.
const PLATFORM_TABLES: &[&str] = &["public._sqlx_migrations"];

/// Checks every table in the database against the tenant isolation rules of
/// `docs/architecture/multi-tenancy.md` and returns one message per
/// violation. A table passes when it:
///
/// * has a `tenant_id uuid NOT NULL` column;
/// * has row-level security enabled and forced;
/// * carries the `tenant_isolation` policy, as created by
///   `platform.enable_tenant_rls`;
/// * has a primary key that starts with `tenant_id`;
/// * includes `tenant_id` in every foreign key.
///
/// # Panics
///
/// Panics if the catalog cannot be read.
pub async fn schema_violations(owner: &PgPool) -> Vec<String> {
    type Row = (String, bool, bool, bool, bool, bool);

    let tables: Vec<Row> = sqlx::query_as(
        r"
        SELECT
            n.nspname || '.' || c.relname,
            EXISTS (
                SELECT FROM pg_attribute a
                WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
                  AND a.atttypid = 'uuid'::regtype AND a.attnotnull AND NOT a.attisdropped
            ),
            c.relrowsecurity AND c.relforcerowsecurity,
            EXISTS (
                SELECT FROM pg_policy p
                WHERE p.polrelid = c.oid AND p.polname = 'tenant_isolation'
            ),
            COALESCE((
                SELECT a.attname = 'tenant_id'
                FROM pg_index i
                JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
                WHERE i.indrelid = c.oid AND i.indisprimary
            ), false),
            NOT EXISTS (
                SELECT FROM pg_constraint k
                WHERE k.conrelid = c.oid AND k.contype = 'f'
                  AND NOT EXISTS (
                      SELECT FROM pg_attribute a
                      WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
                        AND a.attnum = ANY (k.conkey)
                  )
            )
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind IN ('r', 'p')
          AND NOT c.relispartition
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg\_%'
        ORDER BY 1
        ",
    )
    .fetch_all(owner)
    .await
    .expect("catalog query");

    let mut found = Vec::new();
    for (table, has_tenant_id, rls_forced, has_policy, key_leads, foreign_keys_ok) in tables {
        if PLATFORM_TABLES.contains(&table.as_str()) {
            continue;
        }
        let checks = [
            (has_tenant_id, "has no `tenant_id uuid NOT NULL` column"),
            (
                rls_forced,
                "does not have row-level security enabled and forced",
            ),
            (has_policy, "has no `tenant_isolation` policy"),
            (key_leads, "has no primary key starting with `tenant_id`"),
            (
                foreign_keys_ok,
                "has a foreign key that does not include `tenant_id`",
            ),
        ];
        for (passes, problem) in checks {
            if !passes {
                found.push(format!("{table} {problem}"));
            }
        }
    }
    found
}
