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
const PLATFORM_LOGIN: &str = "hodor_platform_login";
const PLATFORM_PASSWORD: &str = "platform";

/// Docker struggles when many containers start at the same instant, which is
/// what a parallel test run does: a start can fail, and so can asking for the
/// mapped port or opening the first connection. Starts are limited, and the
/// whole sequence is retried with a fresh container.
static STARTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
const START_ATTEMPTS: u32 = 4;

struct Started {
    container: ContainerAsync<Postgres>,
    host: String,
    port: u16,
    owner: PgPool,
}

async fn try_start() -> Result<Started, String> {
    let container = Postgres::default()
        .with_tag(IMAGE_TAG)
        .start()
        .await
        .map_err(|e| format!("start: {e}"))?;
    let host = container
        .get_host()
        .await
        .map_err(|e| format!("host: {e}"))?
        .to_string();
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .map_err(|e| format!("port: {e}"))?;
    let owner = PgPoolOptions::new()
        .max_connections(2)
        .connect(&format!(
            "postgres://postgres:postgres@{host}:{port}/postgres"
        ))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    Ok(Started {
        container,
        host,
        port,
        owner,
    })
}

async fn start_container() -> Started {
    let _permit = STARTS.acquire().await.expect("semaphore is never closed");
    let mut failures = Vec::new();
    for _ in 0..START_ATTEMPTS {
        match try_start().await {
            Ok(started) => return started,
            Err(failure) => failures.push(failure),
        }
    }
    panic!(
        "PostgreSQL container could not be started; is Docker running? {}",
        failures.join("; ")
    );
}

/// A PostgreSQL container with the schema migrated and two connections: one
/// as the schema owner and one as the application role.
///
/// The container is removed when this value is dropped.
#[derive(Debug)]
pub struct TestDatabase {
    owner: PgPool,
    app: Database,
    platform: PgPool,
    app_url: String,
    platform_url: String,
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
        let Started {
            container,
            host,
            port,
            owner,
        } = start_container().await;
        migrate(&owner).await.expect("migrations should apply");

        // A login role that is a member of the application group role, the
        // way an operator would provision it.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {APP_LOGIN} LOGIN PASSWORD '{APP_PASSWORD}' IN ROLE hodor_app"
        )))
        .execute(&owner)
        .await
        .expect("application login role");

        let app_url = format!("postgres://{APP_LOGIN}:{APP_PASSWORD}@{host}:{port}/postgres");
        let app = Database::connect(&Secret::from(app_url.clone()), 5)
            .await
            .expect("application connection");

        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {PLATFORM_LOGIN} LOGIN PASSWORD '{PLATFORM_PASSWORD}' IN ROLE hodor_platform"
        )))
        .execute(&owner)
        .await
        .expect("platform login role");
        let platform_url =
            format!("postgres://{PLATFORM_LOGIN}:{PLATFORM_PASSWORD}@{host}:{port}/postgres");
        let platform = PgPoolOptions::new()
            .max_connections(2)
            .connect(&platform_url)
            .await
            .expect("platform connection");

        Self {
            owner,
            app,
            platform,
            app_url,
            platform_url,
            _container: container,
        }
    }

    /// Connection as the schema owner, for test setup.
    #[must_use]
    pub const fn owner(&self) -> &PgPool {
        &self.owner
    }

    /// Connection as the cross-tenant platform role, for worker components.
    #[must_use]
    pub const fn platform(&self) -> &PgPool {
        &self.platform
    }

    /// Connection URL of the application login role, for starting a binary
    /// against this database.
    #[must_use]
    pub fn app_url(&self) -> &str {
        &self.app_url
    }

    /// Connection URL of the platform login role.
    #[must_use]
    pub fn platform_url(&self) -> &str {
        &self.platform_url
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
const PLATFORM_TABLES: &[&str] = &[
    // The migration tool's own bookkeeping.
    "public._sqlx_migrations",
    // Routing data only: slug, identifier and status. Justified in
    // docs/architecture/contexts/tenant.md, "Storage".
    "platform.tenant_directory",
];

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
