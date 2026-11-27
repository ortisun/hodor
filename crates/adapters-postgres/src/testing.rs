//! Disposable PostgreSQL for integration tests.

use crate::{Database, migrate};
use hodor_kernel::Secret;
use hodor_test_containers::{HOST, Started};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::time::{Duration, Instant};
use testcontainers::ContainerAsync;
use testcontainers::ImageExt as _;
use testcontainers::core::IntoContainerPort as _;
use testcontainers_modules::postgres::Postgres;

const IMAGE_TAG: &str = "17-alpine";
const PORT: u16 = 5432;
const APP_LOGIN: &str = "hodor_app_login";
const APP_PASSWORD: &str = "app";
const PLATFORM_LOGIN: &str = "hodor_platform_login";
const PLATFORM_PASSWORD: &str = "platform";
/// How long a started container has to accept the first connection.
const FIRST_CONNECTION_WITHIN: Duration = Duration::from_secs(30);

/// Docker struggles when many containers start at the same instant, which is
/// what a parallel test run does. Starts are limited; `hodor-test-containers`
/// publishes the port on `127.0.0.1` alone and starts a new container when
/// one fails, and so when the first connection never succeeds.
static STARTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

/// The address of the owner's database in a container.
fn owner_url(port: u16) -> String {
    format!("postgres://postgres:postgres@{HOST}:{port}/postgres")
}

/// Connects as the owner, trying again for a while: the image says it is
/// ready once its last server listens, and for a moment afterwards a
/// connection through the published port may still be closed unanswered.
async fn first_connection(port: u16) -> Result<PgPool, String> {
    let deadline = Instant::now() + FIRST_CONNECTION_WITHIN;
    loop {
        match PgPoolOptions::new()
            .max_connections(2)
            .connect(&owner_url(port))
            .await
        {
            Ok(owner) => return Ok(owner),
            Err(error) if Instant::now() >= deadline => {
                return Err(format!(
                    "no connection within {} seconds: {error}",
                    FIRST_CONNECTION_WITHIN.as_secs()
                ));
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

async fn start_container() -> (Started<Postgres>, PgPool) {
    let _permit = STARTS.acquire().await.expect("semaphore is never closed");
    hodor_test_containers::start_checked(
        "PostgreSQL",
        || Postgres::default().with_tag(IMAGE_TAG),
        &[PORT.tcp()],
        |started| first_connection(started.port(PORT)),
    )
    .await
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
        let (started, owner) = start_container().await;
        let port = started.port(PORT);
        let host = HOST;
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
            _container: started.into_container(),
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
    // The Open Policy Agent instances of the installation, checked by
    // credential before any tenant is known; only a digest of each
    // credential. Justified in docs/architecture/contexts/authorization.md,
    // "Storage of bundles".
    "platform.policy_agent_instance",
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
