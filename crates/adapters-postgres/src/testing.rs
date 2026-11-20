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
