//! Connection pool and tenant-scoped transactions.

use hodor_kernel::{Secret, TenantContext, TenantId};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};

/// Handle to the database as seen by the application role.
#[derive(Debug, Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Connects with the application role's credentials.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is invalid or the database is unreachable.
    pub async fn connect(url: &Secret<String>, max_connections: u32) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(url.expose())
            .await?;
        Ok(Self { pool })
    }

    /// Wraps an existing pool.
    #[must_use]
    pub const fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Starts a transaction bound to `tenant`.
    ///
    /// The tenant is stored in a transaction-local setting, so it is gone at
    /// commit or rollback and never leaks to the next user of the pooled
    /// connection. This is also what keeps the adapter compatible with
    /// connection poolers in transaction mode.
    ///
    /// # Errors
    ///
    /// Returns an error if a connection cannot be acquired.
    pub async fn begin(&self, tenant: &TenantContext) -> Result<TenantTransaction, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(tenant.tenant_id().to_string())
            .execute(&mut *tx)
            .await?;
        Ok(TenantTransaction {
            tx,
            tenant_id: tenant.tenant_id(),
        })
    }

    /// The underlying pool.
    ///
    /// Queries run directly on the pool have no tenant bound and therefore
    /// see no tenant rows. Use it for health checks only.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// A database transaction scoped to one tenant.
///
/// Dropping it without calling [`TenantTransaction::commit`] rolls back.
#[derive(Debug)]
pub struct TenantTransaction {
    tx: Transaction<'static, Postgres>,
    tenant_id: TenantId,
}

impl TenantTransaction {
    /// The tenant this transaction is bound to. Repositories use it for the
    /// explicit `tenant_id` filter of every query.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// The connection to run queries on.
    pub fn connection(&mut self) -> &mut PgConnection {
        &mut self.tx
    }

    /// Commits the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the commit fails; the changes are then not applied.
    pub async fn commit(self) -> Result<(), sqlx::Error> {
        self.tx.commit().await
    }

    /// Rolls the transaction back.
    ///
    /// # Errors
    ///
    /// Returns an error if the rollback cannot be sent; the server discards
    /// the transaction when the connection is reset.
    pub async fn rollback(self) -> Result<(), sqlx::Error> {
        self.tx.rollback().await
    }
}
