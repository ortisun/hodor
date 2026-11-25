//! Connection pool and tenant-scoped transactions.

use hodor_kernel::{Secret, TenantContext, TenantId};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection as _, PgConnection, PgPool, Postgres, Transaction};
use std::time::Duration;

/// How long a pooled connection may have been idle and still be handed out
/// without being checked first. Every connection is checked when it is
/// handed back, so one that was used a moment ago needs no second check.
const CHECKED_IF_IDLE_FOR: Duration = Duration::from_secs(1);

/// Opens a plain connection pool.
///
/// For connections that are not tenant-scoped: the platform role of the
/// worker. Tenant data is reached through [`Database`] instead.
///
/// The pool checks a connection when it is handed back, as it always does,
/// and before handing it out only if it has been idle for more than
/// [`CHECKED_IF_IDLE_FOR`]: checking both times cost one more round trip to
/// the database for every transaction.
///
/// # Errors
///
/// Returns an error if the URL is invalid or the database is unreachable.
pub async fn connect_pool(
    url: &Secret<String>,
    max_connections: u32,
) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .test_before_acquire(false)
        .before_acquire(|connection, metadata| {
            Box::pin(async move {
                if metadata.idle_for > CHECKED_IF_IDLE_FOR {
                    connection.ping().await?;
                }
                Ok(true)
            })
        })
        .connect(url.expose())
        .await
}

/// Checks that a pool's database answers. For readiness probes.
///
/// # Errors
///
/// Returns an error if no connection can be acquired or the query fails.
pub async fn ping_pool(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT 1").execute(pool).await.map(|_| ())
}

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
        Ok(Self {
            pool: connect_pool(url, max_connections).await?,
        })
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
    /// `BEGIN` and the setting are sent together, in one round trip. The
    /// tenant's identifier is written into the statement: it is a UUID,
    /// made of hexadecimal digits and hyphens only.
    ///
    /// # Errors
    ///
    /// Returns an error if a connection cannot be acquired or the
    /// transaction cannot be started.
    pub async fn begin(&self, tenant: &TenantContext) -> Result<TenantTransaction, sqlx::Error> {
        let tx = self
            .pool
            .begin_with(sqlx::AssertSqlSafe(begin_statement(tenant.tenant_id())))
            .await?;
        Ok(TenantTransaction {
            tx,
            tenant_id: tenant.tenant_id(),
        })
    }

    /// Checks that the database answers. For readiness probes.
    ///
    /// # Errors
    ///
    /// Returns an error if no connection can be acquired or the query fails.
    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
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

/// The statement that starts a transaction bound to `tenant`.
fn begin_statement(tenant: TenantId) -> String {
    format!(
        "BEGIN; SELECT set_config('app.tenant_id', '{}', true)",
        tenant.as_uuid().hyphenated()
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_transaction_starts_with_the_tenant_written_as_a_uuid() {
        let tenant = TenantId::from_uuid(sqlx::types::Uuid::from_u128(
            0x0193_f2a0_0000_7000_8000_0000_0000_002a,
        ));
        assert_eq!(
            begin_statement(tenant),
            "BEGIN; SELECT set_config('app.tenant_id', '0193f2a0-0000-7000-8000-00000000002a', true)"
        );
    }
}
