//! Schema migrations, embedded in the binary.

use sqlx::PgPool;
use sqlx::migrate::{MigrateError, Migrator};

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// Applies all pending migrations.
///
/// The pool must connect as the role that owns the schema, not as the
/// application role. Migrations are applied by `hodor-cli migrate`, never by
/// the server at startup.
///
/// # Errors
///
/// Returns an error if a migration fails or if the database contains a
/// migration this binary does not know.
pub async fn migrate(owner_pool: &PgPool) -> Result<(), MigrateError> {
    MIGRATOR.run(owner_pool).await
}
