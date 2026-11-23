//! PostgreSQL storage for the token endpoint: the assertions clients proved
//! who they are with.
//!
//! See `docs/architecture/contexts/oauth.md`, "Checking a client
//! assertion".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork};
use hodor_oauth::api::{ClientAssertionStore, ClientId};

const ASSERTION_CLIENT_CONSTRAINT: &str = "client_assertion_client_fk";

/// [`ClientAssertionStore`] on `oauth.client_assertion`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgClientAssertionStore;

#[async_trait::async_trait]
impl ClientAssertionStore for PgClientAssertionStore {
    async fn remember(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
        assertion_id: &str,
        expires_at: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // Of two requests with the same assertion at the same moment, the
        // primary key lets one insert and the other find nothing to do.
        let inserted = sqlx::query(
            "INSERT INTO oauth.client_assertion (tenant_id, client_id, jti, expires_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, client_id, jti) DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(client.as_uuid())
        .bind(assertion_id)
        .bind(expires_at)
        .execute(connection(uow)?)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(database)
                if database.constraint() == Some(ASSERTION_CLIENT_CONSTRAINT) =>
            {
                DomainError::not_found("oauth.client_not_found", "there is no such client")
            }
            _ => database_error(&error),
        })?;
        Ok(inserted.rows_affected() == 1)
    }
}
