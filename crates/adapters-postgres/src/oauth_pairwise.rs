//! PostgreSQL storage for the tenant's pairwise secret, sealed.
//!
//! See `docs/architecture/contexts/oauth.md`, "Pairwise subject
//! identifiers".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, SealedSecret, Timestamp, UnitOfWork};
use hodor_oauth::api::PairwiseSecretStore;
use sqlx::types::Uuid;

/// [`PairwiseSecretStore`] on `oauth.pairwise_secret`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgPairwiseSecretStore;

#[async_trait::async_trait]
impl PairwiseSecretStore for PgPairwiseSecretStore {
    async fn find(&self, uow: &mut dyn UnitOfWork) -> Result<Option<SealedSecret>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT sealed_secret FROM oauth.pairwise_secret WHERE tenant_id = $1")
                .bind(tenant.as_uuid())
                .fetch_optional(connection(uow)?)
                .await
                .map_err(|e| database_error(&e))?;
        Ok(row.map(|(sealed,)| SealedSecret::from_stored(sealed)))
    }

    async fn insert_unless_present(
        &self,
        uow: &mut dyn UnitOfWork,
        sealed: &SealedSecret,
        created_at: Timestamp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        // The tenant is unique: of two inserts at the same moment, the
        // second waits for the first and then changes nothing.
        sqlx::query(
            "INSERT INTO oauth.pairwise_secret (tenant_id, id, sealed_secret, created_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id) DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(Uuid::now_v7())
        .bind(sealed.as_bytes())
        .bind(created_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }
}
