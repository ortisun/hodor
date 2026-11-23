//! PostgreSQL storage for the register of access tokens: a record of every
//! access token issued, by its `jti`. Never the token.
//!
//! See `docs/architecture/contexts/oauth.md`, "The register of access
//! tokens".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork};
use hodor_oauth::api::{
    AccessTokenRecord, AccessTokenRecordStore, ClientId, GrantId, RefreshFamilyId,
};
use sqlx::Row as _;
use sqlx::types::Uuid;

const CLIENT_CONSTRAINT: &str = "access_token_client_fk";
const GRANT_CONSTRAINT: &str = "access_token_grant_fk";
const FAMILY_CONSTRAINT: &str = "access_token_family_fk";

fn get(error: sqlx::Error) -> DomainError {
    database_error(&error)
}

/// [`AccessTokenRecordStore`] on `oauth.access_token`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgAccessTokenRecordStore;

#[async_trait::async_trait]
impl AccessTokenRecordStore for PgAccessTokenRecordStore {
    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        record: &AccessTokenRecord,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO oauth.access_token
                 (tenant_id, token_id, client_id, grant_id, family_id, expires_at,
                  revoked_at, revocation_reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(tenant.as_uuid())
        .bind(&record.token_id)
        .bind(record.client_id.as_uuid())
        .bind(record.grant_id.map(|grant| grant.as_uuid()))
        .bind(record.family_id.map(|family| family.as_uuid()))
        .bind(record.expires_at)
        .bind(record.revoked_at)
        .bind(record.revocation_reason.as_deref())
        .execute(connection(uow)?)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(database) => match database.constraint() {
                Some(CLIENT_CONSTRAINT) => {
                    DomainError::not_found("oauth.client_not_found", "there is no such client")
                }
                Some(GRANT_CONSTRAINT) => {
                    DomainError::not_found("oauth.grant_not_found", "there is no such grant")
                }
                Some(FAMILY_CONSTRAINT) => DomainError::not_found(
                    "oauth.refresh_token_family_not_found",
                    "there is no such refresh token family",
                ),
                _ => database_error(&error),
            },
            _ => database_error(&error),
        })?;
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        token_id: &str,
    ) -> Result<Option<AccessTokenRecord>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row = sqlx::query(
            "SELECT client_id, grant_id, family_id, expires_at, revoked_at, revocation_reason
             FROM oauth.access_token
             WHERE tenant_id = $1 AND token_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(token_id)
        .fetch_optional(connection(uow)?)
        .await
        .map_err(get)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let grant: Option<Uuid> = row.try_get("grant_id").map_err(get)?;
        let family: Option<Uuid> = row.try_get("family_id").map_err(get)?;
        Ok(Some(AccessTokenRecord {
            token_id: token_id.to_owned(),
            client_id: ClientId::from_uuid(row.try_get("client_id").map_err(get)?),
            grant_id: grant.map(GrantId::from_uuid),
            family_id: family.map(RefreshFamilyId::from_uuid),
            expires_at: row.try_get("expires_at").map_err(get)?,
            revoked_at: row.try_get("revoked_at").map_err(get)?,
            revocation_reason: row.try_get("revocation_reason").map_err(get)?,
        }))
    }

    async fn revoke(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
        token_id: &str,
        at: Timestamp,
        reason: &str,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // Of two revocations at the same moment, the condition lets one
        // revoke and leaves the other nothing to change.
        let changed = sqlx::query(
            "UPDATE oauth.access_token
             SET revoked_at = $4, revocation_reason = $5
             WHERE tenant_id = $1 AND token_id = $2 AND client_id = $3 AND revoked_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(token_id)
        .bind(client.as_uuid())
        .bind(at)
        .bind(reason)
        .execute(connection(uow)?)
        .await
        .map_err(get)?;
        Ok(changed.rows_affected() == 1)
    }

    async fn remove_expired(
        &self,
        uow: &mut dyn UnitOfWork,
        now: Timestamp,
        batch: u32,
    ) -> Result<u64, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // A batch at a time, chosen once and locked, as the other cleanup
        // jobs do.
        let removed = sqlx::query(
            "WITH chosen AS (
                 SELECT token_id FROM oauth.access_token
                 WHERE tenant_id = $1 AND expires_at <= $2
                 LIMIT $3
                 FOR UPDATE SKIP LOCKED
             )
             DELETE FROM oauth.access_token AS record
             USING chosen
             WHERE record.tenant_id = $1 AND record.token_id = chosen.token_id",
        )
        .bind(tenant.as_uuid())
        .bind(now)
        .bind(i64::from(batch))
        .execute(connection(uow)?)
        .await
        .map_err(get)?;
        Ok(removed.rows_affected())
    }
}
