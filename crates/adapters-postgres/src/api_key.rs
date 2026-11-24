//! PostgreSQL storage for the API keys of service accounts and agents:
//! the SHA-256 of each key, never the key.
//!
//! See `docs/architecture/contexts/credential.md`, "API keys".

use crate::uow::{connection, database_error};
use hodor_credential::api::{
    ApiKey, ApiKeyHash, ApiKeyId, ApiKeySettings, ApiKeySnapshot, ApiKeyStore, KeyApplicationId,
};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use sqlx::types::Uuid;
use time::Duration;

const HASH_CONSTRAINT: &str = "api_key_hash_unique";

const COLUMNS: &str = "id, holder_id, key_hash, hint, name, scopes, application_id, created_at, \
     expires_at, last_used_at, revoked_at, revocation_reason, replaced_by";

/// [`ApiKeyStore`] on `credential.api_key`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgApiKeyStore;

fn get(error: sqlx::Error) -> DomainError {
    database_error(&error)
}

fn key_from(row: &PgRow) -> Result<ApiKey, DomainError> {
    let hash: Vec<u8> = row.try_get("key_hash").map_err(get)?;
    let hash: [u8; 32] = hash.try_into().map_err(|_| {
        DomainError::internal(
            "credential.stored_data_invalid",
            "the API key could not be loaded",
        )
    })?;
    let application: Option<Uuid> = row.try_get("application_id").map_err(get)?;
    let replaced_by: Option<Uuid> = row.try_get("replaced_by").map_err(get)?;
    Ok(ApiKey::from_snapshot(ApiKeySnapshot {
        id: ApiKeyId::from_uuid(row.try_get("id").map_err(get)?),
        holder_id: UserId::from_uuid(row.try_get("holder_id").map_err(get)?),
        key_hash: ApiKeyHash::from_stored(hash),
        hint: row.try_get("hint").map_err(get)?,
        settings: ApiKeySettings {
            name: row.try_get("name").map_err(get)?,
            scopes: row.try_get("scopes").map_err(get)?,
            application: application.map(KeyApplicationId::from_uuid),
        },
        created_at: row.try_get("created_at").map_err(get)?,
        expires_at: row.try_get("expires_at").map_err(get)?,
        last_used_at: row.try_get("last_used_at").map_err(get)?,
        revoked_at: row.try_get("revoked_at").map_err(get)?,
        revocation_reason: row.try_get("revocation_reason").map_err(get)?,
        replaced_by: replaced_by.map(ApiKeyId::from_uuid),
    }))
}

#[async_trait::async_trait]
impl ApiKeyStore for PgApiKeyStore {
    async fn insert(&self, uow: &mut dyn UnitOfWork, key: &ApiKey) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = key.snapshot();
        sqlx::query(
            "INSERT INTO credential.api_key
                 (tenant_id, id, holder_id, key_hash, hint, name, scopes, application_id,
                  created_at, expires_at, last_used_at, revoked_at, revocation_reason,
                  replaced_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.holder_id.as_uuid())
        .bind(state.key_hash.as_bytes().as_slice())
        .bind(&state.hint)
        .bind(&state.settings.name)
        .bind(&state.settings.scopes)
        .bind(state.settings.application.map(|id| id.as_uuid()))
        .bind(state.created_at)
        .bind(state.expires_at)
        .bind(state.last_used_at)
        .bind(state.revoked_at)
        .bind(state.revocation_reason.as_deref())
        .bind(state.replaced_by.map(|id| id.as_uuid()))
        .execute(connection(uow)?)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(database) if database.constraint() == Some(HASH_CONSTRAINT) => {
                DomainError::conflict("credential.api_key_taken", "another key has the same hash")
            }
            _ => database_error(&error),
        })?;
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ApiKeyId,
    ) -> Result<Option<ApiKey>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM credential.api_key WHERE tenant_id = $1 AND id = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(get)?
        .as_ref()
        .map(key_from)
        .transpose()
    }

    async fn find_by_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &ApiKeyHash,
    ) -> Result<Option<ApiKey>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM credential.api_key WHERE tenant_id = $1 AND key_hash = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(get)?
        .as_ref()
        .map(key_from)
        .transpose()
    }

    async fn list_of(
        &self,
        uow: &mut dyn UnitOfWork,
        holder: UserId,
    ) -> Result<Vec<ApiKey>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // Identifiers are made from the time, so the newest sorts last.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM credential.api_key
             WHERE tenant_id = $1 AND holder_id = $2
             ORDER BY id DESC"
        )))
        .bind(tenant.as_uuid())
        .bind(holder.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(get)?
        .iter()
        .map(key_from)
        .collect()
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, key: &ApiKey) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = key.snapshot();
        // What a key is made with never changes; its end, its revocation
        // and its successor do. The time of last use is written apart.
        let updated = sqlx::query(
            "UPDATE credential.api_key
             SET expires_at = $3, revoked_at = $4, revocation_reason = $5, replaced_by = $6
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.expires_at)
        .bind(state.revoked_at)
        .bind(state.revocation_reason.as_deref())
        .bind(state.replaced_by.map(|id| id.as_uuid()))
        .execute(connection(uow)?)
        .await
        .map_err(get)?;
        if updated.rows_affected() == 0 {
            return Err(DomainError::not_found(
                "credential.api_key_not_found",
                "the API key does not exist",
            ));
        }
        Ok(())
    }

    async fn record_use(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ApiKeyId,
        now: Timestamp,
        precision: Duration,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let written = sqlx::query(
            "UPDATE credential.api_key SET last_used_at = $3
             WHERE tenant_id = $1 AND id = $2
               AND (last_used_at IS NULL OR last_used_at <= $4)",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .bind(now)
        .bind(now - precision)
        .execute(connection(uow)?)
        .await
        .map_err(get)?;
        Ok(written.rows_affected() == 1)
    }
}
