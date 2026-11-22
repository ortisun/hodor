//! PostgreSQL storage for the credential context.
//!
//! See `docs/architecture/contexts/credential.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_credential::api::{
    AccessToken, AccessTokenHash, AccessTokenId, AccessTokenSnapshot, AccessTokenStore,
    HistoricHash, PasswordHash, PasswordRecord, PasswordStore, Totp, TotpId, TotpSnapshot,
    TotpStatus, TotpStore,
};
use hodor_kernel::{DomainError, SealedSecret, TenantId, Timestamp, UnitOfWork, UserId};
use sqlx::PgConnection;
use sqlx::types::Uuid;

/// [`PasswordStore`] on `credential.password` and
/// `credential.password_history`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgPasswordStore;

fn out_of_range(what: &str) -> DomainError {
    DomainError::internal(
        "credential.stored_data_invalid",
        "the operation could not be completed",
    )
    .with_detail(what.to_owned())
}

fn stored_version(record: &PasswordRecord) -> Result<i32, DomainError> {
    i32::try_from(record.version()).map_err(|_| out_of_range("version out of range"))
}

async fn insert_history(
    connection: &mut PgConnection,
    tenant: TenantId,
    record: &PasswordRecord,
) -> Result<(), DomainError> {
    for (position, entry) in record.history().iter().enumerate() {
        let position = i16::try_from(position).map_err(|_| out_of_range("history too long"))?;
        sqlx::query(
            "INSERT INTO credential.password_history
                 (tenant_id, id, user_id, position, password_hash, replaced_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(tenant.as_uuid())
        .bind(Uuid::now_v7())
        .bind(record.user_id().as_uuid())
        .bind(position)
        .bind(entry.hash.as_str())
        .bind(entry.replaced_at)
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl PasswordStore for PgPasswordStore {
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Option<PasswordRecord>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let connection = connection(uow)?;
        let row: Option<(String, bool, Timestamp, i32)> = sqlx::query_as(
            "SELECT password_hash, must_change, changed_at, version
             FROM credential.password
             WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
        let Some((hash, must_change, changed_at, version)) = row else {
            return Ok(None);
        };

        let history: Vec<(String, Timestamp)> = sqlx::query_as(
            "SELECT password_hash, replaced_at
             FROM credential.password_history
             WHERE tenant_id = $1 AND user_id = $2
             ORDER BY position",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_all(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;

        Ok(Some(PasswordRecord::from_stored(
            user_id,
            PasswordHash::new(hash),
            must_change,
            changed_at,
            history
                .into_iter()
                .map(|(hash, replaced_at)| HistoricHash {
                    hash: PasswordHash::new(hash),
                    replaced_at,
                })
                .collect(),
            u32::try_from(version).map_err(|_| out_of_range("negative version"))?,
        )))
    }

    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        record: &PasswordRecord,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let version = stored_version(record)?;
        let connection = connection(uow)?;
        // `ON CONFLICT DO NOTHING` rather than catching the error: a failed
        // statement would abort the whole transaction.
        let inserted = sqlx::query(
            "INSERT INTO credential.password
                 (tenant_id, user_id, password_hash, must_change, changed_at, version)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, user_id) DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(record.user_id().as_uuid())
        .bind(record.hash().as_str())
        .bind(record.must_change())
        .bind(record.changed_at())
        .bind(version)
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?
        .rows_affected();
        if inserted == 0 {
            return Err(DomainError::conflict(
                "credential.password_exists",
                "the user already has a password",
            ));
        }
        insert_history(connection, tenant, record).await
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        record: &PasswordRecord,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let version = stored_version(record)?;
        let connection = connection(uow)?;

        let updated = sqlx::query(
            "UPDATE credential.password
             SET password_hash = $3, must_change = $4, changed_at = $5, version = version + 1
             WHERE tenant_id = $1 AND user_id = $2 AND version = $6",
        )
        .bind(tenant.as_uuid())
        .bind(record.user_id().as_uuid())
        .bind(record.hash().as_str())
        .bind(record.must_change())
        .bind(record.changed_at())
        .bind(version)
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?
        .rows_affected();

        if updated == 0 {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT FROM credential.password WHERE tenant_id = $1 AND user_id = $2)",
            )
            .bind(tenant.as_uuid())
            .bind(record.user_id().as_uuid())
            .fetch_one(&mut *connection)
            .await
            .map_err(|e| database_error(&e))?;
            return Err(if exists {
                DomainError::conflict(
                    "credential.password_modified_concurrently",
                    "the password was changed by someone else; try again",
                )
            } else {
                DomainError::not_found("credential.password_not_found", "the user has no password")
            });
        }

        // The version check means nobody else changed this record, so its
        // short history can simply be replaced.
        sqlx::query(
            "DELETE FROM credential.password_history WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(record.user_id().as_uuid())
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
        insert_history(connection, tenant, record).await
    }

    async fn delete(&self, uow: &mut dyn UnitOfWork, user_id: UserId) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let deleted =
            sqlx::query("DELETE FROM credential.password WHERE tenant_id = $1 AND user_id = $2")
                .bind(tenant.as_uuid())
                .bind(user_id.as_uuid())
                .execute(connection(uow)?)
                .await
                .map_err(|e| database_error(&e))?
                .rows_affected();
        Ok(deleted > 0)
    }
}

/// [`AccessTokenStore`] on `credential.access_token`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgAccessTokenStore;

const TOKEN_COLUMNS: &str =
    "id, user_id, token_hash, description, created_at, expires_at, revoked_at";

type TokenRow = (
    Uuid,
    Uuid,
    Vec<u8>,
    String,
    Timestamp,
    Timestamp,
    Option<Timestamp>,
);

fn to_token(row: TokenRow) -> Result<AccessToken, DomainError> {
    let (id, user_id, token_hash, description, created_at, expires_at, revoked_at) = row;
    let hash: [u8; 32] = token_hash
        .try_into()
        .map_err(|_| out_of_range("token hash is not 32 bytes"))?;
    Ok(AccessToken::from_snapshot(AccessTokenSnapshot {
        id: AccessTokenId::from_uuid(id),
        user_id: UserId::from_uuid(user_id),
        token_hash: AccessTokenHash::from_stored(hash),
        description,
        created_at,
        expires_at,
        revoked_at,
    }))
}

#[async_trait::async_trait]
impl AccessTokenStore for PgAccessTokenStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &AccessToken,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = token.snapshot();
        sqlx::query(
            "INSERT INTO credential.access_token
                 (tenant_id, id, user_id, token_hash, description, created_at, expires_at,
                  revoked_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.user_id.as_uuid())
        .bind(state.token_hash.as_bytes().as_slice())
        .bind(&state.description)
        .bind(state.created_at)
        .bind(state.expires_at)
        .bind(state.revoked_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: AccessTokenId,
    ) -> Result<Option<AccessToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<TokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {TOKEN_COLUMNS} FROM credential.access_token WHERE tenant_id = $1 AND id = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_token).transpose()
    }

    async fn find_by_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &AccessTokenHash,
    ) -> Result<Option<AccessToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<TokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {TOKEN_COLUMNS} FROM credential.access_token
             WHERE tenant_id = $1 AND token_hash = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_token).transpose()
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &AccessToken,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = token.snapshot();
        // Only the revocation can change; everything else about a token
        // is fixed when it is issued.
        let updated = sqlx::query(
            "UPDATE credential.access_token SET revoked_at = $3
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.revoked_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if updated.rows_affected() == 0 {
            return Err(DomainError::not_found(
                "credential.access_token_not_found",
                "the access token does not exist",
            ));
        }
        Ok(())
    }
}

/// [`TotpStore`] on `credential.totp`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgTotpStore;

const TOTP_COLUMNS: &str =
    "id, user_id, status, sealed_secret, created_at, confirmed_at, last_used_step";

type TotpRow = (
    Uuid,
    Uuid,
    String,
    Vec<u8>,
    Timestamp,
    Option<Timestamp>,
    Option<i64>,
);

fn to_totp(row: TotpRow) -> Result<Totp, DomainError> {
    let (id, user_id, status, sealed_secret, created_at, confirmed_at, last_used_step) = row;
    Ok(Totp::from_snapshot(TotpSnapshot {
        id: TotpId::from_uuid(id),
        user_id: UserId::from_uuid(user_id),
        status: TotpStatus::parse(&status).ok_or_else(|| out_of_range("unknown status"))?,
        sealed_secret: SealedSecret::from_stored(sealed_secret),
        created_at,
        confirmed_at,
        last_used_step: last_used_step
            .map(u64::try_from)
            .transpose()
            .map_err(|_| out_of_range("negative step"))?,
    }))
}

fn stored_step(step: u64) -> Result<i64, DomainError> {
    i64::try_from(step).map_err(|_| out_of_range("step out of range"))
}

impl PgTotpStore {
    async fn by_status(
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        status: TotpStatus,
    ) -> Result<Option<Totp>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<TotpRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {TOTP_COLUMNS} FROM credential.totp
             WHERE tenant_id = $1 AND user_id = $2 AND status = $3"
        )))
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .bind(status.as_str())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_totp).transpose()
    }
}

#[async_trait::async_trait]
impl TotpStore for PgTotpStore {
    async fn active(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Option<Totp>, DomainError> {
        Self::by_status(uow, user_id, TotpStatus::Active).await
    }

    async fn pending(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Option<Totp>, DomainError> {
        Self::by_status(uow, user_id, TotpStatus::Pending).await
    }

    async fn replace_pending(
        &self,
        uow: &mut dyn UnitOfWork,
        enrollment: &Totp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = enrollment.snapshot();
        sqlx::query(
            "DELETE FROM credential.totp
             WHERE tenant_id = $1 AND user_id = $2 AND status = 'pending'",
        )
        .bind(tenant.as_uuid())
        .bind(state.user_id.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        sqlx::query(
            "INSERT INTO credential.totp
                 (tenant_id, id, user_id, status, sealed_secret, created_at, confirmed_at,
                  last_used_step)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.user_id.as_uuid())
        .bind(state.status.as_str())
        .bind(state.sealed_secret.as_bytes())
        .bind(state.created_at)
        .bind(state.confirmed_at)
        .bind(state.last_used_step.map(stored_step).transpose()?)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn activate(
        &self,
        uow: &mut dyn UnitOfWork,
        confirmed: &Totp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = confirmed.snapshot();
        // The enrollment is locked first. A second confirmation of the same
        // enrollment waits here, then finds it no longer pending and
        // changes nothing.
        let waiting: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM credential.totp
             WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
             FOR UPDATE",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if waiting.is_none() {
            return Err(DomainError::not_found(
                "credential.totp_enrollment_not_found",
                "there is no enrollment of an authenticator application waiting to be confirmed; begin again",
            ));
        }
        sqlx::query(
            "DELETE FROM credential.totp
             WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'",
        )
        .bind(tenant.as_uuid())
        .bind(state.user_id.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        let updated = sqlx::query(
            "UPDATE credential.totp
             SET status = 'active', confirmed_at = $3, last_used_step = $4
             WHERE tenant_id = $1 AND id = $2 AND status = 'pending'",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.confirmed_at)
        .bind(state.last_used_step.map(stored_step).transpose()?)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if updated.rows_affected() == 0 {
            return Err(DomainError::not_found(
                "credential.totp_enrollment_not_found",
                "there is no enrollment of an authenticator application waiting to be confirmed; begin again",
            ));
        }
        Ok(())
    }

    async fn use_step(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TotpId,
        step: u64,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // One statement: of two requests with the same step, the row lock
        // makes the second see the first one's step and change nothing.
        let updated = sqlx::query(
            "UPDATE credential.totp SET last_used_step = $3
             WHERE tenant_id = $1 AND id = $2 AND status = 'active'
               AND (last_used_step IS NULL OR last_used_step < $3)",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .bind(stored_step(step)?)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(updated.rows_affected() == 1)
    }

    async fn remove(&self, uow: &mut dyn UnitOfWork, user_id: UserId) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let had: Option<(i64,)> = sqlx::query_as(
            "WITH gone AS (
                 DELETE FROM credential.totp WHERE tenant_id = $1 AND user_id = $2
                 RETURNING status
             )
             SELECT count(*) FROM gone WHERE status = 'active'",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(had.is_some_and(|(count,)| count > 0))
    }
}
