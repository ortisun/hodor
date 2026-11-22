//! PostgreSQL storage for the session context.
//!
//! See `docs/architecture/contexts/session.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};
use hodor_session::api::{
    Assurance, ClientInfo, Session, SessionId, SessionSnapshot, SessionStore, TokenHash,
};
use sqlx::types::Uuid;
use time::Duration;

/// [`SessionStore`] on `session.session`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgSessionStore;

const COLUMNS: &str = "id, user_id, token_hash, signed_in_at, assurance, methods, started_at,
     last_activity_at, idle_timeout_seconds, absolute_expires_at, client_address,
     client_description, revoked_at, revocation_reason";

type Row = (
    Uuid,
    Uuid,
    Vec<u8>,
    Timestamp,
    String,
    Vec<String>,
    Timestamp,
    Timestamp,
    i32,
    Timestamp,
    Option<String>,
    Option<String>,
    Option<Timestamp>,
    Option<String>,
);

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "session.stored_data_invalid",
        "the session could not be loaded",
    )
    .with_detail(what.to_owned())
}

fn to_session(row: Row) -> Result<Session, DomainError> {
    let (
        id,
        user_id,
        token_hash,
        signed_in_at,
        assurance,
        methods,
        started_at,
        last_activity_at,
        idle_timeout_seconds,
        absolute_expires_at,
        address,
        description,
        revoked_at,
        revocation_reason,
    ) = row;
    let hash: [u8; 32] = token_hash
        .try_into()
        .map_err(|_| corrupted("token hash is not 32 bytes"))?;
    Ok(Session::from_snapshot(SessionSnapshot {
        id: SessionId::from_uuid(id),
        user_id: UserId::from_uuid(user_id),
        token_hash: TokenHash::from_stored(hash),
        signed_in_at,
        assurance: Assurance::from_stored(&assurance)?,
        methods,
        started_at,
        last_activity_at,
        idle_timeout: Duration::seconds(i64::from(idle_timeout_seconds)),
        absolute_expires_at,
        client: ClientInfo {
            address,
            description,
        },
        revoked_at,
        revocation_reason,
    }))
}

#[async_trait::async_trait]
impl SessionStore for PgSessionStore {
    async fn insert(&self, uow: &mut dyn UnitOfWork, session: &Session) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = session.snapshot();
        let idle = i32::try_from(state.idle_timeout.whole_seconds())
            .map_err(|_| corrupted("idle timeout out of range"))?;
        sqlx::query(
            "INSERT INTO session.session
                 (tenant_id, id, user_id, token_hash, signed_in_at, assurance, methods, started_at,
                  last_activity_at, idle_timeout_seconds, absolute_expires_at, client_address,
                  client_description, revoked_at, revocation_reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.user_id.as_uuid())
        .bind(state.token_hash.as_bytes().as_slice())
        .bind(state.signed_in_at)
        .bind(state.assurance.as_str())
        .bind(&state.methods)
        .bind(state.started_at)
        .bind(state.last_activity_at)
        .bind(idle)
        .bind(state.absolute_expires_at)
        .bind(&state.client.address)
        .bind(&state.client.description)
        .bind(state.revoked_at)
        .bind(&state.revocation_reason)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: SessionId,
    ) -> Result<Option<Session>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM session.session WHERE tenant_id = $1 AND id = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_session).transpose()
    }

    async fn find_by_token_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &TokenHash,
    ) -> Result<Option<Session>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM session.session WHERE tenant_id = $1 AND token_hash = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_session).transpose()
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, session: &Session) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = session.snapshot();
        let updated = sqlx::query(
            "UPDATE session.session
             SET token_hash = $3, last_activity_at = $4, revoked_at = $5, revocation_reason = $6
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.token_hash.as_bytes().as_slice())
        .bind(state.last_activity_at)
        .bind(state.revoked_at)
        .bind(&state.revocation_reason)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?
        .rows_affected();
        if updated == 0 {
            return Err(DomainError::not_found(
                "session.not_found",
                "the session does not exist",
            ));
        }
        Ok(())
    }

    async fn list_for_user(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        now: Timestamp,
    ) -> Result<Vec<Session>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM session.session
             WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL AND absolute_expires_at > $3
             ORDER BY started_at DESC, id DESC"
        )))
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .bind(now)
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        rows.into_iter().map(to_session).collect()
    }
}
