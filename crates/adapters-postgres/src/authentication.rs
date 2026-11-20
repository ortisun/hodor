//! PostgreSQL storage for the authentication context.
//!
//! See `docs/architecture/contexts/authentication.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_authentication::api::{
    AttemptCounter, AttemptStore, AttemptSubject, AuthTransaction, TransactionId,
    TransactionSnapshot, TransactionStatus, TransactionStore,
};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};
use hodor_session::api::ClientInfo;
use sqlx::types::Uuid;

/// [`AttemptStore`] on `authentication.attempt_counter`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgAttemptStore;

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "authentication.stored_data_invalid",
        "the operation could not be completed",
    )
    .with_detail(what.to_owned())
}

fn stored(value: u32) -> Result<i32, DomainError> {
    i32::try_from(value).map_err(|_| corrupted("counter out of range"))
}

#[async_trait::async_trait]
impl AttemptStore for PgAttemptStore {
    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        subject: &AttemptSubject,
        now: Timestamp,
    ) -> Result<AttemptCounter, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let connection = connection(uow)?;
        // Make sure the row exists, then lock it. A second transaction
        // asking for the same subject waits here until this one ends.
        sqlx::query(
            "INSERT INTO authentication.attempt_counter
                 (tenant_id, subject_kind, subject_key, failures, window_started_at, lockouts)
             VALUES ($1, $2, $3, 0, $4, 0)
             ON CONFLICT (tenant_id, subject_kind, subject_key) DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(subject.kind())
        .bind(subject.key().as_slice())
        .bind(now)
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;

        let (failures, window_started_at, lockouts, locked_until): (
            i32,
            Timestamp,
            i32,
            Option<Timestamp>,
        ) = sqlx::query_as(
            "SELECT failures, window_started_at, lockouts, locked_until
                 FROM authentication.attempt_counter
                 WHERE tenant_id = $1 AND subject_kind = $2 AND subject_key = $3
                 FOR UPDATE",
        )
        .bind(tenant.as_uuid())
        .bind(subject.kind())
        .bind(subject.key().as_slice())
        .fetch_one(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;

        Ok(AttemptCounter::from_stored(
            *subject,
            u32::try_from(failures).map_err(|_| corrupted("negative failures"))?,
            window_started_at,
            u32::try_from(lockouts).map_err(|_| corrupted("negative lockouts"))?,
            locked_until,
        ))
    }

    async fn save(
        &self,
        uow: &mut dyn UnitOfWork,
        counter: &AttemptCounter,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let subject = counter.subject();
        sqlx::query(
            "UPDATE authentication.attempt_counter
             SET failures = $4, window_started_at = $5, lockouts = $6, locked_until = $7
             WHERE tenant_id = $1 AND subject_kind = $2 AND subject_key = $3",
        )
        .bind(tenant.as_uuid())
        .bind(subject.kind())
        .bind(subject.key().as_slice())
        .bind(stored(counter.failures())?)
        .bind(counter.window_started_at())
        .bind(stored(counter.lockouts())?)
        .bind(counter.stored_locked_until())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn clear(
        &self,
        uow: &mut dyn UnitOfWork,
        subject: &AttemptSubject,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "DELETE FROM authentication.attempt_counter
             WHERE tenant_id = $1 AND subject_kind = $2 AND subject_key = $3",
        )
        .bind(tenant.as_uuid())
        .bind(subject.kind())
        .bind(subject.key().as_slice())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }
}

/// [`TransactionStore`] on `authentication.transaction`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgTransactionStore;

type TransactionRow = (
    Uuid,
    String,
    i32,
    i32,
    bool,
    Option<Uuid>,
    Option<Vec<u8>>,
    Vec<String>,
    i32,
    String,
    Timestamp,
    Timestamp,
    Option<String>,
    Option<String>,
    i32,
);

fn unsigned(value: i32, what: &str) -> Result<u32, DomainError> {
    u32::try_from(value).map_err(|_| corrupted(what))
}

fn to_transaction(row: TransactionRow) -> Result<AuthTransaction, DomainError> {
    let (
        id,
        flow_name,
        flow_version,
        current_step,
        identified,
        candidate,
        identifier_key,
        satisfied_methods,
        rejections,
        status,
        started_at,
        expires_at,
        address,
        description,
        version,
    ) = row;
    let identifier_key = identifier_key
        .map(|key| {
            <[u8; 32]>::try_from(key).map_err(|_| corrupted("identifier key is not 32 bytes"))
        })
        .transpose()?;
    Ok(AuthTransaction::from_snapshot(TransactionSnapshot {
        id: TransactionId::from_uuid(id),
        flow_name,
        flow_version: unsigned(flow_version, "negative flow version")?,
        current_step: usize::try_from(current_step).map_err(|_| corrupted("negative step"))?,
        identified,
        candidate: candidate.map(UserId::from_uuid),
        identifier_key,
        satisfied_methods,
        rejections: unsigned(rejections, "negative rejections")?,
        status: TransactionStatus::from_stored(&status)?,
        started_at,
        expires_at,
        client: ClientInfo {
            address,
            description,
        },
        version: unsigned(version, "negative version")?,
    }))
}

#[async_trait::async_trait]
impl TransactionStore for PgTransactionStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: &AuthTransaction,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = transaction.snapshot();
        sqlx::query(
            "INSERT INTO authentication.transaction
                 (tenant_id, id, flow_name, flow_version, current_step, identified, candidate_user_id,
                  identifier_key, satisfied_methods, rejections, status, started_at, expires_at,
                  client_address, client_description, version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(&state.flow_name)
        .bind(stored(state.flow_version)?)
        .bind(i32::try_from(state.current_step).map_err(|_| corrupted("step out of range"))?)
        .bind(state.identified)
        .bind(state.candidate.map(|user| user.as_uuid()))
        .bind(state.identifier_key.map(|key| key.to_vec()))
        .bind(&state.satisfied_methods)
        .bind(stored(state.rejections)?)
        .bind(state.status.as_str())
        .bind(state.started_at)
        .bind(state.expires_at)
        .bind(&state.client.address)
        .bind(&state.client.description)
        .bind(stored(state.version)?)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TransactionId,
    ) -> Result<Option<AuthTransaction>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<TransactionRow> = sqlx::query_as(
            "SELECT id, flow_name, flow_version, current_step, identified, candidate_user_id,
                    identifier_key, satisfied_methods, rejections, status, started_at, expires_at,
                    client_address, client_description, version
             FROM authentication.transaction
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_transaction).transpose()
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: &AuthTransaction,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = transaction.snapshot();
        let connection = connection(uow)?;
        let updated = sqlx::query(
            "UPDATE authentication.transaction
             SET current_step = $3, identified = $4, candidate_user_id = $5, identifier_key = $6,
                 satisfied_methods = $7, rejections = $8, status = $9, version = version + 1
             WHERE tenant_id = $1 AND id = $2 AND version = $10",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(i32::try_from(state.current_step).map_err(|_| corrupted("step out of range"))?)
        .bind(state.identified)
        .bind(state.candidate.map(|user| user.as_uuid()))
        .bind(state.identifier_key.map(|key| key.to_vec()))
        .bind(&state.satisfied_methods)
        .bind(stored(state.rejections)?)
        .bind(state.status.as_str())
        .bind(stored(state.version)?)
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?
        .rows_affected();
        if updated == 1 {
            return Ok(());
        }
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM authentication.transaction WHERE tenant_id = $1 AND id = $2)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .fetch_one(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
        Err(if exists {
            DomainError::conflict(
                "authentication.transaction_modified_concurrently",
                "this sign-in was advanced by another request",
            )
        } else {
            DomainError::not_found(
                "authentication.transaction_not_found",
                "this sign-in does not exist; start again",
            )
        })
    }
}
