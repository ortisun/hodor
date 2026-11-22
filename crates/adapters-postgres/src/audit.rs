//! PostgreSQL storage for the audit context.
//!
//! See `docs/architecture/contexts/audit.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_audit::api::{AuditLog, AuditRecord, ChainHead};
use hodor_kernel::{Actor, CorrelationId, DomainError, EventId, Timestamp, UnitOfWork};
use sqlx::types::{Json, Uuid};

/// [`AuditLog`] on `audit.record` and `audit.chain_head`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgAuditLog;

type Row = (
    i64,
    Uuid,
    String,
    Timestamp,
    Timestamp,
    Json<Actor>,
    Uuid,
    Json<serde_json::Value>,
    Vec<u8>,
    Vec<u8>,
);

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "audit.stored_data_invalid",
        "the audit record could not be loaded",
    )
    .with_detail(what.to_owned())
}

fn hash_of(bytes: Vec<u8>) -> Result<[u8; 32], DomainError> {
    bytes
        .try_into()
        .map_err(|_| corrupted("hash is not 32 bytes"))
}

fn sequence_of(stored: i64) -> Result<u64, DomainError> {
    u64::try_from(stored).map_err(|_| corrupted("negative sequence"))
}

fn stored(sequence: u64) -> Result<i64, DomainError> {
    i64::try_from(sequence).map_err(|_| corrupted("sequence out of range"))
}

fn to_head(row: Option<(i64, Vec<u8>)>) -> Result<ChainHead, DomainError> {
    row.map_or(Ok(ChainHead::EMPTY), |(sequence, hash)| {
        Ok(ChainHead {
            sequence: sequence_of(sequence)?,
            hash: hash_of(hash)?,
        })
    })
}

fn to_record(row: Row) -> Result<AuditRecord, DomainError> {
    let (
        sequence,
        event_id,
        action,
        occurred_at,
        recorded_at,
        actor,
        correlation_id,
        details,
        previous_hash,
        hash,
    ) = row;
    Ok(AuditRecord {
        sequence: sequence_of(sequence)?,
        event_id: EventId::from_uuid(event_id),
        action,
        occurred_at,
        recorded_at,
        actor: actor.0,
        correlation_id: CorrelationId::from_uuid(correlation_id),
        details: details.0,
        previous_hash: hash_of(previous_hash)?,
        hash: hash_of(hash)?,
    })
}

fn append_error(error: &sqlx::Error) -> DomainError {
    match error {
        sqlx::Error::Database(database) if database.is_unique_violation() => {
            DomainError::conflict("audit.already_recorded", "the event was already recorded")
        }
        other => database_error(other),
    }
}

#[async_trait::async_trait]
impl AuditLog for PgAuditLog {
    async fn lock_head(&self, uow: &mut dyn UnitOfWork) -> Result<ChainHead, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // One statement creates the head if the tenant has none, locks it
        // and returns it. The update that changes nothing is what takes
        // the lock when the row exists; a second transaction appending
        // for the same tenant waits here until this one ends.
        let row: (i64, Vec<u8>) = sqlx::query_as(
            "INSERT INTO audit.chain_head AS head (tenant_id, sequence, hash)
             VALUES ($1, 0, $2)
             ON CONFLICT (tenant_id) DO UPDATE SET sequence = head.sequence
             RETURNING sequence, hash",
        )
        .bind(tenant.as_uuid())
        .bind(ChainHead::EMPTY.hash.as_slice())
        .fetch_one(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        to_head(Some(row))
    }

    async fn append(
        &self,
        uow: &mut dyn UnitOfWork,
        record: &AuditRecord,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let sequence = stored(record.sequence)?;
        let connection = connection(uow)?;
        sqlx::query(
            "INSERT INTO audit.record
                 (tenant_id, sequence, event_id, action, occurred_at, recorded_at, actor,
                  correlation_id, details, previous_hash, hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(tenant.as_uuid())
        .bind(sequence)
        .bind(record.event_id.as_uuid())
        .bind(&record.action)
        .bind(record.occurred_at)
        .bind(record.recorded_at)
        .bind(Json(record.actor))
        .bind(record.correlation_id.as_uuid())
        .bind(Json(&record.details))
        .bind(record.previous_hash.as_slice())
        .bind(record.hash.as_slice())
        .execute(&mut *connection)
        .await
        .map_err(|e| append_error(&e))?;

        sqlx::query(
            "INSERT INTO audit.chain_head AS head (tenant_id, sequence, hash)
             VALUES ($1, $2, $3)
             ON CONFLICT (tenant_id) DO UPDATE SET sequence = $2, hash = $3",
        )
        .bind(tenant.as_uuid())
        .bind(sequence)
        .bind(record.hash.as_slice())
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn head(&self, uow: &mut dyn UnitOfWork) -> Result<ChainHead, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT sequence, hash FROM audit.chain_head WHERE tenant_id = $1")
                .bind(tenant.as_uuid())
                .fetch_optional(connection(uow)?)
                .await
                .map_err(|e| database_error(&e))?;
        to_head(row)
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: u64,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT sequence, event_id, action, occurred_at, recorded_at, actor, correlation_id,
                    details, previous_hash, hash
             FROM audit.record
             WHERE tenant_id = $1 AND sequence > $2
             ORDER BY sequence
             LIMIT $3",
        )
        .bind(tenant.as_uuid())
        .bind(stored(after)?)
        .bind(i64::from(limit))
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        rows.into_iter().map(to_record).collect()
    }
}
