//! PostgreSQL storage for the intermediates a tenant's certificate
//! authority signs.
//!
//! See `docs/architecture/contexts/keys.md`, "Signing intermediates" and
//! "`keys.intermediate`".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork};
use hodor_keys::api::{
    AuthorityId, IntermediateConstraints, IntermediateId, IntermediateSnapshot, IntermediateState,
    IntermediateStore, SignedIntermediate,
};
use sqlx::types::Uuid;
use sqlx::{FromRow, postgres::PgRow};

/// [`IntermediateStore`] on `keys.intermediate`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgIntermediateStore;

const COLUMNS: &str = "id, authority_id, serial_number, subject, uris, dns_names,
     permitted_dns_names, excluded_dns_names, certificate, certificate_sha256, public_key_sha256,
     request_sha256, not_before, not_after, signed_at, state, withdrawn_at, withdrawal_reason,
     version";

#[derive(FromRow)]
struct Row {
    id: Uuid,
    authority_id: Uuid,
    serial_number: String,
    subject: String,
    uris: Vec<String>,
    dns_names: Vec<String>,
    permitted_dns_names: Vec<String>,
    excluded_dns_names: Vec<String>,
    certificate: Vec<u8>,
    certificate_sha256: String,
    public_key_sha256: String,
    request_sha256: String,
    not_before: Timestamp,
    not_after: Timestamp,
    signed_at: Timestamp,
    state: String,
    withdrawn_at: Option<Timestamp>,
    withdrawal_reason: Option<String>,
    version: i32,
}

fn to_intermediate(row: Row) -> Result<SignedIntermediate, DomainError> {
    Ok(SignedIntermediate::from_snapshot(IntermediateSnapshot {
        id: IntermediateId::from_uuid(row.id),
        authority_id: AuthorityId::from_uuid(row.authority_id),
        state: IntermediateState::parse(&row.state)?,
        serial_number: row.serial_number,
        subject: row.subject,
        uris: row.uris,
        dns_names: row.dns_names,
        constraints: IntermediateConstraints {
            permitted_dns_names: row.permitted_dns_names,
            excluded_dns_names: row.excluded_dns_names,
            excluded_ip_ranges: hodor_keys::api::EXCLUDED_IP_RANGES
                .map(str::to_owned)
                .to_vec(),
        },
        certificate: row.certificate,
        certificate_sha256: row.certificate_sha256,
        public_key_sha256: row.public_key_sha256,
        request_sha256: row.request_sha256,
        not_before: row.not_before,
        not_after: row.not_after,
        signed_at: row.signed_at,
        withdrawn_at: row.withdrawn_at,
        withdrawal_reason: row.withdrawal_reason,
        version: u32::try_from(row.version).map_err(|_| {
            DomainError::internal(
                "keys.stored_data_invalid",
                "an intermediate could not be loaded",
            )
        })?,
    }))
}

fn read_all(rows: &[PgRow]) -> Result<Vec<SignedIntermediate>, DomainError> {
    rows.iter()
        .map(|row| {
            Row::from_row(row)
                .map_err(|e| database_error(&e))
                .and_then(to_intermediate)
        })
        .collect()
}

#[async_trait::async_trait]
impl IntermediateStore for PgIntermediateStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        intermediate: &SignedIntermediate,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = intermediate.snapshot();
        sqlx::query(
            "INSERT INTO keys.intermediate
                 (tenant_id, id, authority_id, serial_number, subject, uris, dns_names,
                  permitted_dns_names, excluded_dns_names, certificate, certificate_sha256,
                  public_key_sha256, request_sha256, not_before, not_after, signed_at, state,
                  withdrawn_at, withdrawal_reason, version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                     $18, $19, $20)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.authority_id.as_uuid())
        .bind(&state.serial_number)
        .bind(&state.subject)
        .bind(&state.uris)
        .bind(&state.dns_names)
        .bind(&state.constraints.permitted_dns_names)
        .bind(&state.constraints.excluded_dns_names)
        .bind(&state.certificate)
        .bind(&state.certificate_sha256)
        .bind(&state.public_key_sha256)
        .bind(&state.request_sha256)
        .bind(state.not_before)
        .bind(state.not_after)
        .bind(state.signed_at)
        .bind(state.state.as_str())
        .bind(state.withdrawn_at)
        .bind(state.withdrawal_reason.as_deref())
        .bind(i32::try_from(state.version).unwrap_or(i32::MAX))
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: IntermediateId,
    ) -> Result<Option<SignedIntermediate>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let statement =
            format!("SELECT {COLUMNS} FROM keys.intermediate WHERE tenant_id = $1 AND id = $2");
        let row: Option<PgRow> = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(tenant.as_uuid())
            .bind(id.as_uuid())
            .fetch_optional(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
        row.map(|row| {
            Row::from_row(&row)
                .map_err(|e| database_error(&e))
                .and_then(to_intermediate)
        })
        .transpose()
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        authority: AuthorityId,
        before: Option<IntermediateId>,
        limit: u32,
    ) -> Result<Vec<SignedIntermediate>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let statement = format!(
            "SELECT {COLUMNS} FROM keys.intermediate
             WHERE tenant_id = $1 AND authority_id = $2 AND ($3::uuid IS NULL OR id < $3)
             ORDER BY id DESC
             LIMIT $4"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(tenant.as_uuid())
            .bind(authority.as_uuid())
            .bind(before.map(|id| id.as_uuid()))
            .bind(i64::from(limit))
            .fetch_all(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
        read_all(&rows)
    }

    async fn of_key(
        &self,
        uow: &mut dyn UnitOfWork,
        public_key_sha256: &str,
    ) -> Result<Vec<SignedIntermediate>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let statement = format!(
            "SELECT {COLUMNS} FROM keys.intermediate
             WHERE tenant_id = $1 AND public_key_sha256 = $2
             ORDER BY id"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(tenant.as_uuid())
            .bind(public_key_sha256)
            .fetch_all(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
        read_all(&rows)
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        intermediate: &SignedIntermediate,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = intermediate.snapshot();
        // Only its withdrawal changes.
        let changed = sqlx::query(
            "UPDATE keys.intermediate
             SET state = $3, withdrawn_at = $4, withdrawal_reason = $5, version = version + 1
             WHERE tenant_id = $1 AND id = $2 AND version = $6",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.state.as_str())
        .bind(state.withdrawn_at)
        .bind(state.withdrawal_reason.as_deref())
        .bind(i32::try_from(state.version).unwrap_or(i32::MAX))
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if changed.rows_affected() == 0 {
            return Err(if self.get(uow, state.id).await?.is_some() {
                DomainError::conflict(
                    "keys.intermediate_changed",
                    "the intermediate changed meanwhile; read it again",
                )
            } else {
                DomainError::not_found(
                    "keys.intermediate_not_found",
                    "the certificate authority signed no such intermediate",
                )
            });
        }
        Ok(())
    }

    async fn withdrawn_keys(
        &self,
        uow: &mut dyn UnitOfWork,
        now: Timestamp,
    ) -> Result<Vec<String>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let keys: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT public_key_sha256 FROM keys.intermediate
             WHERE tenant_id = $1 AND state = 'withdrawn' AND not_after > $2
             ORDER BY public_key_sha256",
        )
        .bind(tenant.as_uuid())
        .bind(now)
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(keys)
    }
}
