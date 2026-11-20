//! PostgreSQL storage for the authentication context.
//!
//! See `docs/architecture/contexts/authentication.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_authentication::api::{AttemptCounter, AttemptStore, AttemptSubject};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork};

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
