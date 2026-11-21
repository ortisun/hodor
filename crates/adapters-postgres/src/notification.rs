//! PostgreSQL storage for the notification context.
//!
//! See `docs/architecture/contexts/notification.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, TenantId, Timestamp, UnitOfWork};
use hodor_notification::api::{
    Locale, Message, MessageId, MessageQueue, MessageSnapshot, MessageStatus, PendingMessages,
    Template,
};
use sqlx::PgPool;
use sqlx::types::{Json, Uuid};
use std::collections::BTreeMap;

/// [`MessageQueue`] on `notification.message`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgMessageQueue;

type Row = (
    Uuid,
    String,
    String,
    String,
    Json<BTreeMap<String, String>>,
    String,
    i32,
    Timestamp,
    Timestamp,
    Option<String>,
    Timestamp,
    Option<Timestamp>,
);

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "notification.stored_data_invalid",
        "the message could not be loaded",
    )
    .with_detail(what.to_owned())
}

fn to_message(row: Row) -> Result<Message, DomainError> {
    let (
        id,
        recipient,
        template,
        locale,
        variables,
        status,
        attempts,
        next_attempt_at,
        expires_at,
        last_error,
        created_at,
        sent_at,
    ) = row;
    Ok(Message::from_snapshot(MessageSnapshot {
        id: MessageId::from_uuid(id),
        recipient,
        template: Template::from_key(&template).map_err(|_| corrupted("unknown template"))?,
        locale: Locale::parse(&locale).map_err(|_| corrupted("invalid locale"))?,
        variables: variables.0,
        status: MessageStatus::from_stored(&status).map_err(|_| corrupted("unknown status"))?,
        attempts: u32::try_from(attempts).map_err(|_| corrupted("negative attempts"))?,
        next_attempt_at,
        expires_at,
        last_error,
        created_at,
        sent_at,
    }))
}

fn attempts_of(state: &MessageSnapshot) -> Result<i32, DomainError> {
    i32::try_from(state.attempts).map_err(|_| corrupted("attempts out of range"))
}

#[async_trait::async_trait]
impl MessageQueue for PgMessageQueue {
    async fn insert(&self, uow: &mut dyn UnitOfWork, message: &Message) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = message.snapshot();
        sqlx::query(
            "INSERT INTO notification.message
                 (tenant_id, id, recipient, template, locale, variables, status, attempts,
                  next_attempt_at, expires_at, last_error, created_at, sent_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(&state.recipient)
        .bind(state.template.key())
        .bind(state.locale.as_str())
        .bind(Json(&state.variables))
        .bind(state.status.as_str())
        .bind(attempts_of(state)?)
        .bind(state.next_attempt_at)
        .bind(state.expires_at)
        .bind(&state.last_error)
        .bind(state.created_at)
        .bind(state.sent_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        id: MessageId,
    ) -> Result<Option<Message>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // A message another worker holds is skipped, not waited for.
        let row: Option<Row> = sqlx::query_as(
            "SELECT id, recipient, template, locale, variables, status, attempts,
                    next_attempt_at, expires_at, last_error, created_at, sent_at
             FROM notification.message
             WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
             FOR UPDATE SKIP LOCKED",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_message).transpose()
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, message: &Message) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = message.snapshot();
        let updated = sqlx::query(
            "UPDATE notification.message
             SET variables = $3, status = $4, attempts = $5, next_attempt_at = $6,
                 last_error = $7, sent_at = $8
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(Json(&state.variables))
        .bind(state.status.as_str())
        .bind(attempts_of(state)?)
        .bind(state.next_attempt_at)
        .bind(&state.last_error)
        .bind(state.sent_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if updated.rows_affected() == 0 {
            return Err(DomainError::not_found(
                "notification.message_not_found",
                "the message does not exist",
            ));
        }
        Ok(())
    }
}

/// [`PendingMessages`] on `notification.message`, across tenants.
#[derive(Debug, Clone)]
pub struct PgPendingMessages {
    platform: PgPool,
}

impl PgPendingMessages {
    /// `platform` must connect as a member of `hodor_platform`; it is used
    /// only to find the messages that are due. Each one is then delivered
    /// through the application role, bound to its tenant.
    #[must_use]
    pub const fn new(platform: PgPool) -> Self {
        Self { platform }
    }
}

#[async_trait::async_trait]
impl PendingMessages for PgPendingMessages {
    async fn due(
        &self,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<(TenantId, MessageId)>, DomainError> {
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT tenant_id, id
             FROM notification.message
             WHERE status = 'pending' AND next_attempt_at <= $1
             ORDER BY created_at, id
             LIMIT $2",
        )
        .bind(now)
        .bind(i64::from(limit))
        .fetch_all(&self.platform)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(rows
            .into_iter()
            .map(|(tenant, id)| (TenantId::from_uuid(tenant), MessageId::from_uuid(id)))
            .collect())
    }
}
