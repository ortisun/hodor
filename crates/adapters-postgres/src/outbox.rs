//! Outbox dispatcher: delivers stored events to handlers.

use crate::database::Database;
use crate::uow::PgUnitOfWork;
use hodor_kernel::{
    Actor, CorrelationId, DomainError, EventEnvelope, EventHandler, EventId, EventMetadata,
    TenantContext, TenantId, Timestamp,
};
use sqlx::PgPool;
use sqlx::types::{Json, Uuid};
use std::sync::Arc;

/// Longest text kept from a handler failure.
const MAX_ERROR_LENGTH: usize = 2_000;

/// What one call to [`OutboxDispatcher::dispatch_batch`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DispatchReport {
    /// Events delivered to every interested handler.
    pub delivered: usize,
    /// Events whose delivery failed and will be retried.
    pub failed: usize,
    /// Events another dispatcher was handling or had already delivered.
    pub skipped: usize,
}

/// Delivers pending outbox events.
///
/// Any number of dispatchers may run at once: each event is locked with
/// `FOR UPDATE SKIP LOCKED` while it is handled. All handlers for an event
/// run in one transaction of the event's tenant, together with the update
/// that marks the event delivered. If any handler fails, the transaction is
/// rolled back and the event is retried later with exponential backoff.
pub struct OutboxDispatcher {
    platform: PgPool,
    database: Database,
    handlers: Vec<Arc<dyn EventHandler>>,
}

impl std::fmt::Debug for OutboxDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let handlers: Vec<&str> = self.handlers.iter().map(|h| h.name()).collect();
        f.debug_struct("OutboxDispatcher")
            .field("handlers", &handlers)
            .finish_non_exhaustive()
    }
}

impl OutboxDispatcher {
    /// Creates a dispatcher.
    ///
    /// `platform` must connect as a member of `hodor_platform`; it is used
    /// only to find pending events across tenants. Handlers run through
    /// `database`, as the application role, bound to the event's tenant.
    #[must_use]
    pub fn new(platform: PgPool, database: Database, handlers: Vec<Arc<dyn EventHandler>>) -> Self {
        Self {
            platform,
            database,
            handlers,
        }
    }

    /// Handles up to `limit` pending events.
    ///
    /// # Errors
    ///
    /// Returns an error if the database is unreachable. Handler failures are
    /// not errors here; they are counted in the report and retried.
    pub async fn dispatch_batch(&self, limit: u32) -> Result<DispatchReport, sqlx::Error> {
        let pending: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT tenant_id, id
             FROM platform.outbox
             WHERE dispatched_at IS NULL AND next_attempt_at <= now()
             ORDER BY created_at
             LIMIT $1",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.platform)
        .await?;

        let mut report = DispatchReport::default();
        for (tenant_id, event_id) in pending {
            // The worker's job loader is one of the places allowed to
            // establish a tenant context: the tenant comes from the stored
            // event, not from any request.
            let tenant = TenantContext::assume(TenantId::from_uuid(tenant_id));
            match self.dispatch_one(&tenant, event_id).await? {
                Outcome::Delivered => report.delivered += 1,
                Outcome::Skipped => report.skipped += 1,
                Outcome::Failed(error) => {
                    self.record_failure(&tenant, event_id, &error).await?;
                    report.failed += 1;
                }
            }
        }
        Ok(report)
    }

    async fn dispatch_one(
        &self,
        tenant: &TenantContext,
        event_id: Uuid,
    ) -> Result<Outcome, sqlx::Error> {
        type Row = (
            String,
            Json<serde_json::Value>,
            Timestamp,
            Json<Actor>,
            Uuid,
        );

        let tx = self.database.begin(tenant).await?;
        let mut uow = PgUnitOfWork::new(tx, tenant.clone());

        let row: Option<Row> = sqlx::query_as(
            "SELECT event_type, payload, occurred_at, actor, correlation_id
             FROM platform.outbox
             WHERE tenant_id = $1 AND id = $2 AND dispatched_at IS NULL
             FOR UPDATE SKIP LOCKED",
        )
        .bind(tenant.tenant_id().as_uuid())
        .bind(event_id)
        .fetch_optional(uow.connection())
        .await?;

        let Some((event_type, payload, occurred_at, actor, correlation_id)) = row else {
            return Ok(Outcome::Skipped);
        };
        let event = EventEnvelope {
            metadata: EventMetadata {
                event_id: EventId::from_uuid(event_id),
                tenant_id: tenant.tenant_id(),
                occurred_at,
                actor: actor.0,
                correlation_id: CorrelationId::from_uuid(correlation_id),
            },
            event_type,
            payload: payload.0,
        };

        for handler in &self.handlers {
            if !handler.handles(&event.event_type) {
                continue;
            }
            if let Err(error) = handler.handle(&mut uow, &event).await {
                // Dropping the unit of work rolls back everything the
                // handlers did for this event and releases the lock.
                return Ok(Outcome::Failed(describe(handler.name(), &error)));
            }
        }

        sqlx::query(
            "UPDATE platform.outbox
             SET dispatched_at = now(), last_error = NULL
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.tenant_id().as_uuid())
        .bind(event_id)
        .execute(uow.connection())
        .await?;
        uow.commit_now().await?;
        Ok(Outcome::Delivered)
    }

    async fn record_failure(
        &self,
        tenant: &TenantContext,
        event_id: Uuid,
        error: &str,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.database.begin(tenant).await?;
        // Backoff doubles per attempt, from one second up to one hour.
        sqlx::query(
            "UPDATE platform.outbox
             SET attempts = attempts + 1,
                 last_error = $3,
                 next_attempt_at = now() + make_interval(secs => least(power(2, attempts), 3600))
             WHERE tenant_id = $1 AND id = $2 AND dispatched_at IS NULL",
        )
        .bind(tenant.tenant_id().as_uuid())
        .bind(event_id)
        .bind(error)
        .execute(tx.connection())
        .await?;
        tx.commit().await
    }
}

enum Outcome {
    Delivered,
    Skipped,
    Failed(String),
}

fn describe(handler: &str, error: &DomainError) -> String {
    let mut text = format!("{handler}: {error}");
    if let Some(detail) = error.detail() {
        text.push_str(" (");
        text.push_str(detail);
        text.push(')');
    }
    if text.len() > MAX_ERROR_LENGTH {
        let mut end = MAX_ERROR_LENGTH;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}
