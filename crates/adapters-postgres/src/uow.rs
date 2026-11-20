//! PostgreSQL implementation of the unit of work.

use crate::database::{Database, TenantTransaction};
use hodor_kernel::{DomainError, EventEnvelope, TenantContext, UnitOfWork, UnitOfWorkFactory};
use sqlx::PgConnection;
use sqlx::types::Json;
use std::any::Any;

/// Converts a database failure into a domain error. The driver's message is
/// kept as operator detail and never shown to callers.
pub(crate) fn database_error(error: &sqlx::Error) -> DomainError {
    DomainError::internal("database.error", "the operation could not be completed")
        .with_detail(error.to_string())
}

/// A [`UnitOfWork`] backed by a tenant-scoped PostgreSQL transaction.
#[derive(Debug)]
pub struct PgUnitOfWork {
    tx: TenantTransaction,
    tenant: TenantContext,
    events: Vec<EventEnvelope>,
}

impl PgUnitOfWork {
    pub(crate) fn new(tx: TenantTransaction, tenant: TenantContext) -> Self {
        Self {
            tx,
            tenant,
            events: Vec::new(),
        }
    }

    pub(crate) fn connection(&mut self) -> &mut PgConnection {
        self.tx.connection()
    }

    /// Writes the recorded events to the outbox and commits.
    pub(crate) async fn commit_now(mut self) -> Result<(), sqlx::Error> {
        for event in std::mem::take(&mut self.events) {
            sqlx::query(
                "INSERT INTO platform.outbox
                     (tenant_id, id, event_type, payload, occurred_at, actor, correlation_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(self.tx.tenant_id().as_uuid())
            .bind(event.metadata.event_id.as_uuid())
            .bind(event.event_type)
            .bind(Json(event.payload))
            .bind(event.metadata.occurred_at)
            .bind(Json(event.metadata.actor))
            .bind(event.metadata.correlation_id.as_uuid())
            .execute(self.tx.connection())
            .await?;
        }
        self.tx.commit().await
    }
}

#[async_trait::async_trait]
impl UnitOfWork for PgUnitOfWork {
    fn tenant(&self) -> &TenantContext {
        &self.tenant
    }

    fn record_event(&mut self, event: EventEnvelope) {
        self.events.push(event);
    }

    async fn commit(self: Box<Self>) -> Result<(), DomainError> {
        self.commit_now().await.map_err(|e| database_error(&e))
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait::async_trait]
impl UnitOfWorkFactory for Database {
    async fn begin(&self, tenant: &TenantContext) -> Result<Box<dyn UnitOfWork>, DomainError> {
        let tx = Database::begin(self, tenant)
            .await
            .map_err(|e| database_error(&e))?;
        Ok(Box::new(PgUnitOfWork::new(tx, tenant.clone())))
    }
}

/// Returns the PostgreSQL connection behind a unit of work.
///
/// Repositories in this crate, and event handlers that write to the
/// database, call this to run their queries.
///
/// # Errors
///
/// Returns an internal error if the unit of work was not created by this
/// adapter, which indicates a wiring bug.
pub fn connection(uow: &mut dyn UnitOfWork) -> Result<&mut PgConnection, DomainError> {
    uow.as_any_mut()
        .downcast_mut::<PgUnitOfWork>()
        .map(PgUnitOfWork::connection)
        .ok_or_else(|| {
            DomainError::internal(
                "database.foreign_unit_of_work",
                "the operation could not be completed",
            )
            .with_detail("unit of work was not created by the PostgreSQL adapter")
        })
}
