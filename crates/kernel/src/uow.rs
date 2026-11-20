//! Unit of work: one tenant-scoped transaction as use cases see it.
//!
//! A use case begins a unit of work, passes it to the repositories it calls,
//! records the events that describe what happened and commits. State changes
//! and events are stored atomically; dropping the unit of work without
//! committing discards both.

use crate::error::DomainError;
use crate::event::EventEnvelope;
use crate::tenant::TenantContext;
use std::any::Any;

/// A transaction scoped to one tenant.
#[async_trait::async_trait]
pub trait UnitOfWork: Send {
    /// The tenant this unit of work is bound to.
    fn tenant(&self) -> &TenantContext;

    /// Records an event to be stored when the unit of work commits.
    fn record_event(&mut self, event: EventEnvelope);

    /// Commits state changes and recorded events together.
    ///
    /// # Errors
    ///
    /// Returns an error if the commit fails; nothing is applied in that case.
    async fn commit(self: Box<Self>) -> Result<(), DomainError>;

    /// Gives an adapter access to its own transaction type. Domain and
    /// application code never call this.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Starts units of work.
#[async_trait::async_trait]
pub trait UnitOfWorkFactory: Send + Sync {
    /// Begins a unit of work for `tenant`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying transaction cannot be started.
    async fn begin(&self, tenant: &TenantContext) -> Result<Box<dyn UnitOfWork>, DomainError>;
}
