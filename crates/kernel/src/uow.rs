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

/// In-memory unit of work for tests of use cases.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::{UnitOfWork, UnitOfWorkFactory};
    use crate::error::DomainError;
    use crate::event::EventEnvelope;
    use crate::tenant::TenantContext;
    use std::any::Any;
    use std::sync::{Arc, Mutex};

    /// A unit of work that keeps nothing but the events recorded on it.
    ///
    /// It has no transaction behind it: fake repositories used with it
    /// apply their changes at once. Events reach the factory's log only on
    /// commit, so a test can still assert that an abandoned unit of work
    /// published nothing.
    #[derive(Debug)]
    pub struct InMemoryUnitOfWork {
        tenant: TenantContext,
        pending: Vec<EventEnvelope>,
        committed: Arc<Mutex<Vec<EventEnvelope>>>,
    }

    #[async_trait::async_trait]
    impl UnitOfWork for InMemoryUnitOfWork {
        fn tenant(&self) -> &TenantContext {
            &self.tenant
        }

        fn record_event(&mut self, event: EventEnvelope) {
            self.pending.push(event);
        }

        async fn commit(mut self: Box<Self>) -> Result<(), DomainError> {
            let mut log = self.committed.lock().unwrap_or_else(|e| e.into_inner());
            log.append(&mut self.pending);
            Ok(())
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    /// Starts in-memory units of work and collects the events they commit.
    #[derive(Debug, Clone, Default)]
    pub struct InMemoryUnitOfWorkFactory {
        committed: Arc<Mutex<Vec<EventEnvelope>>>,
    }

    impl InMemoryUnitOfWorkFactory {
        /// Every event committed so far, in order.
        #[must_use]
        pub fn committed_events(&self) -> Vec<EventEnvelope> {
            self.committed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        /// The type names of the committed events, in order.
        #[must_use]
        pub fn committed_event_types(&self) -> Vec<String> {
            self.committed_events()
                .into_iter()
                .map(|event| event.event_type)
                .collect()
        }
    }

    #[async_trait::async_trait]
    impl UnitOfWorkFactory for InMemoryUnitOfWorkFactory {
        async fn begin(&self, tenant: &TenantContext) -> Result<Box<dyn UnitOfWork>, DomainError> {
            Ok(Box::new(InMemoryUnitOfWork {
                tenant: tenant.clone(),
                pending: Vec::new(),
                committed: Arc::clone(&self.committed),
            }))
        }
    }
}
