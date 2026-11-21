//! The use cases of the audit context.

use crate::application::ports::AuditLog;
use crate::domain::record::{AuditRecord, Verification, Verifier};
use hodor_kernel::{
    Clock, Digest, DomainError, EventEnvelope, EventHandler, TenantContext, UnitOfWork,
    UnitOfWorkFactory,
};
use std::sync::Arc;

/// How many records are read at a time when a chain is verified.
const VERIFY_PAGE: u32 = 500;
/// The most records one request for a list may return.
const MAX_PAGE: u32 = 200;

/// The use cases of the audit context.
#[derive(Clone)]
pub struct AuditService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    log: Arc<dyn AuditLog>,
    digest: Arc<dyn Digest>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for AuditService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditService").finish_non_exhaustive()
    }
}

impl AuditService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        log: Arc<dyn AuditLog>,
        digest: Arc<dyn Digest>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            log,
            digest,
            clock,
        }
    }

    /// Appends a record for an event to the chain of the unit of work's
    /// tenant, inside that unit of work: the record exists if and only if
    /// whatever else the unit of work does is committed.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the event belongs to another tenant, and
    /// `Conflict` if it was already recorded.
    pub async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        event: &EventEnvelope,
    ) -> Result<AuditRecord, DomainError> {
        let tenant = uow.tenant().tenant_id();
        if event.metadata.tenant_id != tenant {
            return Err(DomainError::invalid(
                "audit.foreign_event",
                "an event can only be recorded in its own tenant",
            ));
        }
        let head = self.log.lock_head(uow).await?;
        let record =
            AuditRecord::next(tenant, &head, event, self.clock.now(), self.digest.as_ref());
        self.log.append(uow, &record).await?;
        Ok(record)
    }

    /// Returns up to `limit` records of the tenant that come after the
    /// given sequence, in order. At most 200 are returned at a time.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn list(
        &self,
        tenant: &TenantContext,
        after: u64,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.log
            .list(uow.as_mut(), after, limit.clamp(1, MAX_PAGE))
            .await
    }

    /// Checks the tenant's whole chain and reports the first break.
    ///
    /// The chain is read inside one unit of work. Records appended while
    /// it runs may or may not be included; either way what is reported is
    /// a chain that existed.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails. A broken chain is not an error:
    /// it is the answer.
    pub async fn verify(&self, tenant: &TenantContext) -> Result<Verification, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        // The head is read first: records appended afterwards are simply
        // not checked this time.
        let head = self.log.head(uow.as_mut()).await?;
        let mut verifier = Verifier::new(tenant.tenant_id(), self.digest.as_ref());
        while !verifier.is_broken() && verifier.checked() < head.sequence {
            let page = self
                .log
                .list(uow.as_mut(), verifier.checked(), VERIFY_PAGE)
                .await?;
            if page.is_empty() {
                break;
            }
            for record in page
                .iter()
                .filter(|record| record.sequence <= head.sequence)
            {
                verifier.check(record);
            }
        }
        Ok(verifier.finish(&head))
    }
}

/// Turns every event into an audit record. Registered with the outbox
/// dispatcher, which runs it in the transaction that marks the event
/// delivered: an event is recorded once, never zero times and never twice.
#[derive(Debug, Clone)]
pub struct AuditHandler {
    service: AuditService,
}

impl AuditHandler {
    /// Makes the handler.
    #[must_use]
    pub const fn new(service: AuditService) -> Self {
        Self { service }
    }
}

#[async_trait::async_trait]
impl EventHandler for AuditHandler {
    fn name(&self) -> &'static str {
        "audit"
    }

    /// Every event is recorded. The handler does not choose.
    fn handles(&self, _event_type: &str) -> bool {
        true
    }

    async fn handle(
        &self,
        uow: &mut dyn UnitOfWork,
        event: &EventEnvelope,
    ) -> Result<(), DomainError> {
        self.service.record(uow, event).await.map(|_| ())
    }
}
