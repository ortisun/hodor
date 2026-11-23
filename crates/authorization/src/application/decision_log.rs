//! The record of decisions: keeping what the tenant's settings say of
//! each decision, and reading it back.
//!
//! See `docs/architecture/contexts/authorization.md`, "The record of
//! decisions".

use crate::application::ports::DecisionLogStore;
use crate::domain::decision::AuthorizationDecision;
use crate::domain::decision_log::{DecisionFilter, DecisionLogSettings, DecisionRecord};
use crate::domain::event::AuthorizationEvent;
use crate::domain::request::{Attributes, AuthorizationRequest};
use hodor_kernel::{
    Caller, Clock, DomainError, EventEnvelope, EventMetadata, Page, PageRequest, RandomSource,
    TenantContext, UnitOfWorkFactory,
};
use std::sync::Arc;

/// One decision on its way to the record: the request, what Hodor knew of
/// its subject, and the answer.
#[derive(Debug, Clone, Copy)]
pub struct Decided<'a> {
    /// The request.
    pub request: &'a AuthorizationRequest,
    /// The subject's resolved attributes; none when they could not be.
    pub subject_attributes: &'a Attributes,
    /// The answer.
    pub decision: &'a AuthorizationDecision,
}

/// Keeps and reads the record of decisions.
#[derive(Clone)]
pub struct DecisionLog {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    store: Arc<dyn DecisionLogStore>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for DecisionLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionLog").finish_non_exhaustive()
    }
}

impl DecisionLog {
    /// Wires the record to its ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        store: Arc<dyn DecisionLogStore>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            store,
            random,
            clock,
        }
    }

    /// The tenant's settings: the defaults when it never set any.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub async fn settings(
        &self,
        tenant: &TenantContext,
    ) -> Result<DecisionLogSettings, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        Ok(self.store.settings(uow.as_mut()).await?.unwrap_or_default())
    }

    /// Replaces the tenant's settings. Setting the same ones again changes
    /// nothing and announces nothing.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub async fn replace_settings(
        &self,
        tenant: &TenantContext,
        settings: DecisionLogSettings,
        caller: Caller,
    ) -> Result<DecisionLogSettings, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let current = self.store.settings(uow.as_mut()).await?.unwrap_or_default();
        if current == settings {
            return Ok(current);
        }
        let now = self.clock.now();
        self.store
            .put_settings(uow.as_mut(), &settings, now)
            .await?;
        let event = AuthorizationEvent::DecisionLogChanged {
            mode: settings.mode().as_str(),
            allow_percent: settings.mode().allow_percent(),
            masks: settings.masks().len(),
            retention_days: settings.retention_days(),
        };
        let metadata = EventMetadata::new(
            tenant.tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, &event)?);
        uow.commit().await?;
        Ok(settings)
    }

    /// One page of the tenant's records that pass `filter`, newest first.
    ///
    /// # Errors
    ///
    /// `request.query_invalid` for a cursor of another listing, and storage
    /// errors.
    pub async fn page(
        &self,
        tenant: &TenantContext,
        filter: &DecisionFilter,
        page: &PageRequest,
    ) -> Result<Page<DecisionRecord>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.store.page(uow.as_mut(), filter, page).await
    }

    /// Records the decisions the tenant's settings keep, with their input
    /// reduced by its masks, in one transaction. Returns how many were
    /// recorded. Decisions about Hodor's administration are never
    /// recorded here.
    ///
    /// # Errors
    ///
    /// Storage errors. The caller's answers do not depend on them.
    pub async fn record(
        &self,
        tenant: &TenantContext,
        decided: &[Decided<'_>],
    ) -> Result<usize, DomainError> {
        let decided: Vec<&Decided<'_>> = decided
            .iter()
            .filter(|entry| !entry.request.namespace.is_administration())
            .collect();
        if decided.is_empty() {
            return Ok(0);
        }
        let mut uow = self.units_of_work.begin(tenant).await?;
        let settings = self.store.settings(uow.as_mut()).await?.unwrap_or_default();
        let records: Vec<DecisionRecord> = decided
            .into_iter()
            .filter(|entry| settings.mode().keeps(entry.decision.effect, self.draw()))
            .map(|entry| {
                DecisionRecord::of(
                    &settings,
                    entry.request,
                    entry.subject_attributes,
                    entry.decision,
                )
            })
            .collect();
        if records.is_empty() {
            return Ok(0);
        }
        self.store.append(uow.as_mut(), &records).await?;
        uow.commit().await?;
        Ok(records.len())
    }

    /// A number from 0 to 99, drawn from the random source.
    fn draw(&self) -> u8 {
        let mut bytes = [0_u8; 4];
        self.random.fill(&mut bytes);
        // The bias of a 32-bit value taken modulo 100 is below one in forty
        // million, far below what a sampled record needs.
        u8::try_from(u32::from_le_bytes(bytes) % 100).unwrap_or(0)
    }
}
