//! The outbox handler: one delivery for every endpoint subscribed to an
//! event's type.

use crate::application::ports::{DeliveryStore, EndpointStore};
use crate::domain::catalog::is_published;
use crate::domain::delivery::Delivery;
use crate::domain::signature::envelope;
use hodor_kernel::{
    Caller, Clock, DomainError, EventEnvelope, EventHandler, EventMetadata, UnitOfWork,
};
use std::sync::Arc;

/// Makes the deliveries of an event, inside the transaction in which the
/// outbox dispatcher marks it dispatched: an event leads to its deliveries
/// exactly once. Nothing leaves the database here; the worker's delivery
/// loop sends them.
#[derive(Clone)]
pub struct WebhookFanOut {
    endpoints: Arc<dyn EndpointStore>,
    deliveries: Arc<dyn DeliveryStore>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for WebhookFanOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookFanOut").finish_non_exhaustive()
    }
}

impl WebhookFanOut {
    /// Wires the handler to its ports.
    #[must_use]
    pub fn new(
        endpoints: Arc<dyn EndpointStore>,
        deliveries: Arc<dyn DeliveryStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            endpoints,
            deliveries,
            clock,
        }
    }
}

#[async_trait::async_trait]
impl EventHandler for WebhookFanOut {
    fn name(&self) -> &'static str {
        "webhooks"
    }

    fn handles(&self, event_type: &str) -> bool {
        is_published(event_type)
    }

    async fn handle(
        &self,
        uow: &mut dyn UnitOfWork,
        event: &EventEnvelope,
    ) -> Result<(), DomainError> {
        // The unit of work is the event's tenant: only its endpoints are
        // found, whatever the event says.
        if event.metadata.tenant_id != uow.tenant().tenant_id() {
            return Err(DomainError::internal(
                "webhooks.tenant_mismatch",
                "an event was handed over in another tenant",
            ));
        }
        let endpoints = self.endpoints.subscribed_to(uow, &event.event_type).await?;
        if endpoints.is_empty() {
            return Ok(());
        }
        let body = envelope(event);
        let now = self.clock.now();
        for endpoint in endpoints {
            let (delivery, set_aside) = Delivery::make(
                endpoint,
                event.metadata.event_id,
                &event.event_type,
                body.clone(),
                now,
            );
            // Handled again after a failure, an event finds its deliveries
            // made and makes none twice.
            let stored = self.deliveries.insert(uow, &delivery).await?;
            if let (true, Some(set_aside)) = (stored, set_aside) {
                let caller = Caller::system();
                let metadata = EventMetadata::new(
                    uow.tenant().tenant_id(),
                    caller.actor,
                    caller.correlation_id,
                    self.clock.as_ref(),
                );
                uow.record_event(EventEnvelope::new(metadata, &set_aside)?);
            }
        }
        Ok(())
    }
}
