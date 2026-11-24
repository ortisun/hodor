//! What happens to endpoints and deliveries, as the audit log hears it.
//!
//! Events carry identifiers and event types. They never carry an address,
//! which can hold a token of the receiver's in its query, nor a secret.
//! None of them is in the catalog: a webhook never announces a change to
//! webhooks.

use crate::domain::catalog::EventType;
use crate::domain::delivery::DeliveryId;
use crate::domain::endpoint::EndpointId;
use hodor_kernel::{DomainEvent, EventId, Timestamp};
use serde::Serialize;

/// An event of the webhooks context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum WebhookEvent {
    /// An endpoint was registered.
    EndpointRegistered {
        /// The endpoint.
        endpoint_id: EndpointId,
        /// The event types it receives.
        event_types: Vec<EventType>,
    },
    /// Its subscriptions were replaced.
    SubscriptionsChanged {
        /// The endpoint.
        endpoint_id: EndpointId,
        /// The event types it receives now.
        event_types: Vec<EventType>,
    },
    /// Its secret was rotated.
    SecretRotated {
        /// The endpoint.
        endpoint_id: EndpointId,
        /// When the secret it replaced stops signing.
        #[serde(with = "time::serde::rfc3339::option")]
        previous_expires_at: Option<Timestamp>,
    },
    /// It was removed, with its secrets and deliveries.
    EndpointRemoved {
        /// The endpoint.
        endpoint_id: EndpointId,
    },
    /// A delivery was set aside.
    DeliverySetAside {
        /// The delivery.
        delivery_id: DeliveryId,
        /// Where it was going.
        endpoint_id: EndpointId,
        /// The event it carries.
        event_id: EventId,
        /// How many attempts were made.
        attempts: u32,
    },
    /// A set-aside delivery was asked for again.
    RedeliveryRequested {
        /// The delivery.
        delivery_id: DeliveryId,
        /// Where it goes.
        endpoint_id: EndpointId,
        /// The event it carries.
        event_id: EventId,
    },
}

impl DomainEvent for WebhookEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::EndpointRegistered { .. } => "webhooks.endpoint_registered",
            Self::SubscriptionsChanged { .. } => "webhooks.subscriptions_changed",
            Self::SecretRotated { .. } => "webhooks.secret_rotated",
            Self::EndpointRemoved { .. } => "webhooks.endpoint_removed",
            Self::DeliverySetAside { .. } => "webhooks.delivery_set_aside",
            Self::RedeliveryRequested { .. } => "webhooks.redelivery_requested",
        }
    }
}
