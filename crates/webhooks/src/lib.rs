//! The webhooks context.
//!
//! Tells other systems what happened in a tenant. A tenant registers
//! endpoints and subscribes each to types of event; when such an event is
//! dispatched from the outbox, one delivery is made for each subscribed
//! endpoint, and the worker sends it, signed as Standard Webhooks says,
//! with growing waits between attempts, until it is delivered or set aside.
//!
//! The specification is `docs/architecture/contexts/webhooks.md`; this
//! crate follows it. Why it is a context of its own is Decision 0032.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::delivery::{
        AttemptOutcome, DeliverySettings, Lease, SenderPorts, WebhookSender,
    };
    pub use crate::application::fan_out::WebhookFanOut;
    pub use crate::application::ports::{
        DeliveryQuery, DeliveryStore, DueDeliveries, EndpointStore, HmacSha256,
    };
    pub use crate::application::service::{
        EndpointDetails, RegisterEndpoint, SecretInForce, WebhookService,
    };
    pub use crate::domain::catalog::{CATALOG, EventType, is_published};
    pub use crate::domain::delivery::{
        Delivery, DeliveryId, DeliverySnapshot, DeliveryStatus, MAX_ERROR_LENGTH,
        MAX_PAYLOAD_BYTES, RetryPolicy,
    };
    pub use crate::domain::endpoint::{
        Endpoint, EndpointId, EndpointSnapshot, MAX_DESCRIPTION_LENGTH, MAX_ENDPOINTS,
        MAX_URL_LENGTH, event_types,
    };
    pub use crate::domain::event::WebhookEvent;
    pub use crate::domain::secret::{
        DEFAULT_OVERLAP_HOURS, MAX_OVERLAP_HOURS, SECRET_BYTES, SECRET_PREFIX,
        SIGNING_SECRET_PURPOSE, SigningSecret, SigningSecretId,
    };
    pub use crate::domain::signature::{envelope, signature_header, signed_content};
}
