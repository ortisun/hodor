//! The notification context.
//!
//! Sends messages to people: today, email. Other contexts say what to tell
//! whom; this context writes the message in the person's language and gets
//! it delivered. A message is queued in the transaction of the change that
//! causes it, and delivered later by the worker.
//!
//! The specification is `docs/architecture/contexts/notification.md`; this
//! crate follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::ports::{EmailSender, MessageQueue, PendingMessages};
    pub use crate::application::service::{
        DeliveryReport, DeliveryService, EnqueueMessage, Notifier,
    };
    pub use crate::domain::event::NotificationEvent;
    pub use crate::domain::message::{
        Locale, MAX_ATTEMPTS, Message, MessageId, MessageSnapshot, MessageStatus,
    };
    pub use crate::domain::template::{Email, Template};
}
