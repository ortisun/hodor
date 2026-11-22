//! What happens to messages, as other contexts hear about it.
//!
//! Events carry the message's identifier, its template and its status.
//! They never carry the recipient or the variables.

use crate::domain::message::MessageId;
use hodor_kernel::DomainEvent;
use serde::Serialize;

/// An event of the notification context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum NotificationEvent {
    /// The mail server accepted a message.
    MessageSent {
        /// The message.
        message_id: MessageId,
        /// Which message it was.
        template: &'static str,
    },
    /// A message failed for good or expired.
    MessageFailed {
        /// The message.
        message_id: MessageId,
        /// Which message it was.
        template: &'static str,
        /// `failed` or `expired`.
        status: &'static str,
    },
}

impl DomainEvent for NotificationEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::MessageSent { .. } => "notification.message_sent",
            Self::MessageFailed { .. } => "notification.message_failed",
        }
    }
}
