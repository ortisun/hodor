//! What the notification context needs from storage and from a mail server.

use crate::domain::message::{Message, MessageId};
use crate::domain::template::Email;
use hodor_kernel::{DomainError, TenantId, Timestamp, UnitOfWork};

/// Stores the messages of a tenant. Every method works inside the tenant
/// the unit of work is bound to.
#[async_trait::async_trait]
pub trait MessageQueue: Send + Sync {
    /// Stores a new message.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert(&self, uow: &mut dyn UnitOfWork, message: &Message) -> Result<(), DomainError>;

    /// Takes a pending message of the tenant for delivery. Until the unit
    /// of work ends, nobody else can take it. Finds nothing if the tenant
    /// has no such message, if it is no longer pending, or if someone else
    /// has taken it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        id: MessageId,
    ) -> Result<Option<Message>, DomainError>;

    /// Stores what delivery did to a message.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such message.
    async fn update(&self, uow: &mut dyn UnitOfWork, message: &Message) -> Result<(), DomainError>;
}

/// Finds work across tenants. The one port of this context that is not
/// bound to a tenant; only the worker is given it.
#[async_trait::async_trait]
pub trait PendingMessages: Send + Sync {
    /// Returns up to `limit` pending messages whose next try is due at
    /// `now`, the longest waiting first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn due(
        &self,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<(TenantId, MessageId)>, DomainError>;
}

/// Hands a written message to a mail server.
#[async_trait::async_trait]
pub trait EmailSender: Send + Sync {
    /// Sends the message. Success means the mail server accepted it.
    ///
    /// # Errors
    ///
    /// Returns an error of the kind `Invalid` if the message can never be
    /// sent, for example because its recipient cannot be addressed; it is
    /// not tried again. Returns any other error if the mail server refused
    /// the message or could not be reached; it is tried again later. The
    /// error's detail is kept for operators.
    async fn send(&self, email: &Email) -> Result<(), DomainError>;
}
