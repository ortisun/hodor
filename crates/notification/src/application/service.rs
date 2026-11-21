//! The use cases of the notification context.

use crate::application::ports::{EmailSender, MessageQueue, PendingMessages};
use crate::domain::event::NotificationEvent;
use crate::domain::message::{Locale, Message, MessageId};
use crate::domain::template::Template;
use hodor_kernel::{
    Caller, Clock, DomainError, ErrorKind, EventEnvelope, EventMetadata, TenantContext, Timestamp,
    UnitOfWork, UnitOfWorkFactory,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// What is needed to queue a message.
#[derive(Clone, PartialEq, Eq)]
pub struct EnqueueMessage {
    /// The email address to send to.
    pub recipient: String,
    /// Which message to send.
    pub template: Template,
    /// The language to write it in.
    pub locale: Locale,
    /// The values the template needs.
    pub variables: BTreeMap<String, String>,
    /// After this moment the message is no longer worth sending. For a
    /// message with a link, the moment the link stops working.
    pub expires_at: Timestamp,
}

impl std::fmt::Debug for EnqueueMessage {
    /// The variables are left out: a link in them is as good as a token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnqueueMessage")
            .field("template", &self.template)
            .finish_non_exhaustive()
    }
}

/// Queues messages. This is what other contexts use.
#[derive(Clone)]
pub struct Notifier {
    queue: Arc<dyn MessageQueue>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifier").finish_non_exhaustive()
    }
}

impl Notifier {
    /// Wires the use case to its ports.
    #[must_use]
    pub fn new(queue: Arc<dyn MessageQueue>, clock: Arc<dyn Clock>) -> Self {
        Self { queue, clock }
    }

    /// Puts a message in the queue, inside the caller's unit of work: the
    /// message exists if and only if the caller's change is committed.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the message is not acceptable; see
    /// [`Message::enqueue`].
    pub async fn enqueue(
        &self,
        uow: &mut dyn UnitOfWork,
        command: EnqueueMessage,
    ) -> Result<MessageId, DomainError> {
        let message = Message::enqueue(
            &command.recipient,
            command.template,
            command.locale,
            command.variables,
            command.expires_at,
            self.clock.now(),
        )?;
        self.queue.insert(uow, &message).await?;
        Ok(message.id())
    }
}

/// What one call to [`DeliveryService::deliver_pending`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeliveryReport {
    /// Messages the mail server accepted.
    pub sent: usize,
    /// Messages whose delivery failed and will be tried again.
    pub retrying: usize,
    /// Messages that failed for good.
    pub failed: usize,
    /// Messages dropped because they expired.
    pub expired: usize,
    /// Messages another worker was delivering or had already dealt with.
    pub skipped: usize,
}

impl DeliveryReport {
    /// How many messages this pass dealt with.
    #[must_use]
    pub const fn handled(&self) -> usize {
        self.sent + self.retrying + self.failed + self.expired
    }
}

enum Outcome {
    Sent,
    Retrying,
    Failed,
    Expired,
    Skipped,
}

/// Delivers queued messages. This is what the worker runs.
#[derive(Clone)]
pub struct DeliveryService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    queue: Arc<dyn MessageQueue>,
    pending: Arc<dyn PendingMessages>,
    sender: Arc<dyn EmailSender>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for DeliveryService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryService").finish_non_exhaustive()
    }
}

impl DeliveryService {
    /// Wires the use case to its ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        queue: Arc<dyn MessageQueue>,
        pending: Arc<dyn PendingMessages>,
        sender: Arc<dyn EmailSender>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            queue,
            pending,
            sender,
            clock,
        }
    }

    /// Tries to deliver up to `limit` messages that are due.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails. A mail server that refuses a
    /// message or cannot be reached is not an error here: it is counted in
    /// the report and the message is tried again later.
    pub async fn deliver_pending(&self, limit: u32) -> Result<DeliveryReport, DomainError> {
        let due = self.pending.due(self.clock.now(), limit).await?;
        let mut report = DeliveryReport::default();
        for (tenant_id, message_id) in due {
            // The worker's job loader is one of the places allowed to
            // establish a tenant context: the tenant comes from the stored
            // message, not from any request.
            let tenant = TenantContext::assume(tenant_id);
            match self.deliver_one(&tenant, message_id).await? {
                Outcome::Sent => report.sent += 1,
                Outcome::Retrying => report.retrying += 1,
                Outcome::Failed => report.failed += 1,
                Outcome::Expired => report.expired += 1,
                Outcome::Skipped => report.skipped += 1,
            }
        }
        Ok(report)
    }

    async fn deliver_one(
        &self,
        tenant: &TenantContext,
        id: MessageId,
    ) -> Result<Outcome, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let Some(mut message) = self.queue.take(uow.as_mut(), id).await? else {
            return Ok(Outcome::Skipped);
        };

        let (outcome, event) = if message.is_expired_at(self.clock.now()) {
            (Outcome::Expired, Some(message.expire()?))
        } else {
            match message.render() {
                // Trying again would not help: the message cannot be written.
                Err(error) => (
                    Outcome::Failed,
                    Some(message.fail_for_good(&describe(&error))?),
                ),
                Ok(email) => match self.sender.send(&email).await {
                    Ok(()) => (Outcome::Sent, Some(message.mark_sent(self.clock.now())?)),
                    Err(error) if error.kind() == ErrorKind::Invalid => (
                        Outcome::Failed,
                        Some(message.fail_for_good(&describe(&error))?),
                    ),
                    Err(error) => {
                        match message.record_failure(self.clock.now(), &describe(&error))? {
                            Some(event) => (Outcome::Failed, Some(event)),
                            None => (Outcome::Retrying, None),
                        }
                    }
                },
            }
        };

        self.queue.update(uow.as_mut(), &message).await?;
        if let Some(event) = event {
            self.record(uow.as_mut(), &event)?;
        }
        uow.commit().await?;
        Ok(outcome)
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        event: &NotificationEvent,
    ) -> Result<(), DomainError> {
        let caller = Caller::system();
        let metadata = EventMetadata::new(
            uow.tenant().tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }
}

fn describe(error: &DomainError) -> String {
    match error.detail() {
        Some(detail) => format!("{}: {detail}", error.code()),
        None => error.code().to_owned(),
    }
}
