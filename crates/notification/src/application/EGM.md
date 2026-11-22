# Notification application layer

## Overview

The use cases of the notification context and the three ports they need.
`Notifier` is what other contexts use to queue a message inside their own
unit of work; `DeliveryService` is what the worker runs to deliver due
messages. Both modules are `pub(crate)` in `mod.rs` and reach other crates
through `crate::api`.

## Interface

### Ports (`ports.rs`)

| Trait | Method | Signature | Documented contract |
| --- | --- | --- | --- |
| `MessageQueue` | `insert` | `(&self, uow: &mut dyn UnitOfWork, message: &Message) -> Result<(), DomainError>` | Stores a new message in the unit of work's tenant. |
| `MessageQueue` | `take` | `(&self, uow, id: MessageId) -> Result<Option<Message>, DomainError>` | Takes a pending message for delivery; nobody else can take it until the unit of work ends. Finds nothing if absent, no longer pending, or taken by someone else. |
| `MessageQueue` | `update` | `(&self, uow, message: &Message) -> Result<(), DomainError>` | Stores what delivery did; `NotFound` if the tenant has no such message. |
| `PendingMessages` | `due` | `(&self, now: Timestamp, limit: u32) -> Result<Vec<(TenantId, MessageId)>, DomainError>` | Up to `limit` pending messages due at `now`, longest waiting first, across tenants. Only the worker is given it. |
| `EmailSender` | `send` | `(&self, email: &Email) -> Result<(), DomainError>` | Success means the mail server accepted it. An `Invalid` error means it can never be sent; any other error means try again later. |

All three are `#[async_trait]` and `Send + Sync`. Implementations elsewhere:
`PgMessageQueue` and `PgPendingMessages` in
`crates/adapters-postgres/src/notification.rs`, `SmtpSender` in
`crates/adapters-smtp/src/lib.rs`; in-memory versions in
[the test-support module](../EGM.md).

### Service (`service.rs`)

- `EnqueueMessage { recipient: String, template: Template, locale: Locale, variables: BTreeMap<String, String>, expires_at: Timestamp }`;
  its `Debug` leaves the variables out.
- `Notifier::new(queue: Arc<dyn MessageQueue>, clock: Arc<dyn Clock>)` and
  `Notifier::enqueue(&self, uow: &mut dyn UnitOfWork, command: EnqueueMessage) -> Result<MessageId, DomainError>`.
- `DeliveryService::new(units_of_work: Arc<dyn UnitOfWorkFactory>, queue: Arc<dyn MessageQueue>, pending: Arc<dyn PendingMessages>, sender: Arc<dyn EmailSender>, clock: Arc<dyn Clock>)`
  and `DeliveryService::deliver_pending(&self, limit: u32) -> Result<DeliveryReport, DomainError>`.
- `DeliveryReport { sent, retrying, failed, expired, skipped: usize }` with
  `handled()` = `sent + retrying + failed + expired`.

Kernel items used (`hodor_kernel`): `Caller`, `Clock`, `DomainError`,
`ErrorKind`, `EventEnvelope`, `EventMetadata`, `TenantContext`, `TenantId`,
`Timestamp`, `UnitOfWork`, `UnitOfWorkFactory`.

## Invariants

- `Notifier::enqueue` validates through `Message::enqueue`, inserts into the
  caller's unit of work and does not commit: the message exists only if the
  caller's change is committed (`service.rs:Notifier::enqueue`).
- `deliver_pending` builds each tenant context with
  `TenantContext::assume(tenant_id)` from the stored message, not from a
  request (`service.rs:DeliveryService::deliver_pending`).
- Each message is delivered in its own unit of work: begin, `take`, decide,
  `update`, record the event if any, commit. A message `take` does not return
  counts as `skipped` (`service.rs:DeliveryService::deliver_one`).
- Decision order (`service.rs:DeliveryService::deliver_one`):
  1. expired at `now` gives `Message::expire` (counted `expired`);
  2. a render error gives `fail_for_good` (counted `failed`);
  3. sender success gives `mark_sent` (counted `sent`);
  4. a sender error of kind `ErrorKind::Invalid` gives `fail_for_good`
     (counted `failed`);
  5. any other sender error gives `record_failure`, counted `failed` if it
     was the last attempt, otherwise `retrying` with no event.
- A refused or unreachable mail server is not an error of
  `deliver_pending`; only storage errors are returned.
- Stored error text is `"{code}: {detail}"` or the code alone
  (`service.rs:describe`).
- Delivery events carry the metadata of `Caller::system()`
  (`service.rs:DeliveryService::record`).

## Side Effects

- Reads the injected `Clock`.
- Writes messages through `MessageQueue`; reads due work through
  `PendingMessages`; sends email through `EmailSender`.
- Records `NotificationEvent` envelopes with `UnitOfWork::record_event` and
  commits once per delivered message.

## Verification

- Run: `cargo test -p hodor-notification`
