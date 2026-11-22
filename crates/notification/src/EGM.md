# hodor-notification source

## Overview

The notification context sends messages to people; today, email. Other
contexts say what to tell whom; this context writes the message in the
person's language and gets it delivered. A message is queued in the
transaction of the change that causes it and delivered later by the worker
(`lib.rs` crate documentation). The specification it follows is
`docs/architecture/contexts/notification.md`.

`lib.rs` keeps `application` and `domain` private and exposes the public
surface through `pub mod api`.

## Interface

- `api` re-exports:
  - Ports: `MessageQueue`, `PendingMessages`, `EmailSender`.
  - Service: `Notifier`, `EnqueueMessage`, `DeliveryService`,
    `DeliveryReport`.
  - Event: `NotificationEvent`.
  - Domain: `Message`, `MessageId`, `MessageSnapshot`, `MessageStatus`,
    `Locale`, `MAX_ATTEMPTS`, `Template`, `Email`.
- `testing` (public test-support module, compiled only under
  `#[cfg(any(test, feature = "testing"))]`; the `testing` feature enables
  `hodor-kernel/testing`):
  - `InMemoryMessages`: implements `MessageQueue` and `PendingMessages` over
    a shared `Arc<Mutex<BTreeMap<(TenantId, MessageId), Message>>>`;
    `of_tenant(TenantId) -> Vec<Message>`.
  - `RecordingSender`: an `EmailSender` that keeps accepted emails
    (`sent()`) and can be told to refuse everything (`refuse(bool)`).
  - `verification_message(recipient, at) -> Message`: a valid
    `EmailVerification` message in `pt-BR`.
  - `Ports<'a> { units_of_work, queue, pending }` and
    `run_contract(ports: Ports<'_>)`: the rules every message queue must
    obey; it panics on a broken rule.
- Subdirectories:
  - [application](./application/EGM.md): the three ports, `Notifier` and
    `DeliveryService`.
  - [domain](./domain/EGM.md): `Message` lifecycle and retries, `Template`
    rendering and `NotificationEvent`.

## Invariants

- Other crates may use only what `api` re-exports (`lib.rs`).
- The queue contract (`testing.rs:run_contract`) requires that a stored
  message is taken back unchanged; another tenant cannot take or update it
  (`notification.message_not_found`); messages that are sent, expired or
  failed for good can no longer be taken and are never due; `due` works
  across tenants, oldest first, respects `limit`, and leaves out a message
  whose next try is not yet due.
- `RecordingSender::send` fails with `Invalid`
  `notification.recipient_refused` for recipients ending in
  `@unaddressable.example`, and with an internal
  `notification.delivery_failed` error while refusing.

## Side Effects

- None at the crate root. The `testing` module mutates in-process memory
  only (mutex-guarded maps and an atomic flag).

## Verification

- Run: `cargo test -p hodor-notification`
