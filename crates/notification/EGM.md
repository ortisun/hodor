# hodor-notification

## Overview

The `hodor-notification` crate (`Cargo.toml` description: "The notification
context: messages to people, queued with the change that causes them and
delivered by the worker."). Other contexts queue messages through
`Notifier`; the worker delivers them through `DeliveryService`, with retries,
expiry and permanent failure decided in the domain.

## Interface

- Source and public surface: [src](./src/EGM.md).
- Ports implemented elsewhere: `MessageQueue` by `PgMessageQueue` and
  `PendingMessages` by `PgPendingMessages`, both in
  `crates/adapters-postgres/src/notification.rs`; `EmailSender` by
  `SmtpSender` in `crates/adapters-smtp/src/lib.rs`.
- Workspace dependencies: `hodor-kernel` (`crates/kernel`), plus
  `async-trait`, `serde` and `time`.
- Feature `testing`: enables the public `testing` module and
  `hodor-kernel/testing`.
- Dev dependencies: `hodor-kernel` with `testing`, the crate itself with
  `testing`, `proptest`, `tokio`.

## Invariants

- Only the `api` module is public to other crates; see
  [src](./src/EGM.md).
- A queued message exists only if the caller's unit of work commits;
  `PendingMessages` is the only port not bound to a tenant (see
  [application](./src/application/EGM.md)).
- Delivery is tried at most `MAX_ATTEMPTS` (8) times, and a message's
  variables are erased once it leaves `Pending` (see
  [domain](./src/domain/EGM.md)).

## Side Effects

- Through `MessageQueue` and `PendingMessages`: stores and reads messages.
  Through `EmailSender`: hands email to a mail server. Through
  `UnitOfWork::record_event`: records `notification.message_sent` and
  `notification.message_failed` events.

## Verification

- Run: `cargo test -p hodor-notification`
