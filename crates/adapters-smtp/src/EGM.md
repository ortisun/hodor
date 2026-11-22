# hodor-adapters-smtp source

## Overview

The mail adapter. It hands the notification context's messages to a mail server over SMTP, using `lettre`. The single source file is `lib.rs`. It implements a port of the notification context, not a kernel port.

## Interface

- `impl EmailSender for SmtpSender` (`lib.rs:98`, under `#[async_trait::async_trait]`) implements `hodor_notification::api::EmailSender`, a port of the notification context in `crates/notification`. Its one method is `send(&self, email: &Email) -> Result<(), DomainError>` (`lib.rs:SmtpSender::send`).
- `SmtpSender::new(url: &Secret<String>, from: &str) -> Result<Self, ConfigurationError>` builds the transport from the server address with `AsyncSmtpTransport::<Tokio1Executor>::from_url`, sets a 30-second timeout, and parses `from` into a mailbox (`lib.rs:SmtpSender::new`).
- `ConfigurationError` has the variants `InvalidServerAddress` and `InvalidSenderAddress`, with fixed messages from `Display` (`lib.rs:ConfigurationError`).
- The `Debug` output of `SmtpSender` shows only the sender address. It leaves out the transport, which holds the password (`lib.rs:SmtpSender`).

## Invariants

- The code does not choose the transport security itself: the whole address goes to `lettre`'s `from_url`. The documentation describes the schemes: `smtps` encrypts from the start, `smtp` with `?tls=required` encrypts after connecting, and plain `smtp` is for development only. This crate does not reject plain `smtp` (`lib.rs:SmtpSender::new`).
- `ConfigurationError` variants carry no data, so errors never contain the server address or the password (`lib.rs:ConfigurationError`).
- Every message is sent from the one sender mailbox set at construction, to one recipient, as plain text (`ContentType::TEXT_PLAIN`) with `email.subject` and `email.body` (`lib.rs:SmtpSender::send`).
- A recipient that does not parse as a mailbox gives `notification.recipient_refused` (`Invalid`); the code comment says retrying would not help. A message that cannot be built, or a transport failure, gives `notification.delivery_failed` (`Internal`), with the cause in `detail` (`lib.rs:SmtpSender::send`, `lib.rs:failed`).

## Side Effects

- `SmtpSender::new` opens no connection; the server is first contacted when a message is sent (`lib.rs:SmtpSender::new`).
- `SmtpSender::send` connects to the mail server and delivers the message through `AsyncTransport::send`, within the 30-second timeout (`lib.rs:SmtpSender::send`, `lib.rs:TIMEOUT`).

## Verification

- Run: `cargo test -p hodor-adapters-smtp`
