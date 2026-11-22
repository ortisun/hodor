# hodor-adapters-smtp

## Overview

The mail adapter crate (package `hodor-adapters-smtp`). Its manifest describes it as handing "the notification context's messages to a mail server" (`Cargo.toml` `description`).

It implements the notification context port `hodor_notification::api::EmailSender`, from `crates/notification`: `impl EmailSender for SmtpSender` (`src/lib.rs:98`). It implements no kernel port; it uses `DomainError` and `Secret` from [the kernel](../kernel/EGM.md).

## Subdirectories & Boundaries

- `src`: [./src/EGM.md](./src/EGM.md) - `SmtpSender` and `ConfigurationError`. It sends plain-text mail through `lettre`, with a 30-second timeout. Its side effect is a network connection to the mail server when a message is sent.
- `tests`: integration tests (not documented here).

## Workspace Dependencies

From `Cargo.toml`:

- Hodor crates: `hodor-kernel`, `hodor-notification`.
- Runtime: `async-trait`, `lettre`.
- Development only: `reqwest`, `serde_json`, `testcontainers`, `tokio`.

## Verification

- Run: `cargo test -p hodor-adapters-smtp`
