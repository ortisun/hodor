# Notification domain

## Overview

The message aggregate (what is to be sent to whom, and what became of it),
the built-in templates and how they are written in the recipient's language,
and the events other contexts hear about. The domain is pure; time is passed
in. All modules are `pub(crate)` in `mod.rs`; the types below are re-exported
through `crate::api`.

## Interface

### `message.rs`

- `MessageId`: identifier defined with `hodor_kernel::define_id!`.
- `MAX_ATTEMPTS: u32 = 8`.
- `Locale`: `parse(&str)`, `english()` (`"en"`), `as_str()`.
- `MessageStatus { Pending, Sent, Failed, Expired }` with `as_str()` and
  `from_stored(&str)`.
- `MessageSnapshot`: `id`, `recipient`, `template`, `locale`, `variables`,
  `status`, `attempts`, `next_attempt_at`, `expires_at`, `last_error`,
  `created_at`, `sent_at`. Its `Debug` leaves out recipient and variables.
- `Message`: `enqueue(recipient, template, locale, variables, expires_at, now) -> Result<Message, DomainError>`,
  `from_snapshot`, `id`, `snapshot`, `is_pending`, `is_expired_at(now)`,
  `render() -> Result<Email, DomainError>`,
  `mark_sent(now) -> Result<NotificationEvent, DomainError>`,
  `expire() -> Result<NotificationEvent, DomainError>`,
  `record_failure(now, error) -> Result<Option<NotificationEvent>, DomainError>`,
  `fail_for_good(error) -> Result<NotificationEvent, DomainError>`.

### `template.rs`

- `Template { EmailVerification, AlreadyRegistered, PasswordRecovery, PasswordChanged }`
  with `ALL`, `key()`, `from_key(&str)`, `variables()` and
  `render(recipient, locale, variables) -> Result<Email, DomainError>`.

| Template | `key()` | Variables |
| --- | --- | --- |
| `EmailVerification` | `email_verification` | `link`, `tenant_name`, `expires_at` |
| `AlreadyRegistered` | `already_registered` | `tenant_name` |
| `PasswordRecovery` | `password_recovery` | `link`, `tenant_name`, `expires_at` |
| `PasswordChanged` | `password_changed` | `tenant_name` |

- `Email { recipient, subject, body }`; its `Debug` shows only the subject.

### `event.rs`

`NotificationEvent` (`Serialize`, untagged) implements
`hodor_kernel::DomainEvent`:

| Variant | Fields | `event_type()` |
| --- | --- | --- |
| `MessageSent` | `message_id`, `template: &'static str` | `notification.message_sent` |
| `MessageFailed` | `message_id`, `template`, `status` (`failed` or `expired`) | `notification.message_failed` |

Events never carry the recipient or the variables (`event.rs` module
documentation).

## Invariants

- `Message::enqueue` requires a recipient of at most 254 bytes, with no
  control, whitespace, `<`, `>`, `,` or `;` characters and exactly one `@`
  with non-empty sides (`notification.invalid_recipient`); exactly the
  template's variables (`notification.missing_variable`,
  `notification.unknown_variable`); each value non-empty, at most 2,000 bytes
  and free of control characters (`notification.invalid_variable`); and
  `expires_at > now` (`notification.already_expired`)
  (`message.rs:check_recipient`, `check_variables`, `Message::enqueue`).
- A new message is `Pending`, with zero attempts and `next_attempt_at = now`.
- `Locale::parse` accepts 1 to 35 ASCII letters, digits or hyphens
  (`notification.invalid_locale`).
- Every transition requires `Pending`, else `Conflict`
  `notification.not_pending` (`message.rs:Message::require_pending`). Leaving
  `Pending` clears the variables (`message.rs:Message::finish`).
- `mark_sent` adds one attempt, sets `sent_at` and clears `last_error`;
  `fail_for_good` and `expire` do not add an attempt.
- `record_failure` adds one attempt and keeps at most 500 bytes of the error;
  at `MAX_ATTEMPTS` (8) the message becomes `Failed` and the event is
  returned, otherwise `next_attempt_at = now + delay`, where the delay is
  30 seconds doubled per earlier failure, capped at 30 minutes
  (`message.rs:Message::record_failure`, `retry_delay`).
- A message is expired when `now >= expires_at` (`Message::is_expired_at`).
- Rendering picks Portuguese when the locale's language part (before `-` or
  `_`) is `pt` in any case, otherwise English (`template.rs:Language::for_locale`).
- Placeholders `{name}` are replaced in one pass, so a value containing
  `{other}` is inserted as it is; a missing variable gives
  `notification.missing_variable` (`template.rs:fill`).
- `Template::from_key` and `MessageStatus::from_stored` return `Invalid`
  (`notification.unknown_template`, `notification.unknown_status`) for an
  unknown name.

## Side Effects

- None. `Message::enqueue` calls `MessageId::generate` for the identifier.

## Verification

- Run: `cargo test -p hodor-notification`
