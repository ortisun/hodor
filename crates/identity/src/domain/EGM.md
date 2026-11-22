# Identity domain model

## Overview

The user aggregate, its login identifiers and the events it emits. Every
operation that changes a `User` checks its rules and returns the events that
describe the change (`user.rs: User`); nothing here performs input or output.
The modules are `pub(crate)` (`mod.rs`); the public types are re-exported
through `hodor_identity::api` (`src/lib.rs`). The use cases that drive this
model are described in [the application layer](../application/EGM.md).

## Interface

### `user.rs`

- `UserKind`: `Human`, `ServiceAccount`, `Agent`. `as_str()` gives `human`, `service_account`, `agent`; `from_stored(&str)` reads them back.
- `UserStatus`: `Pending`, `Active`, `Suspended`, `Deactivated`, `Deleted`. `as_str()` gives `pending`, `active`, `suspended`, `deactivated`, `deleted`; `from_stored(&str)` reads them back.
- `Profile { display_name: Option<String>, locale: Option<String> }`, with `Profile::MAX_DISPLAY_NAME_LENGTH = 200`.
- `UserSnapshot`: the stored state (`id`, `kind`, `status`, `status_reason`, `profile`, `identifiers` oldest first, `created_at`, `updated_at`, `version` for optimistic locking).
- `User`, with `User::MAX_IDENTIFIERS = 10`:
  - `create(kind, identifiers: Vec<NormalizedIdentifier>, profile, confirmed, now) -> (User, Vec<UserEvent>)`.
  - `from_snapshot`, `snapshot`, `id`, `status`, `identifiers`.
  - `may_sign_in()`: true only for `Active`.
  - Lifecycle: `activate`, `suspend(reason, now)`, `reactivate`, `deactivate`, `restore`, `mark_deleted`. Each returns one `UserEvent`.
  - Identifiers: `add_identifier(value, now) -> UserEvent`, `verify_identifier(id, now) -> Option<UserEvent>`, `choose_primary(id, now) -> Option<UserEvent>`, `remove_identifier(id, now) -> Vec<UserEvent>`.
  - `change_profile(profile, now) -> UserEvent`.
  - Queries: `identifier_matching(&NormalizedIdentifier)`, `primary_identifier(IdentifierKind)`.

### `identifier.rs`

- `IdentifierId`: defined with `hodor_kernel::define_id!`.
- `IdentifierKind`: `Username`, `Email`. `as_str()` gives `username`, `email`; `from_stored`; `needs_verification()` is true only for `Email`.
- `NormalizedIdentifier`: keeps the typed (display) form and the normalized form that is compared and kept unique. `parse(kind, value)`, `from_login(value) -> Option<Self>`, `from_stored(kind, normalized, display)`, `kind`, `normalized`, `display`, `same_as`.
- `LoginIdentifier { id, value, verified_at, primary, created_at }` with `is_verified()`.

### Domain events (`event.rs`)

`UserEvent` implements `hodor_kernel::DomainEvent` and serializes untagged.

| Variant | Fields | `event_type()` |
| --- | --- | --- |
| `Created` | `user_id`, `kind`, `status` | `identity.user_created` |
| `Activated` | `user_id` | `identity.user_activated` |
| `Suspended` | `user_id`, `reason` | `identity.user_suspended` |
| `Reactivated` | `user_id` | `identity.user_reactivated` |
| `Deactivated` | `user_id` | `identity.user_deactivated` |
| `Restored` | `user_id` | `identity.user_restored` |
| `Deleted` | `user_id` | `identity.user_deleted` |
| `IdentifierAdded` | `user_id`, `identifier_id`, `identifier_kind` | `identity.identifier_added` |
| `IdentifierVerified` | `user_id`, `identifier_id`, `identifier_kind` | `identity.identifier_verified` |
| `IdentifierRemoved` | `user_id`, `identifier_id`, `identifier_kind` | `identity.identifier_removed` |
| `PrimaryIdentifierChanged` | `user_id`, `identifier_id`, `identifier_kind` | `identity.primary_identifier_changed` |
| `ProfileChanged` | `user_id` | `identity.profile_changed` |

## Invariants

- Events never carry the value of a login identifier, only its identifier and kind, because an email address is personal data (`event.rs` module documentation and the fields of `UserEvent`).
- Status lifecycle (`User::require` and each lifecycle method). Any other transition fails with `Conflict` code `identity.invalid_transition`:
  - `activate`: `Pending` to `Active`.
  - `suspend`: `Active` to `Suspended`. The reason is trimmed and must not be empty (`Invalid` `identity.suspension_reason_missing`); it is kept in `status_reason`.
  - `reactivate`: `Suspended` to `Active`.
  - `deactivate`: `Pending`, `Active` or `Suspended` to `Deactivated`.
  - `restore`: `Deactivated` to `Active`. A `Human` with no identifier left cannot be restored (`Invalid` `identity.identifier_required`).
  - `mark_deleted`: `Deactivated` to `Deleted`. Clears every login identifier and resets the profile to `Profile::default()`; only the user identifier remains.
  - Leaving `Suspended` clears `status_reason` (`User::transition`).
- `User::create`: a `Human` needs at least one identifier (`Invalid` `identity.identifier_required`). The user starts `Active` when `confirmed`, otherwise `Pending`. Its `UserId` is generated, its version starts at 0, and it emits `Created` followed by one `IdentifierAdded` per identifier.
- A `Deleted` user cannot change: `add_identifier`, `verify_identifier`, `choose_primary`, `remove_identifier` and `change_profile` fail with `Conflict` `identity.invalid_transition` (`User::require_not_deleted`).
- Login identifiers (`User` methods):
  - At most 10 per user (`Invalid` `identity.too_many_identifiers`).
  - The same name twice, however it was typed, is refused (`Conflict` `identity.identifier_duplicate`, compared with `NormalizedIdentifier::same_as`, which compares kind and normalized form, so a username and an email address with the same text never collide).
  - The first identifier of a kind becomes primary.
  - Only kinds that need verification (email) can be verified (`Invalid` `identity.identifier_not_verifiable`). Verifying again returns `None` and changes nothing.
  - An email address must be verified before it becomes primary (`Conflict` `identity.identifier_not_verified`). Choosing the current primary returns `None`.
  - The last identifier cannot be removed unless the user is `Deactivated` (`Conflict` `identity.last_identifier`). Removing a primary identifier promotes the oldest remaining one of its kind and emits `PrimaryIdentifierChanged` as well.
  - An unknown identifier gives `NotFound` `identity.identifier_not_found`.
- Normalization (`identifier.rs`): the value is trimmed and the display form keeps the trimmed text as typed.
  - A username has 3 to 64 bytes of ASCII letters, digits, `.`, `_` or `-`, starts with a letter or digit, and is lowercased (`Invalid` `identity.username_invalid`).
  - An email address is ASCII, at most 254 bytes, with a local part of 1 to 64 visible characters (no spaces), exactly one `@`, and a host of at least two labels. Each label has 1 to 63 letters, digits or hyphens and does not start or end with a hyphen. The address is lowercased (`Invalid` `identity.email_invalid`).
- `NormalizedIdentifier::from_login` treats text containing `@` as an email address and anything else as a username. It returns `None` instead of an error so that a login form does not reveal the identifier rules.
- Profile (`Profile::validated`): the display name and locale are trimmed, and empty values become `None`. A display name has at most 200 characters (`Invalid` `identity.display_name_invalid`). A locale is a language of 2 or 3 letters followed by optional subtags of 2 to 8 letters or digits, joined by `-` (`Invalid` `identity.locale_invalid`).
- Unknown stored names fail as internal errors: `identity.stored_data_invalid` for user kind and status, and `identity.identifier_kind_unknown` for identifier kind.

## Side Effects

- None outside the aggregate's own in-memory state. The only other effect is identifier generation: `UserId::generate()` in `User::create` and `IdentifierId::generate()` in `User::add_identifier`. Both are made by `hodor_kernel::define_id!`, which produces UUID version 7 values (`crates/kernel/src/id.rs`). Timestamps are passed in by the caller.

## Verification

- Run: `cargo test -p hodor-identity`
