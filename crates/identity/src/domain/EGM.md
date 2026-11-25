# Identity domain model

## Overview

The user aggregate, its login identifiers, a person's standard claims and the events it emits. Every
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
- `UserSnapshot`: the stored state (`id`, `kind`, `status`, `status_reason`, `profile`, `claims` (a `StandardClaims`, empty for a workload), `identifiers` oldest first, `created_at`, `updated_at`, `version` for optimistic locking).
- `User`, with `User::MAX_IDENTIFIERS = 10`:
  - `create(kind, identifiers: Vec<NormalizedIdentifier>, profile, confirmed, now) -> (User, Vec<UserEvent>)`.
  - `from_snapshot`, `snapshot`, `id`, `kind`, `status`, `identifiers`.
  - `may_sign_in()`: true only for an `Active` `Human`. A service account or an agent never signs in.
  - `is_workload_that_may_act()`: true only for an `Active` `ServiceAccount` or `Agent`.
- `UserKind::is_workload()`: true for `ServiceAccount` and `Agent`.
  - Lifecycle: `activate`, `suspend(reason, now)`, `reactivate`, `deactivate`, `restore`, `mark_deleted`. Each returns one `UserEvent`.
  - Identifiers: `add_identifier(value, now) -> UserEvent`, `verify_identifier(id, now) -> Option<UserEvent>`, `choose_primary(id, now) -> Option<UserEvent>`, `remove_identifier(id, now) -> Vec<UserEvent>`.
  - `change_profile(profile, now) -> UserEvent`.
  - `change_claims(claims: StandardClaims, now) -> Option<UserEvent>`: replaces the standard claims as a whole, after `StandardClaims::checked`; `None` when they are what the user already has.
  - `change_own_claims(claims, now) -> Option<UserEvent>`: as `change_claims`, for claims the person gives on the account page. Whatever `phone_number_verified` they hold is replaced: the number stays verified only when it is, once normalized, the number already kept and that one was verified.
  - Queries: `identifier_matching(&NormalizedIdentifier)`, `primary_identifier(IdentifierKind)`.

### `claims.rs`

A person's standard claims, as OpenID Connect Core, section 5.1, names them. Every rule is checked here, on values (module documentation).

- Bounds, in characters: `LONGEST_NAME` = 200 (given, family and middle name, nickname), `LONGEST_PAGE_ADDRESS` = 1024 (`profile`, `picture`, `website`), `LONGEST_GENDER` = 50, `LONGEST_ZONEINFO` = 64, `LONGEST_PHONE_NUMBER` = 31 (`+`, 15 digits, `;ext=` and 10 digits), `LONGEST_BIRTHDATE` = 10, `LONGEST_FORMATTED_ADDRESS` = 300, `LONGEST_STREET_ADDRESS` = 200, `LONGEST_ADDRESS_PART` = 100 (locality, region, country), `LONGEST_POSTAL_CODE` = 20.
- `PostalAddress { formatted, street_address, locality, region, postal_code, country }`, each an `Option<String>`. `is_empty()`; `parts()` gives each part with its name as OpenID Connect writes it, in that order.
- `StandardClaims { given_name, family_name, middle_name, nickname, profile, picture, website, gender, birthdate, zoneinfo, phone_number, phone_number_verified: bool, address: Option<PostalAddress> }`, `Default`, compared by value.
  - `is_empty()`, `get(ClaimField) -> Option<&str>`, and `set(ClaimField, Option<String>)`, which checks nothing and drops the address when its last part is removed.
  - `checked(now) -> Result<StandardClaims>`: the claims as they are kept, or `Invalid` with code `identity.claim_invalid` for the first field that breaks its rule. The message is the field's name followed by its rule, never the value.
  - `lenient(now) -> StandardClaims`: as `checked`, but a field that breaks its rule is left out and the others kept; for what an identity provider says.
- `ClaimField`: the seventeen values of text a person can have: one per claim kept as text, and one per part of the address. `ALL` lists them in the order of the claims; `as_str()` gives the claim's name, or `address.` and the part's name, such as `address.locality`; `parse(&str)` reads it back.

### `identifier.rs`

- `IdentifierId`: defined with `hodor_kernel::define_id!`.
- `IdentifierKind`: `Username`, `Email`. `as_str()` gives `username`, `email`; `from_stored`; `needs_verification()` is true only for `Email`.
- `NormalizedIdentifier`: keeps the typed (display) form and the normalized form that is compared and kept unique. `parse(kind, value)`, `from_login(value) -> Option<Self>`, `from_stored(kind, normalized, display)`, `kind`, `normalized`, `display`, `same_as`.
- `LoginIdentifier { id, value, verified_at, primary, created_at }` with `is_verified()`.

### `workload.rs`

- `Workload::of(user, kind, owners) -> Option<Workload>`: only a user of that workload kind that is not Deleted. `id`, `kind`, `name` (the display name), `status`, `owners`, `user`.
- `WorkloadStatus`: `Active` or `Disabled`; `of(UserStatus)` reads Pending, Suspended and Deactivated as `Disabled` and Deleted as none. `as_str()` gives `active`, `disabled`.
- `workload_profile(name)`: the name trimmed, 1 to 200 characters (`Invalid` `identity.display_name_invalid`).
- `checked_owners(owners)`: repeats dropped, 1 to `MAX_WORKLOAD_OWNERS` = 10 (`Invalid` `identity.workload_owner_required`, `identity.too_many_workload_owners`).
- `WorkloadEvent`: `OwnerAdded` and `OwnerRemoved`, each with `workload_id`, `kind` and `owner_id`, as `identity.workload_owner_added` and `identity.workload_owner_removed`; `of_change(workload, kind, before, after)` gives the added ones, then the removed ones.

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
  - `mark_deleted`: `Deactivated` to `Deleted`. Clears every login identifier, resets the profile to `Profile::default()` and the claims to `StandardClaims::default()`; only the user identifier remains.
  - Leaving `Suspended` clears `status_reason` (`User::transition`).
- `User::create`: a `Human` needs at least one identifier (`Invalid` `identity.identifier_required`). The user starts `Active` when `confirmed`, otherwise `Pending`. Its `UserId` is generated, its version starts at 0, and it emits `Created` followed by one `IdentifierAdded` per identifier.
- A `Deleted` user cannot change: `add_identifier`, `verify_identifier`, `choose_primary`, `remove_identifier`, `change_profile` and `change_claims` fail with `Conflict` `identity.invalid_transition` (`User::require_not_deleted`).
- Login identifiers (`User` methods):
  - A `ServiceAccount` or an `Agent` has none: `add_identifier`, and so `create` with identifiers, fails with `Invalid` `identity.workload_identifier_refused`.
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
- Standard claims (`StandardClaims::checked`):
  - Every text is trimmed, and an empty one is no value.
  - Names, nickname and gender are 1 to their bound in characters, without control characters.
  - `profile`, `picture` and `website` are an absolute `https` or `http` address with a host and no `@` in it, at most 1024 printable ASCII characters without a double quote or a backslash. Nothing is fetched.
  - `birthdate` is `YYYY-MM-DD` for a day that exists and is not after today, `0000-MM-DD` for any day of some year (the 29th of February included), or `YYYY` from year 1 to this year.
  - `zoneinfo` is parts separated by `/`, each starting with a letter and made of letters, digits, `_`, `-` and `+`. It is not checked against the time zone database.
  - `phone_number` has spaces, hyphens, dots and parentheses taken out, then is `+` and 4 to 15 digits, with an optional `;ext=` and 1 to 10 digits; it is kept in that form.
  - `address.formatted` and `address.street_address` may hold line breaks and no other control character; the other parts hold none. The address exists while one part has a value.
  - `phone_number_verified` is false when there is no number.
- A `ServiceAccount` or an `Agent` has no standard claims: `change_claims` fails with `Invalid` `identity.workload_claims_refused`. Every change of the claims emits `ProfileChanged`, which carries the user's identifier only, and a refused change leaves the claims as they were.
- Unknown stored names fail as internal errors: `identity.stored_data_invalid` for user kind and status, and `identity.identifier_kind_unknown` for identifier kind.

## Side Effects

- None outside the aggregate's own in-memory state. The only other effect is identifier generation: `UserId::generate()` in `User::create` and `IdentifierId::generate()` in `User::add_identifier`. Both are made by `hodor_kernel::define_id!`, which produces UUID version 7 values (`crates/kernel/src/id.rs`). Timestamps are passed in by the caller.

## Verification

- Run: `cargo test -p hodor-identity`
