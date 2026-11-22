# Credential domain model

## Overview

What is acceptable as a password, what is kept about one, and access tokens,
which let a program act as a user on the administration interface until OAuth
access tokens exist (`access_token.rs` module documentation). Nothing here
performs input or output. The modules are `pub(crate)` (`mod.rs`); public
types are re-exported through `hodor_credential::api` (`src/lib.rs`). The
use cases that drive this model are described in
[the application layer](../application/EGM.md).

## Interface

### `password.rs`

- `MAX_PASSWORD_BYTES: usize = 4096`.
- `PasswordRules { min_length: u16, max_length: u16, history_depth: u8 }`: supplied by the caller from the tenant's password policy.
- `check_acceptable(password: &Secret<String>, rules: &PasswordRules, own_names: &[&str]) -> Result<(), DomainError>`.
- `PasswordHash`: opaque encoded hash. `new(String)`, `as_str()`.
- `HistoricHash { hash: PasswordHash, replaced_at: Timestamp }`.
- `PasswordRecord`:
  - Constructors: `new(user_id, hash, must_change, now)` for a first password (empty history, version 0), and `from_stored(…, history, version)`.
  - Accessors: `user_id`, `hash`, `must_change`, `changed_at`, `history` (newest first), `version`.
  - `hashes_barred_from_reuse(depth) -> impl Iterator<Item = &PasswordHash>`.
  - `replace(hash, must_change, history_depth, now)`, `renew_hash(hash)`.

### `access_token.rs`

- `AccessTokenId`: defined with `hodor_kernel::define_id!`. Safe to show and log; it grants nothing.
- `AccessTokenSecret`: the token text. `expose()`. Constants `SHORTEST_LIFETIME` (1 minute) and `LONGEST_LIFETIME` (30 days).
- `AccessTokenHash`: the SHA-256 of a token, which is what is stored. `of_presented(value, digest) -> Option<Self>`, `from_stored([u8; 32])`, `as_bytes()`.
- `AccessTokenSnapshot { id, user_id, token_hash, description, created_at, expires_at, revoked_at }`.
- `AccessToken`:
  - `issue(user_id, description, lifetime, now, random: &dyn RandomSource, digest: &dyn Digest) -> (AccessToken, AccessTokenSecret)`.
  - `from_snapshot`, `snapshot`, `id`, `user_id`.
  - `is_good_at(now)`, `revoke(now) -> Option<AccessTokenEvent>`, `issued_event()`.

### `totp.rs`

- `TotpId`: defined with `hodor_kernel::define_id!`.
- Constants: `ENROLLMENT_LIFETIME` (10 minutes), `STEP_SECONDS` (30), `SEALING_PURPOSE` (`credential.totp_secret`); crate-private `SECRET_BYTES` (20), `DIGITS` (6), `TOLERATED_STEPS` (1).
- Crate-private functions: `step_at(moment)`, `code_from_mac(&[u8; 20]) -> u32` (the dynamic truncation of RFC 4226), `parse_code(typed) -> Option<u32>` (six digits once spaces are taken out), `candidate_steps(moment)` (the step before, the current one and the one after).
- `TotpStatus`: `Pending` or `Active`; `as_str`, `parse`.
- `TotpSnapshot { id, user_id, status, sealed_secret, created_at, confirmed_at, last_used_step }` and `Totp`: `begin(user_id, sealed, now)`, `from_snapshot`, `snapshot`, `id`, `can_be_confirmed_at(now)`, `confirm(step, now) -> TotpEvent`, `accepts_step(step)` (later than the last step used).
- `TotpEnrollment::new(secret, issuer, account)`: `secret()` in Base32 without padding and `address()` (`otpauth://totp/…?secret=…&issuer=…&algorithm=SHA1&digits=6&period=30`). Its `Debug` prints nothing of either.
- `TotpEvent`: `Enrolled { user_id }` (`credential.totp_enrolled`) and `Removed { user_id }` (`credential.totp_removed`).

### Domain events

Both enums implement `hodor_kernel::DomainEvent` and serialize untagged.

| Enum (file) | Variant | Fields | `event_type()` |
| --- | --- | --- | --- |
| `PasswordEvent` (`event.rs`) | `Set` | `user_id`, `must_change` | `credential.password_set` |
| `PasswordEvent` (`event.rs`) | `Changed` | `user_id` | `credential.password_changed` |
| `PasswordEvent` (`event.rs`) | `Removed` | `user_id` | `credential.password_removed` |
| `AccessTokenEvent` (`access_token.rs`) | `Issued` | `user_id`, `token_id`, `expires_at` (serialized as RFC 3339) | `credential.access_token_issued` |
| `AccessTokenEvent` (`access_token.rs`) | `Revoked` | `user_id`, `token_id` | `credential.access_token_revoked` |

## Invariants

- Events carry identifiers and nothing derived from a password or a token (`event.rs` module documentation, `AccessTokenEvent` doc comment, and their fields).
- `check_acceptable`. Every error is `Invalid`, and no message contains the password.
  - It first refuses more than `MAX_PASSWORD_BYTES` bytes, whatever the rules (`credential.password_too_long`).
  - Length is then counted in characters against `min_length` (`credential.password_too_short`) and `max_length` (`credential.password_too_long`).
  - A password equal to one of `own_names`, ignoring case, is refused (`credential.password_is_own_name`).
  - Nothing else is checked: there are no composition rules and the value is not trimmed. Reuse needs the stored hashes and is checked elsewhere.
- `PasswordRecord::hashes_barred_from_reuse(depth)` yields the current hash and then the newest `depth` historic hashes.
- `PasswordRecord::replace` moves the current hash to the front of the history, trims the history to `history_depth`, and sets `must_change` and `changed_at`. `renew_hash` changes only the hash: the history, `changed_at` and `must_change` stay as they are.
- `PasswordHash`, `AccessTokenSecret` and `AccessTokenHash` hide their contents in `Debug` output (`PasswordHash([REDACTED])`, `AccessTokenSecret([REDACTED])`, `AccessTokenHash(..)`).
- An access token is `hodor_at_` followed by 64 lowercase hexadecimal characters taken from 32 random bytes (`PREFIX`, `SECRET_LENGTH`, `AccessTokenSecret::generate`). `AccessTokenHash::of_presented` returns `None` for any value of another shape, so nothing is computed or looked up for it.
- `AccessToken::issue` refuses a lifetime under 1 minute or over 30 days (`Invalid` `credential.access_token_lifetime_invalid`), so every token expires. After trimming, the description must not be empty, may have at most 200 characters, and must have no control character (`Invalid` `credential.access_token_description_invalid`). The stored hash is the SHA-256 of the full token text, and `expires_at` is `now + lifetime`.
- `AccessToken::is_good_at(now)` is true only while `revoked_at` is unset and `now < expires_at`.
- `AccessToken::revoke` is final. A second call returns `None` and changes nothing.

## Side Effects

- `AccessTokenSecret::generate` (called from `AccessToken::issue`) fills 32 bytes from the injected `RandomSource`. `AccessToken::issue` and `AccessTokenHash::of_presented` call the injected `Digest::sha256`.
- `AccessTokenId::generate()` in `AccessToken::issue` creates a new identifier (UUID version 7, `crates/kernel/src/id.rs`).
- Otherwise none: timestamps are passed in, and changes stay in memory.

## Verification

- Run: `cargo test -p hodor-credential`
