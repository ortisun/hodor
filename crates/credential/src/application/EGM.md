# Credential application layer

## Overview

The use cases of the credential context and the ports they need. There are
four services. `CredentialService` (`service.rs`) sets, changes, verifies and
removes passwords. `AccessTokenService` (`access_tokens.rs`) issues,
authenticates and revokes access tokens. `TotpService` (`totp.rs`) enrolls,
confirms, checks and removes authenticator applications. `WebAuthnService`
(`webauthn.rs`) registers WebAuthn credentials and checks answers to
challenges. They drive the
[domain model](../domain/EGM.md) and reach storage and hashing only through
port traits. The modules are `pub(crate)` (`mod.rs`); other crates use
`hodor_credential::api` (`src/lib.rs`).

## Interface

### Port traits

All are async and `Send + Sync`. Every store method takes
`uow: &mut dyn UnitOfWork` and works inside the tenant that unit of work is
bound to.

- `PasswordHasher` (`ports.rs`). Implemented by `Argon2idHasher` in `crates/adapters-crypto/src/password.rs` and by `FakeHasher` in `src/testing.rs`. Implementations bound how many hashes run at once. When that bound and its queue are full, every method fails at once with `ErrorKind::Unavailable` and code `credential.hashing_overloaded`, instead of waiting.
  - `hash(password: &Secret<String>) -> PasswordHash`: uses a fresh salt and the current parameters.
  - `verify(password, hash: &PasswordHash) -> PasswordVerification`: works whatever parameters the hash was made with. An internal error if the stored hash cannot be read.
  - `verify_nothing(password)`: costs the same as a verification and discards the result, so that response time does not reveal whether a user or a password exists.
- `PasswordVerification { matches: bool, needs_renewal: bool }` (`ports.rs`). `needs_renewal` means the stored hash was made with other parameters than the current ones.
- `PasswordStore` (`ports.rs`). Implemented by `PgPasswordStore` in `crates/adapters-postgres/src/credential.rs` and by `InMemoryPasswords` in `src/testing.rs`.
  - `get(uow, user_id) -> Option<PasswordRecord>`.
  - `insert(uow, record)`: `Conflict` `credential.password_exists` if the user already has a password.
  - `update(uow, record)`: stores changes, history included. `Conflict` `credential.password_modified_concurrently` if the stored version differs, `NotFound` if the user has no password in the tenant.
  - `delete(uow, user_id) -> bool`: removes the password and its history, and returns whether there was one.
- `AccessTokenStore` (`access_tokens.rs`). Implemented by `PgAccessTokenStore` in `crates/adapters-postgres/src/credential.rs` and by `InMemoryAccessTokens` in `src/testing.rs`.
  - `insert(uow, token)`.
  - `get(uow, id: AccessTokenId) -> Option<AccessToken>`.
  - `find_by_hash(uow, hash: &AccessTokenHash) -> Option<AccessToken>`.
  - `update(uow, token)`: stores a revoked token. `NotFound` if the tenant has no such token.
- `TotpStore` (`totp.rs`). Implemented by `PgTotpStore` in `crates/adapters-postgres/src/credential.rs` and by `InMemoryTotps` in `src/testing.rs`.
  - `active(uow, user_id) -> Option<Totp>` and `pending(uow, user_id) -> Option<Totp>`.
  - `replace_pending(uow, enrollment)`: stores an enrollment in place of the user's earlier one still pending.
  - `activate(uow, confirmed)`: puts the pending row in use and removes the user's earlier application in use. `NotFound` `credential.totp_enrollment_not_found` if the row is no longer pending.
  - `use_step(uow, id, step) -> bool`: stores the step only if it is later than the last one used, in one statement.
  - `remove(uow, user_id) -> bool`: removes both rows; answers whether one was in use.
- `HmacSha1` (`totp.rs`), not async: `mac(key, message) -> [u8; 20]`. Implemented by `AwsLcHmacSha1` in `crates/adapters-crypto/src/hmac.rs` and by `FakeHmacSha1` in `src/testing.rs`.

- `WebAuthnStore` (`webauthn.rs`). Implemented by `PgWebAuthnStore` in `crates/adapters-postgres/src/credential.rs` and by `InMemoryWebAuthn` in `src/testing.rs`.
  - `insert_registration(uow, registration)`.
  - `take_registration(uow, id) -> Option<PendingRegistration>`: removes and returns it; of any number of callers at once, one gets it.
  - `insert(uow, credential)`: `Conflict` `credential.webauthn_credential_exists` when the tenant has the credential identifier.
  - `list_for_user(uow, user_id)`: oldest first.
  - `record_use(uow, credential, previous_count) -> bool`: stores the counter, backup state and last use only if the stored counter is still `previous_count`.

### Service entry points

- `NewPassword<'a> { password: &Secret<String>, rules: PasswordRules, own_names: &[&str] }` (`service.rs`). `own_names` holds the user's login identifiers, which the password must not equal.
- `PasswordCheck` (`service.rs`): `Verified { must_change: bool }` or `Rejected`. By design there is no answer for "no such user" or "no password set".
- `CredentialService::new(units_of_work: Arc<dyn UnitOfWorkFactory>, passwords: Arc<dyn PasswordStore>, hasher: Arc<dyn PasswordHasher>, clock: Arc<dyn Clock>)`.
  - `set_password(tenant, user_id, new, must_change, caller)`: sets a password without asking for the current one (registration, recovery, administrator reset).
  - `check_new_password(tenant, user_id, new)`: the same checks as `set_password`, storing nothing.
  - `change_password(tenant, user_id, current, new, caller)`: checks the current password, then replaces it with `must_change` set to false.
  - `verify_password(tenant, user_id: Option<UserId>, password) -> PasswordCheck`.
  - `remove_password(tenant, user_id, caller)`.
  - `has_password(tenant, user_id) -> bool`: for administrators and account pages, never a sign-in form (doc comment).
- `TotpService::new(units_of_work, store: Arc<dyn TotpStore>, secrets: Arc<dyn SecretBox>, mac: Arc<dyn HmacSha1>, random, clock)`.
  - `begin_enrollment(tenant, user_id, issuer, account) -> TotpEnrollment`: 20 random bytes, sealed for `credential.totp_secret`; the secret is returned once, in Base32 and as an `otpauth://totp/` address.
  - `confirm_enrollment(tenant, user_id, code, caller)`: `NotFound` `credential.totp_enrollment_not_found` when nothing waits or it waited ten minutes; `Invalid` `credential.totp_code_wrong` for a wrong code; records `credential.totp_enrolled`.
  - `verify(tenant, user_id: Option<UserId>, code) -> TotpCheck`: `Verified` or `Rejected`; a right code is marked used in the same call.
  - `has_totp(tenant, user_id) -> bool` and `remove(tenant, user_id, caller) -> bool` (records `credential.totp_removed` when one was in use).
- `totp_code_at(mac, secret, moment) -> String` (`totp.rs`): the six digits an application shows.
- `AccessTokenService::new(units_of_work, tokens: Arc<dyn AccessTokenStore>, digest: Arc<dyn Digest>, random: Arc<dyn RandomSource>, clock)`.
  - `issue(tenant, user_id, description, lifetime: time::Duration, caller) -> (AccessToken, AccessTokenSecret)`: the secret is returned once and is not available again.
  - `authenticate(tenant, presented: &str) -> Option<AccessToken>`.
  - `revoke(tenant, id: AccessTokenId, caller)`.
- `WebAuthnService::new(units_of_work, store: Arc<dyn WebAuthnStore>, relying_party: RelyingParty, digest, verifier: Arc<dyn SignatureVerifier>, random, clock)`.
  - `begin_registration(tenant, user_id, name, display_name) -> BegunRegistration { id, options }`: stores a pending registration of five minutes.
  - `finish_registration(tenant, user_id, id, response, caller) -> WebAuthnCredential`: takes the pending registration first; `NotFound` `credential.webauthn_registration_not_found` if it is unknown, another user's, used or expired; `Invalid` `credential.webauthn_registration_refused` with the reason in the detail; records `credential.webauthn_registered`.
  - `list(tenant, user_id)`, `has_credentials(tenant, user_id) -> bool`.
  - `challenge(tenant, user_id) -> AssertionChallenge { challenge, options }`: stores nothing; the caller keeps the challenge.
  - `verify(tenant, user_id, challenge, response) -> bool`: `false` for any refused check; a counter that did not grow records `credential.webauthn_counter_not_increased`; `true` only when the use was stored over the counter that was read.
- The services are `Clone`. `CredentialService`, `AccessTokenService` and `TotpService` show no fields in `Debug`; `WebAuthnService` shows its relying party.

## Invariants

- No database transaction is held open while a hash is computed (`service.rs` module documentation). `CredentialService::read` loads the record in a unit of work that is dropped without commit. Hashing happens next, and `CredentialService::write` stores the result in a second unit of work, guarded by the record version through `PasswordStore::update`.
- New passwords (`CredentialService::check_new`): `check_acceptable` runs first. Then, if a record exists, the password is verified against every hash from `hashes_barred_from_reuse(rules.history_depth)`; a match gives `Invalid` `credential.password_reused`. `set_password`, `check_new_password` and `change_password` all apply these checks.
- Storing (`CredentialService::store_new`): a user without a record gets `PasswordRecord::new` and an `insert`. Otherwise `record.replace(…)` runs, followed by an `update`.
- `change_password`: a missing record runs `verify_nothing(current)`. Both a missing record and a wrong current password give `Unauthenticated` `credential.current_password_wrong`.
- `verify_password` does one hasher check per call, whatever the case, so that the cases cannot be told apart:
  - A password longer than `MAX_PASSWORD_BYTES` runs `verify_nothing` on an empty secret and returns `Rejected` before any storage read.
  - No `user_id`, or no record, runs `verify_nothing(password)` and returns `Rejected`.
  - A wrong password returns `Rejected`.
  - A correct password whose hash `needs_renewal` is hashed again and stored with `renew_hash`, with no event. This renewal is best effort: its errors are ignored and do not change the answer.
  - It returns `Verified { must_change }` from the record.
- `remove_password` on a user with no password succeeds, records nothing and does not commit.
- `authenticate` returns `Ok(None)` without telling the cases apart when the value is malformed (`AccessTokenHash::of_presented` returns `None`, and storage is not read), unknown in the tenant, expired or revoked (`AccessToken::is_good_at`). It fails only on a storage error. Whoever accepts the token must still check that its user may sign in and may do what is asked (doc comment).
- `revoke` gives `NotFound` `credential.access_token_not_found` for an unknown token. Revoking a token that is already revoked stores, records and commits nothing.
- `issue` validates the lifetime and description through `AccessToken::issue` before a unit of work is begun.

## Side Effects

- Password storage: `PasswordStore::get` (all password use cases), `insert` or `update` followed by `commit` (`CredentialService::write`), and `delete` (`remove_password`).
- Access token storage: `insert` and `commit` (`issue`), `find_by_hash` without commit (`authenticate`), `get`, then `update` and `commit` when the token changed (`revoke`).
- Events are recorded in the same unit of work as the write, with `uow.record_event(EventEnvelope::new(EventMetadata::new(tenant_id, caller.actor, caller.correlation_id, clock), event))` (`CredentialService::record_event` and `AccessTokenService::record`).
  - `set_password` records `PasswordEvent::Set`, `change_password` records `Changed`, and `remove_password` records `Removed`.
  - `issue` records `AccessTokenEvent::Issued` (from `AccessToken::issued_event`), and `revoke` records `Revoked`.
  - Hash renewal, `check_new_password`, `has_password` and `authenticate` record nothing.
- Hashing work through `PasswordHasher`: `hash` once per stored password and once per renewal, and `verify` once per barred hash when checking reuse.
- Clock reads (`clock.now()`) for record timestamps, token issue, expiry checks and revocation times. Randomness (`RandomSource`) and `Digest` are used when issuing a token, and `Digest` again when a presented token is hashed.

## Verification

- Run: `cargo test -p hodor-credential`
