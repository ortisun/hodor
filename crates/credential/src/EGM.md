# hodor-credential source

## Overview

The credential context owns what a user proves their identity with, and
answers one kind of question: is this the right secret for this user? It does
not decide whether a sign-in succeeds (`lib.rs` crate documentation). The
crate follows the specification in `docs/architecture/contexts/credential.md`.
The `application` and `domain` modules are private; other crates use the
`api` module.

## Interface

- `lib.rs: pub mod api` re-exports:
  - Access token use cases and port: `AccessTokenService`, `AccessTokenStore`.
  - API key use cases and port: `ApiKeyService`, `ApiKeyStore`.
  - Authenticator application use cases and ports: `TotpService`, `TotpCheck`, `TotpStore`, `HmacSha1`, and `totp_code_at(mac, secret, moment)`, the code an application shows.
  - Recovery code use cases and port: `RecoveryCodeService`, `RecoveryCodeCheck`, `RecoveryCodeStore`.
  - Password ports: `PasswordHasher`, `PasswordStore`, `PasswordVerification`.
  - Password use cases: `CredentialService`, `NewPassword`, `PasswordCheck`.
  - Access tokens: `AccessToken`, `AccessTokenEvent`, `AccessTokenHash`, `AccessTokenId`, `AccessTokenSecret`, `AccessTokenSnapshot`.
  - API keys: `ApiKey`, `ApiKeyEvent`, `ApiKeyHash`, `ApiKeyId`, `ApiKeySecret`, `ApiKeySettings`, `ApiKeySnapshot`, `ApiKeyStatus`, `KeyApplicationId`, `looks_like_api_key`, and the constants `API_KEY_PREFIX` (`hodor_ak_`), `MAX_API_KEYS`, `MAX_API_KEY_SCOPES`, the lifetimes, the overlaps, `LAST_USE_PRECISION` and `REVOKED_BY_ADMINISTRATOR`.
  - Passwords: `PasswordEvent`, `HistoricHash`, `MAX_PASSWORD_BYTES`, `PasswordHash`, `PasswordRecord`, `PasswordRules`, `check_acceptable`.
  - Authenticator applications: `Totp`, `TotpEnrollment`, `TotpEvent`, `TotpId`, `TotpSnapshot`, `TotpStatus`, `ENROLLMENT_LIFETIME`, `STEP_SECONDS`, `TOTP_SEALING_PURPOSE`.
  - WebAuthn use cases and port: `WebAuthnService`, `WebAuthnStore`, `BegunRegistration`, `AssertionChallenge`.
  - WebAuthn: `AssertionResponse`, `Challenge`, `CoseAlgorithm`, `CreationOptions`, `CredentialDescriptor`, `PendingRegistration`, `PendingRegistrationSnapshot`, `RegistrationResponse`, `RelyingParty`, `RequestOptions`, `WebAuthnCredential`, `WebAuthnCredentialId`, `WebAuthnCredentialSnapshot`, `WebAuthnEvent`, `WebAuthnRegistrationId`, `user_handle`.
  - Recovery codes: `RecoveryCodeEvent`, `RecoveryCodeSet`, `RecoveryCodeSetId`, `RecoveryCodes`, `RECOVERY_CODES_PER_SET` (10), `RECOVERY_CODE_CHARACTERS` (16), and `read_recovery_code(typed)`, the canonical form of what a person typed, or nothing if it is not a code.
- `lib.rs: pub mod testing` (`testing.rs`): public test support, compiled only under `#[cfg(any(test, feature = "testing"))]`. The `testing` feature turns on `hodor-kernel/testing` (`Cargo.toml`).
  - `InMemoryPasswords`: an in-memory `PasswordStore`.
  - `InMemoryAccessTokens`: an in-memory `AccessTokenStore`.
  - `InMemoryApiKeys`, `ApiKeyPorts<'a> { units_of_work, keys }` and `run_api_key_contract(ports)`: the same for API keys. The contract checks a key loaded unchanged by identifier and by hash in its tenant only, a holder's keys listed newest first, a use written at most once a minute, a rotation and a revocation stored without losing the use, and another tenant's update refused with `credential.api_key_not_found`.
  - `InMemoryTotps`: an in-memory `TotpStore`. `FakeHmacSha1`: a deterministic stand-in for HMAC-SHA-1, not HMAC. `base32_secret(text)`: the bytes of a Base32 secret, as an application reads it.
  - `TotpPorts<'a> { units_of_work, totps }` and `run_totp_contract(ports)`: the contract every `TotpStore` must pass.
  - `InMemoryRecoveryCodes`: an in-memory `RecoveryCodeStore`. `RecoveryCodePorts<'a>` and `run_recovery_code_contract(ports)`: the contract every `RecoveryCodeStore` must pass.
  - `FakeHasher`: a `PasswordHasher` for tests, with `raise_parameters()`, `set_overloaded(bool)`, and the counters `hashes()`, `verifications()` and `checks_against_nothing()`.
  - `Ports<'a> { units_of_work, passwords }` and `run_contract(ports)`: the contract every `PasswordStore` must pass.
  - `AccessTokenPorts<'a> { units_of_work, tokens }` and `run_access_token_contract(ports)`: the contract every `AccessTokenStore` must pass. It uses `hodor_kernel::random::testing::FakeDigest`.
  - `InMemoryWebAuthn`: an in-memory `WebAuthnStore`. `stored_credential(user_id, credential_id, created_at)` makes a credential as a store keeps it.
  - `WebAuthnPorts<'a> { units_of_work, store }` and `run_webauthn_contract(ports)`: the contract every `WebAuthnStore` must pass: credentials come back unchanged, oldest first, in their own tenant only; a credential identifier is unique within a tenant (`credential.webauthn_credential_exists`) and free in another; a use is stored only over the counter that was read; a pending registration is taken once, in its own tenant only.
- Subdirectories:
  - [application](./application/EGM.md): `CredentialService`, `AccessTokenService`, `TotpService`, `WebAuthnService`, `RecoveryCodeService` and the `PasswordHasher`, `PasswordStore`, `AccessTokenStore`, `TotpStore`, `HmacSha1`, `WebAuthnStore` and `RecoveryCodeStore` ports.
  - [domain](./domain/EGM.md): password rules and records, access tokens, authenticator applications, WebAuthn credentials and their checks, recovery codes, `PasswordEvent`, `AccessTokenEvent`, `TotpEvent`, `WebAuthnEvent` and `RecoveryCodeEvent`.

## Invariants

- The public surface is exactly what `api` re-exports, plus `testing` when the feature is on. `application` and `domain` are declared with plain `mod`.
- `FakeHasher` must never be used outside tests: it is instant, and its "hashes" contain the password in the clear (doc comment).
  - It writes `fake$<generation>$<password>`.
  - `verify` reports `needs_renewal` when the generation differs from the current one, so `raise_parameters` makes earlier hashes ask for renewal.
  - An unreadable hash gives an internal error `credential.hashing_failed`.
  - While overloaded, every method fails with `Unavailable` `credential.hashing_overloaded`.
- `InMemoryPasswords` keys rows by `(TenantId, UserId)` from `uow.tenant().tenant_id()`.
  - `insert` refuses an existing record (`credential.password_exists`).
  - `update` refuses a missing record (`credential.password_not_found`) or a version mismatch (`credential.password_modified_concurrently`), and stores the record with its version one higher.
- `InMemoryAccessTokens` keys rows by `(TenantId, AccessTokenId)`. `find_by_hash` searches only the unit of work's tenant, and `update` refuses an unknown token (`credential.access_token_not_found`).
- `run_contract` checks that a password store:
  - loads a stored record unchanged;
  - keeps one password per user;
  - hides records from other tenants;
  - stores the history newest first, trimmed to the depth;
  - rejects a stale update;
  - rejects an update from another tenant;
  - removes the password and its history on delete, after which a new password starts with an empty history.
- `run_access_token_contract` checks that a token store:
  - loads a stored token unchanged, by identifier and by hash, in its own tenant only;
  - refuses an update from another tenant with `credential.access_token_not_found`;
  - stores a revocation;
  - finds nothing for an unknown hash or identifier.
- Each run of either contract uses tenants of its own, so runs can share one database (doc comments).

## Side Effects

- The in-memory stores keep rows in an `Arc<Mutex<BTreeMap<…>>>` shared by their clones. A poisoned lock is recovered. Writes go straight to the map; they do not wait for the unit of work to commit.
- `FakeHasher` keeps atomic counters and flags (`AtomicU32`, `AtomicBool`, `AtomicUsize`).
- The contract functions write to the implementation they are given and panic when a rule is broken.
- The rest of the crate's side effects are described in [application](./application/EGM.md) and [domain](./domain/EGM.md).

## Verification

- Run: `cargo test -p hodor-credential`
