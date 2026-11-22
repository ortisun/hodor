# hodor-credential

## Overview

The credential context: what a user proves their identity with, starting
with passwords (`Cargo.toml` description). It answers whether a secret is
right for a user and does not decide whether a sign-in succeeds
(`src/lib.rs`). It also issues the access tokens that let a program act as a
user on the administration interface (`src/domain/access_token.rs`),
registers and checks WebAuthn credentials (`src/domain/webauthn/`), and keeps
recovery codes (`src/domain/recovery_code.rs`). Storage, hashing and
signatures are reached only through the `PasswordStore`, `AccessTokenStore`,
`TotpStore`, `WebAuthnStore`, `RecoveryCodeStore`, `PasswordHasher` and
`HmacSha1` ports and the kernel's `SecretBox`, `Digest` and
`SignatureVerifier`, which adapter crates implement.

## Subdirectories & Boundaries

- src: [./src/EGM.md](./src/EGM.md) - the `api` module (`CredentialService`, `AccessTokenService`, `TotpService`, `WebAuthnService`, `RecoveryCodeService`, their ports, the password, access token, authenticator application, WebAuthn and recovery code types and their events) and the feature-gated `testing` module.
- tests: integration tests of the crate (not documented here).

## Workspace Dependencies

- `hodor-kernel` (`crates/kernel`): units of work, tenant context, errors, events, clock, `Secret`, `RandomSource`, `Digest` and identifiers. The `testing` feature of this crate turns on `hodor-kernel/testing`.
- Other dependencies: `async-trait`, `base64`, `serde`, `serde_json`, `time`. Test-only dependencies: `tokio`, `proptest`.
- Crates in this workspace that depend on `hodor-credential` (from their `Cargo.toml`): `crates/adapters-crypto`, `crates/adapters-postgres`, `crates/authentication`, `crates/protocol-http`.
- Port implementations: `Argon2idHasher` (`PasswordHasher`) in `crates/adapters-crypto/src/password.rs`. `AwsLcHmacSha1` (`HmacSha1`) in `crates/adapters-crypto/src/hmac.rs`. `AwsLcVerifier` (kernel `SignatureVerifier`) in `crates/adapters-crypto/src/signature.rs`. `PgPasswordStore` (`PasswordStore`), `PgAccessTokenStore` (`AccessTokenStore`), `PgTotpStore` (`TotpStore`), `PgWebAuthnStore` (`WebAuthnStore`) and `PgRecoveryCodeStore` (`RecoveryCodeStore`) in `crates/adapters-postgres/src/credential.rs`.

## Verification

- Run: `cargo test -p hodor-credential`
