# hodor-credential

## Overview

The credential context: what a user proves their identity with, starting
with passwords (`Cargo.toml` description). It answers whether a secret is
right for a user and does not decide whether a sign-in succeeds
(`src/lib.rs`). It also issues the access tokens that let a program act as a
user on the administration interface (`src/domain/access_token.rs`). Storage
and hashing are reached only through the `PasswordStore`, `AccessTokenStore`,
`TotpStore`, `PasswordHasher` and `HmacSha1` ports and the kernel's
`SecretBox`, which adapter crates implement.

## Subdirectories & Boundaries

- src: [./src/EGM.md](./src/EGM.md) - the `api` module (`CredentialService`, `AccessTokenService`, `TotpService`, their ports, the password, access token and authenticator application types and their events) and the feature-gated `testing` module.
- tests: integration tests of the crate (not documented here).

## Workspace Dependencies

- `hodor-kernel` (`crates/kernel`): units of work, tenant context, errors, events, clock, `Secret`, `RandomSource`, `Digest` and identifiers. The `testing` feature of this crate turns on `hodor-kernel/testing`.
- Other dependencies: `async-trait`, `serde`, `time`. Test-only dependencies: `tokio`, `proptest`.
- Crates in this workspace that depend on `hodor-credential` (from their `Cargo.toml`): `crates/adapters-crypto`, `crates/adapters-postgres`, `crates/authentication`, `crates/protocol-http`.
- Port implementations: `Argon2idHasher` (`PasswordHasher`) in `crates/adapters-crypto/src/password.rs`. `AwsLcHmacSha1` (`HmacSha1`) in `crates/adapters-crypto/src/hmac.rs`. `PgPasswordStore` (`PasswordStore`), `PgAccessTokenStore` (`AccessTokenStore`) and `PgTotpStore` (`TotpStore`) in `crates/adapters-postgres/src/credential.rs`.

## Verification

- Run: `cargo test -p hodor-credential`
