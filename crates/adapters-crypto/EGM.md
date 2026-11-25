# hodor-adapters-crypto

## Overview

The cryptography adapter crate (package `hodor-adapters-crypto`). Its manifest describes it as "password hashing, signatures, secrets at rest, the local key provider and the operating system's random source" (`Cargo.toml` `description`). It also provides SHA-256 digests and signature verification.

It implements these ports:

- Kernel ports (see [the kernel contract](../kernel/EGM.md)):
  - `impl Digest for Sha256Digest` (`src/digest.rs:10`)
  - `impl RandomSource for OsRandom` (`src/random.rs:10`)
  - `impl SignatureVerifier for AwsLcVerifier` (`src/signature.rs:14`)
- Bundles of Open Policy Agent: `impl BundleSigner for BundleSigningKey` (`src/bundle_signing.rs`), the trait `hodor_authorization_opa::api::BundleSigner`.
- Keys context ports: `impl KeyProvider for LocalKeyProvider` (`src/keys.rs`) and `impl FirstFormatSecrets for SecretKeys` (`src/sealing.rs:253`), the traits `hodor_keys::api::KeyProvider` and `hodor_keys::api::FirstFormatSecrets` from `crates/keys`. Secrets at rest are sealed by `hodor_keys::api::TenantSecretBox`, not by this crate.
- Credential context ports: `impl PasswordHasher for Argon2idHasher` (`src/password.rs:228`) and `impl HmacSha1 for AwsLcHmacSha1` (`src/hmac.rs`), the traits `hodor_credential::api::PasswordHasher` and `hodor_credential::api::HmacSha1` from `crates/credential`.
- Webhooks context port: `impl HmacSha256 for AwsLcHmacSha256` (`src/hmac.rs`), the trait `hodor_webhooks::api::HmacSha256` from `crates/webhooks`. `tests/webhook_signature.rs` checks the signatures it makes with the `standardwebhooks` crate, a dev-dependency.
- OAuth context port: `impl hodor_oauth::api::HmacSha256 for AwsLcHmacSha256` (`src/hmac.rs`), for pairwise subject identifiers; `hmac.rs` pins the identifier of one secret, tenant, sector and person, computed apart from Hodor.
- Test support only: `impl HttpClient for TestProvider` (`src/testing.rs:241`).

## Subdirectories & Boundaries

- `src`: [./src/EGM.md](./src/EGM.md) - `Sha256Digest`, `OsRandom`, `Argon2idHasher` with `Argon2Parameters` and `HashingLimits`, `SecretKeys`, `LocalKeyProvider`, `BundleSigningKey`, `AwsLcVerifier`, `AwsLcHmacSha1` and `AwsLcHmacSha256`, plus the `testing` module (`SigningKey`, `TestProvider`). Its side effects are operating system randomness and the `tokio` blocking thread pool; it does no network or file access.
- `tests`: integration tests (not documented here).

## Workspace Dependencies

From `Cargo.toml`:

- Hodor crates: `hodor-kernel`, `hodor-credential`, `hodor-keys`.
- Runtime: `argon2`, `async-trait`, `aws-lc-rs`, `base64`, `getrandom`, `sha2`, `tokio`, `zeroize`, and the optional `form_urlencoded` and `serde_json`.
- Development only:
  - this crate itself with the `testing` feature;
  - `hodor-federation`;
  - `hodor-kernel` with the `testing` feature;
  - `form_urlencoded`, `serde_json` and `time`.

## Features

- `testing = ["dep:form_urlencoded", "dep:serde_json"]`: compiles the public `testing` module, which offers a provider that signs real tokens, for tests of code that checks them (`Cargo.toml` `[features]`; `#[cfg(any(test, feature = "testing"))]` in `src/lib.rs`).

## Verification

- Run: `cargo test -p hodor-adapters-crypto`
