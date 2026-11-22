# hodor-adapters-crypto

## Overview

The cryptography adapter crate (package `hodor-adapters-crypto`). Its manifest describes it as "password hashing, signatures, secrets at rest, the local key provider and the operating system's random source" (`Cargo.toml` `description`). It also provides SHA-256 digests and signature verification.

It implements these ports:

- Kernel ports (see [the kernel contract](../kernel/EGM.md)):
  - `impl Digest for Sha256Digest` (`src/digest.rs:10`)
  - `impl RandomSource for OsRandom` (`src/random.rs:10`)
  - `impl SecretBox for SecretKeys` (`src/sealing.rs:157`)
  - `impl SignatureVerifier for AwsLcVerifier` (`src/signature.rs:14`)
- Keys context port: `impl KeyProvider for LocalKeyProvider` (`src/keys.rs`), the trait `hodor_keys::api::KeyProvider` from `crates/keys`.
- Credential context port: `impl PasswordHasher for Argon2idHasher` (`src/password.rs:228`), the trait `hodor_credential::api::PasswordHasher` from `crates/credential`.
- Test support only: `impl HttpClient for TestProvider` (`src/testing.rs:241`).

## Subdirectories & Boundaries

- `src`: [./src/EGM.md](./src/EGM.md) - `Sha256Digest`, `OsRandom`, `Argon2idHasher` with `Argon2Parameters` and `HashingLimits`, `SecretKeys`, `LocalKeyProvider` and `AwsLcVerifier`, plus the `testing` module (`SigningKey`, `TestProvider`). Its side effects are operating system randomness and the `tokio` blocking thread pool; it does no network or file access.
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
