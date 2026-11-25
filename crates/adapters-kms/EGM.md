# hodor-adapters-kms

## Overview

The adapter crate of key providers outside the server (package `hodor-adapters-kms`). Its manifest describes it as "Key providers outside the server: OpenBao's Transit secrets engine, which makes signing keys and signs without ever letting a key out." (`Cargo.toml` `description`). The cloud's key management services of Phase 9 belong here too, on the same port.

It implements one port of [the keys context](../keys/EGM.md):

- `impl KeyProvider for OpenBaoKeyProvider` (`src/openbao.rs`), the trait `hodor_keys::api::KeyProvider`, named `openbao`.

Specified in `docs/architecture/contexts/keys.md`, "The OpenBao provider" and "Choosing the provider", and `docs/operations/keys-in-openbao.md`.

## Subdirectories & Boundaries

- `src`: [./src/EGM.md](./src/EGM.md) - `OpenBaoKeyProvider`, the settings (`KeyProviderSettings`, `OpenBaoSettings`, `OpenBaoLogin`, `SigningKeysIn`) and the reader of OpenBao's public keys. Its side effects are requests through the kernel's `HttpClient` port and reading the service account's token file at each Kubernetes sign-in.
- `tests`: integration tests (not documented here).

## Workspace Dependencies

From `Cargo.toml`:

- Hodor crates: `hodor-kernel`, `hodor-keys`, as the architecture test allows for this crate (`tests/architecture/src/lib.rs`, layer 4). No other adapter: the binaries give it a `ServiceHttpClient` of `hodor-adapters-http` and the `LocalKeyProvider` of `hodor-adapters-crypto`.
- Runtime: `async-trait`, `base64`, `serde_json`, `tokio` (the token's lock, and reading the token file off the request threads), `tracing`. No HTTP library and no cryptography library: OpenBao signs, and public keys are read by `public_key.rs`.
- Development only: `hodor-adapters-crypto` (`AwsLcVerifier`, `LocalKeyProvider`), `hodor-adapters-http` (`ServiceHttpClient`), `hodor-kernel` and `hodor-keys` with `testing`, `reqwest` (feature `rustls`, for what OpenBao's administrator does in the tests), `hodor-test-containers` (starts OpenBao), `testcontainers`, `tokio`.

## Invariants

- A version is used only when its provider is `openbao`, its use is signing, and its material is exactly `openbao:1:<name>:<algorithm>` for the tenant, version and algorithm given; otherwise `keys.unusable`, before any request (`openbao.rs:OpenBaoKeyProvider::key_of`).
- The Transit key named in a request is always `tenant-<tenant>-version-<version>`, computed from the tenant and the version, never read from the material.
- A key is made with its `type` alone, and kept only if OpenBao reads it back as that type, not exportable, without plaintext backup, not imported and at its first version (`read_key`). Signing names `key_version` 1.
- No failure falls back to anything: every failure of OpenBao is an error of the operation (`keys.provider_unavailable`, `keys.provider_sign_in_refused`, `keys.provider_refused`, `keys.provider_failed`).
- The secret identifier and tokens are `Secret`s, never printed; requests carry the token in `x-vault-token` only.

## Verification

- Run: `cargo test -p hodor-adapters-kms`. `tests/openbao.rs` starts `openbao/openbao:2.7.2` containers, prepared with `deploy/openbao/hodor-policy.hcl` and an AppRole, and needs Docker: the contract of a key provider, the keys as made, the policy refusing every way to a private key, keys found under a version's name refused, signing in again after a revocation, the tenants' token signing keys through `KeyService`, OpenBao stopped, and HTTPS with OpenBao's own authority. `tests/requests.rs` and the unit tests need nothing: what is sent and read, against a scripted client, Kubernetes authentication included, and the settings.
- The local provider passes the same contract: `cargo test -p hodor-adapters-crypto --test keys`.
