# hodor-saml

## Overview

The `hodor-saml` crate, described in `Cargo.toml` as "SAML as computation on text: checks responses from identity providers, writes requests and metadata." Hodor acts as a SAML service provider. This crate checks the signed responses that identity providers post back, writes the unsigned authentication request that sends a person to an identity provider, and writes Hodor's service provider metadata. It does no input or output of its own (`src/lib.rs` doc comment).

This is the only crate in the workspace allowed to depend on an XML library (Decision 0019). The workspace `Cargo.toml` says so in its comment on `xml-sec`, and `crates/saml/Cargo.toml` is the only crate manifest that lists `xml-sec`. The federation context uses the crate through `crates/federation`.

## Interface

- [src](./src/EGM.md) is the public interface: `check_response`, `Expected`, `ServiceProvider`, `Assertion`, `Attribute`, `IdentityProviderKey`, `CertificateError`, `Refusal`, `Reason`, `AuthenticationRequest`, `request_id`, `metadata`, `MAX_RESPONSE_BYTES` and `MAX_POSTED_BYTES`, plus the `testing` module behind a feature gate.
- Feature `testing` enables `xml-sec/xmldsig-sign`, `aws-lc-rs` and `rcgen`, and compiles `hodor_saml::testing`, which provides an identity provider with its own keys that signs real responses. The comment in `Cargo.toml` says signing is compiled only with this feature.
- Workspace dependencies: none. It depends on no other `hodor-*` crate. Its external dependencies are `base64`, `form_urlencoded`, `miniz_oxide`, `thiserror`, `time`, `x509-parser` and `xml-sec`. `aws-lc-rs` and `rcgen` are optional and used only by `testing`.
- Depended on by `crates/federation`, `crates/adapters-postgres` and `crates/protocol-http`, according to their `Cargo.toml` files.

## Invariants

- No input or output: the caller passes in the time and the random bytes (see [src](./src/EGM.md)).
- The workspace `xml-sec` dependency is built with `default-features = false` and the features `std`, `xmldsig` and `xml-backend-differential`. Per the workspace `Cargo.toml` comment, signing, encryption, XSLT and legacy algorithms are not compiled. This crate turns signing on only through its `testing` feature.
- `check_response` refuses everything outside a narrow profile before the signature is checked. It reads values only from the signed assertion. The full list of checks is in [src](./src/EGM.md#invariants).

## Side Effects

- None. The crate is pure computation on text. Only the `testing` feature generates keys and certificates, in `TestIdentityProvider::rsa` and `TestIdentityProvider::ecdsa`.

## Verification

- Run: `cargo test -p hodor-saml`
- The tests in `crates/saml/tests` are the cases of `docs/security/saml-attack-corpus.md` (`src/lib.rs` doc comment). The crate enables its own `testing` feature as a development dependency (`Cargo.toml` `[dev-dependencies]`).
