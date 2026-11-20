# ADR-0008: Cryptographic primitives and key handling

Status: Proposed

## Context

The specification asks for the "audited RustCrypto ecosystem". RustCrypto is a collection of crates with uneven audit coverage, not a single audited library. In particular, the pure-Rust RSA implementation has had a published timing side-channel advisory, and RSA signing (RS256) is unavoidable for OIDC interoperability. The choice of primitives must be made per algorithm, on evidence, and re-verified when implementation starts.

## Decision

- No cryptography is implemented in Hodor. All primitives sit behind ports (`PasswordHasher`, `Signer`, `Verifier`, `Aead`, `RandomSource`) implemented in `adapters-crypto`, so a library can be replaced without touching contexts.
- **Password hashing**: Argon2id from the RustCrypto `argon2` crate, PHC string format, parameters versioned and at or above current OWASP guidance, calibrated per deployment, run on a bounded blocking pool.
- **Signatures, AEAD, TLS**: `aws-lc-rs` (through `rustls` for TLS), which offers constant-time RSA and ECDSA and a FIPS-validated build option.
- **Hashing and HMAC**: SHA-2 from the same library.
- **Algorithms offered**: ES256 (default), RS256 and PS256 (interoperability), EdDSA (optional). `none`, HS* for ID and access tokens, and RSA PKCS#1 v1.5 encryption are not offered.
- **Secrets at rest**: AES-256-GCM with a per-tenant data key, wrapped by the `KeyProvider`; ciphertext carries the key version.
- **Keys**: generated and held by the `KeyProvider`. The local provider stores private keys wrapped under a root key; KMS providers either wrap keys (envelope mode, local signing) or sign remotely (keys never leave the KMS). Envelope mode is the default because remote signing adds a network call to every token.
- **Randomness**: the operating system CSPRNG only.
- Every cryptographic dependency is pinned, tracked by `cargo deny` advisories and reviewed on upgrade. The advisory status of each candidate is checked again at adoption time.

## Consequences

- `aws-lc-rs` brings a C and assembly dependency and a heavier build; accepted for constant-time RSA and the FIPS path.
- This departs from a literal "RustCrypto only" reading of the specification and needs explicit sign-off.
- Swapping a primitive is an adapter change.

## Alternatives considered

- **RustCrypto for everything**: pure Rust and easy builds, but depends on the RSA side-channel status at adoption time.
- **`ring`**: solid, but narrower algorithm set and no FIPS option.
- **OpenSSL bindings**: broad and validated, but a large C surface and deployment friction.
