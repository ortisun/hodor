# hodor-adapters-crypto source

## Overview

The cryptography adapter. Hodor implements no cryptography of its own: this crate connects the ports that contexts define to audited libraries (`argon2`, `aws-lc-rs`, `sha2`, `getrandom`), so replacing a library changes only this crate (`lib.rs` crate documentation, which points to `docs/decisions/0008-cryptography.md`). The modules `digest`, `keys`, `password`, `random`, `sealing` and `signature` are private. Their types are re-exported at the crate root (`lib.rs` `pub use` lines).

## Interface

### Ports implemented

| Implementation line | Trait | Type |
| --- | --- | --- |
| `impl Digest for Sha256Digest` (`digest.rs:10`) | `hodor_kernel::Digest` | `Sha256Digest` |
| `impl RandomSource for OsRandom` (`random.rs:10`) | `hodor_kernel::RandomSource` | `OsRandom` |
| `impl FirstFormatSecrets for SecretKeys` (`sealing.rs:253`) | `hodor_keys::api::FirstFormatSecrets` | `SecretKeys` |
| `impl SignatureVerifier for AwsLcVerifier` (`signature.rs:14`) | `hodor_kernel::SignatureVerifier` | `AwsLcVerifier` |
| `impl KeyProvider for LocalKeyProvider` (`keys.rs`) | `hodor_keys::api::KeyProvider` (keys context port) | `LocalKeyProvider` |
| `impl PasswordHasher for Argon2idHasher` (`password.rs:228`) | `hodor_credential::api::PasswordHasher` (credential context port) | `Argon2idHasher` |
| `impl HmacSha1 for AwsLcHmacSha1` (`hmac.rs`) | `hodor_credential::api::HmacSha1` (credential context port) | `AwsLcHmacSha1` |
| `impl HmacSha256 for AwsLcHmacSha256` (`hmac.rs`) | `hodor_webhooks::api::HmacSha256` (webhooks context port) | `AwsLcHmacSha256` |
| `impl HmacSha256 for AwsLcHmacSha256` (`hmac.rs`) | `hodor_oauth::api::HmacSha256` (OAuth context port, pairwise subject identifiers) | `AwsLcHmacSha256` |
| `impl HttpClient for TestProvider` (`testing.rs:241`, test support only) | `hodor_kernel::HttpClient` | `testing::TestProvider` |

### Public items

- `Sha256Digest`: computes SHA-256 with `sha2` (`digest.rs:Sha256Digest`).
- `OsRandom`: fills buffers through `getrandom::fill` (`random.rs:OsRandom`).
- `Argon2Parameters { memory_kibibytes, passes, lanes }`. `Default` gives 19 × 1024 kibibytes, 2 passes and 1 lane, which the documentation calls the OWASP baseline (`password.rs:Argon2Parameters`).
- `HashingLimits { concurrent, queued }` and `HashingLimits::for_this_machine()`, which takes `concurrent` from `std::thread::available_parallelism()` (1 if that fails) and sets `queued` to four times that (`password.rs:HashingLimits`).
- `Argon2idHasher::new(parameters, limits, random: Arc<dyn RandomSource>) -> Result<Self, DomainError>` (`password.rs:Argon2idHasher::new`). It implements `hash`, `verify` (returning `PasswordVerification` with `matches` and `needs_renewal`) and `verify_nothing` (`password.rs:Argon2idHasher`).
- `SecretKeys` holds the AES-256-GCM keys; the first key seals and every key opens (`sealing.rs:SecretKeys`). Its constructors:
  - `SecretKeys::none()` gives an empty key set.
  - `SecretKeys::parse(&Secret<String>)` reads the `HODOR_SECRET_KEYS` format: comma-separated `identifier:key` pairs, with each key in standard Base64.
  - `SecretKeys::generate(&dyn RandomSource) -> Secret<String>` makes a new 32-byte key in Base64.
- `AwsLcVerifier`: verifies signatures with `aws-lc-rs` (`signature.rs:AwsLcVerifier`).
- `LocalKeyProvider::new(root: Arc<SecretKeys>)`: the local key provider, named `local` (`keys.rs:LocalKeyProvider`). It makes P-256 keys for ES256, RSA keys of 2048 bits for RS256 and PS256, and 32-byte data keys for AES-256-GCM, and keeps each as a PKCS#8 document or raw key sealed with `root` for the tenant and the purpose `keys.<algorithm in lowercase>.<version without hyphens>`.
- `BundleSigningKey` (`bundle_signing.rs`): the installation key that signs bundles for Open Policy Agent. `from_pem(text, key_id)` reads an ECDSA P-256 private key in PKCS #8 PEM, anything else being `authorization.bundle_signing_key_invalid`; `generate()` returns a new private key and its public key, both in PEM; `public_key_pem()`; `sign` gives the 64-byte ES256 signature.
- `AwsLcHmacSha1`: HMAC-SHA-1 with `aws-lc-rs` (`HMAC_SHA1_FOR_LEGACY_USE_ONLY`), for the codes of authenticator applications. Tested against RFC 2202 and the SHA-1 cases of RFC 6238 (`hmac.rs`).
- `AwsLcHmacSha256`: HMAC-SHA256 with `aws-lc-rs` (`HMAC_SHA256`), for the signatures of webhooks and the pairwise subject identifiers of OAuth. Tested against RFC 4231 through both traits (`hmac.rs`), against a pairwise identifier computed with Python's `hmac` module, and, through `tests/webhook_signature.rs`, against the `standardwebhooks` crate.
- `testing` (public test-support module): compiled only under `#[cfg(any(test, feature = "testing"))]` (`lib.rs:12`). The Cargo feature `testing` pulls in the optional `form_urlencoded` and `serde_json`. It provides:
  - the constants `CLIENT_ID` and `CLIENT_SECRET`;
  - `SigningKey`, with `rsa()`, `p256()`, `published(id)` (a JSON Web Key), `sign(algorithm, message)` and `token(header, claims)`;
  - `TestProvider`, an in-memory OpenID Connect provider that serves discovery, keys and token answers through `HttpClient::send` and records every request (`testing.rs`);
  - `webauthn::SoftwareAuthenticator` (`testing/webauthn.rs`), a security key in software with a real P-256 key: `new(origin)`, `passkey(origin)` (a passkey: it verifies the person and answers with the user handle it was registered for), `at_origin(origin)` (the same key on another site), `without_verification()` (the same key, not verifying the person), `credential_id()`, `set_counter(value)`, `register(options)` and `answer(options)`, which take the options of the interaction interface and give the bodies it takes.

## Invariants

- `LocalKeyProvider` opens material only for the tenant, version, algorithm and use it was made for, and only for versions whose provider is `local`; every failure to use a key gives the internal error `keys.unusable`, with the reason in `detail`, and a failure to make one gives `keys.provider_failed` (`keys.rs`). The key in the clear lives only for one operation. A data-key ciphertext is a format byte `1`, a 12-byte nonce, and the AES-256-GCM ciphertext with its tag, the associated data authenticated and not stored (`keys.rs:LocalKeyProvider::encrypt`).
- Password hashes use Argon2id, version 19 (`Version::V0x13`), a 32-byte output and a fresh 16-byte salt from the injected `RandomSource` on every `hash` call (`password.rs:Argon2idHasher::new`, `password.rs:Argon2idHasher::hash`).
- `Argon2idHasher::new` rejects `limits.concurrent == 0` and parameters that `argon2::Params::new` refuses. Both become an internal error (`password.rs:Argon2idHasher::new`).
- Admission control (`password.rs:Argon2idHasher::run`, `password.rs:Admission`):
  - A request is refused at once with `Unavailable` and the code `credential.hashing_overloaded` when `concurrent + queued` requests are already admitted.
  - At most `concurrent` hashes run at a time, held by a `tokio` semaphore permit.
  - A `Drop` guard releases the admission place however the request ends.
- Hashing failures become `credential.hashing_failed`, and the library error text appears only in `detail` (`password.rs:internal`).
- `verify` rejects stored hashes that do not start with `$argon2id$`. A wrong password gives `matches = false`, not an error. `needs_renewal` is true when the stored hash's prefix differs from the current parameters (`password.rs:Argon2idHasher::verify_encoded`, `password.rs:Argon2idHasher::verify`, `password.rs:Argon2Parameters::encoded_prefix`).
- `verify_nothing` verifies against a decoy hash built at construction with the current parameters, so the work matches a real verification (`password.rs:Argon2idHasher::new`, `password.rs:Argon2idHasher::verify_nothing`).
- `OsRandom::fill` panics if `getrandom::fill` fails. It never continues with weak randomness (`random.rs:OsRandom::fill`).
- Sealing (`sealing.rs`). The root keys of `HODOR_SECRET_KEYS` wrap the material of key versions (through `LocalKeyProvider`) and open the secrets of the first format, the one 0.1.0 sealed directly with them; new secrets are sealed by `TenantSecretBox` in `crates/keys` under the tenant's data key. `seal`, `open` and `needs_resealing` are methods of `SecretKeys` itself, no longer the kernel's `SecretBox`:
  - Keys are AES-256-GCM `RandomizedNonceKey` values of exactly 32 bytes; the library generates the nonce (`SecretKeys::parse`, `SecretKeys::seal`).
  - The authenticated associated data is `hodor-secret-v1`, the tenant identifier and the purpose, so a sealed secret is bound to its tenant and purpose without storing them (`associated_data`).
  - The purpose must be 1 to 128 bytes of lowercase ASCII letters, digits, `.` or `_`; otherwise the result is `secret.purpose_invalid` (`check_purpose`).
  - A sealed secret is laid out as a format byte, the key identifier's length, the key identifier, the nonce, and the ciphertext with its tag (`SecretKeys::seal`).
  - `open` reports every failure through `hodor_kernel::sealing::unreadable`, which gives `secret.unreadable`, with the reason in `detail` (`SecretKeys::open`).
  - Sealing with no keys gives `secret.keys_missing`, and a library failure while sealing gives `secret.sealing_failed` (`SecretKeys::seal`).
  - `needs_resealing` is true when the secret was sealed with a key other than the first one configured (`SecretKeys::needs_resealing`).
- `SecretKeys::parse` returns `secret.keys_invalid` in five cases (`sealing.rs:SecretKeys::parse`, `sealing.rs:is_identifier`):
  - a pair without `:`;
  - an identifier that is not 1 to 32 bytes of lowercase ASCII letters, digits or hyphens;
  - a duplicate identifier;
  - a key that is not valid Base64;
  - a key that does not decode to 32 bytes.

  Error messages name the pair by its position, never by its contents.
- Decoded and generated key bytes are zeroized after use, and the ciphertext buffer is zeroized when sealing fails (`sealing.rs:SecretKeys::parse`, `sealing.rs:SecretKeys::generate`, `sealing.rs:SecretKeys::seal`).
- `AwsLcVerifier::verify` accepts three pairs: RS256 (PKCS #1 version 1.5) and PS256 (PSS) with RSA keys of 2048 to 8192 bits, and ES256 with a P-256 key whose coordinates are 32 bytes each. Any other pairing returns `false` (`signature.rs:AwsLcVerifier::verify`).

## Side Effects

- Reads operating system randomness (`random.rs:OsRandom::fill`) and draws from the injected `RandomSource` for salts, the decoy hash and new keys (`password.rs:Argon2idHasher`, `sealing.rs:SecretKeys::generate`).
- Runs Argon2 work on the `tokio` blocking thread pool through `tokio::task::spawn_blocking` (`password.rs:Argon2idHasher::run`).
- Runs RSA signatures (RS256 and PS256, about a millisecond each) on the same blocking pool; ES256 signatures, about a thousand times faster, run in place (`keys.rs:LocalKeyProvider::sign`).
- Queries the processor count through `std::thread::available_parallelism` (`password.rs:HashingLimits::for_this_machine`).
- No file or network access. `testing::TestProvider` answers in memory, behind an `Arc<Mutex<_>>`, and makes no network calls (`testing.rs:TestProvider`).

## Verification

- Run: `cargo test -p hodor-adapters-crypto`
