# hodor-adapters-kms source

## Overview

Key providers outside the server. `lib.rs` keeps the modules `openbao`, `public_key` and `settings` private and re-exports their public types at the crate root.

## Interface

- `OpenBaoKeyProvider::new(http: Arc<dyn HttpClient>, settings: &OpenBaoSettings)` (`openbao.rs`), the `KeyProvider` named `openbao` (`OPENBAO`), and `OpenBaoKeyProvider::key_name(tenant, version) -> String`, `tenant-<tenant>-version-<version>`.
  - `generate`: `POST /v1/<mount>/keys/<name>` with `{"type": "ecdsa-p256"}` for ES256, `"rsa-2048"` for RS256 and PS256, or `"ed25519"` for EdDSA, then `GET` of the same path, checked and read into the public key; `keys.algorithm_unsupported` for A256GCM.
  - `sign`: `POST /v1/<mount>/sign/<name>` with the base64 input and `key_version` 1, and, for ES256, RS256 and PS256, `hash_algorithm` `sha2-256`; `marshaling_algorithm` `jws` or `asn1` for ES256, `signature_algorithm` `pkcs1v15` for RS256, `pss` with `salt_length` `hash` for PS256, and nothing more for EdDSA, whose 64-byte signature is the same in both encodings; the answer's `vault:v1:` signature is decoded from base64url for `jws` and base64 otherwise, and its size checked.
  - `encrypt` and `decrypt`: always `keys.unusable`.
  - Signing in: `POST /v1/auth/<mount>/login` with `role_id` and `secret_id`, or `role` and `jwt` read from the token file. The token is kept behind a `tokio` mutex and replaced once two thirds of its `lease_duration` have passed, or once when a request is answered `403`, after which the request is sent again once.
- `KeyProviderSettings::from_lookup(lookup)` (`settings.rs`) reads `HODOR_KEY_PROVIDER` and `HODOR_OPENBAO_*` through `lookup`, an empty value counting as unset, and refuses what cannot be used with `keys.provider_settings_invalid` naming the variable. `KeyProviderSettings::providers(local, http)` gives the keys context's `KeyProviders`: OpenBao, through the client `http` builds for its settings, when its address is set, making new signing keys when `signing_keys_in` is `SigningKeysIn::OpenBao` and the keys of certificate authorities whenever it is set (`KeyProviders::with_authorities`), and `local` for the rest. `OpenBaoKeyProvider::signs_inside` is `true`.
- `OpenBaoSettings { address, transit_mount, login, time_limit, certificate_authorities }`, `OpenBaoLogin::{Kubernetes { mount, role, token_file }, AppRole { mount, role_id, secret_id }}`, `DEFAULT_TRANSIT_MOUNT` (`hodor-transit`), `DEFAULT_KUBERNETES_TOKEN_FILE`.
- `public_key::read(text, shape)` (private), with `Shape { P256, Rsa, Ed25519 }`: a PEM `PUBLIC KEY` holding a P-256 point, or an RSA key of exactly 2048 bits, or for `Ed25519` the key's 32 bytes in base64 as OpenBao answers them, into the kernel's `PublicKey`; anything else is `None`.

## Dependencies

`hodor-kernel` (`HttpClient`, `HttpRequest`, `Secret`, `DomainError`, `PublicKey`, `TenantContext`), `hodor-keys` (`KeyProvider`, `KeyProviders`, `KeyVersion`, `SignatureEncoding`), `base64`, `serde_json`, `tokio`, `tracing`.
