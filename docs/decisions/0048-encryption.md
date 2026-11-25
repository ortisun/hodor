# Decision 0048: Hodor encrypts and decrypts JSON Web Encryption with its own code over `aws-lc-rs`, for a short list of algorithms, with encryption keys per tenant beside its signing keys

Status: Proposed (requested by the project owner, who asked for every OpenID certification profile)

## Context

OpenID Connect lets a client ask for its ID tokens, its UserInfo answers and its request objects to be encrypted ([OpenID Connect Core, section 10.2](https://openid.net/specs/openid-connect-core-1_0.html#Encryption)), through the members `id_token_encrypted_response_alg` and `_enc`, `userinfo_encrypted_response_alg` and `_enc`, and `request_object_encryption_alg` and `_enc` of [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html). JWT Secured Authorization Response Mode (JARM) and JWT introspection responses ([RFC 9701](https://www.rfc-editor.org/rfc/rfc9701)) have the same members for their own answers. FAPI 1.0 Advanced says a provider "should support signed and encrypted ID Tokens".

No certification plan requires encryption. In release 5.3.5 of the [OpenID conformance suite](../operations/conformance.md), no OpenID Provider plan registers a client that asks for an encrypted answer; the plans only decrypt what arrives encrypted. FAPI 1.0 Advanced checks only that an encrypted ID token, if one comes, does not use `RSA1_5` or a shared key. Encryption is therefore for the product's completeness, and is the last part of [Milestone 18](../product/epics.md#milestone-18-fapi-20-message-signing-and-fapi-10-advanced), marked Optional.

Hodor signs but encrypts nothing in a token today. The [keys context](../architecture/contexts/keys.md) has a use for encryption keys and none made: "offered when Hodor accepts encrypted requests or encrypts tokens". [Decision 0008](0008-cryptography.md) puts every primitive behind ports implemented with `aws-lc-rs`, and refuses RSA with PKCS#1 version 1.5 padding for encryption. [Decision 0024](0024-webauthn-checks.md) set the precedent of checking a standard format with Hodor's own code over the cryptography it already has.

JSON Web Encryption ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516)) and its algorithms ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)) are two steps: a key management algorithm that wraps or agrees on a content key, and a content encryption algorithm. The crates that do both in Rust either bring OpenSSL, which Decision 0008 set aside, or cover few algorithms.

## Decision

### The algorithms, and none else

| Step | Offered | Why |
|---|---|---|
| Key management | `RSA-OAEP`, `RSA-OAEP-256`, `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A256KW` | `RSA-OAEP` is what most relying parties and the suite use; `RSA-OAEP-256` and the elliptic curve agreements are the modern choices. P-256 only for the curves, as the signing keys |
| Content encryption | `A128CBC-HS256`, `A256CBC-HS512`, `A128GCM`, `A256GCM` | `A128CBC-HS256` is OpenID Connect's default when a client names only the key management algorithm |
| Never | `RSA1_5`, `dir`, the password-based algorithms, `A*KW` with a shared key, compression (`zip`) | `RSA1_5` is refused by Decision 0008; a shared key would need a client's secret in clear, which Hodor never keeps; compression leaks length |

Discovery names exactly what is built.

### Hodor's own code, over `aws-lc-rs`

- The JSON Web Encryption layer, the parsing, the header checks and the two steps, is code of `hodor-adapters-crypto`, behind a port of the kernel, `Encrypter` and `Decrypter`, beside `Signer` and `Verifier`. RSA-OAEP, the agreement on P-256, AES key wrap, AES-GCM, AES-CBC and HMAC are all calls into `aws-lc-rs`.
- It is tested with the examples of [RFC 7520](https://www.rfc-editor.org/rfc/rfc7520), with a corpus of malformed objects, and against a library of another language in the tests, as the WebAuthn checks are.
- Decryption is the same for every failure: one error, no difference in time between a bad tag and a bad padding, so that neither gives an oracle.

### Encryption keys per tenant, beside the signing keys

- A tenant gets an `RSA-OAEP-256` key of 3072 bits and an `ECDH-ES` key on P-256 with use `enc`, made when they are first needed, as the first signing key of an algorithm is, and rotated as signing keys are. They are published in the tenant's key set with `use` `enc` and `alg`.
- A retiring key still decrypts for the overlap the signing keys keep, so that a request object encrypted to it just before a rotation still opens.
- They decrypt only what is sent to Hodor: request objects, and later what a client encrypts to it. They never sign.

### Encrypting to a client

- A client's answers are encrypted to a key of its own with use `enc` and the algorithm it chose, from its registered keys or its `jwks_uri` ([Decision 0049](0049-dynamic-client-registration.md)). A client that asks for encryption and has no such key cannot be saved.
- The order is sign, then encrypt: an encrypted ID token or UserInfo answer holds a signed one, as OpenID Connect requires. UserInfo answers signed but not encrypted are offered too, with `userinfo_signed_response_alg`.

## Consequences

- A client can ask for its ID tokens, UserInfo answers, responses of [JARM](0046-responses-through-the-browser.md) and [introspection answers](0052-security-profiles.md) encrypted, and send its request objects encrypted to the tenant.
- Hodor holds more code that touches cryptography. The format is small and the primitives are not Hodor's; the tests above, the corpus and a review before the issue is done are the price.
- A tenant's key set grows by two keys, which every relying party reads; they are ignored by those that only check signatures.

## Alternatives considered

- **A crate that does JSON Web Encryption.** Less code. Set aside: those that cover the algorithms above bring OpenSSL or an unaudited implementation of the primitives; the format is the small part.
- **Only `RSA-OAEP` with `A128CBC-HS256`.** The least that most clients use. Set aside: FAPI and modern clients prefer the elliptic curves, and adding them later would change the key set again.
- **No encryption at all.** Allowed for every profile, since no plan requires it. Set aside: the owner asked for the product to be as complete as possible, FAPI 1.0 Advanced recommends it, and relying parties in regulated sectors ask for it. It comes last, and may slip.
