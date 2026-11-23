# Decision 0024: WebAuthn is checked by Hodor's own code, over the cryptography it already has

Status: Accepted (made for Issue-67; the project owner asked for the feature, not for this choice)

## Context

Issue-67 adds WebAuthn as a second factor: a security key or a platform authenticator registers a public key, and later signs a challenge to prove the person still holds it. The server's part is a list of checks in [the WebAuthn specification](https://www.w3.org/TR/webauthn-3/#sctn-rp-operations): the challenge, the origin, the hash of the relying party identifier, the flags, the signature counter, and the signature itself.

Two ways were looked at:

| | `webauthn-rs` (with `webauthn-rs-core`) | Checks written in the credential context |
|---|---|---|
| Cryptography | OpenSSL, through the `openssl` crate: a second cryptographic library next to `aws-lc-rs`, linked into the image | The `SignatureVerifier` port Hodor already has, implemented with `aws-lc-rs` |
| What it brings | Every attestation format, every algorithm, its own types for a registration and an authentication in progress, which the caller stores as it is told | Only what Hodor accepts: attestation not checked, ES256 and RS256 |
| Where the state lives | In the library's serialized types | In Hodor's own tables and transaction, under row-level security like everything else |
| What must be parsed | Nothing by Hodor | The authenticator data, a fixed binary layout; the client data, JSON; the attestation object and the public key, CBOR |
| Size of Hodor's code | Small glue | A few hundred lines with their tests |

## Decision

- **The checks are written in the credential context**, in the order of the specification's registration and authentication procedures, as pure functions over bytes. The signature goes through the `SignatureVerifier` port and hashes through the `Digest` port; Hodor adds no cryptography of its own.
- **Attestation is not checked.** Registration asks for none. When an authenticator sends a statement anyway, the statement is ignored, whatever its format: nothing is concluded from it, so nothing about it needs to be true. A credential proves that the person holds a key, not who made the key.
- **Two algorithms are accepted: ES256 and RS256** (COSE `-7` and `-257`). Every authenticator in use offers ES256; RS256 is for Windows Hello. An authenticator offering only something else is refused at registration.
- **CBOR is read by a narrow reader of Hodor's own** that accepts the subset authenticators write: integers, byte strings, text strings, arrays and maps of definite length, and the simple values true, false and null, nested at most eight deep. Indefinite lengths, tags and floating-point numbers are refused, and so is a value longer than what is left of the input. Like the narrow SAML profile of [Decision 0019](0019-saml-signature-verification.md), refusing what Hodor does not need is part of the protection.
- **An ES256 signature arrives in DER** and is turned into the fixed form the port takes by a strict reader that refuses anything but one sequence of two positive integers.

## Consequences

- No new dependency, and no second cryptographic library in the image.
- Hodor owns a CBOR reader and the WebAuthn checks. Each check has a test that a response breaking it is refused, and the reader is tested with random input to show it never panics or reads past its end.
- Attestation formats, EdDSA and enterprise attestation can be added later without changing what is stored: the public key is kept as the COSE key the authenticator sent.

## Alternatives considered

- **`webauthn-rs`.** Complete and widely used. Set aside for the second cryptographic library it links, and because its state types would sit beside Hodor's model instead of in it.
- **A CBOR library such as `ciborium`.** Sound, and a smaller step than the whole of `webauthn-rs`. Set aside because a general reader accepts more than authenticators write, and the subset is small enough to read with nothing else.
- **The browser's `getPublicKey()`**, which hands the key over in the X.509 form and spares reading CBOR at registration. Set aside: the authenticator data still has to be read, and a server should not depend on a browser feature for what the authenticator itself sent.
