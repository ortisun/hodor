# hodor-saml source

## Overview

The source of the `hodor-saml` crate. Hodor acts as a SAML service provider. It sends a person to an identity provider with an authentication request, and it gets a signed response back through the person's browser. This crate only does computation on text: it checks a posted response, writes an authentication request and writes Hodor's metadata (`lib.rs` crate doc comment). It never reads the clock, a random source, the network or the disk. The caller passes in the current time (`Expected::now`, `AuthenticationRequest::issue_instant`) and the random bytes (`request_id(random: [u8; 20])`).

Responses are parsed by `xml-sec`, using both of its parsers (`response.rs:check_response`, which calls `XmlSecurity::parse_document`). The order of the checks follows `docs/architecture/contexts/federation.md`. The attack cases each check must refuse are listed in `docs/security/saml-attack-corpus.md` (`lib.rs` doc comment, `response.rs` module doc comment).

## Interface

Everything below is re-exported from `lib.rs`. The modules themselves are private.

- `check_response(posted: &str, expected: &Expected<'_>) -> Result<Assertion, Refusal>` (`response.rs`). It checks the base64 value of `SAMLResponse` as it was posted. On success it returns what the signed assertion says. On failure it returns the reason of the first check that failed.
- `Expected<'a>` (`response.rs`) holds what a response must agree with. Its public fields are `service_provider: &ServiceProvider`, `issuer: &str` (the identity provider's entity identifier, compared exactly), `key: &IdentityProviderKey`, `request_id: &str` and `now: OffsetDateTime`.
- `ServiceProvider` (`response.rs`) is Hodor as the service provider of one identity provider. It has `new(entity_id, assertion_consumer_address)`, `entity_id()` and `assertion_consumer_address()`.
- `Assertion` (`response.rs`) is what was read from the signed assertion only. It has `name_id()`, `name_id_format()`, `session_index()`, `attributes()` and `first_value(name)`.
- `Attribute` (`response.rs`) is one attribute of the assertion. It has `name()` and `values()`, where the values are the text values only.
- `MAX_RESPONSE_BYTES` (256 KiB, decoded) and `MAX_POSTED_BYTES` (384 KiB, as posted in base64) are in `response.rs`.
- `IdentityProviderKey` (`key.rs`) is the key every response of one identity provider is checked with. `from_certificate(text)` accepts PEM, or the bare base64 found in metadata `X509Certificate`. `from_der(der)` accepts DER. Both return `Result<_, CertificateError>`.
- `CertificateError` (`key.rs`) has the variants `Unreadable`, `KeyTooShort` and `KeyNotSupported`. `reason()` returns `certificate_unreadable`, `key_too_short` or `key_not_supported`.
- `Refusal` (`refusal.rs`) is a refused response. `reason()` returns the `Reason`. Its `Display` reads `the SAML response was refused: <reason>`.
- `Reason` (`refusal.rs`) is the reason for a refusal as a fixed name, available through `as_str()`. The variants are `Size`, `Malformed`, `DocumentType`, `Depth`, `ProcessingInstruction`, `Comment`, `Structure`, `Encrypted`, `Status`, `Wrapping`, `Unsigned`, `Reference`, `DuplicateIdentifier`, `Transform`, `Algorithm`, `Signature`, `Digest`, `Destination`, `Request`, `Unsolicited`, `Issuer`, `Confirmation`, `Recipient`, `Time`, `Audience` and `Subject`.
- `AuthenticationRequest<'a>` (`request.rs`) is an unsigned `AuthnRequest` for the HTTP-Redirect binding. Its fields are `id`, `service_provider`, `single_sign_on_address` and `issue_instant`. `xml()` writes the request. `redirect_address(relay_state)` deflates the XML, base64-encodes it, and adds `SAMLRequest` and `RelayState` to the query of the single sign-on address, before any fragment.
- `request_id(random: [u8; 20]) -> String` (`request.rs`) returns an underscore followed by the bytes in hexadecimal.
- `metadata(service_provider: &ServiceProvider) -> String` (`metadata.rs`) writes an `EntityDescriptor` with `AuthnRequestsSigned="false"` and one HTTP-POST `AssertionConsumerService`. It does not say which element must be signed.
- `testing` (`testing.rs`) is public test support, compiled only with the `testing` feature (`lib.rs`: `#[cfg(feature = "testing")]`). It provides `TestIdentityProvider` (`rsa`, `ecdsa`, `certificate_pem`, `key`, `sign`, `sign_with_certificate_as_hmac_key` and `respond`), `ResponseDraft` (`good` and `xml`), `Signed`, `encode`, `signature_template` and `certificate_with_short_rsa_key`. According to its module doc comment, this feature is the only way signing code enters the build.
- These crate-private helpers are not exported: `names.rs` (namespace and algorithm constants) and `text.rs` (`escape` for XML text, and `instant`, which writes UTC to the second).

## Invariants

- Size: a posted value longer than `MAX_POSTED_BYTES`, or a decoded value longer than `MAX_RESPONSE_BYTES`, is refused with `Size`. Whitespace is removed before the value is base64-decoded (`response.rs:decode`).
- Parse limits: the `xml-sec` `SecureSaml` profile is narrowed to at most `MAX_NODES` = 4096 nodes, `MAX_DEPTH` = 64 levels, `MAX_NAMESPACES_IN_SCOPE` = 32 namespace bindings and `MAX_RESPONSE_BYTES`. External resources are disabled (`response.rs:compile_profile`). A document type declaration is refused with `DocumentType`, too much depth with `Depth`, and too many nodes or namespace bindings with `Size` (`response.rs:parse_refusal`).
- Shape checks run before any cryptography (`response.rs:inspect`). The response is refused if it contains any processing instruction or comment. The root must be a SAML 2.0 `Response`. It is refused if it contains any `EncryptedAssertion`, `EncryptedAttribute` or `EncryptedID`. The status must be `Success`.
- Exactly one `Assertion` may appear in the whole document, and it must be a child of the response; otherwise the reason is `Structure` or `Wrapping`. Exactly one `Signature` may appear, either on the assertion or on the response, and it may hold only `SignedInfo`, `SignatureValue` and an optional `KeyInfo`; otherwise the reason is `Unsigned` or `Wrapping` (`response.rs:inspect`).
- The signed element and the assertion must each carry an `ID` that is a plain name (`response.rs:is_plain_name`). No other element may carry the same value under `ID`, `Id`, `id` or `xml:id`; otherwise the reason is `DuplicateIdentifier` (`response.rs:carriers`). There must be exactly one `Reference`, and its `URI` must be `#<that ID>`.
- Only the enveloped signature transform and exclusive canonicalization without comments are accepted; otherwise the reason is `Transform`. The digest must be SHA-256. The signature algorithm must match the key: RSA-SHA256 or RSA-PSS-SHA256 for an RSA key, and ECDSA-SHA256 for a P-256 key; otherwise the reason is `Algorithm` (`response.rs:inspect`).
- The signature is verified with the configured `IdentityProviderKey` only. A key carried in the response is never used (`response.rs:check_response`, `VerificationKey { certificate_der: None, .. }`; `key.rs` doc comment). When the response is signed, the evidence must also cover the assertion; otherwise the reason is `Wrapping`.
- After the signature holds, only the signed assertion is read (`response.rs:read`). The assertion must contain exactly one each of `Issuer`, `Subject`, `Conditions` and `AuthnStatement`, and nothing outside those, `AttributeStatement` and `Signature`.
- The response's `Destination` must equal the assertion consumer address. `InResponseTo` must be present (`Unsolicited` if absent) and equal `Expected::request_id` (`Request` if different). The assertion `Issuer`, and the response `Issuer` if there is one, must equal `Expected::issuer` after trimming (`Issuer` if not).
- At least one bearer `SubjectConfirmation` must hold. Its `Recipient` must be the assertion consumer address, its `InResponseTo` must be the request id, and its `NotOnOrAfter` must be present and in the future, with one minute of tolerance (`response.rs:confirm`, `CLOCK_TOLERANCE`).
- `Conditions`: `NotBefore` and `NotOnOrAfter` are checked with the one-minute `CLOCK_TOLERANCE`. There must be at least one `AudienceRestriction`, and each one must name `ServiceProvider::entity_id`. Only `OneTimeUse` and `ProxyRestriction` are allowed besides it.
- Subject: a `NameID` with the transient format, or one that is empty after trimming, is refused with `Subject`.
- Keys: `IdentityProviderKey::from_der` accepts RSA keys of at least 2048 bits (`SHORTEST_RSA_KEY_BITS`) and elliptic curve keys on P-256 only. The certificate's dates and issuer are not checked (`key.rs` doc comment). The input must be exactly one certificate, with nothing left over after it.
- Values written into XML are escaped with `text.rs:escape`.

## Side Effects

- None. The crate is pure computation on text. It has no clock, random source, network, disk or global state. The time comes from `Expected::now` and `AuthenticationRequest::issue_instant`, and the random bytes come from the `request_id` argument. The only exception is the `testing` module, whose `TestIdentityProvider::rsa` and `ecdsa` constructors generate key pairs with `aws-lc-rs` and certificates with `rcgen`.

## Verification

- Run: `cargo test -p hodor-saml`
