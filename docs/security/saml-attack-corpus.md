# The SAML attack corpus

[Decision 0014](../decisions/0014-saml-deferred-with-spike.md) asks for the attacks on a SAML service provider to be written down, as tests, before any feature code. This page is that list. Each case is a SAML response that must be refused, with the reason it must give; none may be removed or weakened to make an implementation pass.

The corpus is about Hodor as a **service provider**: the side that receives a response from an identity provider and must decide whether to believe it. The threats are [Threat-SAML-01 to Threat-SAML-09](threat-model.md). The checks that refuse them are listed, in order, in [the federation context](../architecture/contexts/federation.md#checking-the-response).

## Where the tests are

Each case is one test, named after the case, in `crates/saml/tests/corpus.rs`, against the crate `hodor-saml` that checks responses. Three cases are about the sign-in a response belongs to rather than the response itself: `in-response-to-other-browser`, `in-response-to-used` and `relay-state-address`. They are tested where sign-ins are, in `crates/federation`, and come with the SAML provider kind (Issue-48).

## How the cases are made

Every case starts from one **good response**: what a well-behaved identity provider sends for one sign-in, signed with a key the test holds, for an audience, a destination and a request that the test's service provider expects. A test that accepts the good response must exist and pass, or the corpus proves nothing: a service provider that refuses everything would pass every other case. The good response is accepted signed on the assertion, signed on the response, with RSA and with an elliptic curve key.

Each attack is then one change to the good response, made after it was signed unless the case says otherwise. Signing happens with a real key and a real XML signature, never a stand-in. Where the change is to an algorithm or a transform that the signing library itself refuses to produce, the name is changed after signing: those are refused on the name, before any cryptography, so a real signature would change nothing.

A test checks the **reason**, not only the refusal: a case refused for the wrong reason is a case not understood. The reasons are fixed names, recorded as `federation.sign_in_refused`.

## Signature wrapping and parser differentials

The family behind most SAML bypasses: the signature is checked on one element, and the data is read from another. The rule against all of them is one rule: **the assertion whose values are used is the very element the signature was checked on**, found once, in one parsed tree.

| Case | The change | Refused because | Reason |
|---|---|---|---|
| `wrapping-assertion-sibling` | A second, unsigned assertion naming another subject is added beside the signed one | Two assertions | `wrapping` |
| `wrapping-assertion-before` | The same, the forged assertion first | Two assertions | `wrapping` |
| `wrapping-in-extensions` | The signed assertion is moved into `samlp:Extensions`, a forged one takes its place | Two assertions; the one read would not be the one signed | `wrapping` |
| `wrapping-in-object` | The signed assertion is moved inside `ds:Signature/ds:Object`, a forged one takes its place | Two assertions | `wrapping` |
| `wrapping-response-signature` | The response is signed, not the assertion; an unsigned forged assertion is put in the signed response's place and the original moved elsewhere | Two assertions | `wrapping` |
| `two-signatures` | A second signature, by another key, is added on the assertion | Exactly one signature | `wrapping` |
| `duplicate-id` | A second element carries the `ID` the reference names | Duplicate identifiers | `duplicate_identifier` |
| `id-in-another-namespace` | A second element carries the same value in an `ID` attribute of another namespace, which `xml-sec` also takes as an identifier | Duplicate identifiers | `duplicate_identifier` |
| `percent-encoded-identifier` | The signed assertion's `ID` is `%5Fresponse-4f1d`; `xml-sec` decodes the reference `#%5Fresponse-4f1d` and finds the response | Only plain names are identifiers | `reference` |
| `id-attribute-case` | The signed assertion carries `id` instead of `ID` | The reference resolves to no element that Hodor reads | `reference` |
| `reference-empty-uri` | The reference's `URI` is empty, which means the whole document | The reference must name the signed element | `reference` |
| `reference-xpointer` | The reference uses an `xpointer` expression | Only a plain `#ID` reference is accepted | `reference` |
| `two-references` | The signature has two references | Exactly one reference | `reference` |
| `namespace-redefinition` | The prefix `saml` is declared again, to another namespace, on the `Subject` inside the signed assertion, so the element is no longer a SAML one | The assertion holds an element that is not SAML | `structure` |
| `comment-in-name-id` | `<NameID>ana@example.com<!---->.evil.example</NameID>`, signed after the comment was added | No comments anywhere | `comment` |
| `doctype` | The response carries a `DOCTYPE` | No document type declarations at all | `document_type` |
| `external-entity` | The `DOCTYPE` declares an external entity | No document type declarations at all | `document_type` |
| `entity-expansion` | Nested entities that expand to gigabytes | No document type declarations at all | `document_type` |
| `processing-instruction` | A processing instruction inside the assertion | No processing instructions anywhere | `processing_instruction` |
| `oversized` | The response is larger than 256 kibibytes | Size | `size` |
| `deeply-nested` | Elements nested 1,000 deep | Depth | `depth` |
| `namespace-flood` | Twenty nested elements that each declare four prefixes, around two thousand empty elements, all within the size limit | Too many namespace prefixes in scope: parsing work grows with elements times prefixes | `size` |
| `node-flood` | Ten thousand empty elements, within the size limit | Too many nodes | `size` |
| `not-base64` | The posted value is not base64 | Not a response | `malformed` |

One case is not refused, and its test says why:

| Case | The change | What happens |
|---|---|---|
| `entity-in-name-id` | After signing `ana@example.com`, the subject is written `ana&#64;example.com` | Accepted, and read as `ana@example.com`: a character reference is the same text to the signature and to Hodor, because both read the one parsed tree. The parser-differential bugs of other libraries came from two parsers reading the same bytes differently; `xml-sec` reads every document with two parsers and refuses it when they disagree (`malformed`) |

## Signatures that do not hold

| Case | The change | Refused because | Reason |
|---|---|---|---|
| `unsigned` | No signature anywhere | A signed assertion is required | `unsigned` |
| `signature-removed` | The good response with its signature element removed | A signed assertion is required | `unsigned` |
| `signature-value-changed` | One bit of the signature value flipped | Signature | `signature` |
| `digest-changed` | One bit of the digest flipped | Signature: the digest is part of what is signed | `signature` |
| `subject-changed` | The subject changed after signing | Digest | `digest` |
| `attribute-added` | An attribute added to the assertion after signing | Digest | `digest` |
| `other-key` | Signed by a key that is not the identity provider's | Not the identity provider's key | `signature` |
| `key-in-message` | Signed by an unknown key that the response carries itself in `ds:KeyInfo` | Keys in the message are never used; only the configured certificate's is | `signature` |
| `sha1-digest` | Digest with SHA-1 | Weak algorithm | `algorithm` |
| `sha1-signature` | `rsa-sha1` | Weak algorithm | `algorithm` |
| `hmac-signature` | `hmac-sha256`, keyed with the public certificate | Not an accepted algorithm | `algorithm` |
| `algorithm-key-mismatch` | `ecdsa-sha256` named, the configured key is RSA | The algorithm must match the key | `algorithm` |
| `unknown-transform` | A transform other than enveloped signature and exclusive canonicalization | Transform not accepted | `transform` |
| `xslt-transform` | An XSLT transform | Transform not accepted | `transform` |
| `short-rsa-key` | An identity provider certificate with an RSA key of 1024 bits | Key too short: the certificate is refused when it is configured, so no response is ever checked with it | `key_too_short` |

## Wrong place, wrong time, wrong request

| Case | The change | Refused because | Reason |
|---|---|---|---|
| `audience-other` | `AudienceRestriction` names another service provider | Audience | `audience` |
| `audience-missing` | No `AudienceRestriction` | Audience | `audience` |
| `destination-other` | `Destination` is another address | Destination | `destination` |
| `destination-missing` | No `Destination` | Destination | `destination` |
| `recipient-other` | `SubjectConfirmationData/@Recipient` is another address | Recipient | `recipient` |
| `issuer-other` | `Issuer` is another identity provider | Issuer | `issuer` |
| `in-response-to-unknown` | `InResponseTo` names a request this service provider never made | Request | `request` |
| `in-response-to-other-browser` | `InResponseTo` names a request made for another browser's sign-in | Request: checked against the request of the sign-in that finishes | `request` |
| `in-response-to-used` | The same response presented a second time | The pending authorization that held the request was taken the first time | `no_pending_authorization` |
| `unsolicited` | No `InResponseTo` at all | Responses not asked for are refused | `unsolicited` |
| `expired` | `NotOnOrAfter` has passed, beyond one minute of clock difference | Time | `time` |
| `not-yet-valid` | `NotBefore` is in the future, beyond one minute | Time | `time` |
| `confirmation-expired` | `SubjectConfirmationData/@NotOnOrAfter` has passed | Time | `time` |
| `status-not-success` | `StatusCode` is not `Success`, with a signed assertion inside anyway | Status | `status` |
| `bearer-missing` | No `SubjectConfirmation` with the bearer method | Confirmation | `confirmation` |
| `transient-name-id` | The `NameID` format is `transient` | A subject that changes every time cannot be linked | `subject` |
| `relay-state-address` | `RelayState` is an address to go to | `RelayState` is an opaque reference to the sign-in, never an address; no pending authorization has it as its state | `no_pending_authorization` |

## Encrypted assertions

Encrypted assertions are [not accepted](../decisions/0019-saml-signature-verification.md) in Milestone 2: a response that carries one is refused whole, with no attempt to decrypt it.

| Case | The change | Refused because | Reason |
|---|---|---|---|
| `encrypted-assertion` | The assertion is an `EncryptedAssertion` | Not accepted | `encrypted` |

## What a refusal looks like

Every case is refused with one error for the person, the same as any refused sign-in through a provider. The reason is recorded as `federation.sign_in_refused`.

## Samples that must be accepted

Real identity providers sign in their own ways, and a service provider that refuses them is of no use. Responses shaped as the identity providers of the [recipes](../architecture/contexts/federation.md#recipes) send them must be accepted: Microsoft Entra ID, Okta, Active Directory Federation Services, Keycloak, Shibboleth. They are tests in `crates/saml/tests/samples.rs`, beside one with an RSA-PSS signature.

**None of them is a real response yet.** Each is built by the test to the shape its identity provider is documented and known to send (which element is signed, the namespace prefixes or a default namespace, the list of namespaces that exclusive canonicalization keeps, typed attribute values, line breaks and indentation, base64 in lines) and signed with a key the test holds. A real response, with its certificate, replaces each one as it is had, and the progress page says which are still shapes.
