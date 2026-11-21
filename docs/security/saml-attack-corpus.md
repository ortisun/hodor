# The SAML attack corpus

[Decision 0014](../decisions/0014-saml-deferred-with-spike.md) asks for the attacks on a SAML service provider to be written down, as tests, before any feature code. This page is that list. Each case is a SAML response that must be refused, with the reason it must give; each becomes one test under `crates/saml/tests/corpus/`, and none may be removed or weakened to make an implementation pass.

The corpus is about Hodor as a **service provider**: the side that receives a response from an identity provider and must decide whether to believe it. The threats are [Threat-SAML-01 to Threat-SAML-09](threat-model.md).

## How the cases are made

Every case starts from one **good response**: what a well-behaved identity provider sends for one sign-in, signed with a key the test holds, for an audience, a destination and a request that the test's service provider expects. A test that accepts the good response must exist and pass, or the corpus proves nothing: a service provider that refuses everything would pass every other case.

Each attack is then one change to the good response, made after it was signed unless the case says otherwise. Signing happens with a real key and a real XML signature, never a stand-in.

## Signature wrapping and parser differentials

The family behind most SAML bypasses: the signature is checked on one element, and the data is read from another. The rule against all of them is one rule: **the assertion whose values are used is the very element the signature's reference resolved to**, found once, by one parser.

| Case | The change | Refused because |
|---|---|---|
| `wrapping-assertion-sibling` | A second, unsigned assertion naming another subject is added beside the signed one | Two assertions |
| `wrapping-assertion-before` | The same, the forged assertion first | Two assertions |
| `wrapping-in-extensions` | The signed assertion is moved into `samlp:Extensions`, a forged one takes its place | The assertion read is not the one signed |
| `wrapping-in-object` | The signed assertion is moved inside `ds:Signature/ds:Object` | The assertion read is not the one signed |
| `wrapping-response-signature` | The response is signed, not the assertion; an unsigned forged assertion is put in the signed response's place and the original moved elsewhere | The assertion read is not covered by the signature |
| `duplicate-id` | Two elements carry the `ID` the reference names | Duplicate identifiers |
| `id-attribute-case` | The forged element carries `id` or `Id` instead of `ID` | The reference resolves to no element |
| `reference-empty-uri` | The reference's `URI` is empty, which means the whole document | The reference must name the assertion |
| `reference-xpointer` | The reference uses an `xpointer` expression | Only a plain `#ID` reference is accepted |
| `two-references` | The signature has two references | Exactly one reference |
| `namespace-redefinition` | The assertion's prefix is redeclared to another namespace inside the signed element | The element is not a SAML assertion |
| `comment-in-name-id` | `<NameID>ana@example.com<!---->.evil.example</NameID>`, signed after the comment was added | Text nodes with a comment are refused |
| `entity-in-name-id` | The subject is written with a character entity that a second parser would read differently | One parser, one reading; differences are refused |
| `doctype` | The response carries a `DOCTYPE` | No document type declarations at all |
| `external-entity` | The `DOCTYPE` declares an external entity | No document type declarations at all |
| `entity-expansion` | Nested entities that expand to gigabytes | No document type declarations at all |
| `processing-instruction` | A processing instruction inside the assertion | Refused in the assertion |
| `oversized` | The response is larger than 256 kibibytes | Size |
| `deeply-nested` | Elements nested 1,000 deep | Depth |

## Signatures that do not hold

| Case | The change | Refused because |
|---|---|---|
| `unsigned` | No signature anywhere | A signed assertion is required |
| `signature-removed` | The good response with its signature element removed | A signed assertion is required |
| `signature-value-changed` | One bit of the signature value flipped | Signature |
| `digest-changed` | One bit of the digest flipped | Digest |
| `subject-changed` | The subject changed after signing | Digest |
| `attribute-added` | An attribute added to the assertion after signing | Digest |
| `other-key` | Signed by a key that is not the identity provider's | Not the identity provider's key |
| `key-in-message` | Signed by an unknown key that the response carries itself in `ds:KeyInfo` | Keys in the message are never trusted; only the configured certificate is |
| `sha1-digest` | Digest with SHA-1 | Weak algorithm |
| `sha1-signature` | `rsa-sha1` | Weak algorithm |
| `hmac-signature` | `hmac-sha256`, keyed with the public certificate | Not an accepted algorithm |
| `unknown-transform` | A transform other than enveloped signature and exclusive canonicalization | Transform not accepted |
| `xslt-transform` | An XSLT transform | Transform not accepted |
| `short-rsa-key` | Signed by an RSA key of 1024 bits that is configured as the identity provider's | Key too short |

## Wrong place, wrong time, wrong request

| Case | The change | Refused because |
|---|---|---|
| `audience-other` | `AudienceRestriction` names another service provider | Audience |
| `audience-missing` | No `AudienceRestriction` | Audience |
| `destination-other` | `Destination` is another address | Destination |
| `recipient-other` | `SubjectConfirmationData/@Recipient` is another address | Recipient |
| `issuer-other` | `Issuer` is another identity provider | Issuer |
| `in-response-to-unknown` | `InResponseTo` names a request this service provider never made | Request |
| `in-response-to-other-browser` | `InResponseTo` names a request made for another browser's sign-in | Request |
| `in-response-to-used` | The same response presented a second time | Request used |
| `unsolicited` | No `InResponseTo` at all | Responses not asked for are refused |
| `expired` | `NotOnOrAfter` has passed, beyond one minute of clock difference | Time |
| `not-yet-valid` | `NotBefore` is in the future, beyond one minute | Time |
| `confirmation-expired` | `SubjectConfirmationData/@NotOnOrAfter` has passed | Time |
| `status-not-success` | `StatusCode` is not `Success`, with a signed assertion inside anyway | Status |
| `bearer-missing` | No `SubjectConfirmation` with the bearer method | Confirmation |
| `relay-state-address` | `RelayState` is an address to go to | `RelayState` is an opaque reference to the sign-in, never an address |

## Encrypted assertions

Encrypted assertions are [not accepted](../decisions/0019-saml-signature-verification.md) in Milestone 2: a response that carries one is refused whole, with no attempt to decrypt it.

| Case | The change | Refused because |
|---|---|---|
| `encrypted-assertion` | The assertion is an `EncryptedAssertion` | Not accepted |

## What a refusal looks like

Every case is refused with one error for the person, the same as any refused sign-in through a provider. The reason, a fixed name such as `wrapping` or `audience`, is recorded as `federation.sign_in_refused`. A test checks the reason, not only the refusal: a case refused for the wrong reason is a case not understood.

## Samples that must be accepted

Real identity providers sign in their own ways. Samples of responses from the identity providers named in the [recipes](../architecture/contexts/federation.md#recipes) are kept next to the corpus, with their certificates, and must be accepted: Microsoft Entra ID, Okta, Active Directory Federation Services, Keycloak, Shibboleth. Where a real response cannot be had, a response built to the identity provider's documentation stands in for it, and says so.
