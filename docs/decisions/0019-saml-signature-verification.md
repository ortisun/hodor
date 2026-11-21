# Decision 0019: How SAML signatures are verified

Status: Accepted (option 1, chosen by the project owner on 2026-11-21)

This is the spike [Decision 0014](0014-saml-deferred-with-spike.md) asks for before any SAML code. It compares the ways Hodor could verify the XML signature of a SAML response, against the criteria Decision 0014 names: resistance to the known attacks, maintenance, build and deployment cost.

## Context

A SAML service provider is only as safe as the code that decides which element a signature covers. The attacks are old and keep working, because a SAML library has to accept a very flexible format:

- **Signature wrapping and parser differentials.** The signature is checked on one element and the data is read from another. In 2025 ruby-saml had two critical bypasses of this kind, CVE-2025-25291 and CVE-2025-25292, because it read the same response with two XML parsers that disagreed about which element was signed; the year before, CVE-2024-45409. The Go library crewjam/saml had a critical bypass with several assertions in 2022 (CVE-2022-41912) and twelve more advisories in November 2026, among them a bypass through several references in its signature library (CVE-2026-33487).
- **Comments and entities in the subject.** CVE-2017-11427 and its relatives: a comment inside `NameID` makes two readings of the same signed text name two different people.
- **XML itself**: external entities, entity expansion, document type declarations.

The [attack corpus](../security/saml-attack-corpus.md) lists what must be refused.

## What exists, as of 2026-11-21

| Option | What it is | Age and use | Language | Audit | Known problems |
|---|---|---|---|---|---|
| **samael** with its `xmlsec` feature | The long-standing Rust SAML crate; verification through the C library xmlsec1 | Since 2020, at 0.0.22; about 960,000 downloads | Rust over C: OpenSSL (always), libxml2, libxslt, xmlsec1 | None found | Two parsers (libxml2 to verify, quick-xml to read), reconciled by reducing the document to its signed part. Without the feature it **does not check signatures at all**. It cannot use `aws-lc-rs` |
| **xmlsec** bindings alone | Bindings to xmlsec1 | Since 2019, at 0.3.0 | Rust over C | None found | No SAML-level protection; xmlsec1 and libxml2 have a long history of advisories |
| **xml-sec** | Pure-Rust XML signature and canonicalization | Since March 2026, at 0.6.0; about 58,000 downloads | Rust | None found | Young. The caller names the elements that must be signed and verification fails otherwise; exactly one signature by default; a mode that fails unless two independent parsers agree, aimed at the ruby-saml kind of bug; `aws-lc-rs` as an optional provider; weak algorithms off by default |
| **bergshamra** | Pure-Rust XML security | Since February 2026, at 0.12.0 | Rust | None found | Fixed two trust bypasses in July 2026. Legacy algorithms on by default |
| **saml-rs** and its fork **risaml** | Pure-Rust SAML over bergshamra | Since June 2026 | Rust | None, said in their own README | Seven advisories in November 2026, among them an unsigned sibling assertion accepted, with no patched version listed |
| **saml** (danielkov) | Pure-Rust SAML | Since May 2026, alpha | Rust | None found | Says itself it is not production ready. Good defenses on paper: duplicate identifiers, several references, DTDs and entities all refused; content reachable only through a verified handle. RustCrypto only |
| **Shibboleth service provider**, in a separate process | The reference implementation in C++ | Decades | C++, Xerces-C, Santuario, OpenSSL | Widely reviewed | Its own advisories, the latest critical in 2025 (CVE-2025-31335). Heavy to run; the project expects to retire this code in a few years |
| **crewjam/saml**, in a separate process | Go library | Since 2015 | Go | None found | See above: several critical bypasses, twelve advisories this month |

**No option is both mature and free of a recent bypass.** The mature ones carry C, two parsers or a large surface; the pure-Rust ones are less than a year old and unaudited.

## The options

### 1. xml-sec, behind a narrow profile of Hodor's own (chosen)

Hodor's `saml` crate accepts only what the identity providers people use actually send, and refuses everything else before any signature is looked at:

- one response, one assertion, exactly one signature, on the assertion or on the response that contains it;
- exactly one reference, of the form `#ID`, resolving to that assertion; duplicate identifiers refused;
- exclusive canonicalization, the enveloped-signature transform, and nothing else;
- `rsa-sha256`, `rsa-pss-sha256` or `ecdsa-sha256`, with RSA keys of 2048 bits at least;
- no document type declaration, no processing instruction, no comment anywhere in the assertion;
- the key is the configured certificate's and never one carried in the message;
- no encrypted assertions in Milestone 2.

`xml-sec` does the canonicalization and the signature check, with its two-parser mode on. The assertion is read from the node the verification resolved, and from nowhere else. The [attack corpus](../security/saml-attack-corpus.md) runs before and after every change.

- **For**: pure Rust, a narrow profile that removes most of what the attacks use, the parser-differential class addressed by design.
- **Against**: `xml-sec` is eight months old with no audit. Hodor depends on its canonicalization being right. The external review of Decision 0014 is what stands between this and production, and it must cover `xml-sec` as used.

### 2. samael with xmlsec1

- **For**: the most used Rust option, and xmlsec1 has decades of use.
- **Against**: OpenSSL, libxml2, libxslt and xmlsec1 go into the image, which today has none of them; a second cryptography library next to `aws-lc-rs`; two parsers by construction; a feature flag whose absence silently turns verification off.

### 3. Leave SAML out of Milestone 2

Finish the milestone with OpenID Connect, the social logins and LDAP, and come back to SAML when a pure-Rust option has a year of releases and an audit, or with the Shibboleth service provider as a separate process. Organizations that only speak SAML can be told to put a bridge in front, such as Keycloak, which receives SAML and speaks OpenID Connect to Hodor.

- **For**: no new risk now.
- **Against**: Requirement-SAML-01 waits, and the project owner asked for SAML.

## Decision

**Option 1.** Hodor verifies SAML signatures with `xml-sec`, behind the narrow profile above, in a new crate `hodor-saml`, the only crate allowed to depend on an XML library.

What the spike found when it looked inside `xml-sec` 0.6.0, and what follows from it:

| Finding | What is done |
|---|---|
| Its `aws-lc-rs` provider is only the FIPS variant, `aws-lc-fips`, which builds the FIPS module from source and needs Go and CMake | The default provider, RustCrypto, is used, **for verification only**: checking a signature uses the public key alone, so the timing weaknesses that matter for private-key operations do not apply. Hodor signs nothing with it. This is the one place where Decision 0008's choice of `aws-lc-rs` for signatures is not followed, and it is recorded there |
| It is about 250,000 lines, because it carries its own parsers, an XPath engine and, behind a feature, XSLT | Only the features `std`, `xmldsig` and `xml-backend-differential` are compiled: no signing, no encryption, no XSLT, no legacy algorithms. About 150 crates in its dependency tree, none with a known advisory, no license outside `deny.toml` |
| Verification succeeding does not say which element was signed; its API returns *evidence* that must be asked about the expected element | Hodor asks it about the assertion it is about to read, found by its `ID` once, and reads only that element. A successful verification without that evidence is a refusal |
| Duplicate identifiers are ambiguous and resolve to nothing | Hodor also refuses them itself, before verification, with its own reason |

The rules of Decision 0014 stand: the [attack corpus](../security/saml-attack-corpus.md) exists as tests before the code, and an **external security review of `hodor-saml` and of `xml-sec` as it is used** is a condition for calling SAML ready for production.

## Consequences

- SAML ships in Milestone 2 as built and tested against the corpus, not yet reviewed. The progress page says so until the review happens.
- A second cryptography library, RustCrypto, enters the server for one purpose. `cargo deny` watches it like every other dependency.
- `xml-sec` is young. Every upgrade of it is read, not taken blindly, and runs the whole corpus first.
- Encrypted assertions are refused whole in Milestone 2. Identity providers can be told to send them unencrypted over TLS, which is how most are configured.
