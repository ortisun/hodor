# Decision 0014: SAML is deferred to Phase 6 and gated by a security spike

Status: Proposed

## Context

SAML 2.0 (identity provider and service provider) is required for enterprise federation. Its security rests on XML Signature and canonicalization, the source of a long line of authentication bypasses (signature wrapping, comment injection, entity expansion). The Rust ecosystem's options for XML Signature are few; the best-known SAML crate relies on C libraries for signature handling. A wrong choice here is a critical vulnerability, not a bug.

## Decision

- SAML stays in Phase 6, after OpenID Connect federation is proven.
- Before Phase 6 planning, a time-boxed spike compares: (a) binding to an established C XML security library, isolated behind a narrow port; (b) a pure-Rust stack; (c) running SAML processing in a separate sandboxed process. Criteria: resistance to the known attack corpus, maintenance status, fuzzing results, build and deployment cost.
- Whatever is chosen, the `saml` crate follows fixed rules: validate the schema first; verify the signature; then read values only from the exact element the signature covered; reject duplicate identifiers, DTDs and weak algorithms; require signed assertions.
- The attack corpus and interoperability suite are written before the feature code.
- An external security review of the SAML implementation is a release gate for Phase 6.
- The `saml` crate is the only place allowed to depend on XML libraries, and the only place where `unsafe` or a foreign function interface may be considered.

## Consequences

- Enterprise customers that only speak SAML wait until Phase 6; OpenID Connect covers Entra ID, Okta and Google Workspace in the meantime.
- Phase 6 has an explicit unknown in its estimate until the spike reports.

## Alternatives considered

- **Implement SAML early with the most available crate**: fastest, highest risk.
- **Never support SAML; recommend an external bridge**: removes the risk but fails a stated product goal.
