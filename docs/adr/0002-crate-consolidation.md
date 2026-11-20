# ADR-0002: Consolidate the proposed workspace from 26 to 24 crates

Status: Proposed

## Context

The specification's repository layout lists 26 crates and says the structure is a starting reference: merge where cohesion is strong, split where a boundary is justified. Four of the proposed splits create shared types with nowhere to live or crates too small to justify, and two responsibilities have no home.

## Decision

| Change | Reason |
|---|---|
| Merge `shared` into `kernel` | Two "common" crates invite dumping. One small shared kernel with a strict admission rule: a type enters only if at least three contexts need it and it carries no business rule of a single context |
| Merge `oauth2` and `oidc` into `oauth` | OIDC extends the same authorization and token endpoints, the same grant and the same client model. Split, the two would either share types through a third crate or depend on each other |
| Merge `social-login` into `federation` | A social connector is a provider preset plus small protocol quirks on the common relying-party machinery |
| Merge `consent` into `oauth` | A small aggregate consumed only by the authorization endpoint |
| Add `keys` | Key sets, versions, rotation and JWKS publication are domain rules. `adapters-kms` only implements the `KeyProvider` port |
| Add `adapters-http` | One outbound HTTP client with SSRF protection, used by federation, OPA, webhooks and JWKS retrieval, instead of each adapter building its own |

Crates are created when the phase that needs them begins, not up front.

## Consequences

- No circular pressure between OAuth and OIDC code.
- `oauth` becomes the largest crate. It is internally split into modules (`client`, `authorize`, `token`, `oidc`, `consent`, `logout`); if it grows unwieldy, `client` (application registry) is the first candidate to extract.
- The SSRF control exists in exactly one place.

## Alternatives considered

- **Keep all 26**: more boundaries than there are real seams, and more shared-type friction.
- **Go further (merge `credential` into `authentication`, `session` into `authentication`)**: rejected because `oauth` needs sessions without needing authentication flows, and credential storage has a different security review profile.
