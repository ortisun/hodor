# Decision 0004: JWT access tokens, opaque hashed refresh tokens and codes

Status: Proposed

## Context

Token format decides who can validate a token, how revocation works and what a database leak exposes.

## Decision

| Artifact | Format | Stored as |
|---|---|---|
| Access token | JWT per RFC 9068, signed with the tenant key, 5-minute default lifetime. Opaque (reference) tokens selectable per client | Not stored; opaque variant stored as SHA-256 |
| ID token | JWT | Not stored |
| Refresh token | 256-bit random, opaque | SHA-256, with family and generation |
| Authorization code, pushed authorization requests URI, device code, verification tokens, session identifier | 256-bit random, opaque | SHA-256 |

- High-entropy random values are hashed with plain SHA-256; a slow hash adds nothing for 256-bit secrets.
- Default signing algorithm is ES256; RS256 is offered for interoperability; EdDSA is optional.
- Immediate revocation of JWT access tokens is available through a `jti` deny-list consulted by introspection and by Hodor's own APIs; resource servers that validate locally accept the short-lifetime window by design.
- Refresh tokens rotate on every use; reuse revokes the family.

## Consequences

- Resource servers validate offline with the JWKS; Hodor is not on the hot path of every API call.
- A database leak yields no usable token.
- Claims in a JWT are readable by the client; access tokens therefore carry identifiers and scopes, not profile data.
- Clients needing instant revocation or opaque tokens pay for introspection calls.

## Alternatives considered

- **Opaque access tokens only**: simplest revocation, but every API call depends on Hodor.
- **PASETO or other formats**: not what OAuth and OpenID Connect ecosystems expect.
- **Encrypting stored refresh tokens instead of hashing**: recoverability is not needed, so hashing is strictly safer.
