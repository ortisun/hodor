# Decision 0072: An ID token through the browser carries `s_hash` whenever the request had `state`, and only a client of the authorization code has response types

Status: Proposed (requested by the project owner, who asked for every OpenID certification profile)

## Context

[Decision 0046](0046-responses-through-the-browser.md) offers every response type of OpenID Connect, each registered per client, and says the ID token of the authorization response carries "`s_hash` when the request had `state` and a client held to a profile asks for it". [Issue-127](../product/epics.md#slice-response-types-and-modes-epic-10), which builds the ID token through the browser, leaves two things open:

- **When `s_hash` is there.** No client is held to a profile yet: [security profiles](0052-security-profiles.md) come with Issue-145, in 0.6.0. Read as written, the decision gives no ID token an `s_hash` until then, though the issue asks for it. FAPI 1.0 Advanced, the profile that needs it, requires it whenever the client sent `state` (section 5.2.2.1). OpenID Connect does not define it, and a client that does not know a claim ignores it ([OpenID Connect Core, section 5.1](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) and JSON Web Token, [RFC 7519, section 4](https://www.rfc-editor.org/rfc/rfc7519#section-4)).
- **Which grant a client of `id_token` holds.** [OpenID Connect Registration, section 2](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata), pairs each response type with grants: `code` with `authorization_code`, `id_token` with `implicit`, `code id_token` with both, `none` with none. Hodor's grants are what a client may ask of the token endpoint, and the rules of a client hang on `authorization_code`: only a client with it has redirect addresses, post-logout redirect addresses, a back-channel logout address, or a pairwise subject ([what a client may be](../architecture/contexts/oauth.md#what-a-client-may-be)). No request to the token endpoint uses `implicit`.

## Decision

### The state hash

**An ID token that comes through the browser carries `s_hash` whenever the request had `state`**, whatever the client: the base64url of the left half of the hash of `state`, the hash the client's ID token algorithm names, as for `c_hash` and `at_hash`: SHA-256 for `ES256`, `RS256` and `PS256`, SHA-512 for `EdDSA`. A client that does not know `s_hash` ignores it; one that does can tell that the `state` it reads is the one it sent, which `state` alone cannot prove against an attacker who swaps the parameters of an answer. When security profiles come, a client of FAPI 1.0 Advanced finds it there already, and nothing about it depends on the profile. The ID token of the token endpoint has none: `state` never reaches the token endpoint.

### The response types of a client

**`authorization_code` stays the grant that lets a client send people to the authorization endpoint, and only a client with it has response types**: at least one, `code` unless chosen. A client of `id_token` alone holds `authorization_code` though it never redeems a code, as it holds a redirect address. Hodor does not keep `implicit` as a grant of a client. Discovery names `implicit` among `grant_types_supported`, as [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata) expects of a provider that answers `id_token`, and how a registration that sends it is read is for [dynamic registration](0049-dynamic-client-registration.md) to say.

A change that takes `authorization_code` away from a client drops its response types, as a change of authentication method drops the secrets of the old one; a change that gives the grant to a client that has no response type gives it `code`. A change that names response types is checked as given.

## Consequences

- The Hybrid plans find `s_hash` in every ID token of a request with `state`, which they ignore; FAPI 1.0 Advanced finds it when its turn comes.
- An ID token through the browser of a request with `state` is about 45 bytes longer.
- Every rule that hangs on `authorization_code` holds for a client of `id_token` as written: it has redirect addresses, may be pairwise and may be told of a logout, without a second grant to keep beside the first.
- An administrator who reads a client of `id_token` sees `authorization_code` among its grants, which names no request it makes. The client's response types say what it is answered with.

## Alternatives considered

- **`s_hash` only for a client held to a profile, as Decision 0046 worded it.** Set aside: until profiles exist, no ID token would carry it, and the condition would need a profile to exist only to add a claim nobody else is harmed by.
- **`s_hash` only for `code id_token`, the type FAPI 1.0 Advanced uses.** Set aside: two rules where one serves, and a client of `id_token` reads `state` just the same.
- **An `implicit` grant kept on the client, as OpenID Connect Registration pairs them.** Set aside: every rule of a client that hangs on `authorization_code` would hang on either grant, for a grant the token endpoint never answers.
