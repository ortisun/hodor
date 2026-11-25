# Decision 0045: A request object and a pushed authorization request become the same pending request, kept per tenant by the hash of its reference, used once

Status: Proposed (requested by the project owner, who asked for every OpenID certification profile)

## Context

Today the authorization endpoint answers `request_not_supported` to a request object and `request_uri_not_supported` to a reference to one ([checking the request](../architecture/contexts/oauth.md#checking-the-request)). Discovery says so. That is allowed for the Basic OpenID Provider profile, and the suite then skips its test. Every other profile needs more:

- **OpenID Connect Core, section 6**, lets a client send its request as a JSON Web Token: by value in `request`, or by reference in `request_uri`, an address the provider fetches. The Dynamic OpenID Provider plan of the [OpenID conformance suite](../operations/conformance.md) registers clients that send both, signed and unsigned.
- **RFC 9101, JWT-Secured Authorization Request (JAR)**, is the OAuth version of the same thing, with stricter rules: the parameters outside the object are ignored, and `client_id` outside must match the one inside.
- **RFC 9126, OAuth 2.0 Pushed Authorization Requests (PAR)**, lets a client post its request to the server first, and send the browser only with a `request_uri` the server made. FAPI 2.0 requires it, and FAPI 1.0 Advanced tests it as a variant.
- **FAPI 1.0 Advanced and FAPI 2.0 Message Signing** require a signed request object, with `exp` no more than 60 minutes after `nbf`, and `aud` the issuer.

The checked request is already kept as a pending authorization request while the person signs in ([signing in and coming back](../architecture/contexts/oauth.md#signing-in-and-coming-back)). Hodor already checks client assertions signed with the client's keys ([checking a client assertion](../architecture/contexts/oauth.md#checking-a-client-assertion)), and fetches outside addresses only through the [guarded outbound client](../security/outbound-http.md).

## Decision

### A request object is checked as a client assertion is, then read as the request

- **Signed request objects** are compact JSON Web Signatures of at most 16 kibibytes, signed with a key of the client (its registered keys, or its `jwks_uri` once [Decision 0049](0049-dynamic-client-registration.md) brings it). The algorithms are those of client assertions, `ES256`, `RS256` and `PS256`, with `ES384` and `EdDSA` once the kernel checks them. A client may name one with `request_object_signing_alg`, and then any other is refused.
- **Encrypted request objects** are decrypted with the tenant's encryption key first, as [Decision 0048](0048-encryption.md) says, and must hold a signed one, except as the next point allows.
- **Unsigned request objects** (`alg` `none`) are accepted only from a client that names `none` as its `request_object_signing_alg`, and never for a client held to a [security profile](0052-security-profiles.md). OpenID Connect allows them, and the Dynamic plan tests them. They add nothing to the request but its shape, so the checks of the request apply to them in full.
- **What the object must say.** `iss` is the client's identifier and `client_id` inside equals the one outside, when the outside one is given. `aud`, when present, holds the tenant's issuer, and a profile may require it. `exp` and `nbf` are required for a client held to a profile, and accepted otherwise, with 60 seconds allowed for clocks. `jti` is remembered until `exp` when a profile asks for it.
- **The parameters inside win.** As RFC 9101 says, only the parameters of the object are read, beside `client_id`; the others are ignored, `response_type` and `scope` included. A client of OpenID Connect that repeats `response_type`, `client_id` and `scope` outside, as OpenID Connect Core asks, must repeat the same values, or the request is `invalid_request`.
- **Every check of the authorization endpoint then applies**, to the parameters read from the object, in the order the endpoint already keeps.

### `request_uri` is either Hodor's own reference or an address the client registered

| Reference | What happens |
|---|---|
| `urn:ietf:params:oauth:request_uri:` followed by 32 random bytes in base64url | A pushed authorization request of this tenant and this client, looked up by the hash of the reference |
| An HTTPS address | Fetched through the guarded outbound client, only when it starts with one of the client's registered `request_uris`, at most 16 kibibytes, within 5 seconds; never followed to another address. A fragment after `#` is the SHA-256 the client gave of the content and is checked |
| Anything else | `invalid_request_uri` |

An address the client registered is fetched once per request and never cached. A client held to a profile may only use Hodor's own references, as FAPI 2.0 requires.

### A pushed authorization request is stored as the pending request it will become

- **The endpoint** is `/t/{slug}/oauth2/par`, `POST` with a form, authenticated as the token endpoint authenticates a client, with the same methods. A public client may push too, proving nothing, as RFC 9126 allows.
- **Checked when pushed**, with every check the authorization endpoint makes that does not need the browser: the client, the redirect address, the response type, the scopes, the resources, PKCE and the request object. A failure is answered there, at once, as JSON, never at the redirect address.
- **Kept as a pending authorization request** in the table that already holds them, `oauth.authorization_request`, with a column for the hash of its reference and one saying it was pushed. The reference itself is never stored, as a code is never stored. It lives 60 seconds by default, from 10 to 600 as the tenant sets it, and is answered as `expires_in`.
- **Used once.** The authorization endpoint takes it with a conditional change, as a code is redeemed, binds it to the browser with the cookie it already uses, and from there the request goes on as any other. A second use of the reference is `invalid_request_uri`.
- **Bound to its client and tenant.** The reference is looked up only in the tenant the address names, and only for the client the browser's request names. A reference of another client or tenant is unknown.
- **A client or a tenant may require it.** `require_pushed_authorization_requests`, per client and as the tenant's default, refuses every request that does not come through it. Discovery names `pushed_authorization_request_endpoint` and the tenant's setting.

### Storage and bounds

- Request objects pushed or fetched are kept only as the checked request, never as the token they came in.
- A client may have at most 5 pending pushed requests at once; the oldest is dropped when a sixth arrives. The pushed request endpoint is limited per client as the token endpoint will be.
- `oauth.authorization_request` keeps its row-level security; the new columns change nothing of who may read a row.

## Consequences

- The Basic, Dynamic, FAPI 1.0 Advanced and FAPI 2.0 plans can test request objects and pushed requests, and the tests the Basic plan skips today run.
- One pending request serves the browser's sign-in, a pushed request, and later a request of [client-initiated backchannel authentication](0054-backchannel-authentication.md), so the resume path stays one.
- Fetching a client's `request_uri` is one more outbound call a client can cause. It goes through the guarded client, only to addresses the client registered, which an administrator or a [registration policy](0049-dynamic-client-registration.md) approved.
- Unsigned request objects stay possible for clients that ask for them; they protect nothing, and a client held to a profile cannot use them.

## Alternatives considered

- **Keeping pushed requests in a table of their own.** Clearer to read. Set aside: a pushed request is a pending request that has not met its browser yet, and two tables would need two ways to resume.
- **Returning the pushed request in the reference itself, signed or encrypted by Hodor.** Nothing stored. Set aside: a reference must be usable once, which needs a record anyway, and RFC 9126 recommends a reference that holds nothing.
- **Never fetching a client's `request_uri`.** One outbound call less. Set aside: OpenID Connect Core defines it and the Dynamic plan tests it; limited to registered addresses through the guarded client, it is as safe as a sector identifier address, which Hodor already fetches.
- **Refusing unsigned request objects.** Simpler. Set aside: OpenID Connect allows them, and refusing them fails tests of the Dynamic plan for no gain a client held to a profile does not already get.
