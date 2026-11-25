# Decision 0046: Every response type and response mode of OpenID Connect is offered, each allowed per client; an access token through the browser only for a client an administrator marks so, and never for a client held to a security profile

Status: Proposed (requested by the project owner, who asked for every OpenID certification profile). It changes a non-goal of the [product requirements](../product/product-requirements.md#5-non-goals), "no implicit grant".

## Context

Hodor answers only `response_type=code`, in the query of the redirect address ([checking the request](../architecture/contexts/oauth.md#checking-the-request)). The [product requirements](../product/product-requirements.md#5-non-goals) list "no implicit grant" as a non-goal, and the [threat model](../security/threat-model.md#oauth-2x) controls token leakage through the front channel (Threat-OAuth-09) by never putting a token in an address.

Several certification profiles need more ([OpenID conformance](../operations/conformance.md#the-target)):

| Profile | Response types | Response mode |
|---|---|---|
| Implicit OpenID Provider | `id_token`, `id_token token` | `fragment` |
| Hybrid OpenID Provider | `code id_token`, `code token`, `code id_token token` | `fragment` |
| Form Post OpenID Provider | Those of Basic, Implicit and Hybrid | `form_post` ([OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)) |
| FAPI 1.0 Advanced | `code id_token`, or `code` with JARM | `fragment`, or `jwt` |
| FAPI 2.0 Message Signing | `code` with JARM | `jwt` |

[OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html) defines the combined types and the `fragment` mode; [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/oauth-v2-jarm.html) defines `query.jwt`, `fragment.jwt`, `form_post.jwt` and `jwt`.

[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.2) says the implicit grant, and any response type that puts an access token in the authorization response, should not be used, because the token can leak and cannot be bound to its client. An ID token through the browser is a different matter: it is meant for the client that asked, carries `nonce`, and is what the hybrid flow of FAPI 1.0 Advanced uses to protect the code (`c_hash`, `s_hash`).

## Decision

### Every type and mode, each allowed per client

- **A client registers the response types it may use** (`response_types` of OpenID Connect Registration), `code` unless chosen. A request with a type the client may not use is `unauthorized_client`, and an unknown type `unsupported_response_type`, as today.
- **Every response mode is offered** to any client: `query` for `code` alone and `none`, `fragment`, `form_post`, and the four of JARM. The default is the one each type defines: `query` for `code`, `fragment` for every type that holds `id_token` or `token`. `query` is refused for a type that returns a token, since a token never goes into a query.
- **`form_post`** answers with a page of Hodor's own that posts the parameters to the redirect address and does nothing else: no script but the one that submits the form, a content security policy that allows only that, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and a button for a browser without script.
- **JARM** answers with one JSON Web Token, signed with the tenant's key of the client's `authorization_signed_response_alg` and encrypted when the client asks, with `iss`, `aud` the client and `exp` within ten minutes, as JARM says. Errors are signed too.
- **The ID token of the authorization response** carries `nonce`, required for every type that returns an ID token, `c_hash` when a code comes with it, `at_hash` when an access token does, and `s_hash` when the request had `state` and a client held to a profile asks for it. It holds the claims [Decision 0047](0047-claims-and-the-person-s-claims.md) says, and is otherwise the ID token of the token endpoint.
- **`response_type=none`** is offered too: the browser comes back with `state` and nothing else.

### An access token through the browser is the exception, marked and bounded

- **Only a client an administrator marks as allowed to receive tokens through the browser** may register `id_token token`, `code token` or `code id_token token`. The mark is recorded with who set it and is a finding of the [security posture](../design/control-plane.md#5-how-the-console-protects-itself) for as long as it stands. A [registration policy](0049-dynamic-client-registration.md) must name it for a registered client to have it.
- **Never for a client held to a [security profile](0052-security-profiles.md)**, and never with a refresh token: the token endpoint issues refresh tokens only for a code.
- **The access token issued through the browser** lives at most five minutes whatever the client's policy says, carries only the scopes of OpenID Connect and those the client marked, and is never bound to a grant that outlives the session.
- **An ID token through the browser is not the exception.** `id_token` and `code id_token` need only the client's response types; they issue no access token through the browser.

### What changes in the product's rules

The non-goal "no implicit grant" becomes "the implicit grant only for a client an administrator marks, for compatibility and certification, never by default". Threat-OAuth-09 keeps its control for every client without the mark. The [threat model](../security/threat-model.md#openid-certification-profiles) adds what the mark exposes.

## Consequences

- The Implicit, Hybrid and Form Post OpenID Provider profiles can be certified, and FAPI 1.0 Advanced and FAPI 2.0 Message Signing get the responses they need.
- A tenant that never marks a client sees no new way for a token to leak: only an ID token or a code goes through the browser.
- A marked client's access tokens can leak through the browser's history, logs and other scripts of its page, as RFC 9700 warns. That is the administrator's choice, made visible on the security posture and bounded to five minutes.
- The authorization endpoint answers in four encodings. Each is a small function over the same answer, tested once per type and mode.

## Alternatives considered

- **Refusing every access token through the browser, and not certifying the Implicit profile and the token types of Hybrid.** Keeps the non-goal as it is. Set aside: the owner asked for every profile; a mark per client keeps the default safe.
- **A setting of the tenant instead of a mark per client.** Simpler to find. Set aside: one legacy client would open the door for every other.
- **Offering `form_post` only to clients that ask for it in their registration.** Narrower. Set aside: OpenID Connect lets any request choose its mode, and `form_post` keeps tokens out of addresses, which is safer than the default `fragment`.
