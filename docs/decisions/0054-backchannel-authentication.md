# Decision 0054: A backchannel authentication request reaches the person on Hodor's account page, by email, and through the tenant's own authentication device service; poll and ping are offered, push for clients outside FAPI

Status: Proposed (requested by the project owner, who asked for every OpenID certification profile)

## Context

[OpenID Connect Client-Initiated Backchannel Authentication Flow, Core 1.0 (CIBA)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) lets a client ask for a person to be signed in without a browser at the client: a call centre, a point of sale, a television. The client posts to the backchannel authentication endpoint a hint of who the person is; the provider reaches the person on a device of theirs, the **authentication device**, where they sign in and approve; the client gets the tokens in one of three modes:

| Mode | How the client gets the tokens |
|---|---|
| Poll | It polls the token endpoint with `grant_type=urn:openid:params:grant-type:ciba` and `auth_req_id` |
| Ping | The provider calls the client's notification endpoint when the person answered; the client then asks the token endpoint |
| Push | The provider sends the tokens to the client's notification endpoint |

The [OpenID conformance suite](../operations/conformance.md) (release 5.3.5) has no plan for backchannel authentication alone, only `fapi-ciba-id1-test-plan`, for [FAPI-CIBA](https://openid.net/specs/openid-financial-api-ciba.html): signed authentication requests, poll required and ping optional, push forbidden, tokens bound to the client's certificate, `private_key_jwt` or mutual TLS. The tester names one hint, `login_hint`, `login_hint_token` or `id_token_hint`. The person approves by hand on the authentication device, unless the tester gives the suite `automated_ciba_approval_url`, an address it calls with `{auth_req_id}` and `{action}`. Certification asks for poll in every submission ([FAPI-CIBA testing](https://openid.net/certification/fapi_ciba_op_testing/)).

Hodor has no application of its own on a person's telephone. It has the account page, email ([the notification context](../architecture/contexts/notification.md)), webhooks ([Decision 0032](0032-webhooks.md)), and passkeys and second factors for strong sign-in. A pending request that waits for a person already exists, as the pending authorization request.

## Decision

### The request

- **The endpoint** is `/t/{slug}/oauth2/bc-authorize`, `POST` with a form, authenticated as at the token endpoint. Only a confidential client allowed the grant of backchannel authentication, `urn:openid:params:grant-type:ciba`, may call it, with its registered `backchannel_token_delivery_mode`.
- **The person is named by one hint**: `login_hint`, an identifier of the person as the sign-in form reads it; `id_token_hint`, an ID token Hodor issued to this client, expired or not; or `login_hint_token`, a signed token whose issuer the tenant trusts, as for [software statements](0049-dynamic-client-registration.md). Two hints, or none, is `invalid_request`. A hint that names nobody is answered `unknown_user_id`, the same for an unknown person and one who may not sign in, so that the endpoint does not tell who exists beyond what the client already knew.
- **Signed requests** are request objects as [Decision 0045](0045-request-objects-and-pushed-requests.md) checks them, with `aud` the issuer and `jti` remembered, and are required for a client held to a [security profile](0052-security-profiles.md).
- **`binding_message`** of at most 64 printable characters is shown to the person; one that cannot be shown is `invalid_binding_message`. `user_code` is not offered. `requested_expiry` is bounded by the tenant, 120 seconds by default and 600 at most.
- **The answer** is `auth_req_id`, 32 random bytes of which only the hash is kept, `expires_in` and `interval`, five seconds unless the tenant sets more.
- **The request is kept** as a pending authorization request, as a pushed one is, with the person named, the mode and what the client asked: scopes, `acr_values`, `binding_message`.

### How the person is reached, and approves

- **On Hodor's account page.** A person signed in to the tenant sees, on the account page, every request waiting for them, with the client's name, the scopes and the binding message, and approves or denies it. Approving demands a sign-in that reaches what the request asks, as a step-up does ([assurance and step-up](../architecture/contexts/oauth.md#assurance-and-step-up)), and at least the tenant's level for backchannel authentication, multi-factor by default.
- **By email**, when the tenant turns it on: a message with the client's name and the binding message, and a link to that page. The link holds no credential; the person signs in there as anywhere else.
- **Through the tenant's own authentication device service.** The event `oauth.backchannel_authentication_requested` is offered to [webhooks](0032-webhooks.md), naming the request and the person by identifier, never the hint. A service of the tenant, its own mobile application's server, reaches the person however it can and reports their answer through the administration interface's operation for it, as a client holding a permission of its own. That service vouches for the sign-in, and the assurance it claims is bounded by the tenant.
- **A denial, or no answer before expiry**, ends the request: `access_denied` or `expired_token` at the token endpoint and in a ping.
- **For the suite**, the conformance stack gives the suite an `automated_ciba_approval_url` served by a helper of the stack, which approves or denies through that same operation. Nothing in Hodor serves that address.

### The modes

- **Poll** at the token endpoint answers `authorization_pending` until the person answers, `slow_down` and a longer interval to a client that polls too fast, then the tokens once, then `invalid_grant`.
- **Ping** sends `{"auth_req_id": …}` with the client's `client_notification_token` as a bearer token to its `backchannel_client_notification_endpoint`, from the worker, through the guarded outbound client, with the retries of a logout token ([Decision 0037](0037-back-channel-logout.md)). The address is checked as a back-channel logout address is.
- **Push** sends the tokens there instead, for a client not held to a security profile, which forbids it.
- **The tokens** are those of the token endpoint, with the grant made when the person approved, so that refresh tokens, consent, bound tokens and revocation work as for a code.

## Consequences

- A tenant can let a call centre or a shop ask for a person's approval with no browser at the client, and the FAPI-CIBA plan can be certified, with poll and ping.
- A person approves only after signing in as strongly as the request asks; a request that floods a person's account page can be denied and is limited per client and person.
- Hodor ships no mobile application. A tenant that wants a notification on a telephone builds it on the webhook and the operation that reports the answer, and that service is trusted for the sign-in it reports, which the tenant chose.
- Push mode is offered for completeness and certified by nobody; it sends tokens to an address, which is why the profiles forbid it.

## Alternatives considered

- **A mobile application of Hodor's own, with push notifications.** What commercial providers do. Set aside: a product of its own, with stores, keys and devices to manage; the webhook lets a tenant use its own application.
- **Email alone.** Simple. Set aside: email is slow and phishable, and a tenant with its own application should be able to use it.
- **Leaving push mode out.** What FAPI-CIBA asks. Set aside: the core specification defines it, and a client outside FAPI may want it; it stays off unless a client registers it.
- **An address in Hodor for the suite's automated approval.** Simpler to configure. Set aside: an address that approves a sign-in without a person must never exist in Hodor; the conformance stack's helper uses the same operation any authentication device service would.
