# Decision 0037: Back-channel logout is made by the OAuth context from the end of a session, and sent by the worker on leases as webhooks are

Status: Accepted (made for Issue-100; the project owner asked for back-channel logout, not for these choices)

## Context

[Milestone 9](../product/epics.md#milestone-9-what-020-left-out) asks for back-channel logout ([OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)): `sid` in ID tokens, logout tokens signed with the tenant's key and delivered by the worker to the addresses clients register, with retries. Every client with a session must receive a logout token when the person signs out, and the back-channel logout plan of the OpenID conformance suite must pass.

Five questions had to be answered before the code:

1. How the OAuth context learns that a session ended.
2. Which clients count as having a session.
3. When a logout token is signed.
4. How the worker sends it, and how much of the webhooks context is reused.
5. Where the worker finds the issuer, which every token names.

What already existed shaped the answers. ID tokens already carried `sid`, the session's identifier, for logout initiated by the relying party (Issue-60). Every grant already records the session it was made in. The session context records `session.revoked` in the outbox, in the transaction that ends a session, whoever ends it. The webhooks context ([Decision 0032](0032-webhooks.md)) sends deliveries from the worker on leases, outside any transaction, through the guarded outbound client, with growing waits and a bound after which a delivery is set aside. The OAuth context depends on the session context's types and on the keys context, never the reverse; no context depends on the webhooks context. Only the server knows the installation's public address; the worker does not.

## Decision

- **The OAuth context hears `session.revoked` from the outbox.** Its handler is given to the outbox dispatcher beside the audit handler and the fan-out of webhooks, and writes one delivery per client, inside the dispatcher's transaction, unique per client and session. No context learns about OAuth: the session context records its event as it always did, and the handler reads the event's stored fields. Every way a session is ended on purpose (signing out, logout initiated by the relying party, an administrator, a password reset, deprovisioning) is covered by the one event.
- **The clients of a session are those with a grant made in it with `openid`.** Grants already hold the session, so nothing new is recorded when a token is issued, and the token endpoint is unchanged. A grant is made a moment before its code is redeemed; a client whose code was never redeemed gets a logout token for a session it never saw, which it ignores. The grant's status does not matter: an application that got an ID token keeps its own session even after its grant was revoked.
- **A logout token is signed at each attempt, not when the delivery is made.** It lives two minutes, as the specification suggests a short life, while the attempts of a delivery last an hour; each attempt has its own `iat`, `exp` and `jti`. It is signed with the tenant's active key of the client's ID token algorithm, through the keys context, so the client checks it as it checks its ID tokens. It always carries both `sub` and `sid`; `backchannel_logout_session_required` is recorded and changes nothing.
- **It is sent as webhooks are, by code of the OAuth context.** A table of its own, `oauth.logout_delivery`, and a loop of the worker of its own, with the same three short steps (lease under a lock of the client, request with no transaction open, record if still as leased), the same bounds in flight, the same waits and the same eight attempts. The rules are copied, not shared: the OAuth context does not depend on the webhooks context, and the retry policy is a few lines.
- **The address is checked as a webhook endpoint's is.** Through the kernel's `DestinationCheck` when it is set, and by the guarded client at every attempt, with the development exception and nothing else.
- **The worker is given `HODOR_PUBLIC_URL`**, the setting the server has, and reads a tenant's slug through the tenant context, to name the issuer `{HODOR_PUBLIC_URL}/t/{slug}` as the server does. A worker without it sends no logout token, as a worker without `HODOR_SECRET_KEYS` cannot sign one; deliveries wait meanwhile.

## Consequences

- A client is told a few seconds after the session ends, not during the request that ended it. The person's browser waits for nobody, and a client that does not answer holds up neither the person nor the other clients.
- Delivery is at least once and not in order. A client may receive a second logout token for a session it already ended; the specification's checks, and ending a session that is already ended, make that harmless. The context page says so.
- A session that runs out by itself, idle or at its absolute end, records no event and sends nothing. The specification asks to tell clients when the session ends at the provider; a session that simply expired was never ended there, and every client's own session expires as well. Recording an event for each expired session is left until an application needs it.
- Installations must give the worker `HODOR_PUBLIC_URL`. The packages and the development stack do; the worker warns at start when it is missing.
- A logout token is a credential an attacker could try to replay against a client; it lives two minutes, its `jti` is new each time, and it names one client alone.
- The conformance suite's back-channel endpoint has a certificate of its own making, which the guarded client refuses, as it should. The conformance stack puts a web server that does not check it between the worker and the suite, under the development exception; nothing real has either.

## Alternatives considered

- **Sending the logout tokens from the server, during the request that ends the session.** No table and no loop. Set aside: the person's browser would wait for every client, a client that does not answer would make signing out slow, a failure would be lost, and the sessions ended by an administrator, a password reset or deprovisioning would each need the same code.
- **Recording, at the token endpoint, each client an ID token was issued to in a session.** Exact: only clients that redeemed a code are told. Set aside: the grant already says it, but for the moment between the code and its redemption; it would change the token endpoint, which other work is changing at the same time, for little.
- **Signing the logout token once, when the delivery is made.** One signature per delivery. Set aside: a token that lives two minutes would be expired by the third attempt, and one that lives an hour would be a long-lived credential.
- **Sending logout tokens through the webhooks context.** One loop of the worker instead of two. Set aside: a logout token is not an event of the catalog, goes to a client's address and not to an endpoint, is signed with the tenant's key and not with an endpoint's secret, and the webhooks context would have to learn clients, grants and keys, which belong to other contexts.
- **Front-channel logout, through the person's browser.** No worker. Set aside: [Milestone 9](../product/epics.md#explicitly-not-in-milestone-9) leaves it out; it needs the browser to stay on Hodor's page while every application loads in a frame, and browsers that block cookies in frames of other sites defeat it.
