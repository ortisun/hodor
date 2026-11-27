# Decision 0077: `hodor-ext-authz` denies claims whose audience is not the one its configuration names for the application

Status: Proposed

## Context

[Decision 0058](0058-hodor-ext-authz.md#what-hodor-ext-authz-does) has `hodor-ext-authz` take the subject from the claims of the token the proxy checked, once `iss` is the tenant's issuer and `exp`, when present, is in the future. It says nothing of `aud`. [Decision 0029](0029-hodor-in-a-service-mesh.md#the-proxies-check-hodors-tokens-themselves) has the proxy check the tenant's tokens "as any resource server does", but a proxy checks an audience only when it is told one: Istio's `RequestAuthentication` without `audiences`, and Envoy's JWT filter without `audiences`, accept a token for any audience, and the example of [the page of `hodor-ext-authz`](../operations/hodor-ext-authz.md#in-istio) named none. The guide to service meshes, while it was written, found the gap and asked the operator to name the audience at the proxy.

The roles of each application do not close it. `evaluate` decides about the resource server of the destination's application, by the roles the subject holds there. Those roles say what a person may do on Orders; nothing in them says the token was given to Orders. A token issued for Invoices when a person signed in there, replayed at Orders by Invoices or by whoever read it there, would then act as that person on Orders, with every role they hold on Orders, and the scopes they consented to for Invoices would stand for a consent they never gave Orders. An ID token, whose audience is a client, would be taken for an access token. This is the replay at another resource server that audience restriction answers ([Threat-OAuth-07](../security/threat-model.md#oauth-2x), [RFC 9068, section 4](https://www.rfc-editor.org/rfc/rfc9068#section-4)), and Hodor's own resource servers already check it.

`hodor-ext-authz` does not know the application's audience: its configuration names the destination and the client, and the adapter reaches Hodor through the token endpoint and `evaluate` alone, neither of which names it. An application has at most one resource server ([the OAuth context](../architecture/contexts/oauth.md#resource-servers)), so one audience per application is enough.

## Decision

- **Each application of the configuration names its resource server's audience, `audience`.** It is required and not empty, even when no `token` is read, so that turning claims on later never skips the check. The chart's `extAuthz.applications[].audience` writes it.
- **Claims are denied unless `aud` holds that audience**: one text equal to it, or a list with it among its values, compared byte for byte, as the audience of a resource server is. A token for several resource servers is good at each of them; one that names only the issuer, another application, or a client, is denied.
- **The check is the adapter's, whatever the proxy does.** The guides still name the audience at the proxy, which then refuses such a token before the check is asked; the adapter's check holds when they do not.
- **A failed audience is a failed claim**: denied, logged with its reason, and never replaced by the caller's identity, as for the other claims.

## Consequences

- A token issued for one application of a tenant no longer acts at another application's proxy, nor does an ID token.
- Every configuration needs one more field per application, the audience the tenant registered for its resource server. A configuration without it stops the process before it listens, with a message naming the entry. `hodor-ext-authz` was not released before this, so no running configuration breaks.
- The adapter still learns nothing from Hodor at start: the audience is written by the operator, beside the `client_id` of the same application. A wrong audience denies every token of that application, which the logs name.
- Threat-Mesh-18 records the threat and its control.

## Alternatives considered

- **Leaving the audience to the proxy, and saying so.** Nothing to build. Set aside: a proxy left with its default checks no audience, and the adapter is where Hodor's rules hold whatever the mesh is told.
- **Learning the audience from Hodor**, by reading the client's application at start. No field to write. Set aside: the adapter's clients hold only `authz:evaluate`, which reads no application, and widening them would widen what a compromised adapter can do (Threat-Mesh-07).
- **A list of audiences per application.** It would let one entry stand for several resource servers. Set aside: an application has at most one resource server, and the Authorization API decides about that one alone.
- **Requiring the audience only when `token` is set.** One field less for an adapter that reads no token. Set aside: the rule would change silently when claims are turned on.
