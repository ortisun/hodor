# Decision 0057: A token is bound to the certificate the proxy forwards when its client asks, and checked wherever Hodor accepts it as a credential

Status: Accepted

## Context

[Issue-108](../product/epics.md#slice-mutual-tls-epic-31) binds access tokens to the certificate their client presented in mutual TLS, as [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705), sections 3 and 4, writes it: the token carries `cnf` with `x5t#S256`, the SHA-256 of the certificate, and whoever accepts the token checks that the request came with that certificate. [Decision 0029](0029-hodor-in-a-service-mesh.md#a-workload-proves-who-it-is-in-one-of-three-ways) says a token can be bound when the certificate or its hash reaches Hodor, and [Decision 0056](0056-forwarded-client-identity.md) says how a certificate reaches it: in the one header a trusted proxy writes. It leaves open:

- which clients get bound tokens, and what happens when such a client sends no certificate;
- where the hash comes from when Envoy forwards only the names of a certificate, as Istio does by default;
- where a bound token is checked: the plan names UserInfo, introspection, the Authorization API and the administration interface ([Threat-Mesh-05](../security/threat-model.md#service-meshes-and-certificates));
- what binds a refresh token, which RFC 8705, section 4, asks of public clients;
- what is stored.

## Decision

- **A client asks for bound tokens with `tls_client_certificate_bound_access_tokens`**, the client metadata of RFC 8705, section 3.4, `false` unless set. Any client may ask, a public one included, whatever its method, but one using `linkerd_identity`: Linkerd forwards no certificate. The binding does not depend on how the client proved who it is (RFC 8705, section 3): a client of a secret may be bound to the certificate its sidecar presents.
- **Such a client gets only bound access tokens.** At the token endpoint, every access token it is issued carries `cnf` with `x5t#S256` of the certificate the request came with. A request of such a client that came with no certificate is refused with `invalid_request`, rather than answered with a token that is not bound: the client asked for the binding, and a token without it would be accepted without the certificate.
- **The certificate is the one the proxy forwarded**, read as [the caller's identity from a proxy](../api/api-spec.md#the-callers-identity-from-a-proxy) says: only the header the operator names, only from a trusted proxy, only its nearest element. Its thumbprint is the SHA-256 of its DER encoding. **When Envoy forwards no `Cert`, its `Hash` is used**: the SHA-256 of the same certificate, in hexadecimal, which Istio forwards by default. A `Hash` that is not 64 hexadecimal digits gives no thumbprint; with a `Cert`, `Hash` is not read. A Linkerd identity gives none.
- **A bound token is checked wherever Hodor accepts an access token as a credential**: UserInfo, the Authorization API and the SCIM server through the resource access use case, and the subject and actor tokens of token exchange. Each refuses a bound token that comes with no certificate, or with another, as it refuses an expired one: `invalid_token` at UserInfo, the Authorization API and SCIM, as RFC 8705, section 3, asks of a resource server, and `invalid_request` at token exchange, as for any token it refuses. A token that carries a `cnf` Hodor cannot read is refused too.
- **The administration interface accepts no OAuth access token**: only the access tokens of the credential context and API keys ([who may call it](../api/admin-api.md#who-may-call-it)). A bound token is refused there with or without its certificate, and is tested as such. When it accepts OAuth access tokens, in Phase 2, it checks them through the resource access use case and so checks `cnf`.
- **Introspection answers `cnf` and does not compare it.** The caller of introspection is a resource server asking about a token it was given, not the token's holder: the certificate that comes with its request is its own, and the holder's certificate reached the resource server, which compares it with the `cnf` introspection answers (RFC 8705, section 3.2). Comparing at introspection would refuse every bound token a resource server asks about. This is how this decision reads "checked by introspection" in the plan and the threat model.
- **Revocation does not compare either.** Only the client the token was issued to can revoke it, after proving who it is, and revoking gives nothing.
- **A refresh token of a public client is bound to the certificate of the request that redeemed the code**, and its family keeps that thumbprint. A refresh that comes with no certificate, or with another, is refused with `invalid_grant` and does not revoke the family: whoever presents it without the certificate is refused, and must not be able to end the client's family. A confidential client's refresh tokens are bound to its authentication already (RFC 8705, section 4); its family keeps no thumbprint, so that a workload whose certificate is renewed goes on refreshing, and each access token is bound to the certificate of its own request.
- **What is stored**: the client's setting, and the thumbprint of a public client's family. An access token's thumbprint is in the token, signed, and read from it where it is checked; the register of access tokens keeps none. Migration 0082.
- **The discovery document says `tls_client_certificate_bound_access_tokens: true`** (RFC 8705, section 3.3) when the operator names a header that forwards certificates, `client-cert` or `x-forwarded-client-cert`; it leaves the member out otherwise. The token type stays `Bearer`: RFC 8705 defines no other, and the token is presented as any other.

## Consequences

- A workload behind Istio gets bound tokens with Istio's default `X-Forwarded-Client-Cert`, which holds `Hash` and the names but no `Cert`, as long as the trust domain is checked by the mesh or the client proves who it is in another way.
- A bound client that is reached without the certificate header, because the operator named none or `l5d-client-id`, gets no token at all. Discovery does not advertise the binding then, and an administrator who sets it there sees the client refused at once.
- A resource server that checks tokens by itself must read `cnf` and compare it, as RFC 8705 asks; one that ignores it accepts a bound token without its certificate. Hodor cannot prevent that, and says so in [the access token](../architecture/contexts/oauth.md#the-access-token).
- A token exchange whose subject token is bound to another client's certificate is refused: the agent presenting it is not its holder. A person's token given to an agent is not bound, unless the person's client asked for it.
- A public client that loses its certificate loses its refresh tokens with it, and signs the person in again.

## Alternatives considered

- **Binding every token whose request came with a certificate.** Nothing to set. Set aside: a client that never asked would be refused by resource servers that check `cnf` once its proxy changes certificates, and RFC 8705, section 3.4, leaves the choice to the client.
- **Answering an unbound token when a bound client sends no certificate.** RFC 8705 allows it. Set aside: the client asked for the binding so that its tokens are worthless without the certificate.
- **Comparing `cnf` with the caller's certificate at introspection.** What the plan's wording could be read as. Set aside, as above: the caller is not the holder.
- **Keeping the thumbprint in the register of access tokens.** Would let introspection answer it without reading the token. Set aside: introspection reads the token anyway, and a column that repeats what the signature already guarantees adds nothing.
