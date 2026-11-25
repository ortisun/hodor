# Decision 0056: A forwarded identity is read from the one header the operator names, bound to a client by its SPIFFE identifier or its Linkerd identity, and checked with `rustls-webpki` in the cryptography adapter

Status: Accepted

## Context

[Issue-107](../product/epics.md#slice-mutual-tls-epic-31) lets a workload prove who it is with the identity the proxy in front of Hodor forwards: the certificate it presented in mutual TLS, or the identity Linkerd's proxy asserts. [Decision 0029](0029-hodor-in-a-service-mesh.md#a-workload-proves-who-it-is-in-one-of-three-ways) says which headers, which methods, and that the chain is checked against the trust domain's bundle unless the trust domain is checked by the mesh. It leaves open:

- how the operator names the header, and how it fits with [the client address](../api/api-spec.md#the-client-address), which already trusts proxies by their address;
- how a client is bound to the identity it must present, and how the trust domain of that identity is found;
- whether a request must still name its `client_id`, which RFC 8705 requires and the SPIFFE draft (draft-ietf-oauth-spiffe-client-auth-03, section 3.3) makes optional;
- which library checks a chain of certificates, and in which crate;
- what checking a bundle's `x509-svid` element means, which [Decision 0042](0042-trust-domains.md#consequences) left to this issue.

## Decision

- **One setting names the header, `HODOR_CLIENT_IDENTITY_HEADER`**: `client-cert` (RFC 9440, with `client-cert-chain`), `x-forwarded-client-cert` (Envoy) or `l5d-client-id` (Linkerd). It is empty by default, and then no header is read. It is read only on a connection from a proxy named in `HODOR_TRUSTED_PROXIES`, the same trust as the client address, and only its nearest element, the last, which the proxy Hodor is connected to wrote. Nothing a caller wrote before it is read.
- **`HODOR_FORWARDED_HEADER` may be `none`.** A sidecar must be a trusted proxy for its identity header to be read, and a sidecar passes `X-Forwarded-For` as the caller wrote it ([Threat-Mesh-08](../security/threat-model.md#service-meshes-and-certificates)). With `none`, the sidecar is trusted for the identity and the client address stays the connection's.
- **A client is bound by one of two fields**: `spiffe_id`, the SPIFFE identifier [Decision 0055](0055-spiffe-jwt-client-authentication.md) gave clients of `spiffe_jwt`, the name the SPIFFE draft gives the client metadata; or `linkerd_identity`, a Linkerd identity. A client of `spiffe_x509` has a `spiffe_id`, a client of `linkerd_identity` has a `linkerd_identity`, and a client of `tls_client_auth` has exactly one of the two, matched against a URI or a DNS name of its certificate. The other methods, but `spiffe_jwt`, have neither. As for `spiffe_jwt`, a bound client acts as a service account, its principal, and each identity is bound to one client of a tenant at most.
- **The trust domain is read from the identity**: the host of a SPIFFE identifier, and the part after `serviceaccount.identity.<namespace>.` of a Linkerd identity. It is found through the keys context's `TrustDomainService`, which the token service already holds for JWT-SVIDs. Only the tenant's trust domain of that name is used, so a certificate chains only to the authorities of the identity's own trust domain, as the draft requires.
- **A request names its `client_id`.** The client is found by it, as for every other method and as Decision 0055 chose for a JWT-SVID, and its bound identity must then be the one forwarded. Finding the client by the identity alone, as the draft allows, is left for later.
- **The chain is checked by `rustls-webpki`, in `hodor-adapters-crypto`**, behind a port of the OAuth context, `CertificateCheck`. It is the path validation `rustls` uses, already in the dependency tree, with signatures made by `aws-lc-rs` as everywhere else in Hodor ([Decision 0008](0008-cryptography.md)). `x509-parser`, already a dependency of `hodor-saml`, reads the names of a certificate and the authority of a bundle's element. The OAuth context stays free of any X.509 library.
- **A bundle's `x509-svid` element trusts something only when its certificate is an authority that holds the element's key**: a certificate with the basic constraint of an authority whose public key is the element's. Any other element is passed over when a chain is checked, and trusts nothing.
- **The proxy's own check is relied on only for a trust domain of source `mesh`.** For such a trust domain, the identity is read from the forwarded certificate or from the names the proxy forwarded, and nothing is checked against a bundle, since it has none. For a trust domain with a bundle, a certificate must be forwarded and must chain to it; names alone are refused.

## Consequences

- Decision 0055's SPIFFE identifier is no longer for `spiffe_jwt` alone: `spiffe_x509` takes it too, and `tls_client_auth` may. The administration interface drops an identity the client's new method does not take, as it drops secrets and keys, where 0055 asked for it to be removed in the same change.
- An installation that names no header is answered as before, and the discovery document advertises the three methods only when a header is named: `tls_client_auth` and `spiffe_x509` for a certificate header, `linkerd_identity` for `l5d-client-id`.
- A proxy whose address is named in `HODOR_TRUSTED_PROXIES` is believed for both the client address and the identity. An operator who trusts a sidecar for the identity sets `HODOR_FORWARDED_HEADER` to `none` until the forwarded address can be read from named gateways only (Issue-112).
- A client sends `client_id` even with the SPIFFE method, which a client library that follows the draft may leave out. Such a request is refused with `invalid_client`.
- `rustls-webpki` refuses a chain through an authority that constrains URIs, since it does not read such constraints. SPIRE's authorities carry none; an authority that does, such as one Hodor will sign in Milestone 12, needs that support first.
- `rustls-webpki` is a direct dependency of the cryptography adapter. It was already compiled into the server through `rustls`.

## Alternatives considered

- **A second list of addresses for the proxies that forward identities.** Finer. Set aside: Issue-81 already says how a proxy is trusted, and two lists that disagree would be a mistake waiting to happen. `none` covers the one case where the two must differ.
- **One field, `identity`, whose meaning depends on the method.** Shorter. Set aside: the draft names `spiffe_id`, which `spiffe_jwt` already uses, and a field that holds a URI for one method and a DNS name for another is harder to read back.
- **Any of the tenant's trust domains as anchors for `tls_client_auth`.** What RFC 8705's PKI method would do with a list of authorities. Set aside: an authority of one trust domain could then vouch for a name of another.
- **`x509-parser` with its `verify` feature, or `x509-cert` with a path validation of Hodor's own.** Set aside: the first brings `ring`, the second would be the first path validation written in Hodor.
