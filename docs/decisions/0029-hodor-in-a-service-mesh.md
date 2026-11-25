# Decision 0029: Hodor accepts the mesh's identities and issues none to workloads; proxies check its tokens and ask its decisions through `hodor-ext-authz`; Linkerd gets policies written from Hodor's roles

Status: Proposed (requested by the project owner)

## Context

[Decision 0028](0028-what-0.4.0-holds.md) puts Hodor in a service mesh for 0.4.0. A mesh's proxies end mutual TLS between workloads, and in most meshes they can also check a token and ask an outside service for a decision. What each mesh offers decides what Hodor can rely on. As found in November 2026:

| Mesh | Workload identity | Checks a JWT | Asks an outside decision | What the application behind the proxy sees |
|---|---|---|---|---|
| Istio, with sidecars | `spiffe://<trust domain>/ns/<namespace>/sa/<service account>` | `RequestAuthentication` | Envoy external authorization: `extensionProviders` and an `AuthorizationPolicy` with `action: CUSTOM` | The peer is always `127.0.0.6`. `X-Forwarded-For` passes unchanged. `X-Forwarded-Client-Cert` names the caller |
| Istio, ambient | The same | At a waypoint | At a waypoint | The caller's own address, kept by ztunnel |
| Consul | `spiffe://<id>.consul/.../svc/<service>` | `jwt-provider` with intentions | The `builtin/ext-authz` extension | `X-Forwarded-For` unchanged; `X-Forwarded-Client-Cert` names the caller |
| Envoy Gateway (a gateway, not a mesh) | — | `SecurityPolicy` `jwt` | `SecurityPolicy` `extAuth`, with context per route | Adds the address it received the request from to `X-Forwarded-For` |
| Linkerd | A DNS name, `<service account>.<namespace>.serviceaccount.identity.linkerd.<trust domain>`, and no URI in the certificate. SPIFFE identifiers only for workloads outside Kubernetes, through SPIRE | No | No | The peer is the proxy. `X-Forwarded-For` unchanged. `l5d-client-id` holds the caller's identity, and the proxy removes any value a caller sent |

Kuma, Cilium and the other meshes are left out of this decision. Kuma checks neither tokens nor outside decisions without patching Envoy, its new identity model is experimental, and how it forwards addresses and certificates was not confirmed. A mesh built on Envoy that forwards `X-Forwarded-Client-Cert` and speaks Envoy's external authorization should work the same way as Istio and Consul, but none was tried.

Three facts shape the design:

- **Every mesh based on Envoy passes the caller's certificate in `X-Forwarded-Client-Cert`, not in the `Client-Cert` header of RFC 9440.** Envoy has an RFC 9440 filter only as an alpha contribution that the meshes do not ship.
- **Linkerd checks neither tokens nor an outside decision**, and the requests for both are still open in its project. What it offers is its own policy: `Server`, `HTTPRoute`, `AuthorizationPolicy`, `MeshTLSAuthentication` and `NetworkAuthentication`, matching callers by identity, by service account or by address.
- **Behind a sidecar, every caller arrives from the same local address and the forwarded address is not checked by anyone.** The rule of [the client address](../api/api-spec.md#the-client-address) trusts a proxy by its address, and that is not enough here: naming the sidecar's address would let any workload of the mesh choose its own address.

The specification of SPIFFE client authentication is an Internet-Draft of the OAuth working group, [draft-ietf-oauth-spiffe-client-auth-03](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-spiffe-client-auth-03). It defines the methods `spiffe_jwt` and `spiffe_x509`. A JWT-SVID's `aud` must be exactly the issuer, which for Hodor is the tenant's issuer, `https://{host}/t/{slug}`. It does not require `jti`.

## Decision

### Hodor accepts the mesh's identities and issues none to workloads

The mesh, or SPIRE, keeps issuing and rotating workload certificates. Hodor never signs a workload's own certificate. The optional authority of [Decision 0030](0030-optional-certificate-authority.md) signs only the intermediates of a tenant's meshes.

### A workload proves who it is in one of three ways

Each way authenticates a client of a service account ([Milestone 8](../product/epics.md#milestone-8-workloads-agents-and-webhooks)) at the token, introspection and revocation endpoints. **Each client is bound to exactly one identity.** The prefix match that the draft allows, with `/*`, is not accepted in 0.4.0: one wildcard would let every workload of a namespace in.

| Way | Method | Where it comes from | What is checked |
|---|---|---|---|
| A JWT-SVID as client assertion | `spiffe_jwt` (the draft) | SPIRE, Istio, or any issuer of JWT-SVIDs | Signed by a key of the trust domain's bundle; `sub` is the client's SPIFFE identifier; `aud` is exactly the tenant's issuer; not expired; not presented before, remembered by its hash until it expires, since `jti` may be absent |
| The certificate the caller presented in mutual TLS, as the proxy that ended it forwards it | `spiffe_x509` (the draft) and `tls_client_auth` (RFC 8705) | `Client-Cert` and `Client-Cert-Chain` (RFC 9440), or `X-Forwarded-Client-Cert` (Envoy: Istio, Consul) | Read only from a trusted proxy. The client's identifier is in the certificate's URI or DNS name. The chain is checked against the trust domain's bundle when the proxy forwards the certificate; when it forwards only the identity, the proxy's own check is relied on, and only for a trust domain marked as checked by the mesh |
| The identity Linkerd's proxy asserts | `linkerd_identity`, Hodor's own name, not registered anywhere | `l5d-client-id`, from the Linkerd proxy of Hodor's own pod | Read only from that proxy; the value is the client's Linkerd identity, exactly |

- **`X-Forwarded-Client-Cert` is read from its nearest element.** Istio's sidecars add their element after whatever the caller sent. The element the local proxy added is the last one, and the elements before it are never believed, as with [the forwarded address](../api/api-spec.md#the-client-address).
- **Only one header is read, the one the operator names.** None is read by default, so a header a client invents is never believed.
- **A token can be bound to the certificate** (`cnf` with `x5t#S256`, RFC 8705), when the certificate or its hash reaches Hodor. Envoy's `Hash` element is the SHA-256 of the certificate, the same value written in another encoding. A token issued through `linkerd_identity` cannot be bound, since Linkerd forwards no certificate.
- **Trust domains belong to a tenant** (Requirement-Workload-04). Each one has a name and a bundle, uploaded by an administrator or fetched from a SPIFFE bundle endpoint (the `https_web` profile) through the guarded outbound client and refreshed by the worker, or is marked as checked by the mesh. A trust domain's name may be used by two tenants, since every cluster's default is `cluster.local`. Bindings are per tenant, so neither tenant can reach the other's clients.

### The proxies check Hodor's tokens themselves

Each tenant is one issuer with its own key set. A proxy checks a tenant's access tokens as any resource server does. Istio uses `RequestAuthentication`, Consul `jwt-provider`, and Envoy Gateway `SecurityPolicy`. Nothing changes in Hodor for this. The [service mesh guide](../product/epics.md#milestone-11-hodor-in-a-service-mesh) shows each one.

The proxy accepts a revoked token until it expires, five minutes by default. [Decision 0004](0004-token-formats.md) accepts that window for every resource server that checks tokens by itself.

### Decisions are asked through `hodor-ext-authz`, a binary of its own

`hodor-ext-authz` serves Envoy's external authorization protocol over gRPC and asks [the Authorization API](../api/api-spec.md#authorization-api). It is a binary of the workspace, built and released with Hodor, and runs in the mesh next to the proxies, not inside `hodor-server`.

- **It holds no decision of its own.** It maps a request to `evaluate` and answers what Hodor decided.
  - **The subject** is the token's `sub` that the proxy checked and passed as metadata. With no token, it is the caller's identity (`source.principal`), which Hodor resolves to the service account bound to it.
  - **The resource and the action** come from route rules in its configuration: a method and a path pattern give a resource type, an identifier taken from the path, and an action. Where the proxy can send context per route (Envoy Gateway, Envoy itself), that context names them instead.
  - **The application asked about** is chosen by the destination's identity (`destination.principal`). The adapter holds one client per protected application, because the Authorization API answers only about the caller's own resource server.
- **It proves who it is to Hodor with its own mesh identity**, through one of the three ways above. It holds no secret.
- **It answers denied whenever it cannot get an answer**, and the guides set the proxy's own failure mode to deny. Failing open stays what it is today: a choice per action of the binding, made in Hodor and recorded there.
- **Every decision is recorded by Hodor**, as for any caller of the API, with the client that asked.
- **It caches nothing in 0.4.0.** Its latency is measured against the target for Open Policy Agent sidecars, 15 ms at the 99th percentile, before a cache is considered.

### Linkerd gets three paths, since it can ask no outside decision

1. **At the edge: a gateway in front.** Envoy Gateway checks the token and asks `hodor-ext-authz`, then sends the request into the Linkerd mesh.
2. **Between workloads, coarse: Linkerd policies written from Hodor's roles.** `hodor-cli mesh linkerd-policy` writes, for one application, the `MeshTLSAuthentication` and the `AuthorizationPolicy` that let in only the Linkerd identities of the service accounts that hold a role on the application's resource server. It writes them; it does not apply them. The operator applies them, by hand or through the tool that deploys their cluster, and the command says what changed since the last run.
3. **Between workloads, fine-grained: the application asks.** The application reads `l5d-client-id`, which its own Linkerd proxy wrote, and calls the Authorization API itself. The guide shows how.

### Hodor runs inside a mesh too

- **A forwarded address is believed from the local proxy only when the caller is a named gateway.** The operator names the identities of the ingress gateways (Requirement-Operations-08). The forwarded address is read only when the request came through the local proxy and the caller's identity, taken from `X-Forwarded-Client-Cert` or `l5d-client-id` as above, is one of them. Any other caller is known by the connection's address, so every caller that does not come through a gateway shares one limit.
- **Until that is built,** the [installation on Kubernetes](../operations/install-on-kubernetes.md) tells an operator not to name the sidecar's address as a trusted proxy. Instead they exclude Hodor's port from the sidecar's inbound interception, so that the ingress controller reaches Hodor directly and the pod range rule holds, or they use Istio's ambient mode, where the caller's address is kept.
- **Probes, egress and network policy** are written down for Istio and Linkerd. The probes stay on the operations port. Identity providers and webhooks are reached through the mesh's egress. The network policy keeps admitting only the gateway.

## Consequences

- A workload in Istio or Consul gets a token from Hodor with no secret at all: its sidecar already presents its certificate. A workload in Linkerd gets one the same way when Hodor runs in the same Linkerd mesh. A workload under SPIRE gets one from its JWT-SVID, in any mesh or in none.
- `linkerd_identity` is a method of Hodor's own and is not standardized. It is advertised in the metadata, and a client library that does not know it uses a JWT-SVID instead.
- Relying on the proxy's check of a certificate is relying on the mesh. It is allowed only for a trust domain an administrator marks as checked by the mesh, and only from the local proxy.
- The adapter is one more thing to deploy, scale and upgrade. In return the core keeps one contract for decisions, the Authorization API, and stays a decision point rather than a gateway, as the [product requirements](../product/product-requirements.md#5-non-goals) say.
- Linkerd's coarse policies trail Hodor's roles until the command is run again. The guide says so, and the fine-grained path does not trail.
- SPIFFE client authentication follows a draft. A change of the draft is a change to Hodor, stated in the changelog.

## Alternatives considered

- **Answering Envoy's external authorization inside `hodor-server`.** One hop less. Set aside because it adds a second public contract for decisions to the core, ties the server's releases to Envoy's protocol, and puts the hop to the mesh inside the server's failure domain.
- **Letting the proxies ask Open Policy Agent directly, with the bundles Hodor builds.** Fast, and the `opa-envoy-plugin` exists. Set aside because those decisions would never reach Hodor's [record of decisions](../architecture/contexts/authorization.md#the-record-of-decisions), and the input would not be the one Hodor builds and masks.
- **A controller that applies Linkerd policies as roles change.** Policies would never trail. Set aside for 0.4.0 because Hodor would need to write into every cluster with rights over its policies. Writing them for the operator to apply comes first, and a controller can follow.
- **Accepting only RFC 9440 for certificates from a proxy.** Simpler and standard. Set aside because no mesh sends it today.
- **Prefix matches of SPIFFE identifiers**, as the draft allows. Set aside for 0.4.0: an exact identifier per client is easier to review, and a prefix can be added later without breaking anything.
