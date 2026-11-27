# Decision 0061: Behind a mesh's proxy, the forwarded address is read only from the ingress gateways the operator names by their identity, and the chart puts Hodor in Istio or Linkerd with one value

Status: Accepted

## Context

[Issue-112](../product/epics.md#slice-inside-a-mesh-epic-32) makes Hodor run inside a service mesh with every client still limited apart (Requirement-Operations-08). [Decision 0029](0029-hodor-in-a-service-mesh.md#hodor-runs-inside-a-mesh-too) says how: the operator names the identities of the ingress gateways, and a forwarded address is read from the local proxy only when the caller's identity is one of them. [Decision 0056](0056-forwarded-client-identity.md) reads that identity from the one header the operator names, and lets `HODOR_FORWARDED_HEADER` be `none` until this is built.

What Hodor sees inside each mesh was not confirmed by research. It was tried on kind, with Kubernetes 1.37, Istio 1.31.4 and Linkerd edge-26.11.1, through an application that answers with the address of the connection and the headers it received:

| Where Hodor runs | The connection comes from | `X-Forwarded-For` a caller wrote | The caller's identity |
|---|---|---|---|
| Istio, with a sidecar | `127.0.0.6`, for every caller | Passed on unchanged | `X-Forwarded-Client-Cert` with one element, the sidecar's: `By`, `Hash`, `Subject` and `URI`, no `Cert`. One a caller wrote is not passed on, whether it came over mutual TLS or not |
| Istio, through its ingress gateway, to a sidecar | `127.0.0.6` | The gateway adds the address it received the request from at the end | `URI` is the gateway's own identity, `spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account` |
| Linkerd | The pod's own address, for every caller | Passed on unchanged | `l5d-client-id`, the caller's Linkerd identity. The proxy replaces one a caller wrote, and removes it when the caller is not in the mesh |
| Istio ambient, ztunnel only | The caller's own address | Passed on unchanged | None. `X-Forwarded-Client-Cert` and `l5d-client-id` a caller wrote are passed on unchanged |
| Istio ambient, behind a waypoint | The waypoint's address, for every caller that goes through it | Passed on unchanged; the waypoint adds nothing | None. The waypoint removes the `X-Forwarded-Client-Cert` a caller wrote and adds none |

Behind a waypoint, a caller outside the mesh, a sidecar and the ingress gateway reached the application directly, without the waypoint, unless the namespace was labelled `istio.io/ingress-use-waypoint`.

Decision 0029 leaves open how the identities are named, what an identity is matched against, what happens without one, how the setting fits with the trusted proxies and the forwarded header, and what the chart does for each mesh.

## Decision

- **One setting, `HODOR_GATEWAY_IDENTITIES`, names the ingress gateways.** Identities separated by commas, each a SPIFFE identifier, `spiffe://…`, read by the rule of a client's `spiffe_id`, or a Linkerd identity, read by the rule of a client's `linkerd_identity`. No prefix match, as for clients ([Decision 0029](0029-hodor-in-a-service-mesh.md#a-workload-proves-who-it-is-in-one-of-three-ways)). Empty by default, and then the forwarded address is read from every trusted proxy, as before.
- **When it names gateways, a forwarded address is read only from a gateway.** The connection must still come from a trusted proxy. The caller's identity is then the one Hodor already reads, from the nearest element of the header named in `HODOR_CLIENT_IDENTITY_HEADER`. When that identity is one of the gateways, the forwarded header is read as [the client address](../api/api-spec.md#the-client-address) says. Otherwise the client address is the connection's: with no identity header, with one that does not read, and with the identity of any other workload.
- **An identity is matched the way a client's is.** A SPIFFE identifier must be a URI of the forwarded certificate, or one of the URIs the proxy forwarded without it. A Linkerd identity must be the value of `l5d-client-id`, or a DNS name of the forwarded certificate. The names of a forwarded certificate are read by the cryptography adapter, as for a client.
- **The proxy's word is taken, and no bundle is asked.** The proxy that ended the gateway's mutual TLS checked its certificate against the mesh's authority. The gateway is not a client of any tenant, and the setting belongs to the installation, while trust domains belong to a tenant. Believing that proxy for the identity is what naming its address in `HODOR_TRUSTED_PROXIES` already does.
- **The server refuses to start when the gateways can never be recognized**: an identity that does not read, gateways named with no trusted proxy, with no header of the caller's identity, or with `HODOR_FORWARDED_HEADER=none`. It says when it starts which gateways it reads the forwarded address from.
- **A forwarded address that is not read is counted.** `hodor.http.forwarded_address.ignored` counts, by `reason`, `no_identity` or `not_a_gateway`, the requests that came from a trusted proxy with a forwarded header, and whose header was not read because the caller is not a gateway.
- **The chart puts Hodor in a mesh with one value, `mesh.provider`, `istio` or `linkerd`.** It then:
  - asks for the server's and the worker's pods to be injected, whatever the namespace says;
  - keeps the operations port out of the proxy, so that the kubelet reaches the health checks directly in either mesh;
  - names the local proxy as a trusted proxy, beside `trustedProxies`: `127.0.0.6` and `::6` for Istio, the pod's own addresses for Linkerd, read from the pod through the downward interface;
  - names the identity header, `x-forwarded-client-cert` or `l5d-client-id`, unless `clientIdentityHeader` names one;
  - reads no forwarded address, `HODOR_FORWARDED_HEADER=none`, unless `gatewayIdentities` names gateways;
  - asks Istio to hold Hodor until its proxy is ready, for clusters without native sidecars;
  - injects the migration job too, unless `mesh.injectMigration` is false. A native sidecar, which both meshes inject by default on recent Kubernetes, stops when the job's own container ends; a classic one never does, and the job then never completes;
  - lets connections to the ports in `mesh.skipOutboundPorts` bypass the proxy;
  - opens the proxy's own inbound port in the network policy where the mesh needs it: `4143` for Linkerd.
- **Istio's ambient mode is not a value of the chart.** Hodor's pods need nothing injected. ztunnel keeps the caller's address, so the gateway is named by its address range, as an ingress controller outside a mesh is, and the network policy admits the gateway's namespace on port 15008 too. No identity header reaches Hodor in ambient mode, so gateways cannot be named by identity there. A waypoint in front of Hodor is never a trusted proxy.

## Consequences

- Behind a gateway each client has a limit of its own, and a workload of the mesh that calls Hodor directly, to get a token with its own identity for instance, is known by the local proxy's address. Every such workload shares one limit on sign-in attempts, as every caller behind a sidecar did with `none`.
- An installation that names no gateway is answered as before. The chart's defaults do not change outside a mesh.
- A caller outside the mesh that reaches Hodor's sidecar in plain text, which Istio's permissive mode allows, forwards no identity, so its forwarded address is never read.
- The gateways are named per installation, not per tenant: one ingress gateway serves every tenant.
- A gateway is believed for every address it forwards. Whatever is in front of it must be named in `HODOR_TRUSTED_PROXIES` too, by its address, as before.
- In ambient mode, a workload the network policy admits can choose its own address if the pod range is a trusted proxy. The installation guide says to admit only the gateway, or to run Hodor's own pods with a sidecar, which Istio allows beside ambient workloads.
- What was tried is the table above, and the chart installing Hodor in each mesh, where each client of the gateway was limited apart and a workload forging its address was not, on kind. Other versions, a cluster of several nodes, a network plugin other than kind's and a real ingress in front of Linkerd were not tried; the service mesh guide (Issue-113) tries the rest.

## Alternatives considered

- **Naming the gateways by their addresses.** What Issue-81 does outside a mesh. Set aside: behind a sidecar every caller comes from the same local address, which is the problem this solves.
- **Checking the gateway's certificate against a trust domain's bundle.** Stricter. Set aside: trust domains belong to tenants and the gateway serves all of them, and the local proxy checked the certificate already.
- **Matching gateways by a prefix, such as every service account of the gateway's namespace.** Shorter to write. Set aside for the reason clients are matched exactly: one prefix would let every workload of that namespace in.
- **Reading the forwarded address from every caller in the mesh, and ignoring only callers outside it.** Set aside: any workload of the mesh could then choose its own address.
- **A value of the chart per setting, with no `mesh.provider`.** Possible already with `server.extraEnvironment` and `server.podAnnotations`. Set aside: the address of the local proxy, the identity header and the ports to open differ per mesh, and getting one wrong lets workloads choose their address or stops the probes.
