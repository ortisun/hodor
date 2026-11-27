# Decision 0078: `mesh.provider` puts every pod of the release in the mesh, and the network policy opens each one's ports to its own callers

Status: Accepted

## Context

[Decision 0061](0061-gateway-identities.md) gave the chart one value, `mesh.provider`, that puts Hodor's server, worker and migration job in Istio or Linkerd. It left out the two binaries the chart can install beside them, [`hodor-ext-authz`](../operations/hodor-ext-authz.md) and [`hodor-cert-manager-issuer`](../operations/hodor-cert-manager-issuer.md), although both prove who they are to Hodor with their mesh identity and so cannot work outside the mesh Hodor is in. The operator had to label the namespace for Istio or set each one's `podAnnotations` for Linkerd, and the service mesh guide listed it as missing.

Preparing the demonstration of Milestone 11 ([Issue-114](../product/epics.md#slice-inside-a-mesh-epic-32)) found two faults in the network policy the chart writes beside a mesh:

- **With Linkerd, the callers of `hodor-ext-authz` were refused.** Every connection between two of Linkerd's proxies arrives on port 4143, whatever port it is for. One policy applied to every pod of the release, and it opened 4143 to `networkPolicy.ingressFrom`, the callers of Hodor's public port, and not to `extAuthz.networkPolicy.ingressFrom`, the proxies of the protected applications. An operator who named the two lists apart had every check refused, and one who named the applications in the first list let them reach Hodor's own port too.
- **`hodor-ext-authz` and `hodor-cert-manager-issuer` could not reach the servers once `networkPolicy.ingressFrom` named anyone.** The policy let their pods out to the servers' public port, but let in only the peers of `ingressFrom`, which name other namespaces.

## Decision

- **`mesh.provider` puts every pod of the release in the mesh**: the server, the worker, the migration job unless `mesh.injectMigration` is false, `hodor-ext-authz` and `hodor-cert-manager-issuer`. Each gets what the server gets: the label or annotation that injects the proxy, the operations port, where the health checks are, kept out of the proxy, Istio asked to hold the process until its proxy starts, and the ports of `mesh.skipOutboundPorts` let past the proxy. The annotations given in `extAuthz.podAnnotations` and `certManagerIssuer.podAnnotations` win over the chart's, as `server.podAnnotations` does.
- **The network policy opens each component's ports to its own callers.** One policy still applies to every pod of the release, opens the servers' public port to `networkPolicy.ingressFrom`, `hodor-ext-authz`'s gRPC port to `extAuthz.networkPolicy.ingressFrom`, and writes the way out. With `mesh.provider: linkerd`, two more open port 4143: one on the servers' pods to `networkPolicy.ingressFrom`, one on `hodor-ext-authz`'s pods to `extAuthz.networkPolicy.ingressFrom`. Port 4143 stays closed on the worker, the job and the issuer, which nothing calls.
- **The release's own pods reach the servers.** When `networkPolicy.ingressFrom` names peers, the pods of `hodor-ext-authz` and of `hodor-cert-manager-issuer` of the same release are added to them, when each is installed. When it names none, anyone in the cluster may connect already. With `networkPolicy.egress.enabled` and Linkerd, the way out of those pods to the servers opens port 4143 beside the public port.

## Consequences

- Turning on `mesh.provider` and `extAuthz.enabled` is enough for `hodor-ext-authz` to get its tokens with its mesh identity. The namespace needs no label, so the stand-ins of [trying the chart](../operations/install-on-kubernetes.md#trying-the-chart-on-a-cluster-of-your-own), a database or a mail server that a sidecar would hold up, stay out of the mesh.
- `hodor-cert-manager-issuer` installed alone, with `certManagerIssuer.only`, joins the mesh `mesh.provider` names in its own namespace, where it must reach a Hodor of that mesh with its identity, or use `private_key_jwt`.
- A release with Linkerd and the network policy on holds up to three network policies instead of one. They add to each other, as Kubernetes's policies do.
- Nothing changes outside a mesh, or with the network policy off.

## Alternatives considered

- **Leave the two binaries to their `podAnnotations`.** Set aside: both must be in the mesh to work at all, and Istio's label is a label, which `podAnnotations` cannot set.
- **Open port 4143 on every pod to both lists.** Set aside: whoever may call one would reach the other through it, the protected applications Hodor's public port and Hodor's callers `hodor-ext-authz`, which is what naming two lists is meant to stop.
