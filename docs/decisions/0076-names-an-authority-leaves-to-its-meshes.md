# Decision 0076: A tenant's certificate authority may leave URIs unconstrained and permit DNS names besides its trust domains, so that Istio and Linkerd run under it together

Status: Accepted

## Context

[Decision 0062](0062-the-certificate-authority-of-a-tenant.md) writes the name constraints of a tenant's certificate authority for URIs, DNS names and addresses: for each trust domain `T`, the URI host `T` and the DNS name `T` are permitted, and every address is excluded. Every intermediate the authority signs carries the same DNS and address constraints, or narrower ones ([Decision 0071](0071-signing-intermediates.md)). A verifier that honors name constraints then refuses a certificate below the authority for any name outside the tenant's trust domains. Hodor reads the URI constraints itself, since `rustls-webpki`, which it checks paths with, refuses every URI below an authority that constrains URIs.

The demonstration of Milestone 12 (Issue-119) puts an Istio cluster and a Linkerd cluster under one tenant's root and has a workload of the first call a workload of the second over mutual TLS. It found two things those constraints break.

**Linkerd's proxy refuses every SPIFFE identity under an authority that constrains URIs.** It checks the certificate a caller presents with `rustls-webpki`, given the trust anchors as they are, name constraints included. It refused the Istio workload's certificate, `spiffe://east.acme.example/ns/payroll/sa/payroll`, with the alert `certificate_unknown`, although the certificate chains to the trust anchor and its URI is within the anchor's constraints. Tried on Linkerd edge-26.10.2 with certificates made by OpenSSL, the same proxy:

| The caller's certificate | Under a root that constrains | Linkerd's proxy |
|---|---|---|
| A SPIFFE identity, a URI | URIs, DNS names and addresses | Refused |
| The same SPIFFE identity | DNS names and addresses only | Accepted, `l5d-client-id` the SPIFFE identity |
| A DNS name | URIs, DNS names and addresses | Accepted |

Linkerd works on its own, its identities being DNS names under the trust domain, but no Linkerd mesh of the tenant accepts an identity of its Istio meshes, of its SPIRE servers, or of anything else that names workloads by SPIFFE URIs. Any other verifier on `rustls-webpki` refuses them the same way, an application of the tenant that checks its callers with `rustls` among them.

**Istio's control plane serves under the mesh's intermediate, by names outside every trust domain.** istiod signs its own serving certificate with the intermediate in `cacerts`, for `istiod.istio-system.svc`, `istio-pilot.istio-system.svc` and `istiod-remote.istio-system.svc`. The Kubernetes interface, calling istiod's sidecar injection, refused it: `DNS name "istio-pilot.istio-system.svc" is not permitted by any constraint`. No pod of an injected namespace could be made again, and the sidecars could not reach istiod either. A trust domain is never `istio-system.svc`, so no choice of trust domains lets Istio run under the authority.

## Decision

### The authority chooses whether its name constraints hold URIs

An authority is created with `uri_constraints`, `true` unless the administrator says otherwise:

- **`true`**: the URI constraints of Decision 0062: for each trust domain, the URI host permitted.
- **`false`**: no URI subtree. A certificate below it may name any URI.

### The authority may permit DNS names besides its trust domains

An authority is created with `additional_dns_names`, none unless the administrator gives them: at most ten DNS names, none twice and none a trust domain of the authority, such as `istio-system.svc`. Each is permitted as a DNS name after the trust domains, in the authority's own certificate, or its certificate signing request for an intermediate, and in every intermediate it signs:

- **A request's DNS names** may be within a trust domain or within an additional DNS name. Its URIs must still have a trust domain as their host: an additional DNS name is never a trust domain, Hodor adds no trust domain for it and never trusts a SPIFFE identity under it.
- **A request's name constraints** may narrow to names within either.
- **An intermediate that does not narrow** permits the trust domains and the additional DNS names.
- **An intermediate authority's certificate** may permit DNS names within either.

### What does not change

Both are chosen once, when the authority is created, since they are written into its certificate: every answer about the authority says them, its name constraints show what they permit, and the event `keys.authority_created` records them. The intermediates never carry a URI constraint, as before, and every address is still excluded. Hodor's own chain checking reads the URI constraints of an anchor that has them, and finds none on one that has not.

### What still keeps a SPIFFE identity to the tenant's trust domains

Without URI constraints, a verifier no longer refuses a certificate below the authority for a URI outside the tenant's trust domains. What still holds:

- **Hodor signs only within them.** Every URI of an intermediate's request must have a trust domain as its host, its DNS names be within the trust domains or the additional DNS names, its name constraints only narrow, and its key and lifetime are bound ([signing intermediates](../architecture/contexts/keys.md#signing-intermediates)).
- **Hodor trusts a SPIFFE identity only under its own trust domain.** A certificate is checked against the bundle of the trust domain its identity names, found by that name in the tenant alone. A certificate under the authority naming a trust domain the authority does not hold is checked against that trust domain's bundle, if the tenant has one, and refused unless that bundle trusts it.
- **The meshes match identities themselves.** Istio and Linkerd authorize a caller by the identity it presents, which an authorization policy names in full, trust domain included.

What is lost is the refusal by a third party that trusts the tenant's root and relies on the root alone to keep URIs within the tenant's trust domains, and, for each additional DNS name, the refusal of a certificate for a name under it by a mesh other than the one meant: every Istio cluster of the tenant names its istiod `istiod.istio-system.svc`. A tenant whose meshes all honor URI constraints keeps them; one with a Linkerd mesh that must accept the SPIFFE identities of its other meshes leaves them out. A tenant with an Istio mesh permits `istio-system.svc`, or the namespace its istiod runs in.

## Consequences

- `keys.certificate_authority` has the columns `uri_constraints`, `true`, and `additional_dns_names`, empty, for every authority made before them, which keep the constraints they were made with.
- The administration interface takes and answers both; the OpenAPI document says what each is for.
- The demonstration of Milestone 12 creates its authority with `uri_constraints` `false` and `additional_dns_names` `["istio-system.svc"]`: istiod serves under Istio's intermediate, and the Linkerd mesh accepts the Istio workload's certificate.
- A tenant that wants Linkerd's proxies to accept its SPIFFE identities and URIs constrained for everyone else cannot have both from one root while `rustls-webpki` refuses URIs below an authority that constrains them. Should it read them one day, a new authority with `uri_constraints` `true` gives them back.

## Alternatives considered

- **No URI constraints for any authority.** The simplest. Set aside: a tenant whose verifiers all honor URI constraints would lose them for nothing, and authorities made before would differ from those made after.
- **Linkerd's trust anchors holding Istio's intermediate beside the root.** Linkerd's proxy would stop at the intermediate and never read the root's constraints. Set aside: the anchors would follow every renewal of every other mesh's intermediate, which is what one root is meant to end.
- **No DNS constraints, for an authority with an Istio mesh.** It would let istiod serve. Set aside: Linkerd's identities would no longer be kept to the trust domains, where a name of the control plane needs one more permitted name.
- **istiod's serving certificate from elsewhere**, cert-manager's `istiod-tls` as istio-csr uses it. Possible, and outside Hodor: the sidecars must then be told another root for istiod, and the injection webhook another authority, which is what one root is meant to spare the operator.
