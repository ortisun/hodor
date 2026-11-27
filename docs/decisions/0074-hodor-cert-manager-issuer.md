# Decision 0074: `hodor-cert-manager-issuer` signs approved requests for an authority through the signing operation, which takes an access token for the audience of the certificate authority

Status: Accepted

## Context

[Decision 0030](0030-optional-certificate-authority.md#how-a-mesh-gets-its-intermediate) gives a mesh two ways to get its intermediate from the tenant's certificate authority: by hand, which [Decision 0071](0071-signing-intermediates.md) built, and through `hodor-cert-manager-issuer`, an outside issuer for cert-manager, "a binary of the workspace written with the Kubernetes client for Rust", that "signs through Hodor the approved `CertificateRequest`s addressed to it, and only requests for an authority", and "proves who it is to Hodor with its own mesh identity or a signed assertion, through a client holding only the scope to ask for signatures". Decision 0071 gave signing a permission, a role and a scope of its own, `certificate-authority:sign`, `certificate_signer` and the same scope for API keys, and left to Issue-118 the access token of such a client and the signing operation taking it.

Issue-118 has to settle what those decisions leave open:

- what the issuer is in the cluster: which resources cert-manager's requests name, where the issuer learns Hodor's address, its tenant and its client, and what it may read and write;
- which `CertificateRequest`s it sends to Hodor, and what it writes back when it does not, when Hodor refuses and when Hodor cannot be reached;
- how its client proves who it is, and how the administration interface, which until now took no access token of Hodor's token endpoint, takes one for this one operation.

## Decision

### A binary of its own, which knows Hodor only over HTTP

`hodor-cert-manager-issuer` is a binary of the workspace, `apps/hodor-cert-manager-issuer`, with an image of its own, `ghcr.io/ortisun/hodor-cert-manager-issuer`, and a part of the chart, as `hodor-ext-authz` has ([Decision 0058](0058-hodor-ext-authz.md)). It depends on no crate of the workspace but `hodor-observability`, which the architecture test enforces: it reaches Hodor through the token endpoint and the signing operation of the administration interface, as any program of the tenant would. It reaches Kubernetes with `kube` and `k8s-openapi`, the Kubernetes client for Rust, and reads cert-manager's resources as JSON of its own types, so that no generated code of cert-manager is needed.

### Two kinds of issuer, whose resources hold nothing but their name

cert-manager hands a `CertificateRequest` to an outside issuer by the group and kind its `issuerRef` names. The issuer defines two kinds in the group `hodor.ortisun.github.io`, version `v1alpha1`: `HodorIssuer`, which serves the requests of its own namespace, and `HodorClusterIssuer`, which serves the requests of every namespace. The group is under the address of Hodor's documentation, which the project holds.

**Their `spec` is empty.** Hodor's address, the tenant and the client are the configuration of the issuer's deployment, not of the resources: the client is the deployment's identity, its key or its mesh identity, and a resource naming another tenant or client would ask the deployment to act as something it is not. One deployment serves one tenant, through one client. A resource is a place cert-manager can name, and a way to keep a namespace's requests to the namespace's own issuer. Its `status` holds a `Ready` condition, which the issuer sets every minute from whether Hodor gave it an access token on its last try.

### Only approved requests for an authority reach Hodor

The issuer watches every `CertificateRequest` of the cluster and takes only those whose `issuerRef` names one of its two kinds in its group. Of those, in order:

1. **A request that is already finished is left alone**: one whose `Ready` condition is `True`, or `False` with the reason `Failed` or `Denied`. A request is never signed twice by the issuer, and a refused one is never sent again; cert-manager makes a new request when it tries again.
2. **A denied request** (`Denied` is `True`) is marked `Ready` `False` with the reason `Denied`, and its failure time set. It is never sent.
3. **A request that is not approved** (no `Approved` condition that is `True`) is left alone until it is. It is never sent.
4. **A request whose issuer does not exist**, a `HodorIssuer` of that name in the request's namespace or a `HodorClusterIssuer` of that name, is marked `Ready` `False` with the reason `Pending`, and looked at again later. It is never sent.
5. **A request that does not ask for an authority** (`spec.isCA` is not `true`) is marked `Ready` `False` with the reason `Failed`, and its failure time set. It is never sent: the authority signs the intermediates of meshes and never a workload's own certificate, and Hodor would refuse it anyway with `keys.intermediate_not_an_authority`.
6. **Otherwise it is sent**, with its certificate signing request and its lifetime: `spec.duration` in whole days, rounded down and at least one; with no duration, none, and Hodor gives the authority's bound.

Approving is not the issuer's. cert-manager's own approver approves the requests of the issuers it is allowed to approve for, and approver-policy approves those its policies allow; the chart can give cert-manager's approver that permission for Hodor's two kinds, and gives it to nobody unless asked.

### What it writes back

- **Signed**: `status.certificate` holds the intermediate followed by the chain above it, without its last certificate, and `status.ca` holds that last certificate, the tenant's root: the root authority's own certificate, or the top of the chain an administrator installed for an intermediate authority. `Ready` is `True` with the reason `Issued`, and its message names the intermediate's identifier and serial number. cert-manager then writes `tls.crt` and `ca.crt` into the request's Secret, which Linkerd's identity issuer and Istio's `cacerts` read.
- **Refused by Hodor**, with any status of the `4xx` range other than `401`, `403`, `408` and `429`: `Ready` `False` with the reason `Failed`, the failure time set, and the message naming Hodor's code and its detail, such as `keys.intermediate_name_outside_trust_domains: spiffe://other.example.com/… is outside the authority's trust domains`. The request is finished; cert-manager tries again with a new one after its own wait.
- **Hodor not reached**, or answering `5xx`, `408` or `429`, or the issuer's own client refused, at the token endpoint or with `401` or `403` at the signing operation: `Ready` `False` with the reason `Pending`, the message saying what failed, and the request looked at again after a wait that doubles from 10 seconds to 5 minutes. Nothing is finished: a role given late or Hodor coming back lets the request through without anyone making it again.

Each change of a request's status is written as a merge patch of the status that names the version it was read at, so that two writes never cross.

### Its client proves who it is with its key or its mesh identity

The issuer asks the tenant's token endpoint for an access token with the client credentials grant, `resource=urn:hodor:certificate-authority` and `scope=certificate-authority:sign`, and keeps it until 30 seconds before it expires, or until the signing operation answers `401`. Its client acts as a service account that holds the built-in role `certificate_signer`, and proves who it is in one of two ways, which the configuration names:

- **`private_key_jwt`**: an assertion signed with ES256 by a key of the client, read from a file the chart mounts from a Secret, with `aud` the tenant's issuer, a lifetime of one minute and a `jti` of 16 random bytes.
- **`forwarded`**: nothing but `client_id`. The issuer's sidecar presents its certificate to Hodor's, and Hodor reads the identity the proxy in front of it forwards ([Decision 0056](0056-forwarded-client-identity.md)): the client uses `spiffe_x509`, `tls_client_auth` or `linkerd_identity`, and holds no secret anywhere.

`spiffe_jwt` is not offered: a JWT-SVID is used once ([Decision 0055](0055-spiffe-jwt-client-authentication.md)), and the files the SPIFFE helpers write are read again until they are replaced. An API key works with the operation already, but is a bearer secret that lives as long as an administrator lets it, and is not what the issuer uses.

### The signing operation takes that access token, and no other operation does

`POST /certificate-authority/intermediates` of the administration interface takes, besides a person's access token and a workload's API key, an access token of the tenant's token endpoint:

- checked as every resource server of Hodor checks one, through the OAuth context's resource access use case: a published key of the tenant, the tenant's issuer, not expired, presented with its certificate when it is bound to one, in force in the register of access tokens, an enabled client of an enabled application;
- whose audience includes `urn:hodor:certificate-authority`, which a tenant opens by registering a resource server with that audience and the scope `certificate-authority:sign`, as for [the Authorization API](../architecture/contexts/authorization.md#who-may-ask);
- issued to a client that acts as a service account, as `principal_kind` says;
- holding the scope `certificate-authority:sign`;
- whose service account holds the permission `certificate-authority:sign` through its roles.

A token failing one of the first three is answered `401` `admin.not_authenticated`, as any credential that is not good here; one failing the last two `403` `admin.forbidden`. Every other operation of the administration interface, and every operation of the console interface, still refuses every access token of the token endpoint with `401`. What the token signs is recorded with the service account as the actor.

The audience is the authority's own, not one of the administration interface: a token for it is good at one operation, and naming the administration interface as an audience would invite more.

### One replica

The issuer keeps nothing but its access token, and a request it has signed is marked before it is looked at again. Two replicas could still both sign one request before either marks it, so the chart runs one, replaced with the `Recreate` strategy. Hodor would sign both, each recorded; nothing is trusted that the authority would not have signed anyway.

## Consequences

- A tenant renews its meshes' intermediates without anyone acting: Linkerd's identity issuer and Istio's `cacerts`, kept by cert-manager `Certificate`s whose issuer is a `HodorIssuer`, are signed again before they expire.
- cert-manager writes the basic constraints of an authority into a certificate signing request only with its feature gate `UseCertificateRequestBasicConstraints`, off by default in cert-manager 1.21; Hodor refuses a request without them ([Decision 0071](0071-signing-intermediates.md)). An installation turns the gate on, and the issuer's page says so. Hodor does not take `spec.isCA` instead: the request is what the mesh's key signed, and the issuer is not trusted to say more than it.
- The cluster holds no secret of Hodor's when the issuer proves who it is with its mesh identity, and only the client's own key otherwise, which can sign nothing but an assertion for that client.
- The administration interface takes access tokens of the token endpoint at one operation. The check is the one the Authorization API and the SCIM server already use, and the operation counts are unchanged.
- An installation runs the issuer in each cluster of meshes that renews through Hodor, which may not be where Hodor runs: the chart installs the issuer alone when asked.
- One replica means a renewal waits for the pod to be replaced if its node fails. Intermediates live days and are renewed long before they expire, so the wait is harmless.

## Alternatives considered

- **Hodor's address, the tenant and a Secret with the client's credentials in each issuer resource**, as cert-manager's sample outside issuer has it. One deployment could then serve several tenants. Set aside: whoever can write an issuer resource in a namespace could point the deployment's mesh identity at another tenant, and a tenant per deployment is what the client's single scope and role mean.
- **Signing every approved request**, and letting Hodor refuse what is not an authority. Set aside: Decision 0030 says the issuer never sends such a request, and a workload's own certificate request has nothing to do with Hodor.
- **Marking a request refused for want of a role as `Failed`.** Set aside: the request is right and the issuer's own access is wrong; once an administrator fixes it, the request goes through, where `Failed` would wait for cert-manager's next try, an hour later at first.
- **An audience for the whole administration interface, with scopes for its operations.** Set aside: it is the "OAuth access tokens with scopes" of Phase 2, for every operation, and needs a decision of its own.
- **cert-manager's library for outside issuers**, written in Go. Set aside: the workspace is Rust, and Decision 0030 names the Kubernetes client for Rust.
- **Leader election between replicas.** Set aside for now: one replica suffices for intermediates that live days.
