# Hodor in a service mesh

This guide puts Hodor to work with a service mesh: Istio, with sidecars and in ambient mode, Linkerd, Consul, and Envoy Gateway in front of any of them. For each one it shows how to:

- **check Hodor's tokens** at the proxy, so that a request without a good token of the tenant never reaches the application;
- **ask Hodor's decisions** at the proxy, through [`hodor-ext-authz`](hodor-ext-authz.md) and [the Authorization API](../api/api-spec.md#authorization-api);
- **give workloads their identity at Hodor**, so that a service account gets tokens with no secret: a JWT-SVID, the certificate its proxy presents, or the identity Linkerd asserts;
- **run Hodor inside the mesh**, with each person behind the ingress gateway still limited apart.

Why Hodor fits a mesh this way is [Decision 0029](../decisions/0029-hodor-in-a-service-mesh.md): Hodor accepts the mesh's identities and issues none to workloads, the proxies check its tokens themselves, decisions are asked through a binary of their own, and Linkerd, which can ask no outside decision, gets policies written from Hodor's roles. What each mesh offers, as found in November 2026:

| | Checks Hodor's tokens | Asks Hodor's decisions | A workload proves who it is with | Hodor inside it |
|---|---|---|---|---|
| Istio, with sidecars | `RequestAuthentication` | `AuthorizationPolicy` of action `CUSTOM`, to `hodor-ext-authz` | Its sidecar's certificate, `spiffe_x509` or `tls_client_auth`; a JWT-SVID from SPIRE | `mesh.provider: istio` |
| Istio, ambient | At a waypoint | At a waypoint | A JWT-SVID from SPIRE. No identity reaches a Hodor without a sidecar | No value of the chart: `trustedProxies` and a network policy of your own |
| Linkerd | No | No. Envoy Gateway in front, policies written from roles, or the application asks | The identity its proxy asserts, `linkerd_identity`; a JWT-SVID from SPIRE | `mesh.provider: linkerd` |
| Consul | `jwt-provider` with intentions | The `builtin/ext-authz` extension, to `hodor-ext-authz` | Its proxy's certificate; a JWT-SVID from SPIRE | No value of the chart |
| Envoy Gateway, a gateway rather than a mesh | `SecurityPolicy` with `jwt` | `SecurityPolicy` with `extAuth`, to `hodor-ext-authz` | Nothing: the workloads behind it use their mesh's way | It is the gateway Hodor names |

## What ran each example

Not every example on this page has been run, and those that have were not all run the same way. Each section ends with a table saying, for each example, which of these it is:

| Mark | Meaning |
|---|---|
| **Continuous integration** | Run on every pull request against the images built from it, by [the demonstration of Milestone 10](quick-start.md#the-demonstration-of-milestone-10), `deploy/demo/workload_identity.py`, on a kind cluster with Istio 1.30.8 and its sidecars, SPIRE 1.15.5 and Hodor installed by its chart, or by [the demonstration of Milestone 11](quick-start.md#the-demonstration-of-milestone-11), `deploy/demo/service_mesh.py`, on a kind cluster with Istio 1.30.8, its sidecars and its ingress gateway, and on one with Linkerd edge-26.11.1 and Envoy Gateway 1.10.0 in front, Hodor and `hodor-ext-authz` installed in each by the chart with `mesh.provider` |
| **Rendered in continuous integration** | The chart is linted and rendered with these values on every pull request. Nothing is installed |
| **Tried by hand on kind** | Run once, on a kind cluster of one node with Kubernetes 1.37, while the feature was built, and written down in [the progress of Milestone 11](../product/progress.md#milestone-11--hodor-in-a-service-mesh) or [of Milestone 12](../product/progress.md#milestone-12--an-optional-certificate-authority-per-tenant). Istio 1.31.4, Linkerd edge-26.11.1, cert-manager 1.21.3. Not repeated since |
| **Tested against the real server** | A test of the workspace runs the real binaries against PostgreSQL, with the proxy played by the test, which writes the header a proxy would. No mesh |
| **Not tried** | Written from the mesh's own documentation. Check it against the version you run |

The demonstration of Milestone 11 ([Issue-114](../product/epics.md#slice-inside-a-mesh-epic-32)) runs the examples for Istio with sidecars and for Linkerd, and Envoy Gateway in front of Linkerd, on kind in continuous integration. Istio's ambient mode is not in it, and the demonstration of Milestone 12 ([Issue-119](../product/epics.md#slice-meshes-on-the-authority-epic-33)) runs the meshes under the tenant's certificate authority. Consul is not planned to run anywhere: Milestone 11 leaves meshes other than Istio and Linkerd out of continuous integration.

## What every mesh needs in Hodor

The examples use the tenant `acme`, whose issuer is `https://login.example.com/t/acme`, Hodor installed by [its chart](install-on-kubernetes.md) in the namespace `hodor` as the release `hodor`, and an application Orders whose workload runs in the namespace `shop` as the Kubernetes service account `orders`. Each tenant is one issuer with its own key set, at `https://login.example.com/t/acme/oauth2/jwks`.

- **To ask decisions**, the tenant opens the Authorization API, gives `hodor-ext-authz` a service account and one client per protected application, all bound to the adapter's mesh identity, and Orders a resource server whose roles decide. [Setting it up in Hodor](hodor-ext-authz.md#setting-it-up-in-hodor) lists each step.
- **To give workloads their identity**, the tenant trusts the mesh's trust domain ([trust domains](../architecture/contexts/keys.md#trust-domains)), and each workload's service account has a client bound to its identity, with no secret:

```bash
hodor-cli trust-domain add --tenant acme --name cluster.local --mesh
hodor-cli client add --tenant acme --application <application identifier> --name "Orders in the mesh" \
  --type confidential --grant client_credentials --principal <service account identifier> \
  --method spiffe_x509 --spiffe-id spiffe://cluster.local/ns/shop/sa/orders
```

`--mesh` marks the trust domain as checked by the mesh: Hodor believes the names the proxy in front of it forwards, which is what Istio and Linkerd forward. A trust domain given by its bundle, `--bundle-endpoint` or `--bundle-file`, is needed instead when the proxy forwards the whole certificate and you want Hodor to check it, and for JWT-SVIDs, whose signatures Hodor checks against the bundle. The methods and what each checks are in [an identity forwarded by a proxy](../architecture/contexts/oauth.md#an-identity-forwarded-by-a-proxy) and [checking a JWT-SVID](../architecture/contexts/oauth.md#checking-a-jwt-svid).

- **For a proxy to check tokens**, nothing changes in Hodor. The proxy reads the tenant's key set, which names a new key 24 hours before it signs anything (`HODOR_KEY_PUBLICATION_HOURS`), so a proxy that reads the set at least once a day never misses one. A revoked key is trusted by the proxy until it reads the set again.

### A JWT-SVID, in any mesh or in none

A workload under [SPIRE](https://spiffe.io/docs/latest/spire-about/) proves who it is with a JWT-SVID whose audience is the tenant's issuer, whatever mesh it runs in. Its client uses `spiffe_jwt`, and the tenant trusts SPIRE's trust domain by its bundle endpoint, which the worker fetches again as SPIRE's refresh hint says:

```bash
hodor-cli trust-domain add --tenant acme --name workloads.example.org --bundle-endpoint https://bundle.workloads.example.org
hodor-cli client add --tenant acme --application <application identifier> --name "Orders by its JWT-SVID" \
  --type confidential --grant client_credentials --principal <service account identifier> \
  --method spiffe_jwt --spiffe-id spiffe://workloads.example.org/ns/shop/sa/orders
```

Hodor reaches a bundle endpoint through its guarded outbound client, which refuses a private address, such as a Service of the cluster. Publish SPIRE's bundle endpoint at a public address, or upload its bundle with `--bundle-file` and replace it when SPIRE's keys change. The demonstration of Milestone 10 names its endpoint inside the cluster in `HODOR_OUTBOUND_DEVELOPMENT_HOSTS`, which nothing real should do.

The workload asks the SPIRE agent for a JWT-SVID and sends it as its client assertion:

```bash
spire-agent api fetch jwt -audience https://login.example.com/t/acme
```

```http
POST /t/acme/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=…&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-spiffe&client_assertion=<the JWT-SVID>
```

A JWT-SVID is used once: Hodor refuses one it has seen, so the workload fetches a fresh one for each token, and keeps the token until it expires. Hodor does not need to be inside a mesh for this.

| Example | What ran it |
|---|---|
| A JWT-SVID from the SPIRE agent, its trust domain by its bundle endpoint, kept current by the worker | **Continuous integration**, beside Istio's sidecars |
| A JWT-SVID presented twice, one of another trust domain, one for another tenant's issuer, each refused | **Continuous integration** |
| A JWT-SVID beside Linkerd, Consul or ambient mode | **Not tried**. Nothing of it depends on the mesh |

## Istio, with sidecars

### Checking Hodor's tokens

A `RequestAuthentication` names the tenant's issuer and key set. Name the audience of the application's resource server too, so that the proxy refuses a token for another application of the tenant before it asks anything. `hodor-ext-authz` refuses such a token as well, since its configuration names each application's audience ([Decision 0077](../decisions/0077-ext-authz-checks-the-audience.md)).

```yaml
apiVersion: security.istio.io/v1
kind: RequestAuthentication
metadata:
  name: orders
  namespace: shop
spec:
  selector:
    matchLabels:
      app: orders
  jwtRules:
    - issuer: https://login.example.com/t/acme
      jwksUri: https://login.example.com/t/acme/oauth2/jwks
      audiences:
        - https://orders.example.com
      forwardOriginalToken: true
      outputPayloadToHeader: x-hodor-token-claims
```

A request with a token that fails is refused by the proxy. A request with no token goes through, and Istio's own `AuthorizationPolicy` decides whether that is allowed. To refuse it at the proxy:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: orders-needs-a-token
  namespace: shop
spec:
  selector:
    matchLabels:
      app: orders
  action: DENY
  rules:
    - from:
        - source:
            notRequestPrincipals: ["*"]
```

Leave that policy out when other workloads call Orders with their mesh identity alone and `hodor-ext-authz` decides on it, as below.

### Asking Hodor's decisions

`hodor-ext-authz` runs in the mesh with an identity of its own, given by its Kubernetes service account, `hodor-ext-authz` for the release `hodor`: `spiffe://cluster.local/ns/hodor/sa/hodor-ext-authz`. Install it with the chart, beside Hodor:

```yaml
mesh:
  provider: istio
extAuthz:
  enabled: true
  tenant: acme
  token:
    header: x-hodor-token-claims
  applications:
    - destination: spiffe://cluster.local/ns/shop/sa/orders
      clientId: 0193f1c2-6a1d-7c55-b0c8-6b1f2c9d4e01
      audience: https://orders.example.com
      routes:
        - methods: [GET]
          path: /orders/{id}
          resourceType: order
          action: read
```

`mesh.provider` puts `hodor-ext-authz` in the mesh with Hodor's server, worker and migration job, so the namespace needs no label ([Decision 0078](../decisions/0078-every-pod-of-the-release-in-the-mesh.md)). Then name `hodor-ext-authz` as a provider in Istio's mesh configuration, and send every request for Orders to it:

```yaml
meshConfig:
  extensionProviders:
    - name: hodor
      envoyExtAuthzGrpc:
        service: hodor-ext-authz.hodor.svc.cluster.local
        port: 9191
        timeout: 2s
```

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: orders-through-hodor
  namespace: shop
spec:
  selector:
    matchLabels:
      app: orders
  action: CUSTOM
  provider:
    name: hodor
  rules:
    - {}
```

- **The application asked about** is the one whose `destination` is the identity of the workload the request is for, `destination.principal`, which Orders' sidecar fills with its own certificate's identity.
- **The subject** is the `sub` of the checked token, read from `x-hodor-token-claims` and believed only because it equals the claims of the bearer token the proxy forwarded. With no token, it is the caller's identity, which Hodor resolves to the service account bound to it.
- **Failing closed.** `hodor-ext-authz` answers denied on every failure, and Istio's own `failOpen` is `false` unless set, so a request is refused when `hodor-ext-authz` cannot be reached. Stopping Hodor denies every request.
- **Let only the proxies of the protected applications reach it**, with `extAuthz.networkPolicy.ingressFrom` naming the namespace `shop`.

`hodor-ext-authz` asks Hodor for its tokens with `client_id` alone. Its sidecar presents its certificate to Hodor's sidecar, which forwards the identity in `X-Forwarded-Client-Cert`, so every client of its configuration uses `spiffe_x509` with `spiffe://cluster.local/ns/hodor/sa/hodor-ext-authz` as its `spiffe_id`, in a tenant that trusts `cluster.local` as checked by the mesh.

### Giving workloads their identity at Hodor

A workload whose sidecar presents its certificate to Hodor's gets a token with its `client_id` alone. Istio's sidecar forwards the names and the `Hash` of the caller's certificate in `X-Forwarded-Client-Cert`, and by default not the certificate itself, so:

- the client uses `spiffe_x509`, or `tls_client_auth`, with the workload's identity, `spiffe://cluster.local/ns/shop/sa/orders`;
- the tenant trusts `cluster.local` as checked by the mesh (`--mesh`);
- Hodor reads the header from its own sidecar only: `mesh.provider: istio` sets that up, or `trustedProxies: [127.0.0.6]`, `forwardedHeader: none` and `clientIdentityHeader: x-forwarded-client-cert`, as the demonstration of Milestone 10 does in `deploy/demo/workload-identity/hodor-values.yaml`.

A client with `--bound-tokens` gets tokens bound to that certificate, whose `cnf` holds the certificate's SHA-256 from `Hash` ([certificate-bound access tokens](../architecture/contexts/oauth.md#certificate-bound-access-tokens)). Hodor refuses such a token without the certificate. The proxies' own token checks do not read `cnf`, as far as their documentation says, so a bound token checked only by a proxy is a bearer token there.

### Running Hodor inside

```yaml
mesh:
  provider: istio
gatewayIdentities:
  - spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account
networkPolicy:
  enabled: true
  ingressFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: istio-system
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: shop
```

`mesh.provider` injects the sidecar, leaves the operations port out of it, trusts the sidecar's `127.0.0.6` and `::6` and its header, and reads a forwarded address only from the gateways of `gatewayIdentities`, which become `HODOR_GATEWAY_IDENTITIES`. Every other workload is known by the sidecar's address and shares one limit on sign-in attempts. [Inside a service mesh](install-on-kubernetes.md#inside-a-service-mesh) explains each value, the way out through `outboundTrafficPolicy`, and what to do on a cluster without native sidecars. A gateway made from the Gateway API runs as `<gateway>-istio` in its own namespace; one installed from Istio's `gateway` chart runs as the name of its release, `istio-ingressgateway` in the demonstration of Milestone 11. Name the identity yours runs as.

| Example | What ran it |
|---|---|
| Hodor behind its sidecar, with `trustedProxies`, `forwardedHeader: none` and `clientIdentityHeader` | **Continuous integration**, by the demonstration of Milestone 10 |
| A token with `client_id` alone, `spiffe_x509` under `cluster.local` checked by the mesh, bound to the sidecar's certificate and refused without it | **Continuous integration**, by the demonstration of Milestone 10 |
| `X-Forwarded-Client-Cert` written by a caller outside the mesh, ignored | **Continuous integration**, by the demonstration of Milestone 10 |
| `mesh.provider: istio` with `gatewayIdentities` and the network policy on, the namespace with no label | **Continuous integration**, by the demonstration of Milestone 11: Hodor's pods and `hodor-ext-authz`'s with their sidecar, the stand-ins beside them without; two clients outside the mesh behind the ingress gateway limited apart, one locked out while the other signs in and is known by its own address; a workload of the mesh writing `X-Forwarded-For` known by the sidecar's `127.0.0.6`. **Tried by hand on kind**: a workload forging its address on every request limited as one |
| `RequestAuthentication` against the tenant's key set, with `audiences`, `forwardOriginalToken` and `outputPayloadToHeader` | **Continuous integration**, by the demonstration of Milestone 11: a token of another tenant refused with `401` |
| `hodor-ext-authz` as Istio's provider, in its own sidecar, with an `AuthorizationPolicy` of action `CUSTOM` | **Continuous integration**, by the demonstration of Milestone 11: a person who holds the role let through and one who does not refused with `403`, both decisions in Hodor's record; no token, `403`; Hodor stopped, `403`. **Tested against the real server**: its decision equal to `evaluate`'s, and each denial |
| What the sidecar and the ingress gateway hand Hodor; `REGISTRY_ONLY` and the `Sidecar` that lets Hodor out | **Tried by hand on kind** |
| A gateway made from the Gateway API, Istio with the way out restricted by the network policy, classic sidecars, `failOpen` | **Not tried** |

## Istio's ambient mode

Ambient mode puts no proxy in the pods. ztunnel carries the connections between nodes and keeps the caller's address, and a waypoint, when a namespace or a service is given one, is the proxy that reads HTTP.

### Checking Hodor's tokens and asking Hodor's decisions

Both happen at the waypoint. The policies name the service through `targetRefs` instead of choosing pods with a `selector`, and the service uses the waypoint:

```bash
istioctl waypoint apply --namespace shop
kubectl label service orders --namespace shop istio.io/use-waypoint=waypoint
```

```yaml
apiVersion: security.istio.io/v1
kind: RequestAuthentication
metadata:
  name: orders
  namespace: shop
spec:
  targetRefs:
    - kind: Service
      group: ""
      name: orders
  jwtRules:
    - issuer: https://login.example.com/t/acme
      jwksUri: https://login.example.com/t/acme/oauth2/jwks
      audiences:
        - https://orders.example.com
      forwardOriginalToken: true
      outputPayloadToHeader: x-hodor-token-claims
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: orders-through-hodor
  namespace: shop
spec:
  targetRefs:
    - kind: Service
      group: ""
      name: orders
  action: CUSTOM
  provider:
    name: hodor
  rules:
    - {}
```

**Which identity the waypoint gives as `destination.principal` is not known.** `hodor-ext-authz` chooses the application by it. If it is the waypoint's own identity rather than the service's, every service behind one waypoint is the same application to `hodor-ext-authz`, and its `destination` must be the waypoint's identity; a waypoint per protected application keeps them apart. Check what your waypoint sends before relying on it.

### Giving workloads their identity at Hodor

No identity header reaches a Hodor that has no sidecar: ztunnel forwards none, and a waypoint in front of Hodor removes the `X-Forwarded-Client-Cert` a caller wrote and adds none. A workload of an ambient namespace then proves who it is with a JWT-SVID from SPIRE, which needs nothing of the mesh.

Hodor's own pods may run with a sidecar, `mesh.provider: istio`, while the workloads that call it are in ambient mode, which Istio allows. Whether that sidecar then forwards the identity of an ambient workload, and what `Hash` it gives for a certificate the workload never held, was not tried.

### Running Hodor inside

Leave `mesh.provider` empty. ztunnel keeps the caller's address, so the gateway is named by its address range in `trustedProxies`, as an ingress controller is outside a mesh, and the network policy must admit nothing else in that range. Port 15008, where ztunnel's tunnel arrives, and the address the probes come from, `169.254.7.127/32`, are not values of the chart: [Istio's ambient mode](install-on-kubernetes.md#istios-ambient-mode) gives the values and the second network policy they need. Never put a waypoint in front of Hodor: every caller would come from the waypoint's address, with no identity.

| Example | What ran it |
|---|---|
| What ztunnel and a waypoint hand Hodor: the caller's address, the waypoint's address, the headers; meshed connections on port 15008 | **Tried by hand on kind** |
| The probes' address under a network plugin that enforces it | **Not tried**: kind's plugin let them through |
| Checking tokens and asking decisions at a waypoint, and what it gives as `destination.principal` | **Not tried** |
| Hodor with a sidecar beside ambient workloads | **Not tried** |

## Linkerd

Linkerd names a workload by a DNS name, `<service account>.<namespace>.serviceaccount.identity.linkerd.<trust domain>`, and its proxy writes the caller's identity in `l5d-client-id`, removing any value a caller sent. It checks no token and asks no outside decision, so a decision reaches Hodor by one of three paths ([Decision 0029](../decisions/0029-hodor-in-a-service-mesh.md#linkerd-gets-three-paths-since-it-can-ask-no-outside-decision)).

### Checking Hodor's tokens

Linkerd cannot. Put [Envoy Gateway](#envoy-gateway) in front for requests from outside the cluster, or let the application check the tenant's tokens itself against its key set, as any resource server does.

### Asking Hodor's decisions

**At the edge, a gateway in front.** Envoy Gateway, meshed by Linkerd, checks the token and asks `hodor-ext-authz`, then sends the request into the mesh. Its section below shows how.

**Between workloads, coarse: Linkerd's own policies, written from Hodor's roles.** `hodor-cli mesh linkerd-policy` writes, for one application, a `MeshTLSAuthentication` naming the Linkerd identities of the service accounts that hold a role on its resource server, and an `AuthorizationPolicy` requiring it on a `Server` of yours ([Linkerd policies from roles](../architecture/contexts/authorization.md#linkerd-policies-from-roles)). The `Server` says which pods and which port; Hodor does not know them:

```yaml
apiVersion: policy.linkerd.io/v1beta3
kind: Server
metadata:
  name: orders-http
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: orders
  port: http
```

```bash
hodor-cli mesh linkerd-policy --tenant acme --application <application identifier> \
  --namespace shop --server orders-http --output policies/orders.yaml
kubectl apply --filename policies/orders.yaml
```

The command prints `added <identity>` and `removed <identity>` against the file it wrote last time, then `wrote <file>`, or `unchanged <file>`. Only service accounts whose clients are bound to a Linkerd identity, with `linkerd_identity` or `tls_client_auth`, appear. Once a `Server` exists, Linkerd refuses every caller of its port that no policy lets in, so the gateway, if it calls Orders, needs a policy of its own. The policy trails Hodor's roles until the command runs again and its file is applied: run it after each change of roles, or on a schedule. When nobody holds a role, the file lets in one identity no workload has, so that applying it takes away what an earlier run let in.

**Between workloads, fine-grained: the application asks.** The application reads `l5d-client-id`, which its own proxy wrote, and asks the Authorization API about that identity with a token of its own client:

```http
POST /t/acme/api/v1/authorization/evaluate
Authorization: Bearer <a token of Orders' client with authz:evaluate>
Content-Type: application/json

{
  "subject": { "type": "workload_identity", "id": "web.shop.serviceaccount.identity.linkerd.cluster.local" },
  "resource": { "type": "order", "id": "42" },
  "action": "read"
}
```

Hodor resolves the identity to the service account whose clients are bound to it. An identity no client binds is a subject Hodor does not know, and is denied by the native engine. Believe `l5d-client-id` only on a port the proxy handles: a port in `config.linkerd.io/skip-inbound-ports` reaches the application without the proxy, and a caller could write the header itself.

### Giving workloads their identity at Hodor

With Hodor in the same Linkerd mesh, `mesh.provider: linkerd`, a workload gets a token with its `client_id` alone. Its client uses `linkerd_identity`, bound to the workload's identity, in a tenant that trusts `cluster.local` as checked by the mesh:

```bash
hodor-cli client add --tenant acme --application <application identifier> --name "Orders in Linkerd" \
  --type confidential --grant client_credentials --principal <service account identifier> \
  --method linkerd_identity --linkerd-identity orders.shop.serviceaccount.identity.linkerd.cluster.local
```

Linkerd forwards no certificate, so such a client cannot ask for bound tokens. `hodor-ext-authz` and `hodor-cert-manager-issuer` prove who they are to Hodor the same way, with `hodor-ext-authz.hodor.serviceaccount.identity.linkerd.cluster.local` for the release `hodor`.

### Running Hodor inside

```yaml
mesh:
  provider: linkerd
  skipOutboundPorts: [25, 587]
gatewayIdentities:
  - gateway.edge.serviceaccount.identity.linkerd.cluster.local
networkPolicy:
  enabled: true
  ingressFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: edge
```

`mesh.provider` injects the proxy, leaves the operations port out of it, trusts the pod's own addresses, where the proxy connects from, and `l5d-client-id`, and opens port 4143, where every meshed connection arrives, beside the public port. Linkerd has no ingress of its own: the gateway named here is one you put in front and mesh, such as Envoy Gateway. Ports 25 and 587 bypass the proxy, which otherwise holds a mail server's greeting for about ten seconds. [Inside a service mesh](install-on-kubernetes.md#inside-a-service-mesh) explains each value.

| Example | What ran it |
|---|---|
| `mesh.provider: linkerd` with `gatewayIdentities` and the network policy on | **Continuous integration**, by the demonstration of Milestone 11, Envoy Gateway in front and meshed: Hodor's pods and `hodor-ext-authz`'s with their proxy, the migration job completed, port 4143 open to each one's own callers; two clients outside the mesh behind the gateway limited apart, one locked out while the other signs in and is known by its own address; a workload of the mesh writing `X-Forwarded-For` known by the pod's own address. **Tried by hand on kind**: the way out restricted to the control plane and the database |
| `hodor-ext-authz` getting its tokens with `linkerd_identity`, its proxy asserting its identity to Hodor's | **Continuous integration**, by the demonstration of Milestone 11 |
| `hodor-cli mesh linkerd-policy`, its file applied to a `Server`, and a workload with no role refused by Linkerd | **Continuous integration**, by the demonstration of Milestone 11: before the `Server`, a workload with no role reaches Orders, whose proxy names it in `l5d-client-id`; after the file is applied, Linkerd refuses it with `403` and lets in the workload whose service account holds the role. **Tested against the real server**, its documents checked against Linkerd's custom resource definitions |
| What the proxy hands Hodor: `l5d-client-id` removed for a caller outside the mesh; the delay on port 587 | **Tried by hand on kind** |
| A token with `linkerd_identity` for a workload of its own | **Tested against the real server**, with the proxy played by the test. In Linkerd, only `hodor-ext-authz`'s, above |
| The application asking about `l5d-client-id` | **Tested against the real server**: a workload named by its identity through `evaluate`. **Not tried** in Linkerd |

## Consul

Consul's proxies are Envoy, so `hodor-ext-authz` works with them as with Istio's: each workload is named `spiffe://<trust domain>/ns/<namespace>/dc/<datacenter>/svc/<service>`, where the trust domain is `<the cluster's identifier>.consul`, and the proxy forwards the caller's identity in `X-Forwarded-Client-Cert`. Nothing in this section was tried.

### Checking Hodor's tokens

A `jwt-provider` names the tenant, and the service's intentions require it:

```hcl
Kind   = "jwt-provider"
Name   = "hodor"
Issuer = "https://login.example.com/t/acme"
JSONWebKeySet = {
  Remote = {
    URI = "https://login.example.com/t/acme/oauth2/jwks"
  }
}
```

```hcl
Kind = "service-intentions"
Name = "orders"
JWT = {
  Providers = [
    { Name = "hodor" }
  ]
}
Sources = [
  { Name = "web", Action = "allow" }
]
```

Check the audience in the intentions too, as Consul's documentation shows, so that the proxy refuses a token for another application before it asks `hodor-ext-authz`, which refuses it too.

### Asking Hodor's decisions

The `builtin/ext-authz` extension of the protected service names `hodor-ext-authz`, registered as a service of the mesh:

```hcl
Kind     = "service-defaults"
Name     = "orders"
Protocol = "http"
EnvoyExtensions = [
  {
    Name = "builtin/ext-authz"
    Arguments = {
      ProxyType = "connect-proxy"
      Config = {
        GrpcService = {
          Target = {
            Service = { Name = "hodor-ext-authz" }
          }
        }
      }
    }
  }
]
```

- **The destination** is the service's identity, `spiffe://<trust domain>/ns/default/dc/<datacenter>/svc/orders`: name it in `extAuthz.applications[].destination`.
- **The checked token's claims** reach `hodor-ext-authz` only in the request's metadata, under the namespace of Envoy's JWT filter, and only when the extension forwards that namespace to the check. Whether Consul's extension does was not confirmed. Without the claims, `hodor-ext-authz` decides on the caller's identity, which is what calls between services need, and denies a request with neither.
- **`hodor-ext-authz` proves who it is only with its mesh identity**, so Hodor must run behind a proxy of the same Consul mesh, reading `X-Forwarded-Client-Cert`, for the adapter to get its tokens. That is the next part, and it is not a value of the chart.

### Giving workloads their identity at Hodor, and running Hodor inside

There is no `mesh.provider` for Consul. Ask for Consul's proxy with `server.podAnnotations` and `worker.podAnnotations`, name the address Consul's proxy connects to Hodor from in `trustedProxies`, set `clientIdentityHeader: x-forwarded-client-cert`, and either `forwardedHeader: none` or the SPIFFE identifiers of Consul's gateways in `gatewayIdentities`. The address the proxy connects from was not confirmed. The migration job has no annotations of its own, so run it outside the mesh or let it reach the database another way. A workload's client then uses `spiffe_x509` or `tls_client_auth` with its Consul identity, in a tenant that trusts Consul's trust domain as checked by the mesh.

| Example | What ran it |
|---|---|
| Everything in this section | **Not tried**. Milestone 11 leaves Consul out of continuous integration |

## Envoy Gateway

Envoy Gateway is a gateway built on the Gateway API, not a mesh. It checks tokens and asks `hodor-ext-authz` for the requests that come into the cluster, in front of Linkerd above all, which cannot do either. What follows is what the demonstration of Milestone 11 runs with Envoy Gateway 1.10.0, in front of Linkerd; its files are in `deploy/demo/service-mesh/`.

### Checking Hodor's tokens and asking Hodor's decisions

One `SecurityPolicy` on the route does both:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: orders
  namespace: shop
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: orders
  jwt:
    providers:
      - name: hodor
        issuer: https://login.example.com/t/acme
        audiences:
          - https://orders.example.com
        remoteJWKS:
          uri: https://login.example.com/t/acme/oauth2/jwks
  extAuth:
    grpc:
      backendRefs:
        - name: hodor-ext-authz
          namespace: hodor
          port: 9191
```

- **The key set is fetched over HTTPS only.** `remoteJWKS` takes an `https` address. The demonstration's Hodor answers in plain HTTP inside the cluster, so it gives the key set inline instead, with `localJWKS` of type `Inline`, which must then be replaced when the tenant's keys change.
- **A request without a good token is refused by Envoy Gateway**, with `401`, before anything is asked, unless the `jwt` section says `optional: true`. Keep it required: the next point relies on it.
- **A reference to a service of another namespace needs a `ReferenceGrant`** in the namespace `hodor`, from the `SecurityPolicy` of the namespace `shop`, as the Gateway API requires.

**The claims reach `hodor-ext-authz` from the caller.** Envoy Gateway 1.10.0 checks the token and forwards it, and writes its claims into the request's metadata, but sends `hodor-ext-authz` none of that metadata, and writes no header of the claims as Istio does. So the caller sends the claims of the token it presents in `x-hodor-token-claims`, the token's middle part as it is, and `hodor-ext-authz` reads them with `token.header`. They are believed only when they are exactly the claims of the bearer token, which Envoy Gateway has just checked: a caller that sends another token's claims beside its own token is refused with `403`, and one that sends no token never reaches the check. This is sound only while the route's `SecurityPolicy` requires a token, and only once the token is checked before `hodor-ext-authz` is asked. **Envoy Gateway asks external authorization before it checks a token**, in its default order of filters: unchanged, Hodor would be asked, and would record a decision, about the claims of a token nobody has checked yet, and whether the answer is `403` or `401` would tell the caller what Hodor decided about them. Put the JWT check first with the `filterOrder` of the `EnvoyProxy`, as below.

**At a gateway, the destination is the gateway's listener.** Envoy fills `destination.principal` from the certificate of the listener that received the request: its first URI name, or else its first DNS name. So the listener for Orders serves TLS, with a certificate for `orders.example.com`, and the application's entry in `hodor-ext-authz`'s configuration names `orders.example.com` as its `destination`. A listener without TLS gives no destination, and every check is denied. One application per listener, then, unless the route sends the resource and the action as context per route, `hodor_resource_type`, `hodor_action` and `hodor_resource_id`, which `hodor-ext-authz` reads in place of its rules; the `SecurityPolicy` of Envoy Gateway 1.10.0 has `contextExtensions` for it, which was not tried.

```yaml
extAuthz:
  enabled: true
  tenant: acme
  token:
    header: x-hodor-token-claims
  applications:
    - destination: orders.example.com
      clientId: 0193f1c2-6a1d-7c55-b0c8-6b1f2c9d4e01
      audience: https://orders.example.com
      routes:
        - methods: [GET]
          path: /orders/{id}
          resourceType: order
          action: read
```

### Running it in front of Hodor

In front of Hodor inside Linkerd, mesh the gateway's proxies through Envoy Gateway's `EnvoyProxy` resource, named by the `GatewayClass`'s `parametersRef`:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyProxy
metadata:
  name: meshed
  namespace: envoy-gateway-system
spec:
  # The token is checked before hodor-ext-authz is asked.
  filterOrder:
    - name: envoy.filters.http.jwt_authn
      before: envoy.filters.http.ext_authz
  provider:
    type: Kubernetes
    kubernetes:
      envoyServiceAccount:
        name: edge-gateway
      envoyDeployment:
        pod:
          annotations:
            linkerd.io/inject: enabled
            config.linkerd.io/skip-inbound-ports: "8080,8443"
```

- **Check the token before asking `hodor-ext-authz`**, with `filterOrder`: Envoy Gateway's own order asks external authorization first.

- **Leave the listeners' ports out of Linkerd's proxy on the way in**, with `config.linkerd.io/skip-inbound-ports`. Through the proxy, every client would reach Envoy from the pod's own address, and Envoy would forward that one address for everybody. Envoy listens on the listeners' own ports when they are 1024 or more; below, it adds 10000 unless `useListenerPortAsContainerPort` is set.
- **Name the gateway's service account**, with `envoyServiceAccount`, so that its identity is known before it runs: here `edge-gateway.envoy-gateway-system.serviceaccount.identity.linkerd.cluster.local`, in `gatewayIdentities`. Otherwise Envoy Gateway makes up a name, which `kubectl get pod --namespace envoy-gateway-system <pod> --output jsonpath='{.spec.serviceAccountName}'` reads.
- **Envoy adds the address it received the request from to `X-Forwarded-For`**, as Hodor needs.
- **Install Envoy Gateway before Linkerd.** Its chart brings the Gateway API's definitions, which Linkerd's control plane needs and its own chart no longer installs.

Outside a mesh, name the range Envoy Gateway's pods get their addresses from in `trustedProxies`, as for any ingress controller ([the address of each client](install-on-kubernetes.md#the-address-of-each-client)).

| Example | What ran it |
|---|---|
| The `SecurityPolicy` with `jwt`, the key set inline, and `extAuth` to `hodor-ext-authz`, the token checked first by `filterOrder` | **Continuous integration**, by the demonstration of Milestone 11: a person who holds the role let through and one who does not refused with `403`; no token `401`; a token of another tenant `401`; another token's claims beside the bearer token `403`; Hodor stopped, `403` |
| The destination named by the listener's certificate | **Continuous integration**, by the demonstration of Milestone 11 |
| Envoy Gateway meshed by Linkerd in front of Hodor, named in `gatewayIdentities` | **Continuous integration**, by the demonstration of Milestone 11 |
| `remoteJWKS`, context per route, Envoy Gateway outside a mesh or in front of Istio | **Not tried** |

## One root for every mesh

A tenant with [its own certificate authority](../architecture/contexts/keys.md#the-certificate-authority-of-a-tenant) signs the intermediates of its meshes: Linkerd's identity issuer, Istio's `cacerts`, SPIRE's upstream authority. Every mesh of the tenant then trusts one root, and Hodor trusts what it signed. cert-manager keeps them current through [`hodor-cert-manager-issuer`](hodor-cert-manager-issuer.md), whose page has the `Certificate` for each mesh.

**cert-manager must run with its feature gate `UseCertificateRequestBasicConstraints=true`.** Without it, cert-manager writes no basic constraints into a request, and Hodor refuses every request of a `Certificate` with `keys.intermediate_not_an_authority`. The gate is off by default in cert-manager 1.21:

```bash
helm install cert-manager oci://quay.io/jetstack/charts/cert-manager --namespace cert-manager --create-namespace \
  --set crds.enabled=true --set featureGates=UseCertificateRequestBasicConstraints=true
```

| Example | What ran it |
|---|---|
| The issuer signing approved requests through Hodor, a `Certificate` shaped as Linkerd's identity issuer renewed without anyone acting, the refusals | **Tried by hand on kind**, with cert-manager 1.21.3, which is how the feature gate was found |
| Linkerd and Istio running on intermediates signed this way, and a workload of one calling a workload of the other under the one root | **Not tried**: the demonstration of Milestone 12 (Issue-119) |

## What is missing

| Missing | Until then |
|---|---|
| Envoy Gateway handing `hodor-ext-authz` the claims it checked | The caller sends them in `x-hodor-token-claims`, believed only when they are the claims of the token Envoy Gateway checked first, with the JWT check put before external authorization ([Envoy Gateway](#envoy-gateway)) |
| A value of the chart for Consul and for Istio's ambient mode | `trustedProxies`, `clientIdentityHeader`, `gatewayIdentities`, the pod annotations and a network policy of your own |
| The proxies checking a token's binding to a certificate | A bound token checked only by a proxy is a bearer token there. Hodor checks the binding wherever it accepts a token |
| A revoked token refused by the proxies | They accept it until it expires, five minutes by default, as any resource server that checks tokens by itself does ([Decision 0004](../decisions/0004-token-formats.md)) |
| A controller that applies Linkerd policies as roles change | Run `hodor-cli mesh linkerd-policy` after each change of roles, and apply its file |
| A cache of decisions in `hodor-ext-authz` | Every request is one call of `evaluate`: see the latency below |

### Latency

`hodor-ext-authz` keeps no decision, so each request waits for one `evaluate`. The target is that of Open Policy Agent sidecars, 15 ms at the 99th percentile. On 25 November 2026 it was measured on a laptop that was running other builds and tests at the same time, with PostgreSQL in a container of Docker Desktop and no mesh in the way ([how it was measured](hodor-ext-authz.md#latency)):

| | 50th percentile | 99th percentile |
|---|---|---|
| A check through `hodor-ext-authz` | 11.11 ms | 29.73 ms |
| `evaluate` called directly | 10.86 ms | 31.41 ms |

The adapter adds about a quarter of a millisecond. **Whether the target is met is not confirmed:** `evaluate` alone missed it on that machine, and a measurement on a real server, with its own database and a sidecar on each side, is still to be made. A cache of decisions is considered only after it.

## What was tried and what was not

| Mesh | Checking tokens | Asking decisions | Workloads' identity at Hodor | Hodor inside |
|---|---|---|---|---|
| Istio, with sidecars | Continuous integration: `RequestAuthentication` | Continuous integration: `hodor-ext-authz` as the provider of an `AuthorizationPolicy` of action `CUSTOM` | Continuous integration: `spiffe_x509`, bound tokens, a forged header ignored; a JWT-SVID from SPIRE; `hodor-ext-authz`'s own | Continuous integration with `mesh.provider`, the ingress gateway and the network policy, and with `trustedProxies` and no gateway |
| Istio, ambient | Not tried | Not tried | A JWT-SVID needs no mesh; nothing else reaches Hodor | What ztunnel and a waypoint hand Hodor tried by hand on kind |
| Linkerd | Not possible: Envoy Gateway in front, in continuous integration | Continuous integration: Envoy Gateway in front, and the policies of `hodor-cli mesh linkerd-policy` applied. The application asking tested against the real server | Continuous integration: `hodor-ext-authz`'s, with `linkerd_identity` | Continuous integration with `mesh.provider`, Envoy Gateway in front and the network policy |
| Consul | Not tried | Not tried | Not tried | Not tried |
| Envoy Gateway | Continuous integration, in front of Linkerd, the key set inline | Continuous integration, in front of Linkerd, the claims sent by the caller | Not a mesh | Continuous integration, meshed by Linkerd |

Never tried anywhere: a cluster of several nodes, a network plugin other than kind's, Istio's classic sidecars, Istio's gateways made from the Gateway API, Istio with the way out restricted by the network policy, Kuma, Cilium and any mesh not named here. A mesh built on Envoy that forwards `X-Forwarded-Client-Cert` and speaks Envoy's external authorization should work as Istio and Consul do, but none was tried.
