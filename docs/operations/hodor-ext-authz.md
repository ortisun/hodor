# Envoy's external authorization: `hodor-ext-authz`

`hodor-ext-authz` lets the proxies of a service mesh ask Hodor whether a request may go through. It serves [Envoy's external authorization](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) over gRPC, `envoy.service.auth.v3.Authorization`, and turns each check into one call of [the Authorization API](../api/api-spec.md#authorization-api)'s `evaluate`. Istio, Consul, Envoy Gateway and Envoy itself can call it. Linkerd cannot ask an outside decision, and reaches it through a gateway in front ([Decision 0029](../decisions/0029-hodor-in-a-service-mesh.md#linkerd-gets-three-paths-since-it-can-ask-no-outside-decision)).

It is a binary of its own, in an image of its own, and runs in the mesh next to the proxies, not inside `hodor-server`. It holds no decision of its own and keeps none: Hodor decides, records every decision with the client that asked, and `hodor-ext-authz` answers what Hodor said. Why it is built this way is in [Decision 0029](../decisions/0029-hodor-in-a-service-mesh.md#decisions-are-asked-through-hodor-ext-authz-a-binary-of-its-own) and [Decision 0058](../decisions/0058-hodor-ext-authz.md).

```mermaid
sequenceDiagram
    participant Caller
    participant Proxy as Proxy of the application
    participant Adapter as hodor-ext-authz
    participant Hodor
    Caller->>Proxy: GET /orders/42, with a token or a mesh identity
    Proxy->>Proxy: checks the token (RequestAuthentication)
    Proxy->>Adapter: Check: the checked claims, source and destination identities, method, path
    Adapter->>Adapter: destination → client; route → resource and action; claims or identity → subject
    Adapter->>Hodor: POST /t/acme/api/v1/authorization/evaluate, as the destination's client
    Hodor-->>Adapter: ALLOW or DENY, recorded
    Adapter-->>Proxy: OK, or PERMISSION_DENIED with 403
    Proxy->>Caller: the application's answer, or 403
```

## What a check becomes

Each check Envoy sends is one `evaluate`. Every part of it comes from the check, read as follows. Anything missing denies the request.

| Part of `evaluate` | Where it comes from | When it is missing |
|---|---|---|
| The client that asks, and so the application and its resource server | `destination.principal`, the identity of the workload the request is for, looked up exactly among the configuration's applications | Denied |
| `subject` | The checked token's `sub`, as `user`, or as `client` when `sub` equals `client_id`. With no token, `source.principal`, the caller's identity, as `workload_identity`, which Hodor resolves to the service account bound to it | Denied |
| `resource.type`, `resource.id` and `action` | The first route rule of the application that matches the method and the path; or the proxy's context for the route, `context_extensions` | Denied |

`asserted`, `resource.attributes`, `context` and `organization` are never sent.

### The subject

**A token the proxy checked.** The proxy checks the tenant's access tokens itself, as any resource server does ([Decision 0029](../decisions/0029-hodor-in-a-service-mesh.md#the-proxies-check-hodors-tokens-themselves)): Istio with `RequestAuthentication`, Envoy with its JWT filter, Envoy Gateway with a `SecurityPolicy`. `hodor-ext-authz` reads the claims the proxy checked from one of two places, which `token` in the configuration names:

- **`metadata`**: the request's metadata, where Envoy's JWT filter writes the claims when `payload_in_metadata` is set. The configuration names the namespace, `envoy.filters.http.jwt_authn` by default, and the key, the value of `payload_in_metadata`. A caller cannot write metadata, so this is the place to prefer.
- **`header`**: a header the proxy writes the claims into, base64url-encoded, as Istio's `outputPayloadToHeader` does. A caller can send such a header too, so it is believed only when it is exactly the claims part of the bearer token in `Authorization`, which the proxy has then checked and must forward (`forwardOriginalToken: true` in Istio). A header without a token, or with another token, is denied.

The claims must then hold:

- `iss`, exactly the tenant's issuer. **A token of another tenant is denied**, even if the proxy accepted it.
- `exp`, if present, in the future.
- `sub`, the subject: a person, a service account or an agent by their user identifier, or the client itself when `sub` equals `client_id`. The `sub` of a [pairwise client](../architecture/contexts/oauth.md#pairwise-subject-identifiers) names nobody Hodor knows, and its decisions deny.

Claims that are present but fail any of these are denied. The caller's identity is never used in their place.

**No token: the caller's identity.** With no claims, the subject is `source.principal`, the identity of the workload that called, a SPIFFE identifier or a Linkerd identity. `hodor-ext-authz` sends it as `{"type": "workload_identity", "id": "…"}`, and Hodor resolves it to the service account whose clients are bound to it ([the Authorization API](../api/api-spec.md#authorization-api)). An identity no client binds is a subject Hodor does not know, and is denied by the native engine. With no claims and no identity, the request is denied.

### Route rules

Each application lists its rules. A rule names methods and a path pattern, and gives the resource type, the action and, from the path, the resource's identifier. They are tried in order and the first one that matches decides.

```json
{ "methods": ["POST"], "path": "/orders/{id}/approve", "resource_type": "order", "action": "approve" }
```

- **`methods`**: one or more methods in capitals, compared exactly.
- **`path`**: starts with `/`, and is compared with the request's path segment by segment, without the query. A segment is a literal, compared exactly; `{id}`, which matches any one segment and makes it the resource's identifier, at most once per pattern; `*`, any one segment; or `**`, as the last segment only, any number of segments, none included. `/orders` and `/orders/` are two different paths.
- **`resource_type`** and **`action`**: as the Authorization API reads them. Without `{id}` the request names no resource identifier.
- **A path is denied before any rule is tried** when one of its segments is `.` or `..`, or holds an encoded `/` or `\` (`%2F`, `%5C`). The proxy's own path normalization, on by default in Istio, should have removed them.

**Context per route.** Envoy and Envoy Gateway can attach context to a route, which reaches the check as `context_extensions`. When it holds `hodor_resource_type` and `hodor_action`, those name the resource type and the action, and `hodor_resource_id`, if present, the identifier; the rules are not read. One of the first two without the other is denied.

## How it proves who it is to Hodor

`hodor-ext-authz` holds no secret. It runs as a workload of the mesh with an identity of its own, given by its Kubernetes service account, and asks Hodor for a token for each application's client with nothing but `client_id`:

```http
POST /t/acme/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=…&resource=urn%3Ahodor%3Aauthorization&scope=authz%3Aevaluate
```

Its sidecar presents its certificate to Hodor's, and Hodor's proxy forwards the identity, which Hodor reads as [the caller's identity from a proxy](../api/api-spec.md#the-callers-identity-from-a-proxy) says. Every client of the configuration is bound to that one identity, with `tls_client_auth`, `spiffe_x509` or `linkerd_identity`, and acts as the same service account ([Decision 0058](../decisions/0058-hodor-ext-authz.md#an-identity-binds-the-clients-of-one-service-account)).

It keeps each client's access token until 30 seconds before it expires, and asks for a new one when `evaluate` answers `401`, once. It keeps no decision.

### Setting it up in Hodor

For a tenant `acme` and an application Orders whose workload has the identity `spiffe://cluster.local/ns/shop/sa/orders`, with the administration interface:

1. **Open the Authorization API**, once per tenant: a resource server with the audience `urn:hodor:authorization` and the scopes `authz:evaluate`, `authz:simulate` and `authz:explain`, on an application of the tenant ([who may ask](../architecture/contexts/authorization.md#who-may-ask)).
2. **Trust the mesh's trust domain**, `cluster.local`, by its bundle or as checked by the mesh ([trust domains](../architecture/contexts/keys.md#trust-domains)), and run Hodor behind its proxy with `HODOR_CLIENT_IDENTITY_HEADER` ([the identity of a workload](install-on-kubernetes.md#the-identity-of-a-workload)).
3. **A service account for the adapter**, `POST /service-accounts`, which holds no role.
4. **One client per protected application**: in the application Orders, a confidential client with the grant `client_credentials`, the method `spiffe_x509`, the service account as `principal`, the adapter's identity, here `spiffe://cluster.local/ns/hodor/sa/hodor-ext-authz`, as `spiffe_id`, and `authz:evaluate` among its scopes. The application has a resource server of its own, whose permissions and roles decide.
5. **The application's entry in the configuration**, with the workload's identity as `destination`, the client's `client_id` and the route rules.

## Configuration

The settings of the process are environment variables. The rest is one JSON file.

| Variable | Default | Meaning |
|---|---|---|
| `HODOR_EXT_AUTHZ_CONFIG` | None | The configuration file. Required |
| `HODOR_EXT_AUTHZ_LISTEN_ADDR` | `0.0.0.0:9191` | Where the gRPC service listens, in clear text: the sidecar in front of it ends mutual TLS |
| `HODOR_OPS_ADDR` | `0.0.0.0:9090` | The operations port: `/startupz`, `/readyz` and `/livez` |
| `HODOR_LOG_FORMAT`, `HODOR_LOG_FILTER` | `json`, `info` | As for the server |
| `HODOR_OTLP_METRICS_ENDPOINT`, `HODOR_OTLP_TRACES_ENDPOINT` | Empty | As for the server |

The file:

```json
{
  "hodor": {
    "url": "http://hodor.hodor.svc.cluster.local:8080",
    "tenant": "acme",
    "issuer": "https://login.example.com/t/acme",
    "timeout_milliseconds": 1000
  },
  "token": { "metadata": { "namespace": "envoy.filters.http.jwt_authn", "key": "hodor" } },
  "applications": [
    {
      "destination": "spiffe://cluster.local/ns/shop/sa/orders",
      "client_id": "0193f1c2-6a1d-7c55-b0c8-6b1f2c9d4e01",
      "routes": [
        { "methods": ["GET"], "path": "/orders", "resource_type": "order", "action": "list" },
        { "methods": ["GET"], "path": "/orders/{id}", "resource_type": "order", "action": "read" },
        { "methods": ["POST"], "path": "/orders/{id}/approve", "resource_type": "order", "action": "approve" }
      ]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `hodor.url` | Where `hodor-ext-authz` reaches Hodor, `http` or `https`, with no path. Inside a mesh, the plain address of Hodor's Service: the sidecar adds mutual TLS |
| `hodor.tenant` | The tenant's slug |
| `hodor.issuer` | The tenant's issuer, as tokens name it in `iss`: Hodor's public address followed by `/t/<slug>`. Default: `hodor.url` followed by `/t/<slug>`, right only when the two addresses are the same |
| `hodor.timeout_milliseconds` | How long one call to Hodor may take, from 1 to 60000, default 1000. Keep it under the proxy's own timeout for the check |
| `token` | Where the checked token's claims are: `{"metadata": {"namespace": …, "key": …}}` or `{"header": "<name>"}`. Left out: no token is read, and the subject is always the caller's identity |
| `applications[].destination` | The protected workload's identity, as Envoy gives it in `destination.principal`. Each one once |
| `applications[].client_id` | The application's client, bound to the adapter's identity |
| `applications[].routes` | The route rules, in order. May be empty when every route sends context per route |

The file is read once when the process starts. A file that does not read, or breaks a rule above, stops the process with a message saying why, before it listens. A change takes a restart.

## When it denies

**Every failure is a denial.** Hodor unreachable, or slower than `timeout_milliseconds`; an answer that is not `200`, or not JSON with a `decision`; a decision other than `ALLOW`, `INDETERMINATE` included; a destination with no entry, a route with no rule, claims that fail, no subject. Failing open stays what it is in Hodor: a choice per action of [the engine binding](../architecture/contexts/authorization.md#bindings), made and recorded there ([Threat-Mesh-06](../security/threat-model.md#service-meshes-and-certificates)).

**The answer to the proxy is always a well-formed check response**: `OK` to allow, `PERMISSION_DENIED` with an HTTP `403` and no body to deny, never a gRPC error. Set the proxy's own failure mode to deny all the same, for when `hodor-ext-authz` itself cannot be reached: `failOpen: false` in Istio, the default; `failure_mode_allow: false` in Envoy, the default.

The reason of each denial is logged, at `info` for a denial and at `warn` when Hodor gave no decision, with the destination and the decision identifier when Hodor gave one, never the token. It is never sent to the caller. The metric `hodor.ext_authz.checks` counts checks by `outcome`, `allowed`, `denied` or `failed`, and `hodor.ext_authz.check.duration` measures them, in seconds.

## Latency

`hodor-ext-authz` keeps no decision ([Decision 0029](../decisions/0029-hodor-in-a-service-mesh.md#decisions-are-asked-through-hodor-ext-authz-a-binary-of-its-own)), so each check waits for one `evaluate`. The target is that of Open Policy Agent sidecars, 15 ms at the 99th percentile, before a cache is considered.

Measured on 25 November 2026 on an Apple M3 Max laptop that ran everything at once, while other builds and tests kept it busy (a load average between 26 and 44 during the run), after the decision path of `evaluate` was cut to fewer round trips to the database: the server and the adapter built for release, PostgreSQL in a container of Docker Desktop, a role of the native engine deciding, 2000 checks one after the other after 200 to warm up.

| | 50th percentile | 99th percentile |
|---|---|---|
| A check through `hodor-ext-authz` | 11.11 ms | 29.73 ms |
| `evaluate` called directly | 10.86 ms | 31.41 ms |

The adapter adds about 0.25 ms at the 50th percentile to what `evaluate` itself takes; at the 99th the two differ by less than the machine's own noise. The target of 15 ms at the 99th percentile is not met on this machine, and `evaluate` alone does not meet it either: most of the time is Hodor's own, reading the token's register, the roles and the binding, and writing the record of decisions, on a database reached through Docker Desktop's virtual machine on a busy laptop. A measurement on a quiet machine with its own database, and in a mesh, belongs to the demonstration of the milestone (Issue-114); a cache of decisions is considered only after it. No mesh was in the way here: a sidecar on each side adds its own hops. To measure again:

```bash
cargo test --release -p hodor-server --test ext_authz -- --ignored --nocapture latency
```

It needs Docker, for PostgreSQL, and prints both rows.

## The image and the chart

The image is `ghcr.io/ortisun/hodor-ext-authz:<version>`, published and signed with each release beside Hodor's own ([what a release publishes](../security/supply-chain.md#what-a-release-publishes)). It holds the one binary, distroless, as a user that is not root. To build it:

```bash
docker build --file deploy/docker/ext-authz.Dockerfile --tag registry.example.com/hodor-ext-authz:0.4.0 .
```

The chart installs it with `extAuthz.enabled`, beside Hodor or in a release of its own: a Deployment, its Service, its own Kubernetes service account, which gives it its mesh identity, a ConfigMap with the configuration file written from the values, and a PodDisruptionBudget. [Installing on Kubernetes](install-on-kubernetes.md#envoys-external-authorization) lists the values.

## In Istio

These examples follow Istio's documentation and have not been tried yet: the demonstration of Milestone 11 is to run them on kind (Issue-114). [The service mesh guide](service-mesh.md) shows them with the rest of what Istio needs, does the same for ambient mode, Consul and Envoy Gateway, and says what was tried for each.

The provider, in Istio's mesh configuration:

```yaml
meshConfig:
  extensionProviders:
    - name: hodor
      envoyExtAuthzGrpc:
        service: hodor-ext-authz.hodor.svc.cluster.local
        port: 9191
        timeout: 2s
```

The token checked by the proxy, with its claims for `hodor-ext-authz` (`"token": {"header": "x-hodor-token-claims"}`):

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
      forwardOriginalToken: true
      outputPayloadToHeader: x-hodor-token-claims
```

Every request to Orders asked through `hodor-ext-authz`:

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

## What it does not do yet

| Missing | Until then |
|---|---|
| A cache of decisions | Every check is one `evaluate` (Decision 0029) |
| A JWT-SVID as its credential | It proves who it is with the certificate its sidecar presents, or the identity Linkerd asserts |
| The request's attributes, such as the address or the headers, as `context` | Policies decide on the subject, the resource and the action |
| Reloading the configuration without a restart | A change takes a restart |
| Being tried in a mesh | The demonstration of Milestone 11 (Issue-114). [The service mesh guide](service-mesh.md#what-was-tried-and-what-was-not) says what was tried so far |
