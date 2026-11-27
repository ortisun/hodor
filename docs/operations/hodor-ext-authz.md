# Envoy's external authorization: `hodor-ext-authz`

`hodor-ext-authz` lets the proxies of a service mesh ask Hodor whether a request may go through. It serves [Envoy's external authorization](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) over gRPC, `envoy.service.auth.v3.Authorization`, and turns each check into one call of [the Authorization API](../api/api-spec.md#authorization-api)'s `evaluate`. Istio, Consul, Envoy Gateway and Envoy itself can call it. Linkerd cannot ask an outside decision, and reaches it through a gateway in front ([Decision 0029](../decisions/0029-hodor-in-a-service-mesh.md#linkerd-gets-three-paths-since-it-can-ask-no-outside-decision)).

It is a binary of its own, in an image of its own, and runs in the mesh next to the proxies, not inside `hodor-server`. It holds no decision of its own and keeps none: Hodor decides, records every decision with the client that asked, and `hodor-ext-authz` answers what Hodor said. It checks the signature of a bearer token itself, against the tenant's published key set, so that Hodor is never asked about a token nobody signed. Why it is built this way is in [Decision 0029](../decisions/0029-hodor-in-a-service-mesh.md#decisions-are-asked-through-hodor-ext-authz-a-binary-of-its-own), [Decision 0058](../decisions/0058-hodor-ext-authz.md) and [Decision 0082](../decisions/0082-ext-authz-checks-the-signature.md).

```mermaid
sequenceDiagram
    participant Caller
    participant Proxy as Proxy of the application
    participant Adapter as hodor-ext-authz
    participant Hodor
    Caller->>Proxy: GET /orders/42, with a token or a mesh identity
    Proxy->>Adapter: Check: the bearer token, source and destination identities, method, path
    Adapter->>Hodor: GET /t/acme/oauth2/jwks, when no set is kept or the token's key is not in it
    Hodor-->>Adapter: the tenant's published key set, kept five minutes
    Adapter->>Adapter: the token's signature; destination → client; route → resource and action; claims or identity → subject
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
| `subject` | The bearer token's `sub`, once its signature and its claims hold, as `user`, or as `client` when `sub` equals `client_id`. With no token, `source.principal`, the caller's identity, as `workload_identity`, which Hodor resolves to the service account bound to it | Denied |
| `resource.type`, `resource.id` and `action` | The first route rule of the application that matches the method and the path; or the proxy's context for the route, `context_extensions` | Denied |

`asserted`, `resource.attributes`, `context` and `organization` are never sent.

### The subject

**A bearer token, checked by `hodor-ext-authz` itself.** When `token` in the configuration is set, the token is the bearer token in `Authorization`, and `hodor-ext-authz` checks its signature before anything else, against the tenant's published key set ([Decision 0082](../decisions/0082-ext-authz-checks-the-signature.md)). It does not rely on the proxy having checked it: Istio's sidecar asks external authorization before its own `RequestAuthentication`, and Envoy Gateway does too in its default order of filters, so a workload inside the mesh can reach the check with a token it made. The proxy still checks the tenant's tokens as any resource server does ([Decision 0029](../decisions/0029-hodor-in-a-service-mesh.md#the-proxies-check-hodors-tokens-themselves)), and refuses a bad one itself when it checks first.

- **The key set** is the tenant's published one, the set its discovery document names as `jwks_uri`, `<issuer>/oauth2/jwks`. `hodor-ext-authz` reads it at Hodor's own address, `hodor.url` followed by `/t/<slug>/oauth2/jwks`, where it already asks for tokens and calls `evaluate`, since the issuer's public address may not be reachable from inside the mesh.
- **It is kept in memory for five minutes**, the time Hodor's answer allows, so a key Hodor revokes stops being accepted within five minutes. A token whose `kid` the kept set lacks, or the first one after the five minutes, fetches the set again, at most once every ten seconds, whatever caused it. Checks that arrive while a fetch runs wait for it. A fetch takes at most `hodor.timeout_milliseconds`, reads at most 64 kibibytes and 32 keys, and follows no redirect; one that fails keeps the set that was kept, until its five minutes end, and then every token is denied until a fetch answers.
- **Only the algorithms Hodor signs with are accepted**: `ES256`, `RS256`, `PS256` and `EdDSA`. The header must name a `kid` of the set, whose key has that same algorithm. `none`, `HS256` and every other algorithm are refused before a key is looked for; so is a header with `crit`.
- **A token whose signature fails is denied before Hodor is asked anything**, so Hodor records no decision about it. A bearer token that is not a JSON Web Token is denied too; an `Authorization` header of another scheme, such as `Basic`, is no token.

The proxy must pass `Authorization` to the check. Istio's sidecar does, since it asks before it checks; a proxy whose JWT filter runs first must forward the token, with `forward: true` in Envoy's JWT filter and `forwardOriginalToken: true` in Istio's `RequestAuthentication`.

`token` is `"bearer"`. Two forms written before Decision 0082 are still read, and mean the same, with one more rule each. Neither place is read for claims any more:

- **`{"header": "<name>"}`**: a header the proxy, or behind Envoy Gateway the caller, wrote the claims into, base64url-encoded, as Istio's `outputPayloadToHeader` does. It is not needed: Envoy Gateway 1.10.0 writes no such header and passes no metadata of its own token check, so behind it the caller had to send its claims itself, and `"bearer"` asks nothing of it. A request that carries it is denied unless it is exactly the claims part of the bearer token, and when it comes without a bearer token.
- **`{"metadata": {"namespace": …, "key": …}}`**: the request's metadata, where Envoy's JWT filter writes the claims it checked with `payload_in_metadata`, under the namespace `envoy.filters.http.jwt_authn` by default. A request whose metadata holds claims without a bearer token is denied: the filter checked a token and removed it, which it does without `forward: true`.

The token's claims must then hold:

- `iss`, exactly the tenant's issuer. **A token of another tenant is denied**, even if the proxy accepted it.
- `aud`, holding the audience of the application's resource server, `audience` in the application's entry: one text equal to it, or a list with it among its values. **A token for another application of the same tenant is denied**, and so is an ID token, whose audience is a client, even if the proxy accepted them.
- `exp`, if present, in the future.
- `sub`, the subject: a person, a service account or an agent by their user identifier, or the client itself when `sub` equals `client_id`. The `sub` of a [pairwise client](../architecture/contexts/oauth.md#pairwise-subject-identifiers) names nobody Hodor knows, and its decisions deny.

A token that is present but fails its signature or any of these is denied. The caller's identity is never used in its place.

**Why the audience, when Hodor decides by the roles of each application.** `evaluate` is asked about the resource server of the destination's application, so the roles that count are the ones the subject holds there. They say what Ana may do on Orders; they do not say that the token was given to Orders. Without the check, a token issued for Invoices when Ana signed in there, replayed at Orders by Invoices or by anyone who read it there, would act as Ana on Orders, with every role she holds on Orders, and the scopes she consented to for Invoices would stand for consent she never gave Orders. The audience is what binds a token to the resource server it was issued for ([RFC 9068, section 4](https://www.rfc-editor.org/rfc/rfc9068#section-4), [Threat-OAuth-07](../security/threat-model.md#oauth-2x)), so `hodor-ext-authz` checks it whatever the proxy does ([Decision 0077](../decisions/0077-ext-authz-checks-the-audience.md)). A token Hodor issues names the resource servers of the request as its audiences, and the issuer too when it carries `openid` ([the access token](../architecture/contexts/oauth.md#the-access-token)), so a token issued for several applications is good at each of them.

**No token: the caller's identity.** With no bearer token, the subject is `source.principal`, the identity of the workload that called, a SPIFFE identifier or a Linkerd identity. `hodor-ext-authz` sends it as `{"type": "workload_identity", "id": "…"}`, and Hodor resolves it to the service account whose clients are bound to it ([the Authorization API](../api/api-spec.md#authorization-api)). An identity no client binds is a subject Hodor does not know, and is denied by the native engine. With no token and no identity, the request is denied.

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

It keeps each client's access token until 30 seconds before it expires, and asks for a new one when `evaluate` answers `401`, once. It keeps the tenant's key set for five minutes, as [the subject](#the-subject) says. It keeps no decision.

### Setting it up in Hodor

For a tenant `acme` and an application Orders whose workload has the identity `spiffe://cluster.local/ns/shop/sa/orders`, with the administration interface:

1. **Open the Authorization API**, once per tenant: a resource server with the audience `urn:hodor:authorization` and the scopes `authz:evaluate`, `authz:simulate` and `authz:explain`, on an application of the tenant ([who may ask](../architecture/contexts/authorization.md#who-may-ask)).
2. **Trust the mesh's trust domain**, `cluster.local`, by its bundle or as checked by the mesh ([trust domains](../architecture/contexts/keys.md#trust-domains)), and run Hodor behind its proxy with `HODOR_CLIENT_IDENTITY_HEADER` ([the identity of a workload](install-on-kubernetes.md#the-identity-of-a-workload)).
3. **A service account for the adapter**, `POST /service-accounts`, which holds no role.
4. **One client per protected application**: in the application Orders, a confidential client with the grant `client_credentials`, the method `spiffe_x509`, the service account as `principal`, the adapter's identity, here `spiffe://cluster.local/ns/hodor/sa/hodor-ext-authz`, as `spiffe_id`, and `authz:evaluate` among its scopes. The application has a resource server of its own, whose permissions and roles decide.
5. **The application's entry in the configuration**, with the workload's identity as `destination`, the client's `client_id`, the audience of the application's resource server as `audience`, and the route rules.

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
  "token": "bearer",
  "applications": [
    {
      "destination": "spiffe://cluster.local/ns/shop/sa/orders",
      "client_id": "0193f1c2-6a1d-7c55-b0c8-6b1f2c9d4e01",
      "audience": "https://orders.example.com",
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
| `hodor.issuer` | The tenant's issuer, as tokens name it in `iss`: Hodor's public address followed by `/t/<slug>`. Default: `hodor.url` followed by `/t/<slug>`, right only when the two addresses are the same. The key set is read at `hodor.url` whatever the issuer is |
| `hodor.timeout_milliseconds` | How long one call to Hodor may take, the fetch of the key set included, from 1 to 60000, default 1000. Keep it under the proxy's own timeout for the check |
| `token` | `"bearer"`: the bearer token in `Authorization` is read, and its signature checked against the tenant's key set. `{"header": "<name>"}` and `{"metadata": {"namespace": …, "key": …}}`, written before, mean the same with one more rule each ([the subject](#the-subject)). Left out: no token is read, and the subject is always the caller's identity |
| `applications[].destination` | The protected workload's identity, as Envoy gives it in `destination.principal`. Each one once |
| `applications[].client_id` | The application's client, bound to the adapter's identity |
| `applications[].audience` | The audience of the application's resource server, as tokens for it name it in `aud`. Required, and not empty, even with no `token`, so that reading claims later never skips the check: claims whose `aud` does not hold it are denied |
| `applications[].routes` | The route rules, in order. May be empty when every route sends context per route |

The file is read once when the process starts. A file that does not read, or breaks a rule above, stops the process with a message saying why, before it listens. A change takes a restart.

## When it denies

**Every failure is a denial.** Hodor unreachable, or slower than `timeout_milliseconds`; an answer that is not `200`, or not JSON with a `decision`; a decision other than `ALLOW`, `INDETERMINATE` included; a destination with no entry, a route with no rule, a token whose signature fails, a key set that cannot be fetched, claims that fail, no subject. Failing open stays what it is in Hodor: a choice per action of [the engine binding](../architecture/contexts/authorization.md#bindings), made and recorded there ([Threat-Mesh-06](../security/threat-model.md#service-meshes-and-certificates)).

**The answer to the proxy is always a well-formed check response**: `OK` to allow, `PERMISSION_DENIED` with an HTTP `403` and no body to deny, never a gRPC error. Every denial is the same answer, whether Hodor denied or the token failed before Hodor was asked, so the answer tells a caller nothing of why. Set the proxy's own failure mode to deny all the same, for when `hodor-ext-authz` itself cannot be reached: `failOpen: false` in Istio, the default; `failure_mode_allow: false` in Envoy, the default.

The reason of each denial is logged, at `info` for a denial and at `warn` when Hodor gave no decision, with the destination and the decision identifier when Hodor gave one, never the token. It is never sent to the caller. The metric `hodor.ext_authz.checks` counts checks by `outcome`, `allowed`, `denied` or `failed`, and `hodor.ext_authz.check.duration` measures them, in seconds.

## Latency

`hodor-ext-authz` keeps no decision ([Decision 0029](../decisions/0029-hodor-in-a-service-mesh.md#decisions-are-asked-through-hodor-ext-authz-a-binary-of-its-own)), so each check waits for one `evaluate`. The target is that of Open Policy Agent sidecars, 15 ms at the 99th percentile, before a cache is considered.

Measured on 25 November 2026 on an Apple M3 Max laptop that ran everything at once, while other builds and tests kept it busy (a load average between 26 and 44 during the run), after the decision path of `evaluate` was cut to fewer round trips to the database: the server and the adapter built for release, PostgreSQL in a container of Docker Desktop, a role of the native engine deciding, 2000 checks one after the other after 200 to warm up.

| | 50th percentile | 99th percentile |
|---|---|---|
| A check through `hodor-ext-authz` | 11.11 ms | 29.73 ms |
| `evaluate` called directly | 10.86 ms | 31.41 ms |

The adapter adds about 0.25 ms at the 50th percentile to what `evaluate` itself takes; at the 99th the two differ by less than the machine's own noise. The target of 15 ms at the 99th percentile is not met on this machine, and `evaluate` alone does not meet it either: most of the time is Hodor's own, reading the token's register, the roles and the binding, and writing the record of decisions, on a database reached through Docker Desktop's virtual machine on a busy laptop. A measurement on a quiet machine with its own database, and in a mesh, is still to be made: the demonstration of Milestone 11 runs every check through a mesh, on a shared machine of continuous integration, and does not time them. A cache of decisions is considered only after it. No mesh was in the way here: a sidecar on each side adds its own hops. To measure again:

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

These examples run in continuous integration, in [the demonstration of Milestone 11](quick-start.md#the-demonstration-of-milestone-11), on kind with Istio 1.30.8, and with Envoy Gateway 1.10.0 in front of Linkerd. [The service mesh guide](service-mesh.md) shows them with the rest of what Istio needs, does the same for ambient mode, Consul and Envoy Gateway, and says what was tried for each.

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

The token checked by the proxy. `hodor-ext-authz` checks it too, with `"token": "bearer"`, since the sidecar asks it before `RequestAuthentication` runs:

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
```

`audiences` makes the proxy refuse a token for another application too. `hodor-ext-authz` checks the signature and the audience either way, so leaving either out lets no such token in; `forwardOriginalToken` passes the token on to Orders and to a check asked after it.

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
