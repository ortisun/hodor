# Installing on Kubernetes

Hodor on a Kubernetes cluster, installed with [Helm](https://helm.sh/): several servers behind one Service, the workers beside them, and a job that migrates the database before every install and upgrade. To run it on one machine instead, see [installing with Docker](install-with-docker.md).

The chart is in `deploy/install/helm/hodor/`. It installs Hodor and nothing around it: the database, the mail server and the Secret with the passwords are yours, and exist before the chart is installed. To try the chart without them, [a file beside the chart](#trying-the-chart-on-a-cluster-of-your-own) provides stand-ins.

> Hodor itself is still being built. [What is not built yet](../product/progress.md#known-gaps-in-what-is-done) applies to every installation, and [what the chart does not do yet](#what-the-chart-does-not-do-yet) is at the end of this page. Read both before real accounts depend on it.

## What the chart creates

| Resource | Name | What it is |
|---|---|---|
| Job | `<release>-migration` | Runs before every install and upgrade, as a Helm hook: `hodor-cli migrate` as the owner of the schema, then `hodor-cli tenant create-system`. The servers and workers are created after it succeeds |
| Deployment | `<release>-server` | `hodor-server`, three replicas by default, spread across zones and nodes. A new server is ready before an old one stops |
| Deployment | `<release>-worker` | `hodor-worker`, two replicas by default. Workers share the work without a leader |
| Service | `<release>` | The servers' public port, 8080. The operations port is not in it |
| PodDisruptionBudget | `<release>-server`, `<release>-worker` | At most one of each is taken down at a time by a planned disruption |
| ServiceAccount | `<release>` | Carries no token: Hodor never talks to the Kubernetes interface |
| Ingress | `<release>` | Only with `ingress.enabled`: routes the name in `publicUrl` to the Service |
| HorizontalPodAutoscaler | `<release>-server` | Only with `server.autoscaling.enabled`: adds servers as processor use grows |
| NetworkPolicy | `<release>` | Only with `networkPolicy.enabled`: who may reach the servers, and optionally where Hodor's pods may connect |
| Deployment, Service, ServiceAccount, ConfigMap, PodDisruptionBudget | `<release>-ext-authz` | Only with `extAuthz.enabled`: [`hodor-ext-authz`](hodor-ext-authz.md), from its own image, two replicas by default, its gRPC port 9191 in the Service. Its service account gives it its mesh identity. See [Envoy's external authorization](#envoys-external-authorization) |
| CustomResourceDefinition, Deployment, ServiceAccount, ClusterRole, ClusterRoleBinding, ConfigMap | `<release>-cert-manager-issuer` | Only with `certManagerIssuer.enabled`: [`hodor-cert-manager-issuer`](hodor-cert-manager-issuer.md), from its own image, one replica, with the kinds `HodorIssuer` and `HodorClusterIssuer` and what it may do in the cluster. See [cert-manager's issuer](#cert-managers-issuer) |

Every pod runs as a user that is not root, with a read-only file system, no Linux capability, no privilege escalation and the default seccomp profile, which the `restricted` Pod Security Standard asks for. The three health checks of [deployment](deployment.md#kubernetes-reference), `/startupz`, `/readyz` and `/livez`, are wired to the operations port.

## What you need

| What | Why |
|---|---|
| A Kubernetes cluster, version 1.27 or newer, and `kubectl` | Where Hodor runs |
| Helm 3 or newer | To install the chart |
| The published image, or a registry of your own | From 0.3.0, the cluster pulls `ghcr.io/ortisun/hodor`. For an earlier version, you build the image and push it to a registry the cluster can pull from |
| A PostgreSQL database, version 16 or newer, reachable from the cluster | Everything Hodor knows is there. A managed service with a standby and point-in-time recovery, as [deployment](deployment.md#database) describes |
| A way in: an ingress controller, or a gateway of your own, serving HTTPS | The session cookie is marked `Secure`, and browsers do not send it over plain HTTP |
| A mail server that accepts messages over SMTP | For the links that verify an address and recover a password |

Run every command of this page from the root of a checkout of the repository; the [quick-start](quick-start.md#0-get-the-code) says how to get one. The commands use the namespace `hodor` and the release name `hodor`.

## 1. Get the image

From 0.3.0, every release publishes its image, `ghcr.io/ortisun/hodor:<version>`, and the chart uses it unless `image.repository` says otherwise. There is nothing to do in this step. To check its signature first, see [what a release publishes](../security/supply-chain.md#what-a-release-publishes).

For an earlier version, or for a checkout of `develop`, build the image and push it to your registry. Replace `registry.example.com` with your registry, here and in the steps that follow:

```bash
docker build --file deploy/docker/Dockerfile --tag registry.example.com/hodor:0.3.0 .
```

```bash
docker push registry.example.com/hodor:0.3.0
```

## 2. Prepare the database

Hodor never connects as the owner of its tables: [database roles](../development/local-setup.md#database-roles) explains the four roles and why. Create them and the database as an administrator of PostgreSQL, with a password of your own for each; the owner needs no special privilege:

```sql
CREATE ROLE hodor_app NOLOGIN;
CREATE ROLE hodor_platform NOLOGIN;
CREATE ROLE hodor_owner LOGIN PASSWORD 'owner-password';
CREATE ROLE hodor_server LOGIN PASSWORD 'server-password' IN ROLE hodor_app;
CREATE ROLE hodor_worker LOGIN PASSWORD 'worker-password' IN ROLE hodor_app;
CREATE ROLE hodor_worker_platform LOGIN PASSWORD 'worker-platform-password' IN ROLE hodor_platform;
CREATE DATABASE hodor OWNER hodor_owner;
```

On Kubernetes the role names are yours to choose, since each connection address is given whole in the next step. What matters is the membership: the server's role and one of the worker's in `hodor_app`, the worker's other role in `hodor_platform`.

## 3. Create the Secret

The chart never takes a password or a key as a value: it reads them from one Secret, by name. Create the namespace:

```bash
kubectl create namespace hodor
```

Make the key that keeps the secrets of identity providers encrypted. It is written after an identifier of your choice, as `identifier:key`; [secrets at rest](../security/secrets-at-rest.md#root-keys) explains the format and how to change the key later:

```bash
docker run --rm --entrypoint /usr/local/bin/hodor-cli registry.example.com/hodor:0.3.0 secrets generate-key
```

Then create the Secret, with your own addresses, passwords and key in place of the examples:

```bash
kubectl create secret generic hodor --namespace hodor \
  --from-literal=owner-database-url='postgres://hodor_owner:owner-password@database.example.com:5432/hodor?sslmode=verify-full' \
  --from-literal=server-database-url='postgres://hodor_server:server-password@database.example.com:5432/hodor?sslmode=verify-full' \
  --from-literal=worker-database-url='postgres://hodor_worker:worker-password@database.example.com:5432/hodor?sslmode=verify-full' \
  --from-literal=worker-platform-database-url='postgres://hodor_worker_platform:worker-platform-password@database.example.com:5432/hodor?sslmode=verify-full' \
  --from-literal=secret-keys='2026-11:the-key-printed-above' \
  --from-literal=smtp-url='smtps://user:password@mail.example.com:465'
```

| Key | Read by | What it holds |
|---|---|---|
| `owner-database-url` | The migration job only | Connection address of the role that owns the schema |
| `server-database-url` | The servers, and the migration job to create the system tenant | Connection address of the server's role |
| `worker-database-url` | The workers | Connection address of the worker's role in `hodor_app` |
| `worker-platform-database-url` | The workers | Connection address of the worker's role in `hodor_platform` |
| `secret-keys` | The servers and the workers | `HODOR_SECRET_KEYS`: one or more `identifier:key` pairs, separated by commas. The workers make the tenants' signing keys with them, and the servers use those keys |
| `smtp-url` | The workers, with `mail.enabled` | Address of the mail server |
| `openbao-role-id`, `openbao-secret-id` | The servers and the workers, when they sign in to OpenBao with an AppRole | The identifiers of Hodor's AppRole: [keys in OpenBao](keys-in-openbao.md) |

A password written into an address must be made of letters and digits, or be percent-encoded. A tool that manages secrets in the cluster can make this Secret instead of `kubectl`; `secret.keys` renames the keys if it needs other names.

## 4. Install the chart

Write your settings in a file, `hodor-values.yaml`. Two have no default: the address people use, and the name of the Secret. With an image you built, also set `image.repository` to where you pushed it.

```yaml
publicUrl: https://login.example.com
secret:
  name: hodor
mail:
  enabled: true
  from: "Hodor <no-reply@example.com>"
ingress:
  enabled: true
  className: nginx
```

From 0.3.0, install the published chart of the version you want:

```bash
helm install hodor oci://ghcr.io/ortisun/charts/hodor --version 0.3.0 --namespace hodor --values hodor-values.yaml --wait
```

For an earlier version, or a checkout of `develop`, install the chart from the checkout:

```bash
helm install hodor deploy/install/helm/hodor --namespace hodor --values hodor-values.yaml --wait
```

The command returns when the migration job has succeeded and every server and worker is ready. If it does not, the job's log usually says why:

```bash
kubectl logs --namespace hodor job/hodor-migration --all-containers
```

## 5. Create a tenant and its first administrator

The command-line tool is in the image, and a server pod already has the settings it needs. Create a tenant:

```bash
kubectl exec --namespace hodor deployment/hodor-server -- /usr/local/bin/hodor-cli tenant create --slug acme --name "Acme"
```

Its pages are at `/t/acme/account` under your address. Make someone its first administrator; the command prints an access token for the [administration interface](../api/admin-api.md), once:

```bash
kubectl exec --namespace hodor deployment/hodor-server -- /usr/local/bin/hodor-cli admin bootstrap --tenant acme --email you@example.com
```

[A tenant and its first administrator](../examples/first-tenant-and-administrator.md) continues from here. Its commands are written for the development stack; here, `kubectl exec --namespace hodor deployment/hodor-server -- /usr/local/bin/hodor-cli` takes the place of the longer command that starts each of them.

## Settings

`deploy/install/helm/hodor/values.yaml` lists every setting with its meaning. The ones most installations touch:

| Setting | Default | Meaning |
|---|---|---|
| `image.repository`, `image.tag` | `ghcr.io/ortisun/hodor`; the version of the chart | Where the image is, and which version runs |
| `publicUrl` | None | The address people use: `https://`, the name, no path |
| `secret.name` | None | The Secret of [step 3](#3-create-the-secret) |
| `server.replicas` | `3` | Servers, when autoscaling is off |
| `server.autoscaling.enabled` | `false` | Adds servers between `minReplicas` and `maxReplicas` as average processor use passes `targetProcessorUtilizationPercentage`. Needs the cluster's metrics server |
| `server.passwordHashConcurrency` | `4` | Password hashes one server computes at once. Each uses about 19 MiB, so this value times 19 MiB must fit under `server.resources.limits.memory` with room for the rest |
| `server.resources`, `worker.resources` | 500m and 256Mi to 512Mi; 100m and 128Mi to 512Mi | Requests and limits. The worker's limit leaves room for one run of `opa`, which checks policies and is bounded only by it |
| `worker.replicas` | `2` | Workers |
| `mail.enabled`, `mail.from` | `false` | Whether messages are delivered, and the address they come from |
| `directoryHosts` | Empty | The LDAP directories identity providers may name, each as `host:port` |
| `telemetry.metricsEndpoint`, `telemetry.tracesEndpoint` | Empty | Where metrics and traces are sent over OTLP/HTTP. [Deployment](deployment.md#observability) says what is sent |
| `ingress.enabled`, `ingress.className`, `ingress.annotations`, `ingress.tls` | `false` | The Ingress for the name in `publicUrl`. The certificate is read from the Secret `ingress.tls.secretName`, `<release>-tls` when empty, which a certificate manager can fill |
| `networkPolicy.enabled` | `false` | See [network policy](#network-policy) |
| `trustedProxies`, `forwardedHeader` | Empty; `x-forwarded-for` | The address ranges of the ingress controller and of any load balancer in front of it, and the header they write, or `none`. See [the address of each client](#the-address-of-each-client) |
| `clientIdentityHeader` | Empty | The header a trusted proxy writes the caller's identity into: `client-cert`, `x-forwarded-client-cert` or `l5d-client-id`. See [the identity of a workload](#the-identity-of-a-workload) |
| `keyProvider.signingKeys` | `local` | Where new signing keys are made: `local`, or `openbao`, which needs `keyProvider.openbao.enabled`. See [keys in OpenBao](keys-in-openbao.md) |
| `keyProvider.openbao.enabled`, `address`, `transitMount` | `false`; none; `hodor-transit` | Whether the servers and workers use OpenBao, its address, and Hodor's Transit mount. Keep it enabled while a key made there may sign |
| `keyProvider.openbao.authMethod` | `kubernetes` | `kubernetes`: the pods present a token of the release's service account made for the audience `keyProvider.openbao.tokenAudience` alone, mounted for that purpose, under the role `kubernetesRole`. `approle`: the identifiers in the Secret |
| `keyProvider.openbao.certificateAuthority.configMap`, `key` | Empty; `ca.crt` | A ConfigMap holding the certificate of the authority that issued OpenBao's certificate. Set, only that authority is trusted for OpenBao |
| `outboundAuthorities.configMap`, `outboundAuthorities.key` | Empty; `authorities.pem` | A ConfigMap of yours whose key holds the certificates, in PEM, of the authorities Hodor's outbound requests trust in place of the image's, for an identity provider or a bundle endpoint served under an authority of your own. It replaces them all: [the authorities it trusts](../security/outbound-http.md#the-authorities-it-trusts) |
| `extAuthz.enabled` | `false` | Installs `hodor-ext-authz`. See [Envoy's external authorization](#envoys-external-authorization) |
| `certManagerIssuer.enabled` | `false` | Installs `hodor-cert-manager-issuer`. See [cert-manager's issuer](#cert-managers-issuer) |

Changing the Secret does not restart anything. After changing it, restart the pods so that they read it again:

```bash
kubectl rollout restart --namespace hodor deployment/hodor-server deployment/hodor-worker
```

### Network policy

With `networkPolicy.enabled`, one policy applies to every pod of the release:

- **In**: only the servers' public port accepts connections, from the peers listed in `networkPolicy.ingressFrom`, or from anywhere in the cluster when the list is empty. Nothing can connect to a worker or to the migration job. The health checks still work, because the kubelet that runs them is not subject to network policies.
- **Out**: unrestricted, unless `networkPolicy.egress.enabled` is set. Then the pods reach the cluster's name service and what `networkPolicy.egress.to` lists, and nothing else. List the database, the mail server, the collector of metrics and traces, the identity providers and directories your tenants use, and OpenBao when the keys are there.

A cluster enforces network policies only if its network plugin does.

### The address of each client

Hodor limits sign-in attempts by the [client address](../api/api-spec.md#the-client-address). Behind an Ingress, the connection Hodor sees comes from the ingress controller, so everyone shares one limit until the ingress controller is named in `trustedProxies`:

```yaml
trustedProxies:
  - 10.244.0.0/16
networkPolicy:
  enabled: true
  ingressFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
```

- **Name the range the ingress controller's pods get their addresses from.** That is usually the cluster's pod range, here `10.244.0.0/16`, the default of kind.
- **Turn on the network policy so that only the ingress controller can connect.** The pod range also holds every other pod of the cluster, and any of them could otherwise write the header.
- **The ingress controller must see the client's own address.** Behind a cloud load balancer, that takes the load balancer's PROXY protocol or a service with `externalTrafficPolicy: Local`, as your ingress controller's documentation describes. Otherwise it forwards the address of a node.

#### Inside a service mesh

A service mesh that puts a sidecar in Hodor's pods, as Istio does in its sidecar mode and as Linkerd does, changes what Hodor sees. Every connection then comes from the sidecar in Hodor's own pod: from `127.0.0.6` with Istio, from the pod itself with Linkerd. The sidecar passes `X-Forwarded-For` on as the caller wrote it, without checking it.

**Never name the sidecar's address in `trustedProxies`.** Every request reaches Hodor through the sidecar, so every workload that can reach Hodor would choose its own address, and the limits on sign-in attempts would count whatever it wrote.

Telling the ingress controller from other callers by their identity in the mesh is planned, as [Hodor runs inside a mesh too](../decisions/0029-hodor-in-a-service-mesh.md#hodor-runs-inside-a-mesh-too) says (Issue-112), and not built yet. Until it is, choose one of these:

| Choice | What it takes | What it gives |
|---|---|---|
| Keep Hodor's pods out of the mesh | Install Hodor in a namespace the mesh does not inject. With Istio, no `istio-injection` or `istio.io/rev` label on it; with Linkerd, no `linkerd.io/inject` annotation | The rules above hold as written. Connections to Hodor are not mutual TLS of the mesh; the network policy is what limits who connects |
| Istio's ambient mode instead of sidecars | Hodor's namespace in ambient mode, with no waypoint in front of Hodor | ztunnel keeps the caller's own address, so the ingress controller's pod range is named as above |
| Leave `trustedProxies` empty | Nothing | Safe, but everyone shares one limit on sign-in attempts, as with no proxy named |

Behind a waypoint of Istio's ambient mode, what address Hodor sees has not been checked. Treat a waypoint as a sidecar until it has.

### The identity of a workload

A workload of a service mesh can get a token with no secret, with the certificate its sidecar presents or the identity Linkerd asserts ([an identity forwarded by a proxy](../architecture/contexts/oauth.md#an-identity-forwarded-by-a-proxy)). Hodor reads it from a header the proxy in front of it writes, only when `clientIdentityHeader` names that header and only from the proxies of `trustedProxies` ([the caller's identity from a proxy](../api/api-spec.md#the-callers-identity-from-a-proxy)).

```yaml
trustedProxies:
  - 127.0.0.6
forwardedHeader: none
clientIdentityHeader: x-forwarded-client-cert
```

- **Name only the proxy that ends the workload's mutual TLS**, here Istio's sidecar, which connects to Hodor from `127.0.0.6`, and only if it replaces or appends to the header a caller sends. Linkerd's proxy connects from inside the pod as well, and removes any `l5d-client-id` a caller sent: name the address it connects from. The service mesh guide will say which address each mesh uses, as tried (Issue-113).
- **Set `forwardedHeader` to `none` when the sidecar is named.** A sidecar passes `X-Forwarded-For` as the caller wrote it, so any workload could choose its own address. With `none`, every caller is known by the sidecar's address and shares one limit on sign-in attempts, until the forwarded address can be read from named gateways only (Issue-112).
- **Give the tenant the workload's trust domain**: by its bundle, so that the forwarded certificate is checked against it, or as checked by the mesh, which is needed when the proxy forwards only the names of the certificate, as Istio does by default, or the Linkerd identity.

[The demonstration of Milestone 10](quick-start.md#the-demonstration-of-milestone-10) installs the chart this way on a kind cluster with Istio and SPIRE, and checks it: Istio's sidecar does connect to Hodor from `127.0.0.6`, takes away an `X-Forwarded-Client-Cert` sent by a caller outside the mesh, and forwards the names and the `Hash` of the certificate of a caller inside it. Its settings are in `deploy/demo/workload-identity/hodor-values.yaml`.

### Envoy's external authorization

With `extAuthz.enabled`, the chart installs [`hodor-ext-authz`](hodor-ext-authz.md), which lets the proxies of a service mesh ask Hodor's decisions. It runs from its own image, `ghcr.io/ortisun/hodor-ext-authz`, as a Kubernetes service account of its own, `<release>-ext-authz`, so that its mesh identity is its own: in Istio, `spiffe://<trust domain>/ns/<namespace>/sa/<release>-ext-authz`. Its configuration file is written from the values into a ConfigMap, and a change of the values restarts its pods.

```yaml
extAuthz:
  enabled: true
  tenant: acme
  token:
    header: x-hodor-token-claims
  applications:
    - destination: spiffe://cluster.local/ns/shop/sa/orders
      clientId: 0193f1c2-6a1d-7c55-b0c8-6b1f2c9d4e01
      routes:
        - methods: [GET]
          path: /orders/{id}
          resourceType: order
          action: read
```

| Setting | Default | Meaning |
|---|---|---|
| `extAuthz.image.repository`, `extAuthz.image.tag` | `ghcr.io/ortisun/hodor-ext-authz`; the version of the chart | Where its image is, and which version runs |
| `extAuthz.replicas` | `2` | Replicas. Each answers alone, keeping nothing but its access tokens |
| `extAuthz.tenant` | None | The tenant's slug. Required when enabled |
| `extAuthz.hodorUrl` | The release's Service, `http://<release>.<namespace>.svc.cluster.local:8080` | Where it reaches Hodor |
| `extAuthz.issuer` | `publicUrl` followed by `/t/<tenant>` | The tenant's issuer, which `iss` must name |
| `extAuthz.timeoutMilliseconds` | `1000` | How long one call to Hodor may take before the request is denied |
| `extAuthz.token` | Empty | Where the checked token's claims are: `metadata` with `namespace` and `key`, or `header`. Empty: the subject is always the caller's identity |
| `extAuthz.applications` | Empty | One entry per protected application: `destination`, `clientId` and `routes`, each route with `methods`, `path`, `resourceType` and `action`, as [the configuration](hodor-ext-authz.md#configuration) says |
| `extAuthz.serviceAccount.name`, `extAuthz.serviceAccount.annotations` | `<release>-ext-authz` | Its Kubernetes service account. `extAuthz.serviceAccount.create: false` uses one that exists |
| `extAuthz.service.port` | `9191` | The gRPC port of its Service, which the mesh's provider names |
| `extAuthz.resources` | 100m and 32Mi to 128Mi | Requests and limits |
| `extAuthz.networkPolicy.ingressFrom` | Empty | With `networkPolicy.enabled`, who may reach its gRPC port, as network policy peers. Empty: anyone in the cluster. Name the namespaces of the protected applications, whose proxies call it |
| `extAuthz.podAnnotations`, `extAuthz.extraEnvironment`, `extAuthz.nodeSelector`, `extAuthz.tolerations`, `extAuthz.affinity` | Empty | As for the server. The annotations are where a mesh's sidecar is asked for, when the namespace does not ask for it already |

With `networkPolicy.enabled` and `networkPolicy.egress.enabled`, its pods may also reach the servers' public port. Setting up the tenant, the service account and the clients it uses is in [setting it up in Hodor](hodor-ext-authz.md#setting-it-up-in-hodor).

### cert-manager's issuer

With `certManagerIssuer.enabled`, the chart installs [`hodor-cert-manager-issuer`](hodor-cert-manager-issuer.md), which signs the intermediates cert-manager keeps for the tenant's meshes through the tenant's certificate authority. It runs from its own image, `ghcr.io/ortisun/hodor-cert-manager-issuer`, as a Kubernetes service account of its own, `<release>-cert-manager-issuer`, bound to the one ClusterRole of [what it may do in the cluster](hodor-cert-manager-issuer.md#what-it-may-do-in-the-cluster). Its configuration file is written from the values into a ConfigMap, and a change of the values restarts its pod. cert-manager must be installed first, with its feature gate `UseCertificateRequestBasicConstraints` on, so that the requests it writes ask for an authority ([what it signs](hodor-cert-manager-issuer.md#what-it-signs)).

Beside Hodor, proving who it is with its mesh identity:

```yaml
certManagerIssuer:
  enabled: true
  tenant: acme
  clientId: 0193f3c0-2d4e-7b1a-9c55-6b1f2c9d4e01
  podAnnotations:
    linkerd.io/inject: enabled
```

Alone, in a cluster of meshes where Hodor does not run, proving who it is with its key:

```bash
helm install hodor-issuer deploy/install/helm/hodor --namespace cert-manager \
  --set certManagerIssuer.enabled=true --set certManagerIssuer.only=true \
  --set certManagerIssuer.tenant=acme --set certManagerIssuer.hodorUrl=https://login.example.com \
  --set certManagerIssuer.clientId=0193f3c0-2d4e-7b1a-9c55-6b1f2c9d4e01 \
  --set certManagerIssuer.authentication.method=private_key_jwt \
  --set certManagerIssuer.authentication.privateKeyJwt.secretName=hodor-cert-manager-issuer-key
```

| Setting | Default | Meaning |
|---|---|---|
| `certManagerIssuer.only` | `false` | The release holds the issuer alone: no migration, server, worker or Service of Hodor, and none of Hodor's own values needed |
| `certManagerIssuer.image.repository`, `certManagerIssuer.image.tag` | `ghcr.io/ortisun/hodor-cert-manager-issuer`; the version of the chart | Where its image is, and which version runs |
| `certManagerIssuer.tenant` | None | The tenant's slug. Required when enabled |
| `certManagerIssuer.hodorUrl` | The release's Service, `http://<release>.<namespace>.svc.cluster.local:8080` | Where it reaches Hodor. Required with `only` |
| `certManagerIssuer.issuer` | `publicUrl` followed by `/t/<tenant>`; with `only`, `hodorUrl` followed by `/t/<tenant>` | The tenant's issuer, which its assertions name |
| `certManagerIssuer.timeoutMilliseconds` | `10000` | How long one call to Hodor may take |
| `certManagerIssuer.clientId` | None | Its client in Hodor. Required when enabled |
| `certManagerIssuer.authentication.method` | `forwarded` | `forwarded`: its mesh identity; `private_key_jwt`: its key |
| `certManagerIssuer.authentication.privateKeyJwt.secretName`, `key`, `keyId` | None; `key.pem`; empty | For `private_key_jwt`: the Secret holding its key in PEM, the key of the Secret, and the key's `kid` among the client's keys |
| `certManagerIssuer.customResourceDefinitions` | `true` | Whether the chart defines `HodorIssuer` and `HodorClusterIssuer`. `false` when another release of the cluster defines them |
| `certManagerIssuer.approveWithCertManager.enabled`, `serviceAccount`, `namespace` | `false`; `cert-manager`; `cert-manager` | Lets cert-manager's own approver approve every request of Hodor's two kinds. Prefer approver-policy: [who may have an intermediate signed](hodor-cert-manager-issuer.md#who-may-have-an-intermediate-signed) |
| `certManagerIssuer.serviceAccount.name`, `certManagerIssuer.serviceAccount.annotations` | `<release>-cert-manager-issuer` | Its Kubernetes service account. `certManagerIssuer.serviceAccount.create: false` uses one that exists |
| `certManagerIssuer.resources` | 50m and 32Mi to 128Mi | Requests and limits |
| `certManagerIssuer.podAnnotations`, `certManagerIssuer.extraEnvironment`, `certManagerIssuer.nodeSelector`, `certManagerIssuer.tolerations`, `certManagerIssuer.affinity` | Empty | As for the server. The annotations are where a mesh's sidecar is asked for, when the namespace does not ask for it already |

With `networkPolicy.enabled` and `networkPolicy.egress.enabled`, its pod may also reach the servers' public port; list the Kubernetes interface's address in `networkPolicy.egress.to`, since the issuer watches it. Setting up the tenant, the service account and the client it uses is in [setting it up in Hodor](hodor-cert-manager-issuer.md#setting-it-up-in-hodor). Uninstalling the release removes the two kinds, and every `HodorIssuer` and `HodorClusterIssuer` with them.

## Upgrading

1. With a published version, there is nothing to build. With an image of your own, build and push the image of the new version, as in [step 1](#1-get-the-image).
2. Upgrade the release with the same values, and the chart of the new version. The published chart:

```bash
helm upgrade hodor oci://ghcr.io/ortisun/charts/hodor --version 0.3.0 --namespace hodor --values hodor-values.yaml --wait
```

Or the chart of a checkout at the new version:

```bash
helm upgrade hodor deploy/install/helm/hodor --namespace hodor --values hodor-values.yaml --wait
```

If [deployment](deployment.md#upgrades) lists a command for the version you upgraded from, run it in a server once the upgrade is done. From 0.1.0:

```bash
kubectl exec --namespace hodor deployment/hodor-server -- /usr/local/bin/hodor-cli secrets reseal
```

The migration job runs first, against the database the old servers are still using; then the servers and workers are replaced one at a time. Upgrade one release at a time: [deployment](deployment.md#upgrades) explains why the migrations allow that and no more. Going back within one release is `helm rollback`.

## Uninstalling

```bash
helm uninstall hodor --namespace hodor
```

This removes what the chart created, the last migration job aside, which Helm leaves. The database, the Secret and the namespace are yours and are not touched.

## Trying the chart on a cluster of your own

`deploy/install/helm/evaluation.yaml` stands in for what a real installation brings: a PostgreSQL with Hodor's roles, a mail server that delivers nothing and shows what it received, and the Secret, named `hodor-evaluation`. **Every password and the encryption key in it are written in the repository.** It is for a cluster on your machine and nothing else.

With [kind](https://kind.sigs.k8s.io/), which runs a cluster in Docker, build the image and load it into the cluster:

```bash
kind create cluster --name hodor
```

```bash
docker build --file deploy/docker/Dockerfile --tag hodor:0.3.0 .
```

```bash
kind load docker-image hodor:0.3.0 --name hodor
```

Create the namespace and the stand-ins, and wait for the database:

```bash
kubectl create namespace hodor
```

```bash
kubectl apply --namespace hodor --filename deploy/install/helm/evaluation.yaml
```

```bash
kubectl rollout status --namespace hodor statefulset/hodor-evaluation-database
```

Install the chart, pointed at them:

```bash
helm install hodor deploy/install/helm/hodor --namespace hodor --set image.repository=hodor --set publicUrl=http://localhost:8080 --set secret.name=hodor-evaluation --set mail.enabled=true --set mail.from="Hodor <no-reply@hodor.localhost>" --wait
```

Create a tenant that lets people register:

```bash
kubectl exec --namespace hodor deployment/hodor-server -- /usr/local/bin/hodor-cli tenant create --slug acme --name "Acme" --open-registration
```

Reach Hodor from your machine, leaving this command running:

```bash
kubectl port-forward --namespace hodor service/hodor 8080:8080
```

The tenant's pages are at <http://localhost:8080/t/acme/account>, in Chromium, Chrome, Edge or Firefox; Safari refuses the session cookie over plain HTTP. To read the messages Hodor sends, forward the mail server's page the same way, in another terminal, and open <http://localhost:8025>:

```bash
kubectl port-forward --namespace hodor service/hodor-evaluation-mail 8025:8025
```

When you are done, delete the cluster:

```bash
kind delete cluster --name hodor
```

## What the chart does not do yet

[Deployment](deployment.md) describes where the chart is heading. Against that page, this is missing:

| Missing | Until then |
|---|---|
| Trusting a forwarded address behind a mesh's sidecar | Hodor's pods stay out of the mesh, or Istio's ambient mode is used, as [inside a service mesh](#inside-a-service-mesh) says |
| Autoscaling on request concurrency | The autoscaler follows processor use only |
| Dashboards and alerts | Metrics and traces are sent where `telemetry` says; what is drawn and alerted from them is yours |
| The Open Policy Agent sidecar and Redis | Neither is used by Hodor yet: both belong to later phases of the [roadmap](../product/roadmap.md) |
