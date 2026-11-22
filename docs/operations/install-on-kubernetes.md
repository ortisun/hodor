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

Every pod runs as a user that is not root, with a read-only file system, no Linux capability, no privilege escalation and the default seccomp profile, which the `restricted` Pod Security Standard asks for. The three health checks of [deployment](deployment.md#kubernetes-reference), `/startupz`, `/readyz` and `/livez`, are wired to the operations port.

## What you need

| What | Why |
|---|---|
| A Kubernetes cluster, version 1.27 or newer, and `kubectl` | Where Hodor runs |
| Helm 3 or newer | To install the chart |
| A registry the cluster can pull from, and Docker to build | The image is built from this repository: no registry publishes one yet |
| A PostgreSQL database, version 16 or newer, reachable from the cluster | Everything Hodor knows is there. A managed service with a standby and point-in-time recovery, as [deployment](deployment.md#database) describes |
| A way in: an ingress controller, or a gateway of your own, serving HTTPS | The session cookie is marked `Secure`, and browsers do not send it over plain HTTP |
| A mail server that accepts messages over SMTP | For the links that verify an address and recover a password |

Run every command of this page from the root of a checkout of the repository; the [quick-start](quick-start.md#0-get-the-code) says how to get one. The commands use the namespace `hodor` and the release name `hodor`.

## 1. Build and push the image

Replace `registry.example.com` with your registry, here and in the steps that follow:

```bash
docker build --file deploy/docker/Dockerfile --tag registry.example.com/hodor:0.1.0 .
```

```bash
docker push registry.example.com/hodor:0.1.0
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
docker run --rm --entrypoint /usr/local/bin/hodor-cli registry.example.com/hodor:0.1.0 secrets generate-key
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

A password written into an address must be made of letters and digits, or be percent-encoded. A tool that manages secrets in the cluster can make this Secret instead of `kubectl`; `secret.keys` renames the keys if it needs other names.

## 4. Install the chart

Write your settings in a file, `hodor-values.yaml`. Three have no default: where the image is, the address people use, and the name of the Secret.

```yaml
image:
  repository: registry.example.com/hodor
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
| `image.repository`, `image.tag` | None; the version of the chart | Where the image is, and which version runs |
| `publicUrl` | None | The address people use: `https://`, the name, no path |
| `secret.name` | None | The Secret of [step 3](#3-create-the-secret) |
| `server.replicas` | `3` | Servers, when autoscaling is off |
| `server.autoscaling.enabled` | `false` | Adds servers between `minReplicas` and `maxReplicas` as average processor use passes `targetProcessorUtilizationPercentage`. Needs the cluster's metrics server |
| `server.passwordHashConcurrency` | `4` | Password hashes one server computes at once. Each uses about 19 MiB, so this value times 19 MiB must fit under `server.resources.limits.memory` with room for the rest |
| `server.resources`, `worker.resources` | 500m and 256Mi to 512Mi; 100m and 128Mi to 256Mi | Requests and limits |
| `worker.replicas` | `2` | Workers |
| `mail.enabled`, `mail.from` | `false` | Whether messages are delivered, and the address they come from |
| `directoryHosts` | Empty | The LDAP directories identity providers may name, each as `host:port` |
| `telemetry.metricsEndpoint`, `telemetry.tracesEndpoint` | Empty | Where metrics and traces are sent over OTLP/HTTP. [Deployment](deployment.md#observability) says what is sent |
| `ingress.enabled`, `ingress.className`, `ingress.annotations`, `ingress.tls` | `false` | The Ingress for the name in `publicUrl`. The certificate is read from the Secret `ingress.tls.secretName`, `<release>-tls` when empty, which a certificate manager can fill |
| `networkPolicy.enabled` | `false` | See [network policy](#network-policy) |

Changing the Secret does not restart anything. After changing it, restart the pods so that they read it again:

```bash
kubectl rollout restart --namespace hodor deployment/hodor-server deployment/hodor-worker
```

### Network policy

With `networkPolicy.enabled`, one policy applies to every pod of the release:

- **In**: only the servers' public port accepts connections, from the peers listed in `networkPolicy.ingressFrom`, or from anywhere in the cluster when the list is empty. Nothing can connect to a worker or to the migration job. The health checks still work, because the kubelet that runs them is not subject to network policies.
- **Out**: unrestricted, unless `networkPolicy.egress.enabled` is set. Then the pods reach the cluster's name service and what `networkPolicy.egress.to` lists, and nothing else. List the database, the mail server, the collector of metrics and traces, and the identity providers and directories your tenants use.

A cluster enforces network policies only if its network plugin does.

## Upgrading

1. Build and push the image of the new version, as in [step 1](#1-build-and-push-the-image).
2. Get the chart of the same version: it is in the same checkout.
3. Upgrade the release with the same values:

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
docker build --file deploy/docker/Dockerfile --tag hodor:0.1.0 .
```

```bash
kind load docker-image hodor:0.1.0 --name hodor
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
| Trusting a forwarded client address | Hodor limits sign-in attempts by the address of the connection it sees, which behind an Ingress is the ingress controller's. Everyone shares one limit. [The interaction interface](../api/interaction-api.md) lists this as not built |
| Autoscaling on request concurrency | The autoscaler follows processor use only |
| Dashboards and alerts | Metrics and traces are sent where `telemetry` says; what is drawn and alerted from them is yours |
| The Open Policy Agent sidecar and Redis | Neither is used by Hodor yet: both belong to later phases of the [roadmap](../product/roadmap.md) |
| A published image, its software bill of materials and its signature | The image is built from the checkout and pushed to your registry |
| A published chart | The chart is installed from the checkout |
