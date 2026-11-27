# install

## Overview

The two packages Hodor is installed from, kept apart from the development stack in `../docker`: `docker/`, a Compose file for one machine, and `helm/`, a Helm chart for Kubernetes with a file of stand-ins for trying it. They use the image built by `../docker/Dockerfile` and share nothing else with the development stack. Neither holds a secret: the Compose file reads them from a file `.env` that git ignores, the chart from a Secret that exists before it is installed. The reasons are in `docs/decisions/0022-installation-packages.md`; how to use them is in `docs/operations/install-with-docker.md` and `docs/operations/install-on-kubernetes.md`, which are the specification.

## Interface

### `docker/` (no contract file)

- `compose.yaml`, project `name: hodor-install`. Services: `postgres` (`postgres:17-alpine`, profile `database`), `migrate` (`hodor-cli migrate`), `system-tenant` (`hodor-cli tenant create-system`), `server` (published on `127.0.0.1:${HODOR_HTTP_PORT:-8080}`), `worker`, `https` (`caddy:2.10-alpine`, profile `https`, ports 80 and 443, `caddy reverse-proxy --from ${HODOR_PUBLIC_URL} --to server:8080`) and `cli` (`hodor-cli`, profile `tools`, started only by `docker compose run`). Volumes: `postgres-data`, `https-data`, `https-configuration`.
- `.env.example`: every setting, copied to `.env`. Required, with no default: `HODOR_IMAGE`, `HODOR_PUBLIC_URL`, `HODOR_OWNER_DATABASE_PASSWORD`, `HODOR_SERVER_DATABASE_PASSWORD`, `HODOR_WORKER_DATABASE_PASSWORD`, `HODOR_SECRET_KEYS`. `COMPOSE_PROFILES` chooses the optional parts. `HODOR_DATABASE_ADDRESS`, `HODOR_DATABASE_NAME` and `HODOR_DATABASE_OPTIONS` point at a database that is not the container.
- `postgres-roles.sh`: mounted into `/docker-entrypoint-initdb.d/`; creates `hodor_app`, `hodor_platform`, `hodor_server`, `hodor_worker` and `hodor_worker_platform` with the passwords of the container's environment. It must stay executable.

### `helm/hodor/` (no contract file)

- `Chart.yaml`: `version` and `appVersion` equal the version of the workspace in `Cargo.toml`; `.github/workflows/ci.yml` (job `installation`) fails when they differ.
- `values.yaml`: every setting, documented in place. Required, with no default: `image.repository`, `publicUrl`, `secret.name`.
- `templates/`: `migration-job.yaml` (a `pre-install,pre-upgrade` hook: init container `migrate`, then container `system-tenant`), `server-deployment.yaml`, `worker-deployment.yaml`, `service.yaml`, `serviceaccount.yaml`, `disruption-budgets.yaml`, and, each behind a switch, `ingress.yaml`, `server-autoscaler.yaml`, `networkpolicy.yaml` (which also opens the port `grpc` of `hodor-ext-authz` to `extAuthz.networkPolicy.ingressFrom` and, with egress, lets it reach the servers) and `ext-authz.yaml` (`extAuthz.enabled`: the ConfigMap with `config.json` written from `extAuthz` by `hodor.extAuthzConfig`, the Deployment from the image `extAuthz.image`, restarted by a checksum of the configuration, the Service on port `grpc`, its own ServiceAccount `<release>-ext-authz` and a PodDisruptionBudget). Behind `certManagerIssuer.enabled`, `cert-manager-issuer.yaml` (the ConfigMap written by `hodor.certManagerIssuerConfig`, a Deployment of one replica with the `Recreate` strategy, its ServiceAccount, the ClusterRole that reads `certificaterequests` and both kinds and patches their status, its binding, and with `approveWithCertManager.enabled` the ClusterRole and binding that let cert-manager's approver approve for both kinds) and `cert-manager-issuer-kinds.yaml` (the CustomResourceDefinitions of `HodorIssuer` and `HodorClusterIssuer`, unless `customResourceDefinitions` is false). With `certManagerIssuer.only`, `hodor.installsHodor` renders nothing and every other template, the network policy and the notes on Hodor included, is left out, so that none of Hodor's own values is needed. `_helpers.tpl` holds the names, the labels, the security contexts, the health checks, the configuration of `hodor-ext-authz`, the checks of the required values (`extAuthz.tenant` when it is enabled), and the key providers' environment, mounts and volumes (`keyProvider`: a projected service account token for OpenBao's audience, the ConfigMap of OpenBao's authority, the AppRole's identifiers from the Secret), `hodor.certificateAuthorityEnvironment`, which sets the servers' `HODOR_CERTIFICATE_AUTHORITY` to `on` with `certificateAuthority.enabled`, to `development` with `certificateAuthority.development` too, renders nothing when it is not enabled and refuses `development` alone, and `hodor.authoritiesEnvironment`, `hodor.authoritiesVolumeMounts` and `hodor.authoritiesVolumes`, which, when `outboundAuthorities.configMap` names a ConfigMap, mount its key `outboundAuthorities.key` at `/etc/hodor/authorities/` in the server and the worker and point `SSL_CERT_FILE` at it, and render nothing otherwise. The deployments put the mounts and volumes of both in one list each.
- The Secret named by `secret.name` holds `owner-database-url`, `server-database-url`, `worker-database-url`, `worker-platform-database-url`, `secret-keys` and, with `mail.enabled`, `smtp-url`. `secret.keys` renames them.

### `helm/evaluation.yaml`

A Secret `hodor-evaluation`, a PostgreSQL StatefulSet `hodor-evaluation-database` with Hodor's roles, and a mail server `hodor-evaluation-mail` that delivers nothing. Its passwords and key are written in the file: it is for a local cluster only.

### Related contracts

- The image and the development stack: [docker](../docker/EGM.md).
- The binaries and their settings: [hodor-server](../../apps/hodor-server/EGM.md), [hodor-worker](../../apps/hodor-worker/EGM.md), [hodor-cli](../../apps/hodor-cli/EGM.md).
- The migrations and the roles they expect: [migrations](../../migrations/EGM.md).

## Invariants

- No password, key or token is written in a file of this directory, except in `helm/evaluation.yaml`, which says so at its top.
- Only the migrations hold the owner's connection address: the service `migrate` in Compose, the init container `migrate` in the chart.
- The worker gets the same `HODOR_PUBLIC_URL` as the server, in Compose from `.env` and in the chart from `hodor.publicUrl`: it names the issuer of the logout tokens it sends.
- The migrations finish before a server or a worker starts: `depends_on` with `service_completed_successfully` in Compose, the Helm hook in the chart.
- `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` is never set here.
- The Hodor containers run as a user that is not root, with a read-only root file system and every capability dropped, in both packages.
- The operations port, 9090, is not published by Compose and is not in the chart's Service.
- The Compose project name is not `hodor`, the name of the development stack, so that the two never share a container or a volume.

## Side Effects

- `docker compose -f deploy/install/docker/compose.yaml up` changes the schema of the database it points at and inserts the system tenant if missing; with the profile `https` it asks a public certificate authority for a certificate for the name in `HODOR_PUBLIC_URL`.
- `helm install` and `helm upgrade` do the same to the database through the hook, before any other resource of the release is created or changed. The hook's job is left in the namespace by `helm uninstall`.

## Verification

`.github/workflows/ci.yml` (job `installation`) lints and renders the chart, checks that it refuses to render without its required values, and validates the Compose file:

```sh
helm lint deploy/install/helm/hodor --strict --set image.repository=registry.example.com/hodor --set publicUrl=https://login.example.com --set secret.name=hodor
```

The Compose file is installed by no automated test. The chart is installed by two: the job `workload-identity` runs `deploy/demo/workload_identity.py`, which installs it on a kind cluster in Istio's mesh with the stand-ins of `helm/evaluation.yaml` and the values of `../demo/workload-identity/hodor-values.yaml`; the job `certificate-authority` runs `deploy/demo/certificate_authority.py`, which installs it the same way with `../demo/certificate-authority/hodor-values.yaml`, then with `certificateAuthority.enabled` and the key provider in OpenBao, and alone with `certManagerIssuer.only` in both of its clusters. The pages in `docs/operations/` give the commands to install each from nothing.
