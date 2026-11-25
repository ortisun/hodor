# docker

## Overview

The container images of Hodor and the local development stack that runs it. `ext-authz.Dockerfile` builds the image of `hodor-ext-authz` alone. `cert-manager-issuer.Dockerfile` builds the image of `hodor-cert-manager-issuer` alone. `Dockerfile` builds one image holding the three binaries (`hodor-server`, `hodor-worker`, `hodor-cli`), the hosted pages and the administration console. `compose.yaml` runs that image beside PostgreSQL, a mail server that delivers nothing, VictoriaMetrics, VictoriaTraces, OpenBao and three development identity providers. `postgres-init.sql` creates the database roles the migrations expect.

The header comment of `compose.yaml` states the scope: "Not for production: credentials are placeholders and nothing is persisted outside named volumes."

## Interface

### `Dockerfile`

Three stages:

| Stage | Base image | What it does |
| --- | --- | --- |
| `pages` | `node:24-bookworm-slim` | `npm ci --ignore-scripts` then `npm run build` in `frontend/auth-ui` and `frontend/admin-console`, in one stage because the console reads the compiled theme of the hosted pages |
| `build` | `rust:1.98-bookworm` | `cargo build --release --locked --bin hodor-server --bin hodor-worker --bin hodor-cli`, copied to `/out` |
| final | `gcr.io/distroless/cc-debian12:nonroot` | binaries in `/usr/local/bin/`, hosted pages in `/usr/share/hodor/auth-ui/`, console in `/usr/share/hodor/admin-console/` |

The final image runs as `nonroot:nonroot`, exposes `8080` and `9090`, sets `HODOR_LISTEN_ADDR=0.0.0.0:8080`, `HODOR_OPS_ADDR=0.0.0.0:9090`, `HODOR_PAGES_DIRECTORY` and `HODOR_CONSOLE_DIRECTORY`, and has `ENTRYPOINT ["/usr/local/bin/hodor-server"]`. The worker and the command-line tool run by overriding the entrypoint. The build context is the repository root (`compose.yaml` service `migrate`, `build.context: ../..`).

### `ext-authz.Dockerfile`

The image of `hodor-ext-authz` alone (Issue-110, Decision 0058). Two stages: `build` (`rust:1.98-bookworm`, `cargo build --release --locked --package hodor-ext-authz --bin hodor-ext-authz`, with the same cache mounts and touch as `Dockerfile`) and the final `gcr.io/distroless/cc-debian12:nonroot` with the binary in `/usr/local/bin/`. It runs as `nonroot:nonroot`, exposes `9191` (gRPC) and `9090` (operations), sets `HODOR_EXT_AUTHZ_LISTEN_ADDR=0.0.0.0:9191`, `HODOR_OPS_ADDR=0.0.0.0:9090` and `HODOR_EXT_AUTHZ_CONFIG=/etc/hodor-ext-authz/config.json`, and has `ENTRYPOINT ["/usr/local/bin/hodor-ext-authz"]`. The release workflow builds, joins and signs it beside the image of Hodor, as `ghcr.io/<owner>/hodor-ext-authz`.

### `cert-manager-issuer.Dockerfile`

The image of `hodor-cert-manager-issuer` alone (Issue-118, Decision 0074). Two stages: `build` (`rust:1.98-bookworm`, `cargo build --release --locked --package hodor-cert-manager-issuer --bin hodor-cert-manager-issuer`, with the same cache mounts and touch as `Dockerfile`) and the final `gcr.io/distroless/cc-debian12:nonroot` with the binary in `/usr/local/bin/`. It runs as `nonroot:nonroot`, exposes `9090` (operations), sets `HODOR_OPS_ADDR=0.0.0.0:9090` and `HODOR_CERT_MANAGER_ISSUER_CONFIG=/etc/hodor-cert-manager-issuer/config.json`, and has `ENTRYPOINT ["/usr/local/bin/hodor-cert-manager-issuer"]`; `jwk --key <file>` prints a key's public part instead. The release workflow builds, joins and signs it beside the image of Hodor, as `ghcr.io/<owner>/hodor-cert-manager-issuer`.

### `compose.yaml` (project `name: hodor`)

| Service | Image | Role | Host port (override variable, default) |
| --- | --- | --- | --- |
| `postgres` | `postgres:17-alpine` | database `hodor`, owner `hodor_owner`; mounts `postgres-init.sql` as `/docker-entrypoint-initdb.d/10-roles.sql`; health check `pg_isready` | none |
| `migrate` | `hodor:dev` (built here) | `hodor-cli migrate` with `HODOR_DATABASE_OWNER_URL`; runs once after `postgres` is healthy | none |
| `system-tenant` | `hodor:dev` | `hodor-cli tenant create-system` as `hodor_server`; creates the system tenant unless it exists | none |
| `victoriametrics` | `victoriametrics/victoria-metrics:v1.156.0` | metrics store, `-retentionPeriod=7d` | `HODOR_VM_PORT`, 8428 |
| `victoriatraces` | `victoriametrics/victoria-traces:v0.13.0` | trace store, receives OpenTelemetry traces and answers queries in the Jaeger format, `-retentionPeriod=7d` | `HODOR_TRACES_PORT`, 10428 |
| `mail` | `axllent/mailpit:v1.27` | accepts every message on SMTP port 1025 and delivers none; web page on 8025 | `HODOR_MAIL_PORT`, 8025 |
| `provider` | `node:24-bookworm-slim` | `node /provider.mjs`, mounted read-only from `../dev-provider/provider.mjs`, with `PORT`, `ISSUER=http://provider:9400`, `BROWSER_URL`, `CLIENT_ID`, `CLIENT_SECRET`; health check fetches `/health` | `HODOR_PROVIDER_PORT`, 9400 |
| `saml-provider` | `node:24-bookworm-slim` | `node /saml-provider/saml-provider.mjs`, the whole `../dev-saml-provider` directory mounted read-only, with `PORT`, `ENTITY_ID=urn:hodor:development-saml-provider`, `BROWSER_URL`; health check fetches `/health` | `HODOR_SAML_PROVIDER_PORT`, 9500 |
| `webhook-receiver` | `node:24-bookworm-slim` | `node /receiver.mjs`, `../dev-webhook-receiver/receiver.mjs` mounted read-only, with `PORT=9600`; health check fetches `/health` | `HODOR_WEBHOOK_RECEIVER_PORT`, 9600 |
| `openbao` | `openbao/openbao:2.7.2` | `server -dev`, in memory, root token `development-root-token`; health check `bao status` | `HODOR_OPENBAO_PORT`, 8200 |
| `openbao-setup` | `openbao/openbao:2.7.2` | `../openbao/setup.sh`, once: Transit at `hodor-transit`, the policy `../openbao/hodor-policy.hcl`, the AppRole `hodor` with placeholder identifiers. The server and the worker wait for it, and are given OpenBao's settings, with `HODOR_KEY_PROVIDER` from the caller's environment, `local` by default | None |
| `directory` | `osixia/openldap:1.5.0` | LDAP directory for `example.org` with a read-only user `readonly`, transport security off (`LDAP_TLS: "false"`), seeded from `../dev-directory/people.ldif`; health check `ldapwhoami` as the read-only user | none (inside the stack only) |
| `server` | `hodor:dev` (default entrypoint `hodor-server`) | the server, as database role `hodor_server`; health check `hodor-cli probe --addr 127.0.0.1:9090 --path /readyz` | `HODOR_HTTP_PORT`, 8080; `HODOR_OPS_PORT`, 9090 |
| `worker` | `hodor:dev`, entrypoint `hodor-worker` | the worker, as `hodor_worker` and `hodor_worker_platform`, sending mail to `smtp://mail:1025`; same `probe` health check | none |

Environment the stack gives the server: `HODOR_DATABASE_URL`, `HODOR_PUBLIC_URL` (`http://localhost:${HODOR_HTTP_PORT:-8080}`), `HODOR_SECRET_KEYS` (a placeholder key that encrypts identity provider secrets and wraps the signing keys in this stack only), `HODOR_OPEN_POLICY_AGENT_ADDRESS` (`http://policy-agent:8181`, where the demonstration of Milestone 5 starts a shared instance; nothing answers there otherwise), `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` (`provider:9400`, the browser address of `provider`, `directory:389`, the browser address of `saml-provider`, `webhook-receiver:9600`), `HODOR_DIRECTORY_HOSTS` (`directory:389`), `HODOR_LOG_FORMAT=pretty`, `HODOR_OTLP_METRICS_ENDPOINT`, `HODOR_OTLP_TRACES_ENDPOINT`. The worker gets `HODOR_SECRET_KEYS` too, the same placeholder, to make the tenants' signing keys, `HODOR_PUBLIC_URL`, the server's, to name the issuer of logout tokens, and additionally `HODOR_PLATFORM_DATABASE_URL`, `HODOR_SMTP_URL`, `HODOR_MAIL_FROM`, `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` (`webhook-receiver:9600`), `HODOR_WEBHOOK_MAX_ATTEMPTS=3` and `HODOR_WEBHOOK_FIRST_RETRY_MS=1000`, so that a failing delivery is set aside within seconds.

Named volumes: `postgres-data`, `victoriametrics-data`, `victoriatraces-data`.

### `postgres-init.sql`

- `hodor_app` and `hodor_platform`: group roles, `NOLOGIN`.
- `hodor_server`: login role in `hodor_app` ("The server only ever acts inside one tenant").
- `hodor_worker_platform`: login role in `hodor_platform`; `hodor_worker`: login role in `hodor_app` ("The worker finds work across tenants, then handles it inside one").
- The owner role `hodor_owner` is created by the `postgres` image from `POSTGRES_USER` in `compose.yaml`, not by this file.

### Related contracts

- The binaries: [hodor-server](../../apps/hodor-server/EGM.md), [hodor-worker](../../apps/hodor-worker/EGM.md), [hodor-cli](../../apps/hodor-cli/EGM.md).
- The migrations that `migrate` applies and that expect these roles: [migrations](../../migrations/EGM.md).
- The administration console built into the image: [admin-console](../../frontend/admin-console/EGM.md).
- The development identity providers mounted into the stack: [dev-provider](../dev-provider/EGM.md), [dev-saml-provider](../dev-saml-provider/EGM.md); and the development receiver of webhooks, [dev-webhook-receiver](../dev-webhook-receiver/EGM.md).
- The demonstrations that drive the running stack: [demo](../demo/EGM.md).

## Invariants

- Start order is enforced by `depends_on`: `migrate` waits for `postgres` to be healthy; `system-tenant`, `server` and `worker` wait for `migrate` to complete successfully; `server` also waits for `system-tenant` to complete, because, as the comment says, Compose treats a service that exits as a failure of `up --wait` unless another service waits for it to complete.
- Only `migrate` connects as the owner (`HODOR_DATABASE_OWNER_URL`). The server and `system-tenant` connect as `hodor_server`, the worker as `hodor_worker` (tenant work) and `hodor_worker_platform` (work across tenants). The role names in `compose.yaml` and `postgres-init.sql` must match.
- Every published port is bound to `127.0.0.1`; `directory` and `postgres` publish none.
- `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` is the setting that lets the server reach the development providers at private addresses over plain HTTP; the comment says to never set it anywhere real. Changing a provider port variable changes both the published port and the matching entry in this list.
- The `provider` service is reached by the server as `provider` and by a browser as `localhost`; `saml-provider` is reached only by the browser (comments on both services).
- All credentials in `compose.yaml` and `postgres-init.sql` are placeholders for local use.

## Side Effects

- `docker compose ... up --build` builds the image `hodor:dev` from the repository root, downloading Node.js and Rust dependencies (with cache mounts for `/root/.npm`, the cargo registry and `/src/target`). The target cache is shared by every build of every branch on the machine, so the build stage touches the workspace's files before `cargo build`: cargo compares modification times, and a file older than what another branch left in the cache would be taken as built.
- `postgres-init.sql` runs only when the `postgres-data` volume is first initialized (it is mounted into `/docker-entrypoint-initdb.d/`).
- `migrate` changes the database schema; `system-tenant` inserts the system tenant if missing.
- Data persists across restarts in the three named volumes; metrics and traces are kept seven days.
- The worker sends mail to the `mail` service, which keeps it for viewing and delivers nothing.
- The server and worker export metrics and traces to `victoriametrics` and `victoriatraces`.

## Verification

No automated test lives in this directory. The stack is started and exercised as in `.github/workflows/ci.yml` (job `pages`):

```sh
docker compose -f deploy/docker/compose.yaml up --build --wait
python3 deploy/demo/demo.py
python3 deploy/demo/external_identities.py
```

The `server` and `worker` health checks (`hodor-cli probe ... --path /readyz`) and the `postgres`, `provider`, `saml-provider`, `webhook-receiver` and `directory` health checks are what `up --wait` waits on.
