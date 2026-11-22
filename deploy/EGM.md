# deploy

## Overview

Everything needed to build Hodor's container image and run it locally for development, testing and demonstration. None of it is for production: the stack's credentials are placeholders, the identity providers let anyone sign in as anyone, and the SAML signing key is committed to the repository. The stack is defined in `docker/compose.yaml`, which mounts the development providers and directory from the sibling directories, and the demonstrations in `demo/` drive the running stack. `.github/workflows/ci.yml` (job `pages`) starts the stack, runs the browser tests against it, then runs both demonstrations.

## Subdirectories & Boundaries

- docker: [./docker/EGM.md](./docker/EGM.md) - `Dockerfile` builds the image `hodor:dev` with `hodor-server`, `hodor-worker`, `hodor-cli`, the hosted pages and the administration console; `compose.yaml` runs PostgreSQL, `migrate`, `system-tenant`, `server`, `worker`, a mail server, VictoriaMetrics, VictoriaTraces and the three development providers; `postgres-init.sql` creates the roles `hodor_app`, `hodor_platform`, `hodor_server`, `hodor_worker` and `hodor_worker_platform`.
- demo: [./demo/EGM.md](./demo/EGM.md) - `demo.py` (Milestone 1: registration, address verification, sign-in, lockout, administrator token, audit log, metrics, traces, tenants kept apart) and `external_identities.py` (Milestone 2: sign-in through OpenID Connect, LDAP and SAML, no takeover by a matching address, a tampered SAML response refused). Both stop with exit status 1 on the first failed check.
- dev-provider: [./dev-provider/EGM.md](./dev-provider/EGM.md) - `provider.mjs`, a dependency-free Node.js OpenID Connect provider (discovery, `/keys`, `/authorize`, `/token` with the `S256` proof key for code exchange) whose key is generated at every start; the compose service `provider`.
- dev-saml-provider: [./dev-saml-provider/EGM.md](./dev-saml-provider/EGM.md) - `saml-provider.mjs`, a dependency-free Node.js SAML identity provider (`/metadata`, `/sso`, `/sso/decision`) that signs assertions with the committed development key `signing-key.pem`, whose certificate is `certificate.pem`; the compose service `saml-provider`. Its human-maintained notes are in [./dev-saml-provider/README.md](./dev-saml-provider/README.md).
- dev-directory (no contract file) - `people.ldif`, the LDAP data that seeds the compose service `directory` (`osixia/openldap`, domain `example.org`) with the organizational unit `people` and one person, `dora`, whose development password is written in the file. `external_identities.py` signs in as her through the directory.

## Boundaries

- Hodor's server reaches `provider` (`provider:9400`) and `directory` (`directory:389`) inside the stack; only the browser, or a demonstration acting as one, reaches `saml-provider`. The server is allowed to reach these private addresses over plain HTTP only because `compose.yaml` sets `HODOR_OUTBOUND_DEVELOPMENT_HOSTS`.
- The binaries come from [hodor-server](../apps/hodor-server/EGM.md), [hodor-worker](../apps/hodor-worker/EGM.md) and [hodor-cli](../apps/hodor-cli/EGM.md); the schema applied by `migrate` comes from [migrations](../migrations/EGM.md).

## Verification

No automated test lives under `deploy/`. As `.github/workflows/ci.yml` runs it:

```sh
docker compose -f deploy/docker/compose.yaml up --build --wait
python3 deploy/demo/demo.py
python3 deploy/demo/external_identities.py
```
