# deploy

## Overview

Everything needed to build Hodor's container image, to run it locally for development, testing and demonstration, and to install it. The development stack is not for production: its credentials are placeholders, the identity providers let anyone sign in as anyone, and the SAML signing key is committed to the repository. The installation packages in `install/` are separate from it and hold no secret. The stack is defined in `docker/compose.yaml`, which mounts the development providers and directory from the sibling directories, and the demonstrations in `demo/` drive the running stack. `.github/workflows/ci.yml` (job `pages`) starts the stack, runs the browser tests against it, then runs both demonstrations.

## Subdirectories & Boundaries

- docker: [./docker/EGM.md](./docker/EGM.md) - `Dockerfile` builds the image `hodor:dev` with `hodor-server`, `hodor-worker`, `hodor-cli`, the hosted pages and the administration console; `compose.yaml` runs PostgreSQL, `migrate`, `system-tenant`, `server`, `worker`, a mail server, VictoriaMetrics, VictoriaTraces and the three development providers; `postgres-init.sql` creates the roles `hodor_app`, `hodor_platform`, `hodor_server`, `hodor_worker` and `hodor_worker_platform`.
- install: [./install/EGM.md](./install/EGM.md) - the two installation packages: `docker/compose.yaml` for one machine (project `hodor-install`, with PostgreSQL and HTTPS as optional profiles and every secret read from `.env`), and the Helm chart `helm/hodor` for Kubernetes (server, worker, migration hook, Service, disruption budgets, optional Ingress, autoscaler and network policy, every secret read from an existing Secret), with `helm/evaluation.yaml` for trying it on a local cluster.
- demo: [./demo/EGM.md](./demo/EGM.md) - `demo.py` (Milestone 1: registration, address verification, sign-in, lockout, administrator token, audit log, metrics, traces, tenants kept apart) and `external_identities.py` (Milestone 2: sign-in through OpenID Connect, LDAP and SAML, no takeover by a matching address, a tampered SAML response refused). Both stop with exit status 1 on the first failed check.
- dev-provider: [./dev-provider/EGM.md](./dev-provider/EGM.md) - `provider.mjs`, a dependency-free Node.js OpenID Connect provider (discovery, `/keys`, `/authorize`, `/token` with the `S256` proof key for code exchange) whose key is generated at every start; the compose service `provider`.
- dev-saml-provider: [./dev-saml-provider/EGM.md](./dev-saml-provider/EGM.md) - `saml-provider.mjs`, a dependency-free Node.js SAML identity provider (`/metadata`, `/sso`, `/sso/decision`) that signs assertions with the committed development key `signing-key.pem`, whose certificate is `certificate.pem`; the compose service `saml-provider`. Its human-maintained notes are in [./dev-saml-provider/README.md](./dev-saml-provider/README.md).
- conformance: [./conformance/EGM.md](./conformance/EGM.md) - the OpenID conformance suite of the OpenID Foundation against Hodor: `compose.yaml` (project `hodor-conformance`: Hodor behind Caddy at `https://hodor.localhost:8453`, the suite `release-v5.3.4` at `https://localhost.emobix.co.uk:8443`), `run.mjs`, which makes the tenant, clients and person, runs the Basic OpenID Provider and Config OpenID Provider plans through the suite's interface and is the browser they wait for, and `expected.json`, the result other than passed each test may end with. Run by the job `conformance` of `.github/workflows/ci.yml`; see [OpenID conformance](../docs/operations/conformance.md).
- open-policy-agent (no contract file) - `capabilities.json`, the built-in functions a policy may use: those of Open Policy Agent 1.10.1 without `http.send`, `net.lookup_ip_addr`, `opa.runtime` and `providers.aws.sign_req`, and with an empty `allow_net`. Policies are checked and built against it; `crates/authorization-opa/tests/capabilities.rs` checks its contents and that `opa check` refuses a policy calling a removed built-in. See [the authorization context](../docs/architecture/contexts/authorization.md#the-capabilities-file). `decision-log-mask.rego`, the mask policy every instance starts with: it erases `/input` from every decision before it is uploaded ([who writes the record](../docs/architecture/contexts/authorization.md#who-writes-it)).
- dev-directory (no contract file) - `people.ldif`, the LDAP data that seeds the compose service `directory` (`osixia/openldap`, domain `example.org`) with the organizational unit `people` and one person, `dora`, whose development password is written in the file. `external_identities.py` signs in as her through the directory.

## Boundaries

- Hodor's server reaches `provider` (`provider:9400`) and `directory` (`directory:389`) inside the stack; only the browser, or a demonstration acting as one, reaches `saml-provider`. The server is allowed to reach these private addresses over plain HTTP only because `compose.yaml` sets `HODOR_OUTBOUND_DEVELOPMENT_HOSTS`.
- The binaries come from [hodor-server](../apps/hodor-server/EGM.md), [hodor-worker](../apps/hodor-worker/EGM.md) and [hodor-cli](../apps/hodor-cli/EGM.md); the schema applied by `migrate` comes from [migrations](../migrations/EGM.md).

## Verification

No automated test lives under `deploy/`. `.github/workflows/ci.yml` (job `installation`) lints and renders the chart and validates the installation's Compose file. The development stack, as the job `pages` runs it:

```sh
docker compose -f deploy/docker/compose.yaml up --build --wait
python3 deploy/demo/demo.py
python3 deploy/demo/external_identities.py
```
