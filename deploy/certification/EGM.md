# deploy/certification

## Overview

The deployment the owner asks the OpenID Foundation to certify, and the script that prepares it for the hosted suite and retires it afterwards (Issue-142, [Decision 0051](../../docs/decisions/0051-conformance-runs-and-certification.md)). [The certification deployment](../../docs/operations/certification-deployment.md) is the human-maintained runbook; [how certification is obtained](../../docs/operations/certification.md) says what the Foundation asks.

## Files

- `compose.yaml` - an override of `deploy/install/docker/compose.yaml`, read after it with `--env-file deploy/certification/.env`: project `hodor-certification`; the service `https` runs `caddy run` on `Caddyfile`, mounted as `../../certification/Caddyfile` because Compose reads every path from the folder of the first file; `mail` (Mailpit `axllent/mailpit:v1.27`) on `127.0.0.1:${CERTIFICATION_MAIL_PORT:-8025}`; the worker sends to `smtp://mail:1025`.
- `Caddyfile` - `key_type rsa2048`; the site `{$HODOR_PUBLIC_URL}` with TLS 1.2 and 1.3 and, on 1.2, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`; `Client-Cert` and `Client-Cert-Chain` removed from requests; `reverse_proxy server:8080`. The site of client certificates for 0.6.0 is commented out until Issue-146.
- `.env.example` - the settings to copy to `.env`: `HODOR_IMAGE`, `COMPOSE_PROFILES=database,https`, `HODOR_PUBLIC_URL`, the three database passwords, `HODOR_SECRET_KEYS`.
- `plans.json` - `features` (each `built`, `issue`, `pullRequest`, `what`, and optionally `clientArguments` or `tenantCommands`), `responseTypes` (the features each response type needs), `tenants` (name, needs, application, `commands` and `retireCommands` with `{tenant}`, `{application}`, `{suite}`, `{suiteHost}` and `{alias}` filled in), `clients` (tenant, name, method, needs, `arguments`), `allResponseTypes`, and `plans` (name, profile, suite plan, tenant, needs, variant, `eachResponseType`, and the configuration field of each client).
- `certification.mjs` - `make`: refuses when `output/state.json` exists; checks that Hodor answers `GET /t/system/.well-known/openid-configuration` with the document or its problem in JSON; runs `hodor-cli --version`, `tenant list`, then for each tenant a ready run needs `tenant create`, `application add`, the tenant's commands, `client add` for each client a ready run names (confidential, `--without-pkce`, `authorization_code` and `refresh_token`, the suite's `callback` and `post_logout_redirect` for the alias, six scopes, `--request-object-signing-alg none`, `--response-type` only when a type other than `code` is built), `admin bootstrap`, `POST {issuer}/api/v1/admin/users`, `user claims`, `POST {issuer}/interaction/recovery`, the link from Mailpit's `api/v1/search` and `api/v1/message/{id}`, and `POST {issuer}/interaction/recovery/complete`; saves `state.json` (mode 600) after each step; writes `NN-<run>.json` per ready run and `configuration.json`; prints the document `{suite, alias, version, person, plans, waiting}` and nothing else on the standard output. `retire`: per tenant, `client disable`, `application disable`, the retire commands, `keys list` and `keys revoke` of every version not revoked, then checks `invalid_client` at the token endpoint for each client and that no key published before is still published, then `tenant suspend` and checks `403 tenant.suspended` at discovery; prints `{retired, checks}`, exit 1 when a check does not hold. Exports `readPlans` for the test.
- `test/certification.test.mjs` - `node:test`: `make` then `retire` against `test/fake-hodor-cli.mjs` and a stand-in HTTP server for Hodor and Mailpit sharing one state file; a copy of `plans.json` with features turned on; a `hodor-cli` that changes nothing, which every check must catch; an unknown feature refused.
- `test/fake-hodor-cli.mjs` - answers the commands the script runs as `hodor-cli` prints them, keeping tenants, applications, clients, keys, administrators and users in the file `FAKE_HODOR_STATE`.
- `output/` - written by the script, ignored by git: secrets.

## Invariants

- What is ready is read from `plans.json` alone; nothing is made for a plan, client or tenant that needs a feature whose `built` is not `true`, and every run of every plan is printed either under `plans` or under `waiting`.
- The standard output of `make` and `retire` is one JSON document; everything else goes to the standard error.
- Nothing real: every credential is made for the run, and `retire` must leave no client, key or tenant it made working.

## Verification

```sh
node --test deploy/certification/test/certification.test.mjs
```

The job `Certification deployment` of `.github/workflows/ci.yml` runs it, `docker compose config` on the two files and `caddy adapt --validate` on `Caddyfile`; the job `Certification deployment against Hodor` of `.github/workflows/conformance.yml` runs `make` and `retire` against Hodor started from the conformance stack without the suite, from the image the plans run against.
