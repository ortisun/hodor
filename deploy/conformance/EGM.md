# deploy/conformance

## Overview

The Basic OpenID Provider and Config OpenID Provider plans of the OpenID Foundation's conformance suite, run against a Hodor image. [OpenID conformance](../../docs/operations/conformance.md) is the human-maintained page: what runs, how, and why each expected result is expected.

## Files

- `compose.yaml` - project `hodor-conformance`. Hodor from `HODOR_IMAGE` (`postgres`, `migrate`, `system-tenant`, `hodor`, `worker`, `mail`), Caddy as `https` with its own certificate in front of `hodor:8080` at `https://hodor.localhost:8453` (network alias `hodor.localhost`), and the suite: `server` (`registry.gitlab.com/openid/conformance-suite:release-v5.3.4`, named `server` because the suite's web server proxies to `server:8080`), `suite-https` (its nginx at `127.0.0.1:8443`, network alias `localhost.emobix.co.uk`) and `mongodb`. Mail is at `127.0.0.1:${HODOR_CONFORMANCE_MAIL_PORT:-28025}`.
- `run.mjs` - waits for the suite; makes the tenant `conformance`, a first-party application and three confidential clients without PKCE through `hodor-cli` (`docker compose run`); makes the person `conformance@example.com` with a name through the administration interface and sets the password through recovery; creates the plans through the suite's REST interface (`api/plan`, `api/runner`, `api/runner/{id}/wait-state`, `api/runner/browser/{id}`, `api/info/{id}`, `api/log/{id}/images`); drives Chromium through Playwright for every address a test waits on, signing in on Hodor's pages (`input[name=identifier]`, `input[name=password]`) and uploading a screenshot for every image a test asks for; prints one line per test and exits 1 when a result is neither `PASSED` nor named for the test in `expected.json`. `CONFORMANCE_ONLY` limits the run to named tests; `CONFORMANCE_REPORT` writes the results as JSON.
- `expected.json` - for each test that may end other than `PASSED`, the results it may end with and why.
- `package.json`, `package-lock.json` - Playwright 1.65.1, the version `frontend/auth-ui` uses.

## Invariants

- The suite's image is pinned by its release tag; changing it is a change of this directory and of the page.
- Every result other than `PASSED` that `run.mjs` accepts is named in `expected.json` and explained on the page.
- Nothing here is for anything real: the passwords and the root key are written in `compose.yaml`, and both sides accept any certificate.

## Verification

```sh
docker build --file deploy/docker/Dockerfile --tag hodor:conformance .
HODOR_IMAGE=hodor:conformance docker compose -f deploy/conformance/compose.yaml up --wait
(cd deploy/conformance && npm ci && npx playwright install chromium && node run.mjs)
HODOR_IMAGE=hodor:conformance docker compose -f deploy/conformance/compose.yaml down --volumes
```
