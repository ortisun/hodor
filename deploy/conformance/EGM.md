# deploy/conformance

## Overview

The Basic OpenID Provider, Config OpenID Provider and Back-Channel OpenID Provider plans of the OpenID Foundation's conformance suite, run against a Hodor image, and the Basic and Back-Channel plans again with pairwise clients, the core set; and with every plan, the Form Post plan of the code flow, the Implicit plan for `id_token` and the Hybrid plan for `code id_token`. `.github/workflows/conformance.yml` runs each plan in a job of its own. [OpenID conformance](../../docs/operations/conformance.md) is the human-maintained page: what runs, how, and why each expected result is expected.

## Files

- `compose.yaml` - project `hodor-conformance`. Hodor from `HODOR_IMAGE` (`postgres`, `migrate`, `system-tenant`, `hodor`, `worker`, `mail`; the worker has `HODOR_PUBLIC_URL`, the server's, and `HODOR_OUTBOUND_DEVELOPMENT_HOSTS=suite-relay:8080`), `sector-document` (Caddy answering `http://sector-document:8080` with the JSON array of the suite's redirect address, the sector identifier document of the second pairwise client), `suite-relay` (Caddy at `http://suite-relay:8080`, passing logout tokens on to the suite's `https://localhost.emobix.co.uk:8443` without checking its certificate, `--insecure`), Caddy as `https` with its own certificate in front of `hodor:8080` at `https://hodor.localhost:8453` (network alias `hodor.localhost`), and the suite: `server` (`registry.gitlab.com/openid/conformance-suite:release-v5.3.4`, named `server` because the suite's web server proxies to `server:8080`), `suite-https` (its nginx at `127.0.0.1:8443`, network alias `localhost.emobix.co.uk`) and `mongodb`. Mail is at `127.0.0.1:${HODOR_CONFORMANCE_MAIL_PORT:-28025}`.
- `run.mjs` - waits for the suite; makes the tenant `conformance`, a first-party application and eight confidential clients without PKCE and with `--request-object-signing-alg none`, so that the suite's unsigned request objects are read, through `hodor-cli` (`docker compose run`, with `HODOR_OUTBOUND_DEVELOPMENT_HOSTS=suite-relay:8080,sector-document:8080`), the fourth with the back-channel logout address `http://suite-relay:8080/test/a/hodor/backchannel_logout` for the back-channel plan alone, and the last four the same four with `--subject-type pairwise`, the sixth with `--sector-identifier-uri http://sector-document:8080/redirect_uris.json`, for the plans' second, pairwise run; each with an `--id-token-algorithm`, so that `ES256`, `RS256`, `PS256` and `EdDSA` each sign the ID tokens of some client (`ES256`, `RS256`, `PS256` and `PS256` for the first four, `EdDSA`, `PS256`, `RS256` and `EdDSA` for the pairwise four); the first three also with `--response-type id_token` and `--response-type 'code id_token'` beside `code`, for the Implicit and Hybrid plans; makes the person `conformance@example.com` with a name through the administration interface and sets the password through recovery; creates the plans through the suite's REST interface (`api/plan`, `api/runner`, `api/runner/{id}/wait-state`, `api/runner/browser/{id}`, `api/info/{id}`, `api/log/{id}/images`); drives Chromium through Playwright for every address a test waits on, signing in on Hodor's pages (`input[name=identifier]`, `input[name=password]`) and uploading a screenshot for every image a test asks for; prints one line per test and exits 1 when a result is neither `PASSED` nor named for the test and its plan in `expected.json`; refuses to run when a plan of `plans.json` has no runner in `main` or a runner is not in `plans.json`. `CONFORMANCE_ONLY` limits the run to named tests; `CONFORMANCE_REPORT` writes the results as JSON, each with `run`, its plan's short name, `outcome` and `allowed`; `CONFORMANCE_PLANS` names the plans of `plans.json` to run, the core set unless given; `formpost-basic` is `oidcc-formpost-basic-certification-test-plan` with the Basic plan's configuration and variants; `implicit-id-token` and `hybrid-code-id-token` are `oidcc-implicit-certification-test-plan` and `oidcc-hybrid-certification-test-plan` with the same. The Implicit and Hybrid plans set the response type of each test themselves, so `runPlan` takes the type and runs only the tests whose variant names it, `id_token` and `code id_token`.
- `plans.json` - every plan `run.mjs` can run, by its short name (`basic`, `config`, `backchannel`, `basic-pairwise`, `backchannel-pairwise`, `formpost-basic`, `implicit-id-token`, `hybrid-code-id-token`), each with `core`, true for the core set. The workflow's matrix is made from it.
- `expected.json` - for each test that may end other than `PASSED`, each result it may end with (`REVIEW`, `WARNING` or `SKIPPED` only), `why`, and `plans`, the short names of the plans it may end so in.
- `runs.mjs` - Node's standard library only. Exports the checks of `plans.json` and `expected.json`, `allowedResults`, `choose` (the set, `core`, `every` or `none`, for a GitHub event: `schedule` and a pull request into `main` or labelled `conformance: full` every plan, a push and a pull request into `develop` the core set, any other label added nothing) and `report` (the body of the issue of a failed night). `node runs.mjs choose` prints `set=` and `plans=` for `$GITHUB_OUTPUT`; `node runs.mjs report DIRECTORY` prints the issue from the downloaded artifacts `conformance-results-{plan}`.
- `test/runs.test.mjs` - `node --test deploy/conformance/test/`.
- `package.json`, `package-lock.json` - Playwright 1.65.1, the version `frontend/auth-ui` uses.

## Invariants

- The suite's image is pinned by its release tag; changing it is a change of this directory and of the page.
- Every result other than `PASSED` that `run.mjs` accepts is named in `expected.json` for its plan and explained on the page.
- Every plan of `plans.json` has its runner in `run.mjs`, and every runner its entry; the workflow names no plan.
- Only the back-channel plan's clients have a back-channel logout address, so that no test of the other plans receives a logout token it does not wait for.
- Nothing here is for anything real: the passwords and the root key are written in `compose.yaml`, and both sides accept any certificate.

## Verification

```sh
node --test deploy/conformance/test/
docker build --file deploy/docker/Dockerfile --tag hodor:conformance .
HODOR_IMAGE=hodor:conformance docker compose -f deploy/conformance/compose.yaml up --wait
(cd deploy/conformance && npm ci && npx playwright install chromium && node run.mjs)
HODOR_IMAGE=hodor:conformance docker compose -f deploy/conformance/compose.yaml down --volumes
```
