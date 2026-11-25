# OpenID conformance

Hodor runs the [OpenID conformance suite](https://openid.net/certification/) of the OpenID Foundation against itself on every pull request: the **Basic OpenID Provider**, the **Config OpenID Provider** and the **Back-Channel OpenID Provider** plans, and the Basic and Back-Channel plans again with pairwise clients. Passing them is the exit criterion of Phase 2 in the [roadmap](../product/roadmap.md) and the acceptance of Issue-61 in [the epics](../product/epics.md#slice-o--openid-connect-epic-10). The suite is the same one the OpenID Foundation uses to certify providers. Running it here is not a certification: nobody at the Foundation has looked at the results, and no certification has been asked for.

**Not for anything real.** The stack it runs in has passwords and keys written in the repository, and both sides trust whatever certificate the other shows.

## What runs

| Plan | Variant | Tests |
|---|---|---|
| `oidcc-basic-certification-test-plan` | `server_metadata=discovery`, `client_registration=static_client` | 35 |
| `oidcc-config-certification-test-plan` | as the plan sets it | 1 |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | `client_registration=static_client`, `response_type=code`; the plan sets the rest | 2 |
| `oidcc-basic-certification-test-plan`, with pairwise clients | as the first | 35 |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan`, with a pairwise client | as the third | 2 |

The back-channel plan is the acceptance of Issue-100 ([back-channel logout](../architecture/contexts/oauth.md#back-channel-logout)). Its first test reads discovery, which must say `backchannel_logout_supported` and `backchannel_logout_session_supported`. Its second signs the person in, sends the browser to the end-session endpoint with the ID token as `id_token_hint`, and waits for both the browser at the post-logout redirect address and a logout token at its back-channel logout address, in either order; it checks the token's signature against the tenant's key set, its claims, that its `sub` and `sid` are those of the ID token, and then that a new request with `prompt=none` is answered `login_required`. A token that never arrives does not fail the test by itself: the test keeps waiting, and the script stops waiting after five minutes and counts the test as unfinished, which fails the run.

**The pairwise configuration** is the acceptance of Issue-98 ([pairwise subject identifiers](../architecture/contexts/oauth.md#pairwise-subject-identifiers)). The suite's own pairwise tests, `oidcc-registration-sector-uri` and `oidcc-registration-sector-bad`, belong to the Dynamic OpenID Provider plan: they register a client through dynamic client registration, which Hodor does not offer, so they cannot run ([Decision 0040](../decisions/0040-pairwise-subjects.md)). What can run is every test of the Basic and Back-Channel plans against clients that are pairwise. There the suite checks, test by test, that UserInfo answers the `sub` of the ID token, that a second sign-in gives the same `sub` as the first, and that the logout token carries the `sub` and `sid` of the ID token, all of them pairwise identifiers. Of the two clients of the Basic plan, the first takes its sector from its redirect address, the host `localhost.emobix.co.uk`, and the second names a sector identifier address, whose host `sector-document` is its sector, so each of the two ways to a sector signs the person in. That two sectors give two identifiers and one sector the same is checked by the tests of the server, not by the suite.

The suite is the image `registry.gitlab.com/openid/conformance-suite:release-v5.3.4`, with its web server `registry.gitlab.com/openid/conformance-suite/nginx:release-v5.3.4` and MongoDB 6.0.13: the releases of 2026-10-26, pinned by tag in `deploy/conformance/compose.yaml`.

## How it runs

`deploy/conformance/compose.yaml` starts Hodor from an image given by `HODOR_IMAGE`, with PostgreSQL, the worker and a mail server that delivers nothing, behind a web server with a certificate of its own, and the suite beside it. Two names reach the stack from a browser on the machine and from inside it alike:

| Name | What answers |
|---|---|
| `https://hodor.localhost:8453` | Hodor. The issuer is `https://hodor.localhost:8453/t/conformance` |
| `https://localhost.emobix.co.uk:8443` | The suite. The name is the suite's own: a public name that points to `127.0.0.1` |

A browser resolves any name ending in `.localhost` to the machine itself; inside the stack, both names are aliases of the containers that answer them.

**The back-channel logout address.** The suite takes logout tokens at `https://localhost.emobix.co.uk:8443/test/a/hodor/backchannel_logout`, over HTTPS only, behind its web server's certificate of its own making. Hodor's worker calls out through the [guarded client](../security/outbound-http.md), which checks certificates and refuses private addresses, as it must. So the stack has one more web server, `suite-relay`: Caddy, answering plain HTTP at `http://suite-relay:8080` and passing every request to the suite's web server without checking its certificate. The back-channel logout address of the two clients that have one is `http://suite-relay:8080/test/a/hodor/backchannel_logout`, and `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` names `suite-relay:8080` for the worker, which calls it, and for `hodor-cli`, which checks it when the client is made. The worker is given `HODOR_PUBLIC_URL`, the server's, to name the issuer of the tokens. None of this is for anything real.

**The sector identifier address.** The second pairwise client's sector identifier address is `http://sector-document:8080/redirect_uris.json`, answered by one more Caddy, `sector-document`, with the JSON array of the suite's redirect address. `hodor-cli` fetches it once, when it makes the client, through its guarded client, with `sector-document:8080` in `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` beside the relay.

**HTTPS.** Hodor's cookies are `Secure`, and the suite expects an issuer over HTTPS. Caddy answers in front of Hodor with a certificate from its own authority (`--internal-certs`), as the [installation packages](install-with-docker.md) put a web server in front of Hodor. The suite does not check the certificates of the provider it tests, and the browser and the script are told to accept both.

**The browser.** The suite comes with a browser of its own, built on HtmlUnit, which runs a list of clicks and fields given in its configuration. It cannot run Hodor's pages: they are a React application, and HtmlUnit's JavaScript engine does not run it. `deploy/conformance/run.mjs` is the browser instead. It creates each test through the suite's interface, and whenever a test waits for a browser it opens in Chromium, through Playwright, the addresses the test names. It signs in on Hodor's pages as the person below, and lets the suite's own page take the answer back. When a test expects Hodor to show an error page instead, the script takes a screenshot of the page and gives it to the test, which is what a person running the suite by hand would do.

**What the script makes in Hodor**, through `hodor-cli` and the pages, as an operator and a person would:

- the tenant `conformance`, open to registration;
- an application, **first party**, so that consent is not asked;
- eight confidential clients, each with the suite's redirect address `https://localhost.emobix.co.uk:8443/test/a/hodor/callback` and post-logout address, the grants `authorization_code` and `refresh_token`, and the scopes `openid`, `profile`, `email` and `offline_access`:
  - two send their secret by `client_secret_basic`, because the Basic plan needs two clients;
  - one sends it by `client_secret_post`, for the one test that does;
  - one sends it by `client_secret_basic` and has a back-channel logout address, for the back-channel plan alone, so that no test of the other plans receives a logout token it does not wait for;
  - four more, the same four made pairwise, for the second run of the two plans: each takes its sector from the redirect address, but the second, whose sector identifier address names another host.
- the person `conformance@example.com`, registered through the pages with the link from the message the mail server caught.

**Discovery names more grants than the plans use.** `grant_types_supported` also names `client_credentials` and, since Issue-95, `urn:ietf:params:oauth:grant-type:token-exchange`. The plans check that the grants they need are there, `authorization_code` for both and `refresh_token` where it is tested, and ignore the others, as OpenID Connect Discovery lets a client do.

**Every client is made `--without-pkce`.** The Basic OpenID Provider plan is the code flow of OpenID Connect as written in 2014: only one of its tests sends a code challenge, and a client that requires one would refuse all the others. A confidential client may be registered this way; a public client always uses PKCE.

## Running it

```bash
docker build --file deploy/docker/Dockerfile --tag hodor:conformance .
```

```bash
HODOR_IMAGE=hodor:conformance docker compose -f deploy/conformance/compose.yaml up --wait
```

```bash
cd deploy/conformance && npm ci && npx playwright install chromium && node run.mjs
```

The script waits for the suite to start, which takes a minute or two, makes what it needs in Hodor, runs the five plans and prints one line per test with the address of its log in the suite, `https://localhost.emobix.co.uk:8443/log-detail.html?log=…`, which a browser on the machine can open while the stack runs. `CONFORMANCE_ONLY=oidcc-server,oidcc-prompt-login` runs only the tests named; `CONFORMANCE_REPORT=results.json` writes the results to a file.

It ends in failure when a test ends in a result other than `PASSED` that [`deploy/conformance/expected.json`](#expected-results) does not name for it. A test that the suite left unfinished or interrupted is a failure.

```bash
HODOR_IMAGE=hodor:conformance docker compose -f deploy/conformance/compose.yaml down --volumes
```

Continuous integration does the same in the job `OpenID conformance` of `.github/workflows/ci.yml`, and keeps the results as an artifact of the run.

## Expected results

Every test of the five plans passes except those below, in each plan they belong to. Each ends in a result the suite counts as allowed, and `deploy/conformance/expected.json` names it with the same reason; a test that ends otherwise fails the run.

| Test | Result | Why |
|---|---|---|
| `oidcc-userinfo-post-body` | Warning | UserInfo reads the access token from the `Authorization` header only ([the oauth context](../architecture/contexts/oauth.md#userinfo)). RFC 6750 lets a resource server also take it in a form body (section 2.2, "MAY"); Hodor does not |
| `oidcc-scope-profile` | Warning | The suite wants every standard claim of `profile`. Hodor keeps a person's name and language and gives those with `updated_at`; it keeps no given or family name, nickname, picture, website, gender, birth date or time zone, and a provider returns only the claims it has (OpenID Connect Core, section 5.4) |
| `oidcc-claims-essential` | Warning | It asks for `name` through the `claims` parameter alone. Hodor does not read that parameter, and discovery says so (`claims_parameter_supported` is false); UserInfo gives the claims of the scopes, here only `sub`. Supporting the parameter is optional (OpenID Connect Core, section 5.5) |
| `oidcc-scope-address`, `oidcc-scope-phone` | Skipped | Hodor keeps no postal address and no telephone number: the scopes are not offered, and discovery does not name them |
| `oidcc-scope-all` | Skipped | It asks for every standard scope at once, `address` and `phone` among them |
| `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | Skipped | Hodor answers `request_not_supported` to a request object, which the specification allows; the suite then has nothing to test. Request objects are left to Phase 4 ([Decision 0023](../decisions/0023-what-0.2.0-holds.md)) |
| `oidcc-prompt-login`, `oidcc-max-age-1` | Review | The test passes, and keeps a screenshot of the second sign-in page it made Hodor show, for a person to look at |
| `oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-request-object-with-redirect-uri` | Review | Hodor shows its own error page and never sends the browser to an address it cannot trust; the suite keeps a screenshot of that page for a person to look at |

A result of **Review** is the suite saying that a person must look at the screenshots before the test can count toward a certification. Here nobody does: the screenshots are taken and given to the suite, and the run accepts the result. The pages they show are tested on their own by the browser tests of the hosted pages.

A full run takes about 30 minutes on a laptop: about 29 for the 75 tests and one for the suite to start. In continuous integration, building the image adds its own time.

## What the suite found in Hodor

Running the plans found four things wrong in Hodor, all fixed in the change that brought the suite in:

- **No `RS256` for ID tokens.** OpenID Connect Discovery requires every OpenID Provider to offer `RS256` in `id_token_signing_alg_values_supported`; Hodor signed with `ES256` only, and the Config OpenID Provider plan failed. A client now has an ID token algorithm, `ES256` unless `RS256` is chosen ([the ID token](../architecture/contexts/oauth.md#the-id-token)).
- **A new tenant could not issue a token.** A tenant has no signing key until the worker's next rotation pass, up to ten minutes later; every token asked for in between was a `server_error`. The first key of an algorithm is now made when something must sign with it ([the keys context](../architecture/contexts/keys.md#rotation)).
- **The key set did not name the key of the first token.** The suite reads a tenant's key set once at the start of a test; a key made after that read was unknown to it, and the ID token failed. The published key set now makes sure the tenant has a key of every algorithm a token may be signed with before it answers ([the published key set](../architecture/contexts/keys.md#the-published-key-set)).
- **The image could be built from another branch's code.** Not in Hodor itself: the build stage's target cache is shared by every build on a machine, and cargo took a file older than what another branch had built as already built. The build stage now touches the workspace's files first ([deploy/docker](https://github.com/ortisun/hodor/blob/develop/deploy/docker/EGM.md)).

The conformance clients are registered without PKCE, which the command-line tool could not do: `hodor-cli client add --without-pkce` came with them.
