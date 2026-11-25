# OpenID conformance

Hodor runs the [OpenID conformance suite](https://openid.net/certification/) of the OpenID Foundation against itself on every pull request: the **Basic OpenID Provider**, the **Config OpenID Provider** and the **Back-Channel OpenID Provider** plans, and the Basic and Back-Channel plans again with pairwise clients. Passing them is the exit criterion of Phase 2 in the [roadmap](../product/roadmap.md) and the acceptance of Issue-61 in [the epics](../product/epics.md#slice-o--openid-connect-epic-10). The suite is the same one the OpenID Foundation uses to certify providers. Running it here is not a certification: nobody at the Foundation has looked at the results, and no certification has been asked for. [The target](#the-target) says which plans 0.5.0 and 0.6.0 add, and [how certification is obtained](certification.md) what a certification takes.

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

**Request objects** are the acceptance of Issue-120 ([request objects](../architecture/contexts/oauth.md#request-objects)). The Basic plan's two tests of them, `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` and `oidcc-ensure-request-object-with-redirect-uri`, send the whole request again as an unsigned object, and are skipped unless discovery names `none` among `request_object_signing_alg_values_supported`. Hodor reads an unsigned object only from a client whose administrator chose `none` for it, so every client of the run is made with `hodor-cli client add --request-object-signing-alg none`. The second test puts outside the object a redirect address that is not the client's, and the client's own inside: Hodor reads only the one inside, as RFC 9101 says, and the person signs in. A signed object is tried by the tests of the server, as the Basic plan's clients prove who they are with a secret and have no keys.

**The Form Post plan** of the code flow, `oidcc-formpost-basic-certification-test-plan`, is the acceptance of Issue-129 ([response modes](../architecture/contexts/oauth.md#response-modes)), and runs only when asked for, `CONFORMANCE_PLANS=formpost-basic`, until Issue-131 adds it to continuous integration. It is the Basic plan's 35 tests with `response_mode=form_post` on every request, against the same clients, configuration and variants: every answer and every error reaches the suite's redirect address posted by Hodor's page of `form_post`, and the suite reads it from the body of the post. Run against an image of the change that built the mode, it ended as the Basic plan does: 26 passed, and the three warnings, three skips and three reviews of [the expected results](#expected-results), which name the same tests in either plan.

The suite is the image `registry.gitlab.com/openid/conformance-suite:release-v5.3.4`, with its web server `registry.gitlab.com/openid/conformance-suite/nginx:release-v5.3.4` and MongoDB 6.0.13: the releases of 2026-10-26, pinned by tag in `deploy/conformance/compose.yaml`.

## The target

What follows is planned, not built. 0.5.0 and 0.6.0 make Hodor able to pass every plan the OpenID Foundation certifies an OpenID Provider with ([Decision 0044](../decisions/0044-what-0.5.0-and-0.6.0-hold.md)), and each milestone's last issue adds its plans to continuous integration, which runs them as [Decision 0051](../decisions/0051-conformance-runs-and-certification.md) says. How a passing plan becomes a certification is [a page of its own](certification.md).

The requirements below were read from the suite's plans at `release-v5.3.5`, of 2026-11-24, in `src/main/java/net/openid/conformance/` of [the suite's repository](https://gitlab.com/openid/conformance-suite), and from the Foundation's instructions for [OpenID Providers](https://openid.net/certification/connect_op_testing/), [logout](https://openid.net/certification/connect_op_logout_testing/), [FAPI](https://openid.net/certification/certification-fapi_op_testing/) and [FAPI-CIBA](https://openid.net/certification/fapi_ciba_op_testing/). The stack moves to that release when the first plan of Milestone 13 is added. A profile is certified when every test of its plan ends passed, in review, with a warning or skipped, and none failed or unfinished.

### OpenID Connect and logout: 0.5.0

| Profile | Plan | What the provider must do | Hodor today | Where it is planned |
|---|---|---|---|---|
| Basic OP | `oidcc-basic-certification-test-plan` | The code flow with two `client_secret_basic` clients and one `client_secret_post`; `prompt`, `max_age`, `id_token_hint`, `login_hint`, `display`, `ui_locales`, `claims_locales` and `acr_values` honored or harmless; a code used once; a request with PKCE accepted. A request object and the `claims` parameter may be refused or ignored, with a skip or a warning | Passes, with one warning ([expected results](#expected-results)); its request object tests pass since Issue-120, its tests of the scopes since Issue-123, and the warning of the access token in a form body at UserInfo went with Issue-125 | The warning goes: the `claims` parameter (Issue-124) |
| Config OP | `oidcc-config-certification-test-plan` | Discovery, with `RS256` among the ID token algorithms | Passes | — |
| Implicit OP | `oidcc-implicit-certification-test-plan`, once for `id_token` and once for `id_token token` | The two types in the fragment; `nonce` required; `at_hash`; the claims in the ID token when no access token comes with it | Missing: only `code` is answered, and the implicit grant is a non-goal | Issues 127 and 128 ([Decision 0046](../decisions/0046-responses-through-the-browser.md)) |
| Hybrid OP | `oidcc-hybrid-certification-test-plan`, once for each of `code id_token`, `code token`, `code id_token token` | The three types in the fragment; `c_hash` and `at_hash`; `nonce` where an ID token is returned | Missing | Issues 127 and 128 |
| Form Post OP | `oidcc-formpost-basic-`, `-implicit-` and `-hybrid-certification-test-plan` | The same flows answered with `response_mode=form_post`, one plan per flow supported | `form_post` is built (Issue-129); the plan of the code flow passes when run by hand, with the Basic plan's warnings and skips ([the Form Post plan](#what-runs)) | Continuous integration (Issue-131); the Implicit and Hybrid flows with their response types (Issues 127 and 128) |
| Dynamic OP | `oidcc-dynamic-certification-test-plan` | Dynamic registration, with an initial access token if the provider wants one; `private_key_jwt`; keys by value and at `jwks_uri`; `request_uri` with unsigned and `RS256` request objects; UserInfo signed with `RS256`; refresh tokens with `offline_access`; the client's key rotated at its `jwks_uri`; the provider's own key rotated during a test, or attested; discovery naming `code`, `id_token` and `id_token token`; a sector identifier address registered, when pairwise is offered; a fragment in a redirect address refused | Missing: no registration | Milestone 15 (Issues 132 to 137), on Issues 120 to 122, 127, 128 and 130 |
| 3rd Party-Init OP | `oidcc-3rdparty-init-login-certification-test-plan` | `initiate_login_uri` registered, given back, readable with the registration access token; one that is not HTTPS refused | Missing | Issue-134 |
| RP-Initiated OP | `oidcc-rp-initiated-logout-certification-test-plan`, for each response type | The end-session endpoint; `state` given back; a page, never a redirect, for a bad or missing hint or an address not registered | Built; the plan does not run | Issue-138 |
| Back-Channel OP | `oidcc-backchannel-rp-initiated-logout-certification-test-plan`, for each response type | Logout tokens with `sid` | Passes for `code` | Issue-138, for the other response types |
| Front-Channel OP | `oidcc-frontchannel-rp-initiated-logout-certification-test-plan`, for each response type | `frontchannel_logout_supported` and `frontchannel_logout_session_supported`; a frame with `iss` and the `sid` of the ID token | Missing | Issue-139 ([Decision 0050](../decisions/0050-logout-and-session-state-in-the-browser.md)) |
| Session OP | `oidcc-session-management-certification-test-plan`, for each response type | `session_state` in the authorization response; a `check_session_iframe` that answers `unchanged`, then `changed` after logout | Missing | Issue-140 |

No plan of OpenID Connect tests encryption or `client_secret_jwt`; the unsigned ID token test is skipped for a provider that does not offer `none`, as Hodor never will.

### FAPI and backchannel authentication: 0.6.0

| Profile | Plan and variants | What the provider must do | Hodor today | Where it is planned |
|---|---|---|---|---|
| FAPI 1.0 Advanced | `fapi1-advanced-final-test-plan`: `private_key_jwt` or mutual TLS, by value or pushed, plain or JARM; each combination a profile of its own | A signed request object with `exp` and `nbf` at most 60 minutes apart; `code id_token` with `s_hash` and `c_hash`, or `code` with JARM; `PS256` or `ES256`, never `RS256`; tokens bound to the client's certificate whatever its authentication; `mtls_endpoint_aliases`; pushed requests with PKCE; the `claims` parameter; an assurance level named `urn:mace:incommon:iap:silver`; TLS 1.2 or later with four cipher suites only | Missing; mutual TLS and certificate-bound tokens are planned in 0.4.0 (Issues 107 and 108) | Issues 120, 121, 124, 127, 146, 148 and 151 ([Decision 0052](../decisions/0052-security-profiles.md)) |
| FAPI 2.0 Security Profile | `fapi2-security-profile-final-test-plan`: `private_key_jwt` or mutual TLS, each with DPoP or mutual TLS; OpenID Connect as an addition; client credentials as a family of its own | Pushed requests always, under 600 seconds; `code` only with PKCE and `iss`; DPoP, its nonces and its checks at the resource, here UserInfo; the issuer alone as a client assertion's `aud`; codes of 60 seconds; refresh tokens not rotated; `PS256`, `ES256` or `EdDSA`; TLS 1.2 or later with the cipher suites of RFC 9325 | `iss`, PKCE and codes of 60 seconds are built; the rest is missing | Issues 121, 130 and 144 to 147 ([Decision 0053](../decisions/0053-dpop.md)) |
| FAPI 2.0 Message Signing | `fapi2-message-signing-final-test-plan`, with signed requests and with JARM as additions | Pushed requests as signed request objects with the 60-minute bounds; JARM; JWT introspection responses are in the specification but not tested | Missing | Issues 148 to 150 |
| FAPI-CIBA | `fapi-ciba-id1-test-plan`: poll or ping, `private_key_jwt` or mutual TLS; poll required in every submission | The backchannel authentication endpoint; signed requests; one hint; `binding_message`; poll and ping; tokens bound to the certificate; the person approves on a device, by hand or through an address the suite calls | Missing | Milestone 19 (Issues 154 to 158, [Decision 0054](../decisions/0054-backchannel-authentication.md)) |

For the FAPI plans the suite also probes the TLS of every endpoint it calls and presents client certificates. Hodor does not end TLS: the web server in front of it does, as [Decision 0052](../decisions/0052-security-profiles.md#what-the-web-server-in-front-must-do) says, and the conformance stack's web server is set the same way.

### Not targeted

OpenID Connect for Identity Assurance and OpenID Federation (in the suite but not part of certification), OpenID for Verifiable Credential Issuance and for Verifiable Presentations (certified, for issuers, wallets and verifiers rather than OpenID Providers), the Shared Signals Framework, AuthZEN, and the ecosystems' profiles of FAPI. [Decision 0044](../decisions/0044-what-0.5.0-and-0.6.0-hold.md#what-is-in-and-what-is-out) gives the reason for each.

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
- eight confidential clients, each with the suite's redirect address `https://localhost.emobix.co.uk:8443/test/a/hodor/callback` and post-logout address, the grants `authorization_code` and `refresh_token`, and the scopes `openid`, `profile`, `email`, `address`, `phone` and `offline_access`:
  - two send their secret by `client_secret_basic`, because the Basic plan needs two clients; the first's ID tokens are signed with `ES256`, the default, the second's with `RS256`;
  - one sends it by `client_secret_post`, for the one test that does, and its ID tokens are signed with `PS256`;
  - one sends it by `client_secret_basic` and has a back-channel logout address, for the back-channel plan alone, so that no test of the other plans receives a logout token it does not wait for; its ID tokens and logout tokens are signed with `PS256`;
  - four more, the same four made pairwise, for the second run of the two plans: each takes its sector from the redirect address, but the second, whose sector identifier address names another host. Their ID tokens are signed with `EdDSA`, `PS256` and `RS256`, and the back-channel one's with `EdDSA`.
- the person `conformance@example.com`, made by an administrator through the administration interface with the username `ada`, a display name and a language, given every [standard claim](../architecture/contexts/identity.md#standard-claims) with `hodor-cli user claims`, a verified telephone number and a postal address among them, so that the tests of the scopes `profile`, `address` and `phone` and of every scope at once find each claim they want; the person then chooses a password through the link from the message the mail server caught.

**Signing algorithms** are part of the acceptance of Issue-130 ([which algorithm](../architecture/contexts/oauth.md#the-id-token)). A static client of the suite cannot choose how its ID tokens are signed, so the script chooses for it, with `hodor-cli client add --id-token-algorithm`, as the list above says: every one of `ES256`, `RS256`, `PS256` and `EdDSA` signs the ID tokens of some client of the runs, and the suite checks every ID token, and every logout token of the back-channel plan, against the tenant's key set, which names a key of each. The back-channel plan's ID tokens, signed with `PS256` and `EdDSA`, come back as `id_token_hint` at the end-session endpoint. The Config plan checks that `id_token_signing_alg_values_supported` names `RS256` and that `userinfo_signing_alg_values_supported` is a list. The suite tests [signed UserInfo answers](../architecture/contexts/oauth.md#signed-userinfo-answers) only in the Dynamic plan, `oidcc-userinfo-rs256`, with a client it registers itself: it runs with [Milestone 15](../product/epics.md#milestone-15-clients-that-register-themselves). A static client must not have one, since every test of the Basic plan reads UserInfo as JSON.

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

The script waits for the suite to start, which takes a minute or two, makes what it needs in Hodor, runs the five plans and prints one line per test with the address of its log in the suite, `https://localhost.emobix.co.uk:8443/log-detail.html?log=…`, which a browser on the machine can open while the stack runs. `CONFORMANCE_ONLY=oidcc-server,oidcc-prompt-login` runs only the tests named; `CONFORMANCE_REPORT=results.json` writes the results to a file; `CONFORMANCE_PLANS=formpost-basic` runs only the plans named, by the short names of the script (`basic`, `config`, `backchannel`, `basic-pairwise`, `backchannel-pairwise`, `formpost-basic`), the first five unless given. `HODOR_IMAGE` must be set for the script as for Compose, since it runs `hodor-cli` through the same file.

It ends in failure when a test ends in a result other than `PASSED` that [`deploy/conformance/expected.json`](#expected-results) does not name for it. A test that the suite left unfinished or interrupted is a failure.

```bash
HODOR_IMAGE=hodor:conformance docker compose -f deploy/conformance/compose.yaml down --volumes
```

Continuous integration does the same in the job `OpenID conformance` of `.github/workflows/ci.yml`, and keeps the results as an artifact of the run.

## Expected results

Every test of the five plans, and of the Form Post plan when it runs, passes except those below, in each plan they belong to. Each ends in a result the suite counts as allowed, and `deploy/conformance/expected.json` names it with the same reason; a test that ends otherwise fails the run.

| Test | Result | Why |
|---|---|---|
| `oidcc-claims-essential` | Warning | It asks for `name` through the `claims` parameter alone. Hodor does not read that parameter, and discovery says so (`claims_parameter_supported` is false); UserInfo gives the claims of the scopes, here only `sub`. Supporting the parameter is optional (OpenID Connect Core, section 5.5) |
| `oidcc-prompt-login`, `oidcc-max-age-1` | Review | The test passes, and keeps a screenshot of the second sign-in page it made Hodor show, for a person to look at |
| `oidcc-ensure-registered-redirect-uri` | Review | Hodor shows its own error page and never sends the browser to an address it cannot trust; the suite keeps a screenshot of that page for a person to look at |

The tests of the scopes, `oidcc-scope-profile`, `oidcc-scope-email`, `oidcc-scope-address`, `oidcc-scope-phone` and `oidcc-scope-all`, want every claim of each scope asked for at UserInfo. They pass since Issue-123 with the person above, who has them all; a person without some of them would make them end in a warning, as OpenID Connect Core, section 5.4, lets a provider answer only the claims it has.

A result of **Review** is the suite saying that a person must look at the screenshots before the test can count toward a certification. Here nobody does: the screenshots are taken and given to the suite, and the run accepts the result. The pages they show are tested on their own by the browser tests of the hosted pages.

A full run takes about 30 minutes on a laptop: about 29 for the 75 tests and one for the suite to start. In continuous integration, building the image adds its own time.

## What the suite found in Hodor

Running the plans found four things wrong in Hodor, all fixed in the change that brought the suite in:

- **No `RS256` for ID tokens.** OpenID Connect Discovery requires every OpenID Provider to offer `RS256` in `id_token_signing_alg_values_supported`; Hodor signed with `ES256` only, and the Config OpenID Provider plan failed. A client now has an ID token algorithm, `ES256` unless `RS256` is chosen ([the ID token](../architecture/contexts/oauth.md#the-id-token)).
- **A new tenant could not issue a token.** A tenant has no signing key until the worker's next rotation pass, up to ten minutes later; every token asked for in between was a `server_error`. The first key of an algorithm is now made when something must sign with it ([the keys context](../architecture/contexts/keys.md#rotation)).
- **The key set did not name the key of the first token.** The suite reads a tenant's key set once at the start of a test; a key made after that read was unknown to it, and the ID token failed. The published key set now makes sure the tenant has a key of every algorithm a token may be signed with before it answers ([the published key set](../architecture/contexts/keys.md#the-published-key-set)).
- **The image could be built from another branch's code.** Not in Hodor itself: the build stage's target cache is shared by every build on a machine, and cargo took a file older than what another branch had built as already built. The build stage now touches the workspace's files first ([deploy/docker](https://github.com/ortisun/hodor/blob/develop/deploy/docker/EGM.md)).

The conformance clients are registered without PKCE, which the command-line tool could not do: `hodor-cli client add --without-pkce` came with them.
