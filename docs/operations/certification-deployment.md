# The certification deployment

This page is the runbook of `deploy/certification/`, which Issue-142 builds: a public deployment of Hodor, the tenants, clients and person each plan of the OpenID Foundation's hosted suite needs, the configuration to paste into the suite, and, once the plans have run, the clients disabled and the keys revoked before the logs are published. [How certification is obtained](certification.md) says what the Foundation asks and who does what; [Decision 0051](../decisions/0051-conformance-runs-and-certification.md) says when. This page says how.

**Nothing real goes into this deployment.** Its tenants, clients, person and keys exist for the run and are retired before the logs are published, as the Foundation advises: "The full supplied log files will be published as part of a successful certification and these may contain client credentials, private keys" ([submission rules](https://openid.net/certification/fapi_op_submission/)). Use a host, a name and secrets made for it, and reset the host afterwards.

## What it is made of

| File | What it is |
|---|---|
| `deploy/certification/compose.yaml` | An override of the [installation with Docker](install-with-docker.md): the same database, server and worker, under the project name `hodor-certification`, with the web server of the profile `https` reading `Caddyfile`, and a mail server that delivers nothing |
| `deploy/certification/Caddyfile` | The web server's settings: the certificate, the versions of TLS and the cipher suites ([the web server](#the-web-server)) |
| `deploy/certification/.env.example` | The settings to copy to `.env` and fill in |
| `deploy/certification/plans.json` | The plans of 0.5.0, the variants of each, the tenants and clients they need, and what each waits for ([plans that wait](#plans-that-wait-for-a-feature)) |
| `deploy/certification/certification.mjs` | The script: `make` makes everything and prints the configuration of every plan; `retire` disables, revokes and suspends everything it made, and checks that nothing still works |
| `deploy/certification/test/` | Its test, against a stand-in for `hodor-cli` and for Hodor ([how it is tested](#how-it-is-tested)) |

The script needs Node.js 24 and nothing else: no package to install. It runs `hodor-cli` through `docker compose run`, the way an operator of the installation does, and reaches Hodor and the mail server over HTTP from the host it runs on.

## What the owner needs first

- **A host reachable from the internet**, with Docker and Docker Compose 2.20 or newer. Two processor cores and 4 gibibytes of memory are enough: the suite runs one test at a time.
- **A name for it**, such as `hodor-certification.example.org`, whose address record points at the host. It becomes the start of every issuer, `https://<name>/t/certification`, and is named in the Certification of Conformance as the deployment. Choose it before the first run: a certification is of one deployment, and a different endpoint is a different deployment ([the frequently asked questions](https://openid.net/certification/what-is-self-certification-faq/)).
- **Ports 80 and 443 open to the internet.** Port 80 answers the certificate authority's challenge, and is redirected to port 443 otherwise; port 443 is where the hosted suite, and the owner's browser, reach Hodor. If a firewall stands in front, it must let in the hosted suite's address for outbound calls, which the Foundation publishes on its testing pages.
- **The Hodor image of the version to certify**, such as `ghcr.io/ortisun/hodor:0.5.0`. The version string of the declaration is this version.
- **An account on the hosted suite**, `https://www.certification.openid.net`, which the owner signs in to with Google or GitLab.

## The web server

Hodor does not end TLS; the web server in front of it does, and the suite checks what it negotiates ([Decision 0052](../decisions/0052-security-profiles.md#what-the-web-server-in-front-must-do)). `Caddyfile` sets Caddy so that every profile Hodor will be certified for, those of 0.5.0 and of 0.6.0, finds what it asks:

- **A certificate from Let's Encrypt** for the name in `HODOR_PUBLIC_URL`, obtained and renewed by Caddy. The suite refuses a certificate it cannot verify, so a certificate of one's own making will not do.
- **An RSA key**, because the cipher suites FAPI 1.0 Advanced names for TLS 1.2 are those of RSA.
- **TLS 1.2 and 1.3 only.** On TLS 1.2, only `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`: the two of the four suites FAPI 1.0 Advanced allows that Caddy offers, and two that RFC 9325 recommends for FAPI 2.0. TLS 1.3 chooses its own suites, all of them allowed.
- **The address of each client forwarded** in `X-Forwarded-For`, replacing any the client sent, as the installation expects ([the address of each client](install-with-docker.md#the-address-of-each-client)).
- **No client certificate is asked for yet.** The profiles of 0.5.0 never present one, and a browser asked for one may show the person a choice of certificates. The FAPI profiles of 0.6.0 need a second name where the web server asks for one and forwards it to Hodor, once Hodor can name that second address in discovery (Issue-146); `Caddyfile` holds that part, commented out, for then.

## Starting the deployment

On the host, in a checkout of the repository at the tag of the version to certify:

1. Copy the settings and fill them in. Every secret in it is new, made for this deployment alone.

    ```bash
    cp deploy/certification/.env.example deploy/certification/.env
    ```

    `.env.example` says how to make each value: the image, `HODOR_PUBLIC_URL` with the name above, a password for each database role, and `HODOR_SECRET_KEYS`.

2. Start it.

    ```bash
    docker compose --env-file deploy/certification/.env \
      -f deploy/install/docker/compose.yaml -f deploy/certification/compose.yaml \
      up --detach --wait
    ```

    The two files are read together: the paths in the second are written from the folder of the first, as Compose reads them. The project is `hodor-certification`, so that it never shares containers or volumes with an installation on the same host.

3. Check that the internet sees it: from another machine, `https://<name>/t/system/.well-known/openid-configuration` answers with Hodor's JSON, behind a certificate the browser trusts.

The mail server, Mailpit, catches every message Hodor sends and delivers none. Its interface is published on `127.0.0.1:8025` of the host alone; the script reads the link that lets it set the person's password from there.

## Making what the plans need

```bash
node deploy/certification/certification.mjs make
```

The script reads `deploy/certification/.env` for `HODOR_PUBLIC_URL`, checks that Hodor answers there, and makes, through `hodor-cli`, everything the plans that are ready need, and nothing for a plan that is not ([plans that wait](#plans-that-wait-for-a-feature)):

- **The tenant `certification`**, with an application of its own, first party, so that consent is not asked, for the plans whose clients are registered by hand: Basic, Config, Implicit, Hybrid, the three Form Post plans and the logout plans.
- **Its clients**, each confidential, without PKCE, as the Basic plan of 2014 needs, reading unsigned request objects, with the grants `authorization_code` and `refresh_token`, the scopes `openid`, `profile`, `email`, `address`, `phone` and `offline_access`, the suite's redirect address `https://www.certification.openid.net/test/a/<alias>/callback` and its address after logout `…/post_logout_redirect`, and every response type that is built:
    - two that send their secret by `client_secret_basic` and one by `client_secret_post`, the three clients of the Basic plan, whose ID tokens are signed with `ES256`, `RS256` and `PS256`;
    - one for the RP-Initiated plan, with no logout address of its own;
    - one for the Back-Channel plan, with the suite's `…/backchannel_logout` as its back-channel logout address, `sid` required;
    - one for the Front-Channel plan, with `…/frontchannel_logout`, once front-channel logout is built.
- **The tenant `certification-session`**, for the Session plan alone, once session management is built: a tenant turns it on for all its clients, and the other plans need not see it.
- **The tenant `certification-dynamic`**, for the Dynamic and 3rd Party-Init plans, once the registration endpoint is built: client registration turned on, open, for an application of registered clients that is never first party, and only for addresses on the suite's host.
- **In each tenant, the person the owner signs in as**, `certification@example.com` unless `CERTIFICATION_PERSON_EMAIL` says otherwise, made by an administrator through the administration interface and given every standard claim, so that the tests of the scopes find each claim they want. The script chooses a long random password and sets it through recovery, reading the link from the mail server.

**The alias.** The suite's addresses for a test contain an alias, which "should be unique to yourself" among everyone who uses the hosted suite ([OpenID Provider testing](https://openid.net/certification/connect_op_testing/)). The script makes one, `hodor-` and eight random hexadecimal digits, unless `CERTIFICATION_ALIAS` gives it, and registers every client with it. Every plan uses the same alias, so the plans are run one at a time.

**What it prints** on its standard output is one JSON document, and nothing else; what it is doing goes to the standard error:

```json
{
  "suite": "https://www.certification.openid.net",
  "alias": "hodor-3fa9c2d1",
  "version": "0.5.0",
  "person": { "email": "certification@example.com", "password": "…" },
  "plans": [
    {
      "profile": "Basic OP",
      "plan": "oidcc-basic-certification-test-plan",
      "variant": { "server_metadata": "discovery", "client_registration": "static_client" },
      "file": "01-basic.json",
      "configuration": {
        "alias": "hodor-3fa9c2d1",
        "description": "Hodor 0.5.0, Basic OP",
        "server": { "discoveryUrl": "https://<name>/t/certification/.well-known/openid-configuration" },
        "client": { "client_id": "…", "client_secret": "…" },
        "client2": { "client_id": "…", "client_secret": "…" },
        "client_secret_post": { "client_id": "…", "client_secret": "…" }
      }
    }
  ],
  "waiting": [
    {
      "profile": "Implicit OP",
      "plan": "oidcc-implicit-certification-test-plan",
      "waitingFor": ["Issue-127, pull request 178: an ID token through the browser", "Issue-128: an access token through the browser"]
    }
  ]
}
```

It also writes each plan's `configuration` alone to a file of `deploy/certification/output/`, named as `file` says, ready to paste, and what it made, with the secrets, to `deploy/certification/output/state.json`, which `retire` reads. That folder is ignored by git, readable by the owner alone, and is lost with the host: keep it until the deployment is retired.

The script refuses to run `make` twice on one deployment. To start again, retire, reset the deployment ([afterwards](#afterwards)) and run it anew.

| Setting | What it is | Unless given |
|---|---|---|
| `HODOR_PUBLIC_URL` | Hodor's address, as the deployment has it | Read from `deploy/certification/.env` |
| `CERTIFICATION_SUITE_URL` | The hosted suite | `https://www.certification.openid.net` |
| `CERTIFICATION_ALIAS` | The alias of every plan | `hodor-` and eight random hexadecimal digits |
| `CERTIFICATION_PERSON_EMAIL` | The person's address | `certification@example.com` |
| `CERTIFICATION_MAIL_URL` | The mail server's interface | `http://127.0.0.1:8025` |
| `CERTIFICATION_OUTPUT` | Where the files are written | `deploy/certification/output` |
| `CERTIFICATION_CLI` | The command that runs `hodor-cli`, as a JSON array | `docker compose run` of the service `cli`, with the two files above |
| `CERTIFICATION_ACCEPT_ANY_CERTIFICATE` | `1` to accept Hodor's certificate unchecked, for a stack of one's own making; never for the real deployment | Checked |

## The plans

The plans of 0.5.0, as [the target](conformance.md#the-target) names them, with what to choose on the hosted suite. A logout plan is run once for each response type Hodor supports, as the Foundation asks ([logout testing](https://openid.net/certification/connect_op_logout_testing/)); a Form Post plan once for each flow ([OpenID Provider testing](https://openid.net/certification/connect_op_testing/)).

| Profile | Plan | Variants to choose | Tenant and clients | Ready |
|---|---|---|---|---|
| Basic OP | `oidcc-basic-certification-test-plan` | `server_metadata=discovery`, `client_registration=static_client` | `certification`: the three of the Basic plan | Yes |
| Config OP | `oidcc-config-certification-test-plan` | Set by the plan | The same | Yes |
| Implicit OP | `oidcc-implicit-certification-test-plan` | As Basic; the plan runs each response type of its profile itself | The same | Waits for Issues 127 and 128 |
| Hybrid OP | `oidcc-hybrid-certification-test-plan` | As Basic | The same | Waits for Issues 127 and 128 |
| Form Post OP | `oidcc-formpost-basic-certification-test-plan` | As Basic | The same | Yes |
| Form Post OP | `oidcc-formpost-implicit-certification-test-plan`, `oidcc-formpost-hybrid-certification-test-plan` | As Basic | The same | Wait for Issues 127 and 128 |
| RP-Initiated OP | `oidcc-rp-initiated-logout-certification-test-plan`, once per response type | `client_registration=static_client`, `response_type` | `certification`: the RP-Initiated client | `code` yes; the others wait for Issues 127 and 128 |
| Back-Channel OP | `oidcc-backchannel-rp-initiated-logout-certification-test-plan`, once per response type | As RP-Initiated | `certification`: the Back-Channel client | `code` yes; the others wait for Issues 127 and 128 |
| Front-Channel OP | `oidcc-frontchannel-rp-initiated-logout-certification-test-plan`, once per response type | As RP-Initiated | `certification`: the Front-Channel client | Waits for Issue-139 |
| Session OP | `oidcc-session-management-certification-test-plan`, once per response type | As RP-Initiated | `certification-session` | Waits for Issue-140 |
| Dynamic OP | `oidcc-dynamic-certification-test-plan` | `response_type=code`; the plan sets the rest | `certification-dynamic`: the suite registers its own | Waits for Issues 127, 128, 134 and 137 |
| 3rd Party-Init OP | `oidcc-3rdparty-init-login-certification-test-plan` | Set by the plan | `certification-dynamic` | Waits for Issue-134 |

The response types are `code`, `id_token`, `code id_token`, `id_token token`, `code token` and `code id_token token`. The suite's plan of the Dynamic profile offers the response type in its menu and the Foundation's page names none; `code` is what continuous integration runs ([Decision 0051](../decisions/0051-conformance-runs-and-certification.md#what-runs-and-when)), and `plans.json` lists it alone until the Foundation is asked.

### Plans that wait for a feature

Some plans need what is not built on `develop` yet. The script never guesses: `plans.json` names each feature, whether it is built, and the issue and pull request that build it, and a plan, a response type, a client or a tenant that needs a feature not built is left out and listed under `waiting` with the reason. **The script is driven by `plans.json`, so turning a plan on is a change of one line there**: `"built": false` becomes `"built": true` for its feature, in the pull request that merges the feature. The features, as `plans.json` names them:

| Feature | Built by | What turning it on adds |
|---|---|---|
| `id-token-through-the-browser` | Issue-127, pull request 178 | `id_token` and `code id_token` on every client of `certification`; with Issue-128, the Implicit, Hybrid and two Form Post plans |
| `access-token-through-the-browser` | Issue-128 | `id_token token`, `code token` and `code id_token token`. Also give its `clientArguments` the option of `hodor-cli client add` that marks a client as allowed tokens through the browser, which that issue names |
| `front-channel-logout` | Issue-139, pull request 184 | The Front-Channel client and plan |
| `session-management` | Issue-140 | The tenant `certification-session` and the Session plan. Also give its `tenantCommands` the command of `hodor-cli` that turns session management on for a tenant, which that issue names |
| `registration-endpoint` | Issue-133, pull request 179; built | The tenant `certification-dynamic` with registration on, made once a plan that uses it is ready: the 3rd Party-Init plan with Issue-134, the Dynamic plan with Issues 127, 128, 134 and 137. Its command turns registration on with the six response types, so it needs Issue-128 too, or fewer response types, before either plan is ready |
| `registration-management` | Issue-134 | The 3rd Party-Init plan, with the Dynamic plan |
| `dynamic-plan` | Issue-137 | What the Dynamic plan needs of a tenant beyond the endpoint, such as registered clients without PKCE, which Issue-137 decides; its `tenantCommands` take the command it names |

## Running the plans on the hosted suite

The suite drives the tests; the owner's browser is the browser. For each plan of `plans` in what the script printed:

1. Sign in to `https://www.certification.openid.net`, and choose **Create a new test plan**.
2. Choose the plan named in `plan`, and in each menu the value `variant` gives. A menu the entry does not name is set by the plan.
3. Open the tab of the configuration as JSON and replace its content with the plan's file of `deploy/certification/output/`, or with its `configuration`.
4. Create the plan, then run each test, one at a time. When a test sends the browser to Hodor, sign in as the person, with the address and password the script printed. A test that asks for another sign-in, such as `oidcc-prompt-login`, wants it done again.
5. When a test asks for a screenshot, of Hodor's error page or of its sign-in page asked for again, take one of the page the browser shows and upload it to the test. Look at every one: a test in review counts toward certification only once a person has looked.
6. During `oidcc-server-rotate-keys` of the Dynamic plan, when the test says so, rotate the tenant's signing key on the host:

    ```bash
    docker compose --env-file deploy/certification/.env \
      -f deploy/install/docker/compose.yaml -f deploy/certification/compose.yaml \
      run --rm -T cli keys rotate --tenant certification-dynamic --algorithm rs256
    ```

7. A plan is finished when every test ended passed, in review, with a warning or skipped, and none failed or unfinished: "You cannot certify with any FAILED or INTERRUPTED results" ([OpenID Provider testing](https://openid.net/certification/connect_op_testing/)). Run a failed test again once the cause is understood. [The expected results](conformance.md#expected-results) say which tests end otherwise than passed in continuous integration, and why.
8. Choose **Publish for certification** on the plan's page, and download the package the suite makes for it.

Keep the list of plans, their identifiers on the suite and their packages together: each goes into the submission, under the profile `profile` names.

## Retiring what was made

Once every plan has run and every package is downloaded, and before anything is submitted:

```bash
node deploy/certification/certification.mjs retire
```

It reads `deploy/certification/output/state.json` and, in each tenant it made:

1. disables every client it made, and every application, which stops the clients the suite registered itself;
2. runs what each tenant's `retireCommands` names, such as turning client registration off;
3. revokes every version of the tenant's signing keys, which leave the published key set at once, so that no token in the logs can be checked any more;
4. checks that each client it made is refused at the token endpoint, `invalid_client`, and that no key the tenant published before is published still;
5. suspends the tenant, and checks that its discovery document is refused with `tenant.suspended`.

It prints what it did and each check, and ends in failure if a check did not hold. A refresh token, a secret or an access token from the logs then gets nothing anywhere in the deployment.

## Afterwards

What only people can do, in order:

1. **Fill in the Certification of Conformance** ([the form](https://openid.net/wordpress-content/uploads/2021/07/OpenID-Certification-of-Conformance.pdf)) for the batch: the implementer, the deployment, its address `https://<name>`, the version printed as `version`, each profile as the Foundation names it, and the suite's version, shown on the hosted suite. Issue-143 drafts the fields for the owner.
2. **Pay, or ask for the open-source fee waiver**, to get a payment code ([what it costs](certification.md#what-it-costs)). The waiver covers one batch of every OpenID Connect and logout profile a year: submit them all at once.
3. **Submit at `submissions.openid.net`**, with the packages attached ([how it is sent](certification.md#what-the-foundation-asks)).
4. **Sign the declaration** sent by DocuSign, "Declaration of Conformance signing", as a person who works for the implementer. Nothing is processed until it is signed.
5. **Take the deployment down**, or reset it, once the Foundation has what it needs:

    ```bash
    docker compose --env-file deploy/certification/.env \
      -f deploy/install/docker/compose.yaml -f deploy/certification/compose.yaml \
      down --volumes
    ```

    and delete `deploy/certification/.env` and `deploy/certification/output/`.

6. **Once the Foundation lists the certification**, link the listing from the [conformance page](conformance.md) and the changelog.

## How it is tested

`deploy/certification/test/certification.test.mjs` runs the script, `make` then `retire`, against a stand-in for `hodor-cli` and a stand-in for Hodor and its mail server, which share what was made: a client disabled is refused, a key revoked leaves the key set, a tenant suspended answers `tenant.suspended`. It checks that the output is one JSON document, that every plan that is ready has a complete configuration, with the discovery address, the alias and each client the plan needs, that every plan that is not ready is listed with what it waits for, that a feature turned on in a copy of `plans.json` moves its plans from waiting to ready, and that after `retire` nothing made still works. It runs with `node --test deploy/certification/test/certification.test.mjs`, in the job `Certification deployment` of continuous integration, which also checks that Compose reads the two files together and that Caddy reads `Caddyfile`.

The job `Certification deployment against Hodor` of `.github/workflows/conformance.yml` also runs the script against Hodor itself, from the image the conformance plans run against, whichever of their sets runs ([when each plan runs](conformance.md#when-each-plan-runs)): it starts Hodor, its worker and the mail server of the conformance stack without the suite, then runs `make`, a check that every ready plan has a configuration with a discovery address and a client, and `retire`, whose checks must all hold. Any stack will do, given `CERTIFICATION_CLI`, `HODOR_PUBLIC_URL`, `CERTIFICATION_MAIL_URL` and `CERTIFICATION_ACCEPT_ANY_CERTIFICATE=1` for a stack with a certificate of its own making; the job's step is the example. Nothing there calls the hosted suite: its addresses are only registered with the clients.
