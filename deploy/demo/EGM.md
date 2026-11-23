# demo

## Overview

Three demonstration scripts that run against the development stack of [docker](../docker/EGM.md) and check, step by step, what the milestones promise. All use Python 3 and nothing outside the standard library, and all run `hodor-cli` through Docker Compose. Every answer is checked; the first one that is not what it should be stops the demonstration with exit status 1.

- `demo.py`: the demonstration of Milestone 1. A person registers, verifies an address and signs in to a tenant, and tenants are kept apart.
- `external_identities.py`: the demonstration of Milestone 2. Signing in with external identities through the development OpenID Connect provider ([dev-provider](../dev-provider/EGM.md)), the development LDAP directory and the development SAML identity provider ([dev-saml-provider](../dev-saml-provider/EGM.md)).
- `strong_authentication.py`: the demonstration of Milestone 4. An authenticator application, recovery codes, a tenant that requires a second factor, a passkey that signs in alone, a step-up asked for by an application, and an administrator removing a person's factors.

## Interface

No script takes command-line arguments. Each has a `main()` run under `if __name__ == "__main__"`.

### `demo.py`

Environment variables, with defaults:

| Variable | Default |
| --- | --- |
| `HODOR_URL` (`SERVER`) | `http://localhost:8080` |
| `HODOR_MAIL_URL` (`MAIL`) | `http://localhost:8025` |
| `HODOR_METRICS_URL` (`METRICS`) | `http://localhost:8428` |
| `HODOR_TRACES_URL` (`TRACES`) | `http://localhost:10428` |

Shared helpers, also imported by `external_identities.py`:

- `Failed`: the exception that stops a demonstration.
- `step(title)`, `shown(text)`, `check(condition, what)`: output; `check` raises `Failed` when the condition is false.
- `Answer`: status, headers and text of an answer, with `json()` and `code` (the `code` of a problem document).
- `OPENER`, `request(method, url, body=None, headers=None)`: HTTP with a JSON body, never following redirects (`NoRedirects`), 30 second timeout.
- `Browser`: keeps cookies and the `csrf_token` returned by the server, sending it as `X-CSRF-Token` on calls other than `GET`; `call(method, path, body)` and `sign_in(tenant, identifier, password)` through `/t/{tenant}/interaction/sign-in`, `.../steps/identifier`, `.../steps/password`.
- `compose()`: `docker compose -f deploy/docker/compose.yaml`, or `docker compose` alone when `COMPOSE_FILE` is set, so that a copy of the stack started with `COMPOSE_FILE` and `COMPOSE_PROJECT_NAME` is the one the scripts use.
- `cli(*arguments)`: `compose()` followed by `run --rm --no-deps -T --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=... server ...`.
- `until(what, attempt, seconds=60)`: polls once a second until `attempt()` returns something.
- `link_from_message(address, tenant)`: searches the mail server's `/api/v1/search` and `/api/v1/message/{ID}` for a link to `/t/{tenant}/account/...#token=...`.
- `COMPOSE_FILE`, `CLI_DATABASE_URL`, `SERVER`, `MAIL`.

Steps of `main()`, in order: `the_stack_answers`, `two_tenants` (`tenant create --open-registration` for `acme-<suffix>` and `globex-<suffix>`), `the_same_person_in_both`, `the_link`, `signing_in`, `the_pages`, `tenants_apart_session`, `tenants_apart_password`, `lockout`, `an_administrator` (`admin bootstrap`), `tenants_apart_token`, `the_audit_log` (`audit verify`), `metrics`, `a_trace`.

### `external_identities.py`

- Environment: `HODOR_SAML_PROVIDER_URL` (`SAML_PROVIDER`, default `http://localhost:9500`), plus the variables read by `demo.py`.
- Constants: `SAML_CERTIFICATE` (`deploy/dev-saml-provider/certificate.pem`), `SAML_ENTITY_ID` (`urn:hodor:development-saml-provider`), `DORA` (the one person of `deploy/dev-directory/people.ldif`).
- Its own `cli(*arguments, environment=())` adds `-e NAME=value` pairs, used to pass `HODOR_PROVIDER_CLIENT_SECRET`.
- Helpers: `post_form`, `hidden_fields`, `query_of`, `completed`, `rejected`, `leave` (starts a sign-in and chooses a provider by alias), `through_openid` (alias `development`), `through_saml` (alias `corp`, with an optional `tamper` function applied to the signed response), `who`.
- Steps of `main()`, in order: `a_provider` (`provider add` for the OpenID Connect provider), `the_first_sign_in`, `the_second_sign_in`, `no_takeover`, `tenants_apart`, `a_directory` (`provider add --kind ldap`), `a_saml_identity_provider` (`provider add --kind saml --certificate`), `a_tampered_response`.

### `strong_authentication.py`

- Imports from `demo` and from `external_identities` (`completed`, `post_form`, `query_of`, `rejected`); reads the same environment variables.
- Constants: `PASSWORD`, `REDIRECT_URI` (`http://127.0.0.1:8765/callback`, registered for the client and never listened on: the script reads where the browser is sent), `SINGLE_FACTOR`, `MULTI_FACTOR`, `PHISHING_RESISTANT` (`urn:example:acr:phishing-resistant`, a level the script adds to its tenant).
- `Passkey`: a software authenticator for one discoverable credential, present and verified. Its P-256 key pair and ECDSA signatures are computed by hand (`point_add`, `point_multiply`, `sign`); it answers registrations with `fmt` `none` and the COSE key, and assertions with the user handle it was given.
- `AuthenticatorApplication`: codes of RFC 6238 with HMAC-SHA-1, never the same time step twice, waiting for the clock when the next step is beyond the server's window.
- `Application`: `authorize(browser, **extra)` with PKCE `S256`, `tokens(location, parameters, verifier)` with `client_secret_basic`, and `checked(token, what)`, which checks an ES256 signature against `/t/{tenant}/oauth2/jwks` (`verified`).
- Steps of `main()`, in order: `a_tenant_and_a_person` (`tenant create` for `acme-<suffix>` and `globex-<suffix>`, `keys rotate`, `tenant assurance-levels` with three levels, a registration), `an_application` (`application add --first-party`, `client add`), `a_password_session`, `an_authenticator_application`, `a_step_up`, `a_tenant_that_requires_it` (`tenant second-factor --policy required`), `a_recovery_code`, `a_passkey`, `tenants_apart`, `an_administrator` (`admin bootstrap` for `operator-ana-<suffix>@example.com`, `audit verify`).

## Invariants

- Each run makes its own tenants and addresses from a hexadecimal time suffix (`acme-`, `globex-`, `initech-`, `umbrella-`, `ana-`, `bia-`, `sam-`, `mallory-`, `operator-ana-`), so the scripts can run again against the same stack.
- `external_identities.py` and `strong_authentication.py` import their siblings as modules, so they must be run as scripts from their file paths (the script's directory is then on the import path).
- `cli` runs `hodor-cli` with the placeholder `hodor_server` connection string (`CLI_DATABASE_URL`), the way the server connects.
- Checks the scripts rely on, with the problem codes they expect: a verification link of one tenant is refused by the other (`404`, `authentication.verification_token_invalid`) and works only once; a session cookie of one tenant is refused by the other (`401`, `session.not_authenticated`); after five wrong passwords the right one is refused (`429`, `authentication.too_many_attempts`) in that tenant only; an administrator token of one tenant is refused by the other (`401`, `admin.not_authenticated`); the audit log of the first tenant holds `identity.user_created`, `authentication.registration_completed`, `session.started` and `authentication.succeeded` but not the other tenant's `authentication.locked_out`; a provider of one tenant does not exist in another (`404`, `federation.provider_not_found`); an external identity with a vouched email address that already has a password account is refused; a SAML response whose `NameID` was changed after signing is refused and recorded as `federation.sign_in_refused` with reason `digest`. In `strong_authentication.py`: a password session's tokens say `amr` `pwd` and the single-factor level; a step-up to the multi-factor level asks only for `totp` and the tokens then say `pwd`, `otp` and `mfa`; with `tenant second-factor --policy required` a password alone leaves the sign-in at `totp`; a recovery code completes it once and is rejected the second time, leaving nine; a passkey completes a sign-in from the identifier step, and its tokens say `pop`, `user` and `mfa` and the phishing-resistant level; the passkey is rejected by the other tenant; the administrator's token is refused by the other tenant (`401`, `admin.not_authenticated`); after the administrator removes the passkey and the application nothing is left, the password alone ends the sign-in as `failed`, and the log of the tenant holds `credential.webauthn_removed` and `credential.totp_removed` with the administrator as the actor.

## Side Effects

- Creates tenants, users, external identity providers, administrator tokens, signing keys, applications and clients, authenticator applications, recovery codes and passkeys in the running stack's database, through HTTP and `hodor-cli`; nothing is cleaned up.
- Runs `docker compose ... run --rm` containers of the `server` service.
- Reads the mail server, VictoriaMetrics (`/api/v1/series`) and VictoriaTraces (`/select/jaeger/api/traces`); waits up to 60 seconds for messages and audit records and up to 120 seconds for metrics and traces.
- `external_identities.py` reads `deploy/dev-saml-provider/certificate.pem`.
- Prints each step line by line (`sys.stdout.reconfigure(line_buffering=True)`); on failure prints the reason to standard error and exits with status 1.

## Verification

These scripts are the verification of the stack. As their docstrings and `.github/workflows/ci.yml` (job `pages`) run them:

```sh
docker compose -f deploy/docker/compose.yaml up --build --wait
python3 deploy/demo/demo.py
python3 deploy/demo/external_identities.py
python3 deploy/demo/strong_authentication.py
```
