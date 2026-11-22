# demo

## Overview

Two demonstration scripts that run against the development stack of [docker](../docker/EGM.md) and check, step by step, what the milestones promise. Both use Python 3 and nothing outside the standard library, and both run `hodor-cli` through Docker Compose. Every answer is checked; the first one that is not what it should be stops the demonstration with exit status 1.

- `demo.py`: the demonstration of Milestone 1. A person registers, verifies an address and signs in to a tenant, and tenants are kept apart.
- `external_identities.py`: the demonstration of Milestone 2. Signing in with external identities through the development OpenID Connect provider ([dev-provider](../dev-provider/EGM.md)), the development LDAP directory and the development SAML identity provider ([dev-saml-provider](../dev-saml-provider/EGM.md)).

## Interface

Neither script takes command-line arguments. Each has a `main()` run under `if __name__ == "__main__"`.

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
- `cli(*arguments)`: `docker compose -f deploy/docker/compose.yaml run --rm --no-deps -T --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=... server ...`.
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

## Invariants

- Each run makes its own tenants and addresses from a hexadecimal time suffix (`acme-`, `globex-`, `initech-`, `umbrella-`, `ana-`, `bia-`, `sam-`, `mallory-`), so the scripts can run again against the same stack.
- `external_identities.py` imports from `demo` as a sibling module, so it must be run as a script from its file path (the script's directory is then on the import path).
- `cli` runs `hodor-cli` with the placeholder `hodor_server` connection string (`CLI_DATABASE_URL`), the way the server connects.
- Checks the scripts rely on, with the problem codes they expect: a verification link of one tenant is refused by the other (`404`, `authentication.verification_token_invalid`) and works only once; a session cookie of one tenant is refused by the other (`401`, `session.not_authenticated`); after five wrong passwords the right one is refused (`429`, `authentication.too_many_attempts`) in that tenant only; an administrator token of one tenant is refused by the other (`401`, `admin.not_authenticated`); the audit log of the first tenant holds `identity.user_created`, `authentication.registration_completed`, `session.started` and `authentication.succeeded` but not the other tenant's `authentication.locked_out`; a provider of one tenant does not exist in another (`404`, `federation.provider_not_found`); an external identity with a vouched email address that already has a password account is refused; a SAML response whose `NameID` was changed after signing is refused and recorded as `federation.sign_in_refused` with reason `digest`.

## Side Effects

- Creates tenants, users, external identity providers and administrator tokens in the running stack's database, through HTTP and `hodor-cli`; nothing is cleaned up.
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
```
