# demo

## Overview

Demonstration scripts that run against the development stack of [docker](../docker/EGM.md) and check, step by step, what the milestones promise. All use Python 3 and nothing outside the standard library, and all run `hodor-cli` through Docker Compose. Every answer is checked; the first one that is not what it should be stops the demonstration with exit status 1.

- `demo.py`: the demonstration of Milestone 1. A person registers, verifies an address and signs in to a tenant, and tenants are kept apart.
- `external_identities.py`: the demonstration of Milestone 2. Signing in with external identities through the development OpenID Connect provider ([dev-provider](../dev-provider/EGM.md)), the development LDAP directory and the development SAML identity provider ([dev-saml-provider](../dev-saml-provider/EGM.md)).
- `applications.py`: the demonstration of Milestone 3. A third-party application registered with the command-line tool, the consent page, the ID token and UserInfo, a refresh token that ends when an old one comes back, a token a client gets for itself, revocation and introspection, a rotated key, and tenants kept apart.
- `authorization.py`: the demonstration of Milestone 5. Permissions and roles given to a person and a client, decisions asked for with a client-credentials token, a condition that changes the answer, a resource server answered by an Open Policy Agent instance the script starts next to the stack, with policies published, simulated and rolled back, a stopped instance whose answer is indeterminate, and the record of decisions.
- `organizations.py`: the demonstration of Milestone 7. A group inside another group and a cycle refused, an organization with a department and an invitation accepted from the link in the message, a role given to a group and evaluated for a member until the member is taken out, a sign-in for the organization whose tokens carry `org_id`, a user and a group provisioned and changed through SCIM, the user deactivated with their session and refresh token ended, and a group, an organization and a SCIM token of one tenant refused by another.
- `workloads.py`: the demonstration of Milestone 8. A service account with a client, an API key made with the command-line tool and a role, allowed by the Authorization API with its token and with its key; an agent exchanging a person's token for one that names it in `act`, and a wider exchange refused; a webhook endpoint registered with the command-line tool whose deliveries the script checks as Standard Webhooks say, retried and set aside while the receiver is stopped and delivered again; and a key and a webhook of one tenant refused by another.
- `what_was_left_out.py`: the demonstration of Milestone 9. Two pairwise applications of two sectors that know one person by two `sub`; a claim mapper of the person's groups in the ID token and a reserved name refused; a logout token for each application at the stack's receiver when the person signs out, checked against the key set; a code and a link by email, each refused the second time and the link signing nothing in from another browser; an authenticator application set up from its `otpauth://` address during a sign-in under the second factor policy; a document shared with a group through an access control list; and a mapper and an entry of one tenant out of reach of another.
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

### `applications.py`

- Imports from `demo`, from `external_identities` (`post_form`, `query_of`) and from `strong_authentication` (`REDIRECT_URI`, `Application`, `decode`); reads the same environment variables.
- Constants: `PASSWORD`, `AUDIENCE` (`https://api.billing.example.com`), `SCOPES` (`openid email offline_access invoices:read`), `AGREED` (the same without `offline_access`, which is asked every time), `RETRY_WINDOW_SECONDS` (10, the development stack's `HODOR_REFRESH_RETRY_SECONDS`).
- `ThirdPartyApplication(Application)`: `endpoint(name, fields)` posts to `/t/{tenant}/oauth2/{name}` with `client_secret_basic`; `exchange` redeems a code and answers the token response with both tokens' checked claims; `code_at_once` asks for a code a person agreed to already; `active` introspects.
- Steps of `main()`, in order: `two_tenants_and_a_person`, `a_third_party_application` (`application add`, `application list`, `resource-server add`, `client add` with three grants), `asked_once` (the consent page over `/interaction/consent`), `userinfo_answers`, `a_refresh_token` (waits `RETRY_WINDOW_SECONDS + 1`), `a_token_for_itself`, `revocation_and_introspection`, `a_rotated_key` (`keys rotate`), `tenants_apart`.
### `authorization.py`

- Imports from `demo` (and `cli` with `volumes` and `environment`, for the key that signs bundles and a directory of policy files) and `post_form` from `external_identities`; reads the same environment variables.
- Starts `openpolicyagent/opa:1.10.1` with `docker run` on the stack's network under the alias `policy-agent`, the address the stack gives the server in `HODOR_OPEN_POLICY_AGENT_ADDRESS`, with a configuration it writes into a temporary directory: the instance's credential, the tenant's bundle, the public key and `deploy/open-policy-agent/decision-log-mask.rego`. It stops the instance and removes the directory at the end, also when it fails.
- Steps of `main()`, in order: `two_tenants` (`tenant create`, `keys rotate`, `admin bootstrap`), `roles_and_who_holds_them`, `decisions_by_role`, `a_condition`, `open_policy_agent` (`policy-agent signing-key`, `policy-agent instance add`, `policy-agent bundle-name`, `policy draft --written-by operator`, `policy publish`, `policy rollback`; validation, tests and simulation through the administration interface), `the_record`, `tenants_apart`.

### `organizations.py`

- Imports from `demo`, from `external_identities` (`completed`, `post_form`, `query_of`), from `strong_authentication` (`REDIRECT_URI`, `Application`) and from `authorization` (`API`, `Administrator`, `application`, `decided`, `evaluate`, `service_client`, `token_for`); reads the same environment variables.
- Constants: `PASSWORD`, `PAYROLL` (`https://payroll.example.com`), `SCIM` (`urn:hodor:scim`) and the SCIM schemas of users, groups, the enterprise extension and `PATCH`.
- `Portal(Application)`: the tenant's first-party application, registered with `application add --first-party` and `client add` with the `authorization_code` and `refresh_token` grants; `signed_in(browser, **extra)` gets a code at once and redeems it, answering the token response with both tokens' checked claims; `refresh(token)`.
- `Directory`: the SCIM client, `call(method, path, body, tenant)` under `/t/{tenant}/scim/v2` with its client-credentials token.
- Steps of `main()`, in order: `two_tenants` (`tenant create`, `keys rotate`, `admin bootstrap` in both), `a_group_inside_another` (`identity.group_cycle`), `an_organization_and_an_invitation` (the link read with `link_from_message`, `/interaction/invitations/describe` and `/interaction/invitations/accept`), `a_role_through_a_group`, `signed_in_for_the_organization` (`organization` at the authorization endpoint), `a_directory`, `provisioned`, `deactivated` (`/interaction/recovery` for the provisioned person's password, then `active: false` through `PATCH`), `tenants_apart`, `the_audit_log` (`audit verify`).
- Runs before `operations.py`, whose second worker removes the delivered messages it reads.

### `workloads.py`

- Imports from `demo` (and `compose`), from `external_identities` (`completed`, `post_form`, `query_of`), from `strong_authentication` (`REDIRECT_URI`, `Application`, whose `checked` verifies a token against the key set) and from `authorization` (`API`, `Administrator`, `application`, `decided`, `evaluate`); reads the same environment variables, and `HODOR_WEBHOOK_RECEIVER_URL` (`RECEIVER`, default `http://localhost:9600`).
- Constants: `RECEIVER_INSIDE` (`http://webhook-receiver:9600`, where Hodor reaches the receiver), `ATTEMPTS` (3, the development stack's `HODOR_WEBHOOK_MAX_ATTEMPTS`), `PASSWORD`, `PAYROLL` (`https://payroll.example.com`), `ASSISTANT` (`https://assistant.example.com`), `TOKEN_EXCHANGE`, `ACCESS_TOKEN_TYPE`.
- Helpers: `received(path, webhook_id)` reads `GET /received` of the receiver ([dev-webhook-receiver](../dev-webhook-receiver/EGM.md)); `signed_with(delivery, secret)` recomputes the HMAC-SHA256 of `{webhook-id}.{webhook-timestamp}.{body}` with the Base64 key after `whsec_`, compares it in constant time with every `v1,` value of `webhook-signature`, and refuses a timestamp more than five minutes away; `receiver(action)` runs `compose() stop|start webhook-receiver`; `a_person` creates a user through the administration interface and sets the password with a recovery link read from the mail server.
- Steps of `main()`, in order: `two_tenants` (`tenant create`, whose output gives the tenant's identifier, `keys rotate`, `admin bootstrap` in both), `a_service_account` (`service-account key create --application`), `evaluated_with_its_token_and_its_key`, `an_agent_acts_for_a_person` (a client with `client_credentials` and the token exchange grant, `principal` and `exchange_rules`; the person's code at `resource` `ASSISTANT`), `a_wider_exchange_refused` (`invalid_scope`, `invalid_target`), `a_webhook_endpoint` (`webhook add`, `webhook list`), `retried_set_aside_and_delivered_again` (`webhook deliveries --status set_aside`; the receiver is started again in a `finally`), `tenants_apart`, `the_audit_log` (`audit verify`).
- Runs before `operations.py`, whose second worker removes the delivered messages it reads.

### `what_was_left_out.py`

- Imports from `demo` (and `MAIL`), from `external_identities` (`completed`, `post_form`, `query_of`, `rejected`), from `strong_authentication` (`Application`, `AuthenticatorApplication`, `decode`, `encode`, `sha256`) and from `authorization` (`API`, `Administrator`, `application`, `decided`, `evaluate`); reads the same environment variables, and `HODOR_WEBHOOK_RECEIVER_URL` (`RECEIVER`, default `http://localhost:9600`).
- Constants: `RECEIVER_INSIDE` (`http://webhook-receiver:9600`), `PASSWORD`, `DOCUMENTS` (`https://documents.example.com`), `BACKCHANNEL_LOGOUT_EVENT`.
- `SectorApplication(Application)`: a first-party application with a redirect address of its own, `https://travel-<suffix>.example.com/callback` or `https://payroll-<suffix>.example.com/callback`, whose host is its sector; `signed_in(browser)` gets a code at once and redeems it, answering the token response and the checked claims of the ID token.
- Helpers: `message_ids` and `a_new_message(address, before, pattern)` read the mail server for a message that was not there before and match a code (six digits on a line) or a link to `/account/sign-in-link#token=` and 64 hexadecimal characters; `received(path)` reads `GET /received` of the receiver; `a_person` creates a user through the administration interface and sets the password with a recovery link.
- Steps of `main()`, in order: `two_tenants` (`tenant create`, `keys rotate`, `admin bootstrap` in both), `two_applications_of_two_sectors` (pairwise clients with `backchannel_logout_uri` at the receiver under `/<tenant>/travel` and `/<tenant>/payroll`), `the_same_person_by_two_subs`, `a_claim_mapper` (`oauth.claim_mapper_name_reserved` for `sub`, then a mapper of kind `groups` named `teams`), `logout_tokens` (`DELETE /interaction/session`, then each form's `logout_token` checked: `typ` `logout+jwt`, signature, `aud`, `iss`, `events`, no `nonce`, and the `sub` and `sid` of the client's ID token), `by_email` (`tenant email-sign-in --code on --link on`), `enrolled_during_the_sign_in` (`tenant second-factor --policy required`; `/interaction/sign-in/steps/enrollment/kinds`, `/options` and the step), `a_document_shared_with_a_group` (`/resource-servers/{id}/access-entries`, `matching_entry` and `no_matching_role`), `tenants_apart` (`oauth.client_not_found`, `authorization.access_entry_not_found`), `the_audit_log` (`audit verify`).
- Runs before `operations.py`, whose second worker removes the delivered messages it reads.

## Invariants

- Each run makes its own tenants and addresses from a hexadecimal time suffix (`acme-`, `globex-`, `initech-`, `umbrella-`, `ana-`, `bia-`, `bob-`, `carla-`, `sam-`, `mallory-`, `operator-`, `operator-ana-`, `operator-globex-`, and the hosts `travel-` and `payroll-`), so the scripts can run again against the same stack.
- `external_identities.py`, `applications.py`, `strong_authentication.py`, `authorization.py`, `organizations.py`, `workloads.py` and `what_was_left_out.py` import their siblings as modules, so they must be run as scripts from their file paths (the script's directory is then on the import path).
- `cli` runs `hodor-cli` with the placeholder `hodor_server` connection string (`CLI_DATABASE_URL`), the way the server connects.
- Checks the scripts rely on, with the problem codes they expect: a verification link of one tenant is refused by the other (`404`, `authentication.verification_token_invalid`) and works only once; a session cookie of one tenant is refused by the other (`401`, `session.not_authenticated`); after five wrong passwords the right one is refused (`429`, `authentication.too_many_attempts`) in that tenant only; an administrator token of one tenant is refused by the other (`401`, `admin.not_authenticated`); the audit log of the first tenant holds `identity.user_created`, `authentication.registration_completed`, `session.started` and `authentication.succeeded` but not the other tenant's `authentication.locked_out`; a provider of one tenant does not exist in another (`404`, `federation.provider_not_found`); an external identity with a vouched email address that already has a password account is refused; a SAML response whose `NameID` was changed after signing is refused and recorded as `federation.sign_in_refused` with reason `digest`. In `strong_authentication.py`: a password session's tokens say `amr` `pwd` and the single-factor level; a step-up to the multi-factor level asks only for `totp` and the tokens then say `pwd`, `otp` and `mfa`; with `tenant second-factor --policy required` a password alone leaves the sign-in at `totp`; a recovery code completes it once and is rejected the second time, leaving nine; a passkey completes a sign-in from the identifier step, and its tokens say `pop`, `user` and `mfa` and the phishing-resistant level; the passkey is rejected by the other tenant; the administrator's token is refused by the other tenant (`401`, `admin.not_authenticated`); after the administrator removes the passkey and the application nothing is left, the password alone ends the sign-in as `failed`, and the log of the tenant holds `credential.webauthn_removed` and `credential.totp_removed` with the administrator as the actor.

## Side Effects

- Creates tenants, users, external identity providers, administrator tokens, signing keys, applications and clients, authenticator applications, recovery codes, passkeys, groups, organizations, invitations, service accounts, agents, API keys, webhook endpoints, claim mappers and entries of access control lists in the running stack's database, through HTTP and `hodor-cli`; nothing is cleaned up.
- Runs `docker compose ... run --rm` containers of the `server` service. `workloads.py` stops the `webhook-receiver` service and starts it again, which forgets what it had received.
- Reads the mail server, VictoriaMetrics (`/api/v1/series`) and VictoriaTraces (`/select/jaeger/api/traces`); waits up to 60 seconds for messages and audit records and up to 120 seconds for metrics and traces.
- `external_identities.py` reads `deploy/dev-saml-provider/certificate.pem`.
- Prints each step line by line (`sys.stdout.reconfigure(line_buffering=True)`); on failure prints the reason to standard error and exits with status 1.

## Verification

These scripts are the verification of the stack. As their docstrings and `.github/workflows/ci.yml` (job `pages`) run them:

```sh
docker compose -f deploy/docker/compose.yaml up --build --wait
python3 deploy/demo/demo.py
python3 deploy/demo/external_identities.py
python3 deploy/demo/applications.py
python3 deploy/demo/strong_authentication.py
python3 deploy/demo/authorization.py
python3 deploy/demo/organizations.py
python3 deploy/demo/workloads.py
python3 deploy/demo/what_was_left_out.py
python3 deploy/demo/operations.py
```
