# Quick-start

From a clean checkout to a tenant that people sign in to, on one machine, in about ten minutes. Then the demonstration of [Milestone 1](../product/epics.md#milestone-1-walking-skeleton), which shows the same things and checks them.

This page is for someone who wants to run Hodor and see what it does. To change Hodor, read [local setup](../development/local-setup.md) instead.

> What this page starts is a development stack. Its passwords are written in the repository and it speaks plain HTTP. [Before anything real](#before-anything-real) lists what must change.

## What you need

| Tool | Why |
|---|---|
| Git | To get the code |
| Docker with Compose | Everything runs in containers, built from this checkout. Nothing else is installed on the machine |
| A browser | Chromium, Chrome, Edge or Firefox. Safari refuses the session cookie over plain HTTP |
| Python 3 | Only for [the demonstration](#the-demonstration). It uses nothing outside the standard library |

The stack uses the ports 8080, 9090, 8025, 8428, 9400, 9500 and 10428 on `localhost`. [Local setup](../development/local-setup.md#running-the-development-stack) says how to choose others.

## 0. Get the code

The branch `main` holds the latest release, 0.2.0, whose [changelog](https://github.com/ortisun/hodor/blob/main/CHANGELOG.md#020---2026-11-23) says what it holds and what it is not ready for; the work towards the next one happens on `develop`. Clone the release and run every command of this page from the root of the checkout:

```bash
git clone https://github.com/ortisun/hodor.git
```

```bash
cd hodor
```

## 1. Start the stack

```bash
docker compose -f deploy/docker/compose.yaml up --build --wait
```

The first run builds the image, which takes several minutes. The command returns when everything is healthy:

| What | Where |
|---|---|
| Hodor | <http://localhost:8080> |
| The messages Hodor sends, in a development mail server that delivers none | <http://localhost:8025> |
| Metrics, in VictoriaMetrics | <http://localhost:8428/vmui> |
| Traces, in VictoriaTraces | <http://localhost:10428/select/vmui> |

The database is migrated and the system tenant is created as part of starting.

## 2. Create a tenant

Everything in Hodor belongs to a tenant. Create one that lets people register themselves:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server tenant create --slug acme --name "Acme" --open-registration
```

The tenant's pages are now at <http://localhost:8080/t/acme/account>.

## 3. Register and sign in

1. Open <http://localhost:8080/t/acme/account/register> and give an email address. Any address works: nothing leaves the machine.
2. Open the mail server at <http://localhost:8025>, read the message and follow its link.
3. Choose a password of 12 characters or more.
4. Sign in with the address and the password.

Try a wrong password as well. After five, the address is locked out for a minute, whether or not it belongs to anyone.

## 4. Make an administrator

Make the person who just registered an administrator of the tenant, and get an access token for them:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server admin bootstrap --tenant acme --email ana@example.com
```

Use the address you registered with. The command prints the token once; it lives for an hour.

## 5. Look at what happened

The tenant's users, through [the administration interface](../api/admin-api.md):

```bash
curl -s http://localhost:8080/t/acme/api/v1/admin/users -H 'Authorization: Bearer <the token>'
```

The audit log: every registration, sign-in, refusal and lockout, each with who did it and when.

```bash
curl -s http://localhost:8080/t/acme/api/v1/admin/audit-records -H 'Authorization: Bearer <the token>'
```

Whether anyone has changed that log since it was written:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server audit verify --tenant acme
```

The traces of the requests you made are at <http://localhost:10428/select/vmui>, and the metrics at <http://localhost:8428/vmui>.

## 6. Go further

| Next | What it shows |
|---|---|
| [Signing in through identity providers](../examples/signing-in-through-identity-providers.md) | The stack's OpenID Connect provider, LDAP directory and SAML identity provider, added to `acme` and signed in through; and what GitHub needs |
| [Calling the administration interface](../examples/administration-interface.md) | The token of step 4 used with `curl`: users, sessions, the audit log, identity providers |
| [A tenant and its first administrator](../examples/first-tenant-and-administrator.md) | A tenant where only administrators add people, and its admin console at `/t/{slug}/console` |

## The demonstration

The demonstration does by itself what the steps above do by hand, and more: it shows that two tenants are kept apart. It checks every answer and stops at the first one that is not what it should be.

With the stack running:

```bash
python3 deploy/demo/demo.py
```

| Step | What it shows |
|---|---|
| Two tenants | Two tenants are created with the command-line tool |
| The same person in both | One email address registers in each tenant. Each gets its own message, its own link and its own password |
| The link | A link finishes a registration once, and only in the tenant it was made for |
| Signing in | The person signs in to the first tenant and gets a session, which the server describes and lists |
| The pages | The sign-in page is served with its Content Security Policy |
| Tenants apart: the session | The session cookie of the first tenant is refused by the second |
| Tenants apart: the password | The password of the first tenant does not sign in to the second |
| Lockout | After five wrong passwords the address is locked out in that tenant, even for the right password, and is still free in the other |
| An administrator | The first administrator is made with the command-line tool; their token lists the tenant's users |
| Tenants apart: the token | The administrator's token of the first tenant is refused by the second |
| The audit log | The audit log of the first tenant holds the registration and the sign-in, nothing of the second tenant, and its chain is intact |
| Metrics | The worker's metrics have arrived in VictoriaMetrics |
| A trace | The trace of the sign-in has arrived in VictoriaTraces |

It ends with `The demonstration passed.` and the addresses to look at. It can be run again and again: every run makes two new tenants and removes nothing.

The demonstration runs in continuous integration on every pull request, against the image and from a clean checkout, started with the commands of this page. The script therefore cannot drift from what Hodor does.

If the stack is on other ports, tell the script: `HODOR_URL`, `HODOR_MAIL_URL`, `HODOR_METRICS_URL` and `HODOR_TRACES_URL`. The command-line tool is run through Compose with the environment the script was started in, so the variables that chose the ports when the stack was started must be set again.

## The demonstration of Milestone 2

[Milestone 2](../product/epics.md#milestone-2-signing-in-with-external-identities) lets people sign in with an identity they already have elsewhere. Its demonstration does what a person would do in a browser, through the development providers of the stack: an OpenID Connect provider, an LDAP directory and a SAML identity provider, all of which let anyone sign in as anyone.

With the stack running:

```bash
python3 deploy/demo/external_identities.py
```

| Step | What it shows |
|---|---|
| A provider | An OpenID Connect provider is added to a new tenant with the command-line tool |
| The first sign-in | A person signs in through it and is created, with the address the provider vouched for |
| The second sign-in | The same person signs in again and is the same user |
| No takeover | Someone who registered with a password keeps their account to themselves: the provider vouching for their address does not let anyone into it |
| Tenants apart | The provider of the first tenant does not exist in a second one |
| A directory | A person signs in through the LDAP directory, with what they would type on the page |
| A SAML identity provider | A person signs in through the SAML identity provider: the request, the signed response posted back by the browser, the receipt, the finish |
| A tampered response | The same, with the subject of the signed response changed on the way: refused, and the audit log says why, `digest` |

It ends with `The demonstration passed.` It can be run again and again, and runs in continuous integration after the one of Milestone 1. The variables of [the first demonstration](#the-demonstration) tell it where the stack is, and `HODOR_SAML_PROVIDER_URL` where the SAML identity provider is, `http://localhost:9500` unless set.

## The demonstration of Milestone 3

[Milestone 3](../product/epics.md#milestone-3-applications-ask-hodor-who-someone-is) lets an application registered in a tenant sign a person in through Hodor and use the tokens it gets. Its demonstration plays the operator, the person and a third-party application:

```bash
python3 deploy/demo/applications.py
```

| Step | What it shows |
|---|---|
| Two tenants, and a person in one of them | Two tenants made with the command-line tool; a person registers in the first with a password |
| A third-party application, registered with the command-line tool | The operator registers a third-party application, its resource server with the scope `invoices:read`, and a confidential client allowed a code, refresh tokens and a token for itself. The secret is shown once |
| Signed in from the application, and asked once | The person signs in, and the application's request goes to the consent page, which names the application, each scope in plain words and that access is kept when the person is away. After the person allows it, the code and PKCE give an ID token and an access token, both checked against the tenant's key set. Asked again for the same scopes without `offline_access`, the application gets a code at once; with `offline_access`, which is never agreed to for good, the person is asked again |
| UserInfo | The access token gives the same person as the ID token, with the email address the scope `email` allows |
| A refresh token moves at every use | A refresh gives the next refresh token. Past the window in which a retried refresh is answered again, the first token comes back and is refused, the newest one is refused as well, and introspection calls it not active: reuse ended the whole family |
| A token a service gets for itself | With its own credentials the client gets an access token whose subject is the client, and no refresh token |
| Revocation and introspection | An access token is active, is revoked by the application, and is then not active for introspection and refused by UserInfo long before it expires |
| The tenant's key is rotated | After `hodor-cli keys rotate`, new tokens name the new key, and the old key stays in the key set so that what it signed can still be checked |
| Tenants apart | The client of one tenant is no client in the other, which shows its own error page and sends nothing to the client's address; a code, an access token and the client's secret of one tenant are refused by the other; the code still redeems where it belongs |

The refresh step waits eleven seconds, past the development stack's window for a retried refresh (`HODOR_REFRESH_RETRY_SECONDS`, ten seconds by default). Every token's signature is checked with the P-256 arithmetic of [the demonstration of Milestone 4](#the-demonstration-of-milestone-4), written into the scripts so that they need nothing outside the standard library.

It ends with `The demonstration passed.` It can be run again and again, and runs in continuous integration after the demonstration of Milestone 2. The variables of [the first demonstration](#the-demonstration) tell it where the stack is.

## The demonstration of Milestone 4

[Milestone 4](../product/epics.md#milestone-4-strong-authentication) lets a person prove who they are with more than a password, a tenant require it, and an application ask for more in the middle of a session. Its demonstration plays the person, their authenticator application, their passkey, an application of the tenant and an administrator:

```bash
python3 deploy/demo/strong_authentication.py
```

| Step | What it shows |
|---|---|
| A tenant, and a person in it | A new tenant with a signing key and three assurance levels, one of them phishing-resistant; a person registers with a password |
| An application | The operator registers a first-party application and a confidential client with the command-line tool |
| Signed in with a password | The application gets a code at once; its ID token and access token, checked against the tenant's key set, say `amr` `pwd` and the single-factor level |
| An authenticator application | The person sets one up from their own session and confirms it with a code; ten recovery codes come with it |
| A step-up | The application asks for the multi-factor level in the middle of the same session: the person is asked for the code of the application and nothing else, and the new tokens say `pwd`, `otp` and `mfa` |
| A tenant that requires a second factor | With the policy turned on, the password alone no longer completes a sign-in; the code does |
| A recovery code | A recovery code stands in for the code once, and is refused the second time |
| A passkey | The person registers one, then signs in with it alone, with no identifier and no password. Asked for the phishing-resistant level, the application gets a code at once, and the tokens say `pop`, `user` and `mfa` |
| Tenants apart | The same passkey is refused by a second tenant |
| An administrator removes the person's factors | The administrator sees the factors and no secret, removes the passkey and the application, and the recovery codes go with them; the person's password alone no longer signs them in to a tenant that requires a second factor: the sign-in waits for them to [set one up](../architecture/contexts/authentication.md#enrolling-a-second-factor-during-a-sign-in), with no session until they do, and the audit log names the administrator |

The passkey is a software authenticator written into the script, with the arithmetic of P-256 done by hand so that the demonstration still needs nothing outside the standard library. It answers as a device does after the person unlocked it, and keeps its key in memory for as long as the script runs. A code of an authenticator application is good once, so the script waits for the next one when it needs a third within a minute.

It ends with `The demonstration passed.` It can be run again and again, and runs in continuous integration after the other four. The variables of [the first demonstration](#the-demonstration) tell it where the stack is.

## The demonstration of Milestone 5

[Milestone 5](../product/epics.md#milestone-5-the-authorization-engine) lets an application ask Hodor whether someone may do something, and get an answer from Hodor's native engine or from Open Policy Agent. Its demonstration plays an administrator, an operator and two applications of one tenant:

```bash
python3 deploy/demo/authorization.py
```

| Step | What it shows |
|---|---|
| Two tenants, and an administrator | Two tenants, each with a signing key; the first administrator of the first, made with the command-line tool |
| Permissions and roles | Through the administration interface: an application for the Authorization API, a Payroll application with its resource server and a service client, two permissions, a `clerk` role and an `approver` role that includes it, `approver` given to a person and `clerk` to the client for its own application, and Payroll bound to the native engine |
| The application asks | With a client-credentials token: the approver may approve an invoice, the client may read one and may not approve one, each with its reason |
| A condition changes the answer | `approver` gains the condition `resource.attributes.amount <= 1000`: approving 5000 is now denied with `condition_not_met`, approving 500 is allowed. A condition that does not compile is refused when the role is saved |
| A resource server bound to Open Policy Agent | The operator makes a key that signs bundles and registers a shared instance, which the script starts next to the stack with its configuration. A Ledger application is bound to Open Policy Agent; a policy the operator wrote is drafted, checked and tested by the worker, published with the command-line tool, and the instance runs it: reading is allowed and deleting denied |
| A draft simulated, published, rolled back | A second version that also allows deleting is simulated on two inputs, which shows it differs from the published one on deleting; it is tested and published as revision 2, which allows deleting; rolling back to revision 1 publishes revision 3, which denies it again |
| A stopped instance is never an allow | With the instance stopped, reading is answered `INDETERMINATE`, which denies |
| The record of decisions | The administrator reads the decisions of both engines, the indeterminate one among them |
| Tenants apart | The application's token is refused by the second tenant |

The instance is shared, so it is served only what the operator wrote ([Decision 0010](../decisions/0010-opa-integration.md)): a tenant's own Rego runs only in an instance of the tenant's own, which an operator registers for one tenant and names in `HODOR_OPEN_POLICY_AGENT_TENANT_ADDRESSES`. The stack sets `HODOR_OPEN_POLICY_AGENT_ADDRESS` to the address the script starts its instance at; nothing answers there otherwise. Publishing and rolling back are commands, because only the command line holds the key that signs bundles.

It ends with `The demonstration of Milestone 5 passed.` It can be run again and again, starts and removes its own instance, and runs in continuous integration after the other four. The variables of [the first demonstration](#the-demonstration) tell it where the stack is.

## The demonstration of Milestone 6

[Milestone 6](../product/epics.md#milestone-6-hodor-runs-behind-a-load-balancer-and-cleans-up-after-itself) lets Hodor run behind load balancers and clean up after itself. Its demonstration goes through `edge`, the web server in front of the stack, as clients behind a load balancer would:

```bash
python3 deploy/demo/operations.py
```

| Step | What it shows |
|---|---|
| A tenant behind a web server | A tenant that accepts registrations, reached through `edge` |
| Each client has a limit of its own | One client, named by the `X-Forwarded-For` the script sends as a load balancer would, asks to register a new address again and again until it is answered `429`. Another client behind the same web server is still answered, and so is the script itself, straight to the server |
| A forged address does not help | The limited client writes another address at the start of its header, and is still limited: Hodor reads the header from the end and stops at the first address that is not a trusted proxy |
| Ended sessions are removed | A person registers, signs in and signs out. A second worker starts with a retention of 0 days for sessions and messages, and removes the ended session and the delivered messages of the tenant |
| The audit log is untouched | The audit chain of the tenant is intact after the cleanup, and the cleanup's metric arrived in VictoriaMetrics |

The second worker keeps nothing for any tenant of the stack: it removes every ended session and every delivered message, of the other demonstrations too, and it is stopped at the end. The published image and chart are not part of this script; they are tried by hand at the tag of 0.3.0, as the [release steps](../development/conventions.md#releases) say.

It ends with `The demonstration of Milestone 6 passed.` It can be run again and again, and runs in continuous integration after the other eight. The variables of [the first demonstration](#the-demonstration) tell it where the stack is, and `HODOR_EDGE_URL` where the web server in front is, `http://localhost:8081` unless set.

## The demonstration of Milestone 7

[Milestone 7](../product/epics.md#milestone-7-groups-organizations-and-scim) gathers the people of a tenant in groups and organizations, gives roles to groups, carries the organization of a sign-in in the tokens, and lets a directory provision people through SCIM. Its demonstration plays an administrator, a person invited by email, an application and a SCIM client of one tenant:

```bash
python3 deploy/demo/organizations.py
```

| Step | What it shows |
|---|---|
| Two tenants, and their administrators | Two tenants, each with a signing key and a first administrator made with the command-line tool |
| A group inside another group | Through the administration interface, `finance` is put inside `staff`. Putting `staff` inside `finance` is refused as a cycle, `identity.group_cycle` |
| An organization, a department and an invitation | An organization with a unit of kind department, and a new address invited to it with that department. The link, read from the mail server, describes the invitation; accepting it with a password makes the account and the membership with the department, and the same link is refused the second time |
| A role through a group | A Payroll resource server whose `reader` role is given to `staff`. The invited person is put in `finance`, and the Authorization API allows them, through both groups; taken out of `finance`, the next decision denies |
| Signed in for the organization | The person signs in from an application of the tenant, which names the organization with `organization`: the ID token and the access token carry it in `org_id`, both checked against the tenant's key set. Asking for an organization the person is not a member of is answered `access_denied` at the application's address |
| A directory provisions through SCIM | The tenant opens SCIM with a resource server of audience `urn:hodor:scim` and a client of the client credentials grant allowed the scope `scim`. The SCIM client creates a user and a group with the user in it, and changes both with `PATCH` |
| Deactivated through SCIM | The provisioned person sets a password with a recovery link, signs in from the application, and gets a refresh token that works. The SCIM client sets `active` to false: the person's session ends at once, the refresh token is refused, and the password no longer signs in |
| Tenants apart | The second tenant's administrator finds neither the group nor the organization, and the first tenant's SCIM token is refused by the second tenant's SCIM server |
| The audit log | The log of the first tenant holds the nesting, the accepted invitation and the deactivation, done by the SCIM client |

The application is played by the script, as in [the demonstration of Milestone 4](#the-demonstration-of-milestone-4): it registers a redirect address nobody listens on, and reads where the browser is sent.

It ends with `The demonstration of Milestone 7 passed.` It can be run again and again, and runs in continuous integration after the demonstration of Milestone 5 and before that of Milestone 6, whose second worker removes the delivered messages this one reads. The variables of [the first demonstration](#the-demonstration) tell it where the stack is.

## The demonstration of Milestone 8

[Milestone 8](../product/epics.md#milestone-8-workloads-agents-and-webhooks) gives the services and agents of a tenant identities of their own, with clients, API keys and roles, lets an agent act on a person's behalf through token exchange, and tells other systems what happens in a tenant through signed webhooks. Its demonstration plays an administrator, an operator, a service, an agent, a person and a receiver of webhooks:

```bash
python3 deploy/demo/workloads.py
```

| Step | What it shows |
|---|---|
| Two tenants, and their administrators | Two tenants, each with a signing key and a first administrator made with the command-line tool |
| A service account, its client, its key and its role | Through the administration interface: a Payroll resource server whose `approver` role may approve invoices, a service account owned by a person of the tenant, a client of Payroll that acts as it, and the role given to it. With `hodor-cli service-account key create`, an API key for Payroll with the scope `authz:evaluate`, printed once and never listed again |
| Evaluated with its token and with its key | The client gets a token by client credentials, which names the service account in `sub` with `principal_kind`. The Authorization API allows the service account to approve an invoice, asked with that token and again with the key; the same key with one character changed is refused |
| An agent acts for a person | An agent, with a client allowed the token exchange grant and one exchange rule: a token for the agent's own interface, the assistant, may be exchanged for one for Payroll. A person signs in to the assistant, which gets a token with `payroll:read`. The agent's client exchanges the person's token, with the agent's own token as the actor, for a token for Payroll: checked against the tenant's key set, it names the person in `sub` and the agent in `act`, and comes without a refresh token |
| A wider exchange refused | Asking for a scope the person's token does not hold is refused with `invalid_scope`, and asking for an audience no rule allows with `invalid_target` |
| A webhook endpoint | With `hodor-cli webhook add`, an endpoint at the stack's receiver, `webhook-receiver`, subscribed to `session.started`; its secret is printed once, and `hodor-cli webhook list` never shows it. The person signs in again and the receiver gets the event. The script checks its `webhook-signature` with the secret, as Standard Webhooks say, and reads the tenant and the session in its body |
| Retries, set aside, delivered again | The receiver is stopped. The next sign-in's delivery is tried three times and set aside, as the administration interface and `hodor-cli webhook deliveries --status set_aside` show. The receiver is started again, the administration interface delivers the delivery again, the event arrives with the same `webhook-id`, signed, and the delivery is recorded as delivered. Should it not be, the demonstration shows what each delivery of the endpoint became |
| Tenants apart | The second tenant's Authorization API and administration interface refuse the first tenant's key, and the second tenant's administrator finds neither the endpoint nor its deliveries |
| The audit log | The log of the first tenant holds the key made, the exchange done by the agent for the person, the endpoint registered, the delivery set aside and the request to deliver it again |

The development stack has what this needs: `webhook-receiver`, a receiver of webhooks that keeps what it gets and shows it on its own port, named in `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` of the server and the worker so that it may be called over plain HTTP; and a worker that waits one second after a first failed attempt and sets a delivery aside after three, so that the retries take seconds rather than hours. Nowhere real has either.

It ends with `The demonstration of Milestone 8 passed.` It can be run again and again, and runs in continuous integration after the demonstration of Milestone 7 and before that of Milestone 6, whose second worker removes the delivered messages this one reads. The variables of [the first demonstration](#the-demonstration) tell it where the stack is, and `HODOR_WEBHOOK_RECEIVER_URL` where the receiver is, `http://localhost:9600` unless given.

## The demonstration of Milestone 9

[Milestone 9](../product/epics.md#milestone-9-what-020-left-out) builds what 0.2.0 left out: applications of different sectors know a person by different identifiers, a client gets the claims it is configured for, applications are told when a person signs out, a person signs in with a code or a link sent by email or sets up a second factor while signing in, and an application grants access to one resource at a time. Its demonstration plays an administrator, an operator, two applications, two people and the applications' receiver of logout tokens:

```bash
python3 deploy/demo/what_was_left_out.py
```

| Step | What it shows |
|---|---|
| Two tenants, and their administrators | Two tenants, each with a signing key and a first administrator made with the command-line tool |
| Two applications of two sectors | Through the administration interface, Travel and Payroll, each with a pairwise client whose redirect address names a host of its own, its sector, and a back-channel logout address at the stack's receiver, `webhook-receiver` |
| One person, two sectors, two subjects | A person signs in once and gets a code from each application at once. The two ID tokens, checked against the tenant's key set, name her by two different `sub` and her session by two different `sid`, neither of them her user identifier. Signed in again, Travel is given the same `sub`, and UserInfo answers Travel with it |
| A claim mapper | The person is put in the group `finance`. A mapper that would name `sub` is refused, `oauth.claim_mapper_name_reserved`. A mapper of Travel writes her groups as `teams`, and her next ID token carries the identifier of `finance` there, as UserInfo does |
| Signed out at Hodor | She signs out as the account page does. The receiver gets a logout token for each application, posted as a form: of type `logout+jwt`, checked against the tenant's key set, for that application, with the back-channel logout event, and naming her and her session by the `sub` and `sid` of that application's ID token |
| A code, then a link, by email | `hodor-cli tenant email-sign-in` turns both on. She asks for a code, reads it from the mail server, and is signed in with `email_code`; the same code, presented again in a new sign-in, is refused. She asks for a link: opened in another browser it signs nothing in, in the browser that asked it signs her in with `email_link`, and presented again it is refused |
| A second factor set up during the sign-in | `hodor-cli tenant second-factor --policy required`, and a second person who has no second factor. The password leaves the sign-in waiting at the step `enrollment`, and leaving it there signs nobody in. In another sign-in, the person begins an authenticator application and is given the `otpauth://` address its QR code shows; the script reads the secret from that address, computes the code as the application would, and the code finishes the sign-in with ten recovery codes. The session holds a password and the enrollment, at the multi-factor level, and Travel's ID token says `pwd` and `mfa`. The next sign-in asks for the application's code |
| A document shared with a group | A Documents resource server answered by the native engine, with the permission `document:read`. Before anything is shared, the member of `finance` may not read `budget-2027`; an entry of its access control list lets `finance` read it. The Authorization API then allows the member, with `matching_entry`, and denies the second person and another document |
| Tenants apart | The second tenant's administrator finds neither Travel's mapper nor the entry |
| The audit log | The log of the first tenant holds the mapper made, a code sent by email, the second factor set up and the entry granted |

The applications are played by the script, as in [the demonstration of Milestone 4](#the-demonstration-of-milestone-4): they register redirect addresses nobody listens on, and read where the browser is sent. Their back-channel logout addresses are paths of `webhook-receiver`, which keeps the logout tokens the worker posts as it keeps webhooks.

It ends with `The demonstration of Milestone 9 passed.` It can be run again and again, and runs in continuous integration after the demonstration of Milestone 8 and before that of Milestone 6, whose second worker removes the delivered messages this one reads. The variables of [the first demonstration](#the-demonstration) tell it where the stack is, and `HODOR_WEBHOOK_RECEIVER_URL` where the receiver is, `http://localhost:9600` unless given.

## Stop

Stop the stack and delete its data:

```bash
docker compose -f deploy/docker/compose.yaml down -v
```

## Before anything real

Milestone 1 is a walking skeleton: it proves that the pieces work together. It is not ready to hold real accounts. Beyond what is simply [not built yet](../product/progress.md#known-gaps-in-what-is-done), running it anywhere but on your own machine needs at least:

| What | Why |
|---|---|
| Your own database roles and passwords | The ones in `deploy/docker/postgres-init.sql` and in the Compose file are public. See [database roles](../development/local-setup.md#database-roles) |
| TLS in front of the server, and `HODOR_PUBLIC_URL` set to the address people use | The cookies are marked `Secure`, and the links in messages start with that address |
| The load balancer or web server in front named in `HODOR_TRUSTED_PROXIES` | Attempts are limited by the [client address](../api/api-spec.md#the-client-address). Behind a proxy that is not named, everyone shares one limit |
| A real mail server in `HODOR_SMTP_URL`, with encryption, and `HODOR_MAIL_FROM` | The development mail server delivers nothing |
| The operations listener kept off the internet | It answers health checks without any authentication |
| Backups of the database | Everything Hodor knows is there, the audit log included |

[Installing with Docker](install-with-docker.md) and [installing on Kubernetes](install-on-kubernetes.md) start Hodor with passwords of your own, HTTPS and no development provider, and say which of these they still leave open. [Deployment](deployment.md) describes where this is heading.
