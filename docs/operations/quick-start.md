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

The branch `main` holds the latest release, 0.3.0, whose [changelog](https://github.com/ortisun/hodor/blob/main/CHANGELOG.md#030---2026-11-25) says what it holds and what it is not ready for; the work towards the next one happens on `develop`. Clone the release and run every command of this page from the root of the checkout:

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
| OpenBao, in development mode, root token `development-root-token`. The tenants' signing keys are made there when the stack is started with `HODOR_KEY_PROVIDER=openbao`: [keys in OpenBao](keys-in-openbao.md#in-the-development-stack) | <http://localhost:8200> |

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

## The demonstration of Milestone 10

[Milestone 10](../product/epics.md#milestone-10-workloads-prove-who-they-are-with-their-certificates) lets a service account prove who it is with the identity its service mesh or SPIRE already gave it, and no secret: a JWT-SVID, or the certificate its sidecar presents, which the proxy in front of Hodor forwards; and binds its tokens to that certificate. Its demonstration needs a cluster, not the development stack: it makes a [kind](https://kind.sigs.k8s.io/) cluster with Istio and SPIRE, installs Hodor in the mesh with [its chart](install-on-kubernetes.md), and plays an operator and two workloads:

```bash
python3 deploy/demo/workload_identity.py
```

It needs Docker, kind, `kubectl`, Helm and OpenSSL besides Python 3, and about 2 GiB of memory for Docker besides what it already runs. It never changes the current context of `kubectl` or the repositories of Helm: it gives both files of their own, in a temporary directory.

| Step | What it shows |
|---|---|
| A kind cluster with Hodor's image | The cluster `hodor-milestone-10`, made the first time and taken as it is after. The image `hodor:milestone-10`, built from the checkout when Docker does not have it, and loaded into the cluster |
| Istio | Istio 1.30.8, installed with its charts, whose trust domain is `cluster.local`: a workload's certificate names it `spiffe://cluster.local/ns/<namespace>/sa/<service account>`. Its sidecars are Kubernetes's own sidecar containers, which start before the pod's other containers |
| SPIRE | SPIRE 1.15.5: a server of the trust domain `workloads.example.org`, with its SPIFFE bundle endpoint at `https://spire-server.spire.svc:8443`, and an agent on the node, which gives the pods of the service account `payroll` the identity `spiffe://workloads.example.org/ns/payroll/sa/payroll`. A second server, of `elsewhere.example.org`, which no tenant trusts. The bundle endpoint's certificate is made by the script with OpenSSL, under an authority of its own |
| Hodor in the mesh | The chart, with the stand-ins of [trying the chart](install-on-kubernetes.md#trying-the-chart-on-a-cluster-of-your-own), in a namespace Istio injects its sidecar into: the sidecar named as the trusted proxy and `X-Forwarded-Client-Cert` as the identity header, as [the identity of a workload](install-on-kubernetes.md#the-identity-of-a-workload) says, and the demonstration's authority in `outboundAuthorities`. Two workloads: `payroll`, in the mesh and under SPIRE, and `outsider`, in neither |
| Two tenants, and their administrators | Made with the command-line tool, in the server's pod |
| Two trust domains | `hodor-cli trust-domain add` gives the tenant SPIRE's trust domain by its bundle endpoint, which Hodor fetches at once, and `cluster.local` as checked by the mesh. The bundle Hodor keeps holds the keys SPIRE signs JWT-SVIDs with |
| A service account and its two clients | A Payroll resource server whose `approver` role may approve invoices, and a service account that holds it. `hodor-cli client add` binds one of its clients to its SPIRE identity with `spiffe_jwt`, and another to its identity in the mesh with `spiffe_x509` and bound tokens; neither has a secret |
| A token with a JWT-SVID | `payroll` asks the SPIRE agent for a JWT-SVID for the tenant's issuer, which the script checks against the bundle Hodor fetched, and gets a token with it as its client assertion. The token names the service account and is signed by the tenant; the Authorization API allows the service account to approve an invoice with it |
| A token with no credential at all | `payroll` asks for a token with its `client_id` alone. Its sidecar presents its certificate to Hodor's, which forwards its identity and its `Hash`; the token's `cnf` holds `x5t#S256`, which the script checks is the SHA-256 of the certificate the sidecar holds. The Authorization API takes the token from `payroll`, and introspection answers it with its `cnf` |
| The bound token without its certificate | Presented by `outsider`, which has no sidecar, and from the script's machine: `401` with `invalid_token` |
| JWT-SVIDs refused | The first JWT-SVID presented again; one minted by the SPIRE server of `elsewhere.example.org`; one the agent gives `payroll` for the second tenant's issuer: each `invalid_client` |
| `X-Forwarded-Client-Cert` from outside the mesh | `outsider` asks for a token for the mesh's client with a header naming `payroll`'s identity, and the script does the same from its machine: each `invalid_client`. Hodor's sidecar takes the header away from a caller without a certificate, and Hodor reads it from no one but its sidecar |
| The worker keeps the bundle current | The worker fetches SPIRE's bundle again after the refresh hint SPIRE gives, a minute, as `hodor-cli trust-domain show` says |
| Tenants apart | The second tenant trusts no trust domain and finds none of the first's; it refuses the bound token, even with its certificate, and gives `payroll`'s certificate no token |
| The audit log | The first tenant's log holds both trust domains added and the clients, and its chain is intact |

The script reaches Hodor at `http://localhost:18080` through `kubectl port-forward`, from outside the mesh, as an operator does; the workloads reach it at `http://hodor.hodor.svc:8080`, the address every tenant's issuer starts with. The bundle endpoint is at a private address of the cluster, under the demonstration's own authority: the chart's settings name it in `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` and the authority in `outboundAuthorities`, which nowhere real does for a private address. They are in `deploy/demo/workload-identity/`, with the manifests of SPIRE and of the workloads.

It ends with `The demonstration of Milestone 10 passed.` It can be run again and again against the same cluster, making two new tenants each time, and runs in continuous integration, in a job of its own, against the image built from the pull request. `HODOR_KIND_CLUSTER`, `HODOR_IMAGE` and `HODOR_PORT` choose another cluster, image or port. The cluster is left running; to remove it:

```bash
kind delete cluster --name hodor-milestone-10
```

## The demonstration of Milestone 11

[Milestone 11](../product/epics.md#milestone-11-hodor-in-a-service-mesh) lets a service mesh's proxies check Hodor's tokens and ask Hodor's decisions, and runs Hodor inside the mesh with every client still limited apart. Its demonstration needs clusters, not the development stack: it makes a [kind](https://kind.sigs.k8s.io/) cluster with Istio and one with Linkerd, installs Hodor and `hodor-ext-authz` in each mesh with [its chart](install-on-kubernetes.md), and does what [the service mesh guide](service-mesh.md) says an operator does:

```bash
python3 deploy/demo/service_mesh.py
```

It needs Docker, kind, `kubectl`, Helm and OpenSSL besides Python 3, and about 3 GiB of memory for Docker for each cluster besides what it already runs. It never changes the current context of `kubectl` or the repositories of Helm: it gives both files of their own, in a temporary directory. It runs Istio's cluster first, then Linkerd's; `HODOR_MESH=istio` or `HODOR_MESH=linkerd` runs one.

| Step | What it shows |
|---|---|
| A kind cluster with Hodor's images | The cluster `hodor-milestone-11-istio` or `hodor-milestone-11-linkerd`, made the first time and taken as it is after. The images `hodor:milestone-11` and `hodor-ext-authz:milestone-11`, built from the checkout when Docker does not have them, and loaded into the cluster |
| The mesh and its gateway | Istio 1.30.8 with native sidecars, `hodor-ext-authz` named as a provider in its mesh configuration, and its ingress gateway from the chart `gateway`, which runs as `spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway`. Or Envoy Gateway 1.10.0, then Linkerd edge-26.11.1 with a trust anchor and an identity issuer the script makes with OpenSSL, and Envoy Gateway's proxies meshed by Linkerd, their listeners' ports left out of the proxy, as `edge-gateway.envoy-gateway-system.serviceaccount.identity.linkerd.cluster.local`. Envoy Gateway serves Orders over TLS, with a certificate the script makes for `orders.example.com` |
| The workloads | In the namespace `shop`, in the mesh: `orders`, the protected application, which answers with the headers it received; `web`, whose service account will hold Orders' role; `stranger`, whose service account will hold none. In `outside`, out of it: `visitor-a` and `visitor-b`, two clients at two addresses. Each client runs `deploy/demo/service-mesh/client.py` in its own pod |
| Hodor in the mesh by `mesh.provider` | The chart, with the stand-ins of [trying the chart](install-on-kubernetes.md#trying-the-chart-on-a-cluster-of-your-own), in a namespace with no label: `mesh.provider` gives the server, the worker and the migration job their proxy, and the stand-in database and mail server stay out of the mesh. The gateway is named in `gatewayIdentities`, and the network policy lets in only the gateway's namespace and `shop` |
| A tenant, its administrator, and the mesh's trust domain | Made with the command-line tool, in the server's pod; `cluster.local` as checked by the mesh |
| Orders in Hodor | The Authorization API; Orders' resource server, `https://orders.example.com`, whose role `reader` may read an order; a service account for `hodor-ext-authz` and its client bound to the adapter's identity in the mesh, `spiffe_x509` or `linkerd_identity`; the service accounts of `web` and `stranger`, each with a client bound to its identity, `web`'s holding `reader`; and Orders' own client for people |
| Two people | Ana and Bruno register through the link Hodor mails to the stand-in's mailbox, and sign in; Ana is given `reader` |
| `hodor-ext-authz`, beside Hodor and in the mesh with it | The chart again, with `extAuthz` for the tenant: Orders' entry names its destination, its client, its audience and the route `GET /orders/{id}`. Its pods get their proxy from `mesh.provider` |
| Orders protected | With Istio, a `RequestAuthentication` at the ingress gateway that checks the token and forwards it, one at Orders for the tenant's issuer and audience, and an `AuthorizationPolicy` of action `CUSTOM` naming `hodor-ext-authz`, as the guide writes them: a sidecar asks external authorization before it checks a token, and `hodor-ext-authz`, with `token: bearer`, checks the token's signature itself. With Linkerd, Envoy Gateway's `SecurityPolicy` that checks the token, its key set inline, and asks `hodor-ext-authz` |
| Through the gateway | From `visitor-a`, `GET /orders/42` at `orders.example.com` through the gateway, with Ana's access token, is let through; with Bruno's, `403`. With no token, `403` from Istio, whose check names the gateway's identity, which Hodor knows as nobody, and `401` from Envoy Gateway. A token of a second tenant for the same audience, `401`. The caller sends nothing but its token |
| Both decisions in Hodor's record | `GET /decisions` holds Ana's `allow` and Bruno's `deny`, reading order 42 on Orders' resource server |
| Hodor stopped | With the server scaled to nothing, Ana's request is `403`: `hodor-ext-authz` denies when Hodor cannot answer. The server is started again |
| Two clients behind the gateway, limited apart | `visitor-a` fails passwords through the gateway, each for another identifier, until its address is locked out after about fifty; Ana's own password is then refused from `visitor-a` and signs her in from `visitor-b`, and Hodor knows that session by `visitor-b`'s own address |
| A forwarded address ignored | Bruno signs in from `web`, which writes `X-Forwarded-For: 198.51.100.7` and is not the gateway: Hodor knows that session by the address of its own proxy, `127.0.0.6` with Istio and the pod's own address with Linkerd |
| Linkerd's policies (Linkerd only) | `stranger` reaches Orders, whose proxy names it in `l5d-client-id`. The script applies a `Server` for Orders' port, runs `hodor-cli mesh linkerd-policy` in a pod of its own with the server's settings, checks that the file names `web`'s identity and not `stranger`'s, and applies it: Linkerd refuses `stranger` with `403` and lets `web` in |
| The audit log | The tenant's chain is intact |

The script reaches Hodor at `http://localhost:18111` and the stand-in's mailbox at `http://localhost:18112` through `kubectl port-forward`, from outside the mesh, as an operator does; the workloads reach Hodor at `http://hodor.hodor.svc:8080`, the address every tenant's issuer starts with. Its files are in `deploy/demo/service-mesh/`: the values of each mesh and of the chart, the routes and policies of each gateway, and the workloads.

It ends with `The demonstration of Milestone 11 passed.` It can be run again and again against the same clusters, making new tenants each time, and runs in continuous integration, one job for each mesh, against the images built from the pull request. `HODOR_KIND_ISTIO_CLUSTER`, `HODOR_KIND_LINKERD_CLUSTER`, `HODOR_IMAGE`, `HODOR_EXT_AUTHZ_IMAGE`, `HODOR_PORT` and `HODOR_MAIL_PORT` choose other clusters, images or ports. The clusters are left running; to remove them:

```bash
kind delete cluster --name hodor-milestone-11-istio
kind delete cluster --name hodor-milestone-11-linkerd
```

## The demonstration of Milestone 12

[Milestone 12](../product/epics.md#milestone-12-an-optional-certificate-authority-per-tenant) gives a tenant that turns it on a certificate authority of its own, whose key OpenBao holds, which signs the intermediates of the tenant's meshes, by hand or through cert-manager, so that every mesh of the tenant trusts one root and Hodor trusts what it signed. Its demonstration needs two clusters: it makes a [kind](https://kind.sigs.k8s.io/) cluster with Istio, where Hodor runs in the mesh with [its chart](install-on-kubernetes.md) beside OpenBao, and another with Linkerd, and plays an operator, an administrator, cert-manager and the workloads of both meshes:

```bash
python3 deploy/demo/certificate_authority.py
```

It needs Docker, kind, `kubectl`, Helm and OpenSSL besides Python 3, and about 3 GiB of memory for Docker besides what it already runs. It never changes the current context of `kubectl` or the repositories of Helm: it gives both files of their own, in a temporary directory.

| Step | What it shows |
|---|---|
| Two new kind clusters with Hodor's images | `hodor-milestone-12-istio` and `hodor-milestone-12-linkerd`, made for each run after removing those a run before left, their pods and services on addresses of their own. The images `hodor:milestone-12` and `hodor-cert-manager-issuer:milestone-12`, built from the checkout when Docker does not have them, and loaded into the clusters |
| Istio | Istio 1.30.8, installed with its charts, whose trust domain is `east.acme.example`: a workload's certificate names it `spiffe://east.acme.example/ns/<namespace>/sa/<service account>`, for an ECDSA key, since Linkerd's proxy takes no RSA client certificate. It starts on a root of its own |
| cert-manager in both clusters | cert-manager 1.21.3, its controller run with the feature gate `UseCertificateRequestBasicConstraints`, so that the requests it writes ask for an authority, as [cert-manager's issuer](hodor-cert-manager-issuer.md#what-it-signs) says |
| Hodor in the Istio mesh, the authority off | The chart, with the stand-ins of [trying the chart](install-on-kubernetes.md#trying-the-chart-on-a-cluster-of-your-own), in a namespace Istio injects its sidecar into, the sidecar named as the trusted proxy and `X-Forwarded-Client-Cert` as the identity header. The sidecar in front of Hodor's server writes the caller's certificate and its chain into the header, which Istio does not do unless told: the tenant's trust domains of the authority have a bundle, and Hodor checks the certificate against it. A Service on a port of the node, where the Linkerd cluster reaches Hodor. A workload in the mesh, `payroll`, whose sidecar writes the certificate it holds into a volume its container shares |
| Two tenants, and their administrators | Made with the command-line tool, in the server's pod |
| With the authority off, nothing of it | The administration interface's document names none of its operations, `POST /certificate-authority` is no route, no bundle is published, the tenant's discovery document does not mention it, and `hodor-cli authority` refuses with `keys.authority_setting_invalid` |
| Turned on, on the local key provider | The chart's `certificateAuthority.enabled`: the document names the authority's eight operations, and creating an authority is refused with `keys.authority_provider_unsuitable` |
| OpenBao | OpenBao 2.7.2 in development mode, prepared as [keys in OpenBao](keys-in-openbao.md#preparing-openbao) says: Transit at `hodor-transit`, Hodor's policy, and Kubernetes authentication for Hodor's service account. The chart's `keyProvider` points Hodor at it, and the tenant's next signing key is made there |
| The tenant's authority | A root for `east.acme.example` and `west.acme.example`, its key made in OpenBao, not exportable and with no plaintext backup, as OpenBao itself says. Its name constraints, as Hodor answers them and as OpenSSL reads them in its certificate: the DNS names of both trust domains and `istio-system.svc` (`additional_dns_names`), where istiod serves under Istio's intermediate, and no address. URIs are left unconstrained (`uri_constraints` `false`), since Linkerd's proxy refuses every SPIFFE identity under an authority that constrains them ([Decision 0076](../decisions/0076-names-an-authority-leaves-to-its-meshes.md)). Its bundle is published under the tenant's issuer, and Hodor trusts it for both trust domains |
| A service account that signs | The audience `urn:hodor:certificate-authority` opened, a service account given `certificate_signer` with `hodor-cli admin grant`, and a client of it for each cluster's issuer, proving who it is with `private_key_jwt` and a key the script makes, whose public part `hodor-cert-manager-issuer jwk` prints |
| `hodor-cert-manager-issuer` in both clusters | The chart alone (`certManagerIssuer.only`) in each cluster's `cert-manager` namespace, cert-manager's own approver allowed to approve for Hodor's kinds. The Istio cluster's reaches Hodor at its Service, the Linkerd cluster's at the port of the Istio cluster's node |
| Istio on the tenant's root | A `HodorIssuer` and the `Certificate` of [cert-manager's issuer](hodor-cert-manager-issuer.md#for-linkerd-and-istio), whose request Hodor signs: `cacerts` holds the intermediate, which OpenSSL verifies under the tenant's root, the root as `ca.crt`, and the key cert-manager made. `hodor-cli authority intermediates` lists it. istiod is restarted to sign with it, and every pod of the mesh to take a certificate under it: `payroll`'s sidecar then trusts the tenant's root and holds a certificate of `spiffe://east.acme.example/ns/payroll/sa/payroll` signed by that intermediate |
| Linkerd on the tenant's root | A `HodorIssuer` and the `Certificate` of Linkerd's identity issuer, `linkerd-identity-issuer`, signed through Hodor; Linkerd edge-26.10.2 installed with its charts, `identity.externalCA`, the trust domain `west.acme.example`, and its trust anchors in `linkerd-identity-trust-roots` from the bundle Hodor publishes. A workload in the mesh, `ledger`, which answers with the headers of each request, on a port of the node |
| Renewed with no one acting | The identity issuer's `Certificate` lives two days and is renewed 47 hours and 58 minutes before it expires, two minutes after it is signed: cert-manager renews it through Hodor with a new key, and Hodor has signed two intermediates for `identity.linkerd.west.acme.example`. It is then renewed 25 hours before it expires, as a real cluster would |
| Across the two meshes, over mutual TLS | `payroll`, in the Istio cluster, calls `ledger`, in the Linkerd cluster, with the certificate, the key and the root its sidecar holds, naming `ledger.ledger.serviceaccount.identity.linkerd.west.acme.example`. Linkerd's proxy takes `payroll`'s Istio certificate under the tenant's root and tells `ledger` its identity in `l5d-client-id`; `payroll` takes `ledger`'s certificate, signed by an identity issuer Hodor signed, with Istio's root, the same one |
| Requests refused | With `hodor-cli authority sign`: an intermediate for `spiffe://west.globex.example/…`, the second tenant's trust domain, `keys.intermediate_name_outside_trust_domains`, which the second tenant's own authority then signs; a certificate that is not an authority, `keys.intermediate_not_an_authority`; one for 31 days, past the bound of 30, `keys.intermediate_lifetime_invalid`. Through cert-manager, a `Certificate` of 100 days, whose request the issuer marks `Failed` with Hodor's code and reason |
| An intermediate withdrawn | `payroll` gets a token with its `client_id` alone, its sidecar presenting its certificate, which Hodor checks up to the tenant's root through Istio's intermediate. `hodor-cli authority withdraw` withdraws that intermediate, and `payroll`'s next request is refused. Istio keeps signing with it until it expires: no revocation list is published |
| Tenants apart | The second tenant publishes a bundle of its own, trusts its own trust domain alone, and finds none of the first tenant's intermediates |
| The audit log | The authority's creation, with its provider and its choice of URI constraints; its own certificate and every intermediate the issuers had signed, the issuers' service account the actor, for both trust domains; the withdrawal and its reason; the chain intact |

The script reaches Hodor at `http://localhost:18080` through `kubectl port-forward`, from outside the mesh, as an operator does, starting it again whenever Hodor's server is replaced. The workloads and the issuers name Hodor by `http://hodor.hodor.svc:8080`, the address every tenant's issuer starts with. Everything it installs besides the charts is in `deploy/demo/certificate-authority/`: the clusters, Istio's and Hodor's values, OpenBao, what Hodor's sidecar forwards, the Service on the node, the workloads and the two `Certificate`s. OpenBao keeps everything in memory and Hodor is reached over plain HTTP between the clusters, as nowhere real does.

It ends with `The demonstration of Milestone 12 passed`, and the minutes it took. It runs in continuous integration, in a job of its own, against the images built from the pull request. On a development machine it takes seven to eight minutes from nothing, the images already built. `HODOR_KIND_ISTIO_CLUSTER`, `HODOR_KIND_LINKERD_CLUSTER`, `HODOR_IMAGE`, `HODOR_ISSUER_IMAGE` and `HODOR_PORT` choose other clusters, images or port. The clusters are left running; to remove them:

```bash
kind delete cluster --name hodor-milestone-12-istio
kind delete cluster --name hodor-milestone-12-linkerd
```

## The demonstration of Milestone 13

[Milestone 13](../product/epics.md#milestone-13-requests-that-say-what-they-need) lets an application say what it needs in a signed request, by value, pushed to Hodor first or kept at an address of its own, and ask for exactly the claims it wants; a person has the standard claims of OpenID Connect, and every parameter of a request is honored. Its demonstration plays an administrator, three applications and two people, against the development stack:

```bash
python3 deploy/demo/requests_and_claims.py
```

| Step | What it shows |
|---|---|
| Two tenants, their administrators, and two people | Two tenants, each with a signing key and a first administrator made with the command-line tool; Ana and Bruno in the first, each choosing a password through a recovery link |
| What discovery says a request may say | Request objects by value, signed with `ES256` among others; the pushed request endpoint, which the tenant does not require; request objects at a client's address, which must be registered; the `claims` parameter; the scopes `address` and `phone` |
| Her standard claims, on the account page | Ana signs in and gives, as the profile page does, a given name, a family name, a telephone number and a postal address. The number is kept as E.164, `+5511912345678`, and not verified: she cannot vouch for it herself |
| Two applications that sign their requests | Through the administration interface, Billing and Payroll, each of the tenant's own, each with a client that proves who it is with `private_key_jwt`, signs its request objects with `ES256`, keeps them under an address of its own at the stack's receiver, and has a P-256 key the script makes |
| A request object, signed | Billing sends Ana's browser with its request as a request object signed with its key, asking through `claims` for her names, her number and her address in the ID token. It gets a code at once, redeems it with an assertion signed by the same key, and the ID token, checked against the tenant's key set, holds each claim under its own name |
| A pushed request | Billing pushes its request, proving who it is with its key, and gets a reference that lives 60 seconds. The browser brought with the reference alone gets a code, whose ID token carries the pushed `nonce`; brought again, the reference is `invalid_request_uri` |
| A request object at the application's own address | Billing keeps a signed object at its address at the receiver, and sends the browser with that address and the SHA-256 of the object after `#`. Hodor fetches it once and it is the request. An address under Payroll's, which Billing did not register, is `invalid_request_uri` and never fetched; Billing's own address with the hash of other content is `invalid_request_uri` |
| What must be refused, refused | Billing's request signed by Payroll's key is `invalid_request_object`. A reference Payroll pushed, brought for Billing, and a reference the second tenant's own application pushed there, brought to the first tenant for Billing, are each `invalid_request_uri`. Each is answered at Billing's redirect address, never with a code |
| A claim of a scope she did not agree to | Travel, an application of another company, asks for the scope `openid` alone and, through `claims`, for her email address as essential, in the ID token and at UserInfo. The consent page asks about `openid` alone; she agrees, and neither the ID token nor UserInfo holds her address |
| An essential `acr` steps her up | Ana sets up an authenticator application. Billing asks, in a signed request object, for `acr` as essential with the multi-factor level: the session of her password is not enough, only the application's code is asked for, and the ID token says `urn:hodor:acr:mfa` with `pwd`, `otp` and `mfa` |
| The ID token of another person, as a hint | Billing sends Ana's ID token as `id_token_hint` with `prompt=none`: in her own browser it is answered with a code, asking nothing; in a browser signed in as Bruno it is answered `login_required` |

The applications are played by the script, as in [the demonstration of Milestone 4](#the-demonstration-of-milestone-4): they register redirect addresses nobody listens on, and read where the browser is sent. Their keys are P-256 keys made by the script, with the arithmetic done by hand, for the demonstration only. The address where Billing and Payroll keep their request objects is a path of the stack's receiver of webhooks, `http://webhook-receiver:9600/request-objects/…`, which answers what the script puts there and tells what Hodor fetched ([the development receiver](../development/local-setup.md#the-development-receiver-of-webhooks)); its host is named in the server's `HODOR_OUTBOUND_DEVELOPMENT_HOSTS`, so it may be plain HTTP and inside the stack. Nowhere real has either.

The OpenID conformance suite's Basic plan, the last part of the milestone's demonstration script, is run by [the conformance job](conformance.md) rather than here: every test of the Basic and Config plans passes, but three that keep a screenshot for review ([expected results](conformance.md#expected-results)), and none is skipped.

It ends with `The demonstration of Milestone 13 passed.` It can be run again and again, and runs in continuous integration after the demonstration of Milestone 9 and before that of Milestone 6, whose second worker removes the delivered messages this one reads. The variables of [the first demonstration](#the-demonstration) tell it where the stack is, and `HODOR_WEBHOOK_RECEIVER_URL` where the receiver is, `http://localhost:9600` unless given.

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
