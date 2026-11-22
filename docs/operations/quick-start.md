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

The work happens on the branch `develop`; `main` receives releases and has none yet. Clone `develop` and run every command of this page from the root of the checkout:

```bash
git clone --branch develop https://github.com/ortisun/hodor.git
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
| Hodor reached directly, not through a load balancer | The address used to limit attempts is the connection's. Behind a load balancer everyone would share one limit |
| A real mail server in `HODOR_SMTP_URL`, with encryption, and `HODOR_MAIL_FROM` | The development mail server delivers nothing |
| The operations listener kept off the internet | It answers health checks without any authentication |
| Backups of the database | Everything Hodor knows is there, the audit log included |

[Deployment](deployment.md) describes where this is heading.
