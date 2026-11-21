# Progress

What has been built, issue by issue. This page is updated with every merge into `develop`; the plan it tracks is in [epics.md](epics.md).

Last updated: 2026-11-21.

## Milestone 1: Walking skeleton

All 34 issues of the milestone are done. Its goal — a person registers, verifies an email address, signs in with a password and gets a session in a tenant, with tenant isolation, audit and observability proven — is what [the demonstration](../operations/quick-start.md#the-demonstration) shows and checks on every pull request.

| Slice | Done | Total |
|---|---|---|
| A — Foundation | 11 | 11 |
| B — Tenancy | 3 | 3 |
| C — Identity | 3 | 3 |
| D — Password credential | 3 | 3 |
| E — Authentication and session | 7 | 7 |
| F — Audit, notification, admin | 4 | 4 |
| G — Hosted user interface and acceptance | 3 | 3 |

### Slice A — Foundation

| Issue | Status | What exists |
|---|---|---|
| Issue-01 Workspace skeleton | Done | Cargo workspace, shared lints with `unsafe` forbidden, pinned toolchain, `deny.toml` |
| Issue-02 continuous integration pipeline | Done | GitHub Actions: format, lint, build, test, dependency checks |
| Issue-03 Architecture test | Done | `tests/architecture` checks every crate against the allowed edges in [crates.md](../architecture/crates.md) |
| Issue-04 Kernel | Done | Typed UUIDv7 identifiers, `TenantContext`, `Clock`, `RandomSource`, `Secret<T>`, `DomainError`, event types, pagination |
| Issue-05 PostgreSQL base | Done | Tenant-scoped transactions, forced row-level security helper, embedded migrations, `hodor-cli migrate`, container test harness |
| Issue-06 Schema rules | Done | A catalog check that fails when a table is not a proper tenant table |
| Issue-07 Outbox | Done | `UnitOfWork` port, `platform.outbox`, dispatcher with `SKIP LOCKED`, rollback and backoff |
| Issue-08 Observability | Done, with a gap | Logs, traces and metrics over OTLP; VictoriaMetrics verified by test. Trace export is not yet verified against a backend |
| Issue-09 HTTP base | Done | Tenant resolution from the path, request identifiers, security headers, limits, problem documents, health endpoints, graceful shutdown; `hodor-server` wired |
| Issue-10 Container image and Compose | Done | Distroless image with the three binaries; Compose stack with PostgreSQL, migrations, server and VictoriaMetrics; `hodor-cli probe` |
| Issue-34 Worker runs the outbox dispatcher | Done | `hodor-worker` delivers outbox events in a polling loop, with health endpoints, metrics and a clean stop; part of the Compose stack |

### Slice B — Tenancy

Specified in [the tenant context](../architecture/contexts/tenant.md).

| Issue | Status | What exists |
|---|---|---|
| Issue-11 Tenant domain | Done | `hodor-tenant` crate: slug rules, lifecycle with every transition checked, settings with defaults and bounds, events |
| Issue-12 Tenant persistence and directory | Done | Use cases and ports in `hodor-tenant`; `tenant.tenant` and `platform.tenant_directory` with their triggers; PostgreSQL repository and directory; one contract suite passed by the in-memory fake and by PostgreSQL |
| Issue-13 Tenant commands and server resolver | Done | `hodor-cli tenant` commands; `hodor-server` resolves tenants through the directory and answers by status |

### Slice C — Identity

Specified in [the identity context](../architecture/contexts/identity.md).

| Issue | Status | What exists |
|---|---|---|
| Issue-14 Identity domain | Done | `hodor-identity` crate: users with their lifecycle, login identifiers with normalization, uniqueness within a user and primary rules, events that carry no personal data |
| Issue-15 User repository | Done | `identity.user` and `identity.user_identifier` under row-level security; PostgreSQL repository; one contract suite passed by the in-memory fake and by PostgreSQL |
| Issue-16 Identity use cases | Done | `IdentityService`: create, find by typed login, lifecycle changes, login identifier changes, profile; each change stored with its events in one unit of work |

### Slice D — Password credential

Specified in [the credential context](../architecture/contexts/credential.md).

| Issue | Status | What exists |
|---|---|---|
| Issue-17 Credential domain | Done | `hodor-credential` crate: the rules for an acceptable password, the password record with its history, events, and the hasher port |
| Issue-18 Argon2id hasher | Done | `hodor-adapters-crypto` crate: Argon2id behind the hasher port with bounded concurrency and a bounded queue, renewal of hashes made with older parameters, a check against nothing of equal cost, and the operating system random source |
| Issue-19 Credential storage and use cases | Done | `CredentialService`: set, change, verify with silent renewal, remove; `credential.password` and its history under row-level security; one contract suite passed by the in-memory store and by PostgreSQL |

### Slice E — Authentication and session

| Issue | Status | What exists |
|---|---|---|
| Issue-20 Session | Done | `hodor-session` crate: sessions with tokens stored only as hashes, idle and absolute expiry, revocation, token replacement; `session.session` under row-level security; one contract suite passed by the in-memory store and by PostgreSQL. SHA-256 behind a `Digest` port. Specified in [the session context](../architecture/contexts/session.md) |
| Issue-21 Authentication flow engine | Done | `hodor-authentication` crate: flows as data with the built-in flow, validation of a flow, the transaction that records a sign-in in progress, the `Authenticator` extension point and the engine. No real authenticators or storage yet. Specified in [the authentication context](../architecture/contexts/authentication.md) |
| Issue-22 Authenticators and lockout | Done | The identifier and password authenticators over the identity, credential and tenant contexts; the attempt guard with growing lockouts on identifiers and addresses; `authentication.attempt_counter` under row-level security |
| Issue-23 Completing a sign-in | Done | `AuthenticationService`: start, submit a step, describe, cancel; a completed sign-in starts a session exactly once; `authentication.transaction` under row-level security. A test signs a person in with nothing faked: PostgreSQL, Argon2id, SHA-256 and the operating system's random source |
| Issue-24 Interaction interface | Done | A browser signs in over HTTP: the interaction routes, a sign-in tied to the browser that started it, the sign-in and session cookies, CSRF and origin checks, all served by `hodor-server`. A test signs in to the real binary against PostgreSQL. Specified in [the interaction interface](../api/interaction-api.md) |
| Issue-25 Registration and recovery | Done | A person registers and recovers a forgotten password through their mailbox: verification tokens stored only as hashes and good for one use even when presented many times at once; the password chosen at the end by whoever holds the link; the same answer to asking whoever the address belongs to; limits on asking; a recovery ends every session of the user. Four routes on the interaction interface, served by `hodor-server`. A test does the whole journey on the real binary against PostgreSQL. Specified in [the authentication context](../architecture/contexts/authentication.md#registration-and-password-recovery) and [the interaction interface](../api/interaction-api.md#registering-and-recovering-a-password) |
| Issue-26 Sign out and sessions | Done | A signed-in person signs out, lists their sessions, ends one and ends all others. A session is ended on the server, so a copy of its token stops working on the next request; another person's session is answered like one that does not exist. The requests that change something carry a CSRF token derived from the session token. A test signs out of the real binary against PostgreSQL. Specified in [the interaction interface](../api/interaction-api.md#routes-for-a-signed-in-person) |

### Slice F — Audit, notification, administration

| Issue | Status | What exists |
|---|---|---|
| Issue-27 Notification | Done | `hodor-notification` crate: messages queued in the transaction of the change that causes them, built-in templates in English and Brazilian Portuguese, retries with growing waits, expiry, and contents erased once a message is no longer pending; `notification.message` under row-level security; one contract suite passed by the in-memory queue and by PostgreSQL. `hodor-adapters-smtp` delivers to a mail server and is tested against a real one in a container. `hodor-worker` delivers queued messages; the development stack has a mail server whose web page shows what was sent. Specified in [the notification context](../architecture/contexts/notification.md) |
| Issue-28 Audit | Done | `hodor-audit` crate: every event becomes one record, chained per tenant with SHA-256 so that a changed, removed or inserted record is found; `audit.record` under row-level security, append-only by permission and by a trigger; the worker records each event in the transaction that marks it delivered; `hodor-cli audit verify` checks a tenant's chain. Tests deliver with three workers at once, try to change records as every database role, tamper behind the protections and verify, and search every record for a password, tokens and an email address used in a registration and a recovery. Specified in [the audit context](../architecture/contexts/audit.md) |
| Issue-29 Administration interface | Done | The first routes of the administration interface, served by `hodor-server`: create, list, read and suspend users; list and end a user's sessions; read the audit log. `hodor-authorization` crate with two fixed roles and the check; access tokens in the credential context, stored only as hashes; an OpenAPI document served by the interface. Every operation in the document is tried without a token, with ten kinds of token that are not good, with a role that lacks the permission and with another tenant's token. A test does an administrator's work on the real binary against PostgreSQL and finds it in the audit log under their name. Specified in [the administration interface](../api/admin-api.md), [the authorization context](../architecture/contexts/authorization.md) and [access tokens](../architecture/contexts/credential.md#access-tokens) |
| Issue-30 Bootstrap administrator | Done | `hodor-cli admin bootstrap` makes a user an administrator of a tenant, creating the user if needed, and prints an access token once. Run as the real binary against PostgreSQL: the token and the role work in their tenant and in no other, a second run issues another token for the same user, and a user who may not sign in gets none. Specified in [the administration interface](../api/admin-api.md#the-first-administrator) |

### Slice G — Hosted user interface and acceptance

| Issue | Status | What exists |
|---|---|---|
| Issue-31 Hosted pages | Done | `auth-ui`, a React application in `frontend/auth-ui`, served by `hodor-server` from the directory `HODOR_PAGES_DIRECTORY` names: a person registers, signs in one step at a time, signs out and recovers a password in a browser, in English or Brazilian Portuguese. The pages only show the step the interaction interface names. `index.html` is sent with a Content Security Policy that allows files of this server only, no inline script or style, and no way to turn text into markup; the fonts are bundled. The image builds the pages and serves them. Tested in three layers: unit tests of the application, tests of the HTTP layer that need no Node.js, and browser tests with Chromium against the Compose stack, which fail on any policy violation, script error or accessibility violation and include a pass with the keyboard alone. A new continuous integration job runs all of it. Specified in [the hosted pages](../architecture/hosted-pages.md) |
| Issue-32 Cross-tenant suite | Done | Seven cases on the real `hodor-server` against PostgreSQL, with two tenants that share a person's email address and password: a session cookie, a sign-in in progress, an administrator's access token on every operation of the OpenAPI document, registration and recovery links, and the identifiers of users and sessions are each shown to work in their own tenant and then refused by the other; lists of users and audit logs name nothing of the other tenant; a lockout in one does not reach the other. Runs with every other test in continuous integration. Done ahead of Issue-31: it tests the server, which must not rely on what a browser would or would not send. Specified in [multi-tenancy](../architecture/multi-tenancy.md#the-cross-tenant-suite) |
| Issue-33 Demonstration and quick-start | Done | [The quick-start](../operations/quick-start.md) takes an operator from a clean checkout to a tenant people sign in to. `deploy/demo/demo.py` is the demonstration of the milestone: two tenants made with the command-line tool, the same address registered in both by a link from a message, a sign-in and its session, a lockout after five wrong passwords, the session cookie and the administrator's token of one tenant refused by the other, the audit log with its chain intact, the worker's metrics in VictoriaMetrics and the trace of the sign-in in VictoriaTraces. It checks every answer and runs in continuous integration against the image. The development stack gained VictoriaTraces and creates the system tenant by itself |

### Checked by hand on the development stack

Some things are covered by tests in halves and were also tried whole, on the Compose stack, on 2026-11-21:

- A person asked to register; the server queued the message, the worker delivered it to the development mail server, the message arrived in the language asked for with a working link, and the link finished the registration once and only once.
- The worker's metrics for the outbox and for messages arrived in VictoriaMetrics.
- A person used the pages in Chromium, at desktop and at telephone width, in both languages: registered, followed the link from the message, was told what was wrong with a short password, signed in, was refused with a wrong password, recovered the password and signed out. The first run of the browser tests found the primary button of the light theme below the contrast the design system promises (4.27 to 1); the accent of the light theme was darkened until it measured 4.81 to 1.
- The demonstration ran against the image from start to end and passed: the trace of the sign-in was found in VictoriaTraces, the first time traces of Hodor were received by anything.
- The first administrator of a tenant was made with `hodor-cli admin bootstrap`; the token it printed listed and created users through the administration interface, a request without it was refused, the audit log read through the interface showed each step with the right actor, and `hodor-cli audit verify` found the chain intact.

### Known gaps in what is done

These are recorded here so they are not forgotten; each is picked up by the issue named.

| Gap | Picked up by |
|---|---|
| Tenants have no routes of their own yet: an existing tenant answers `404` with `route.not_found` | Issue-24, the interaction API |
| The Argon2id hasher was not checked against a hash produced by another implementation; it relies on the library's own conformance | When a second implementation is at hand, for example password import |
| Records removed from the end of a tenant's audit chain, or a chain rewritten whole, are noticed only through the chain head, which lives in the same database | Exporting the latest hash regularly, later in Phase 1 |
| Audit records do not carry the address a request came from or the application that made it, and events caused by people who are not signed in are recorded as anonymous | When events carry them: with OAuth clients in Phase 2 |
| Rows of expired and revoked sessions are never removed | A cleanup job, later in Phase 1 |
| The cross-tenant suite does not cover OAuth tokens and codes, which do not exist yet, or the pages in a browser | Phase 2 for OAuth; hardening pass for the pages |
| The pages show the tenant's slug, not its name, logo or colors, and offer registration even when the tenant does not accept it; the person is told after asking | A public description of the tenant, Phase 2; branding, Phase 3 |
| The pages have no place to see and end one's sessions, though the interaction interface can | The account console, Phase 2 |
| The browser tests run in Chromium only. Safari refuses `Secure` cookies on `http://localhost`, so the pages cannot be tried there without TLS | Hardening pass |
| The continuous integration job for the pages builds the image from nothing on every run | When the job is slow enough to matter |
| The dependencies of the pages are checked for known vulnerabilities by `npm audit`, not for licenses | Hardening pass |
| Roles are given only by the bootstrap command and cannot be taken away; access tokens cannot be listed or revoked through any interface | Phase 2, with OAuth and the rest of the administration interface |
| Listing users reads each user with a query of its own | When a tenant's user list is slow |
| Asking to register or recover answers the same whoever the address belongs to, but not in the same time: an address with something to send costs one more write. The difference was not measured | Hardening pass |
| A registration that fails after the user was created and before the password was set leaves an account without a password; the person gets in by recovering it | Accepted; see [the authentication context](../architecture/contexts/authentication.md#registration) |
| Used, replaced and expired verification tokens are never removed | A cleanup job, later in Phase 1 |
| The address used to limit attempts is the connection's, so behind a load balancer everyone shares one limit | Before any deployment behind a load balancer |
| Records of messages that were sent, failed or expired are never removed | A cleanup job, later in Phase 1 |
| The worker opens a new connection to the mail server for every message | When the volume of mail calls for it |
| The mail adapter was tested against a mail server without encryption or a password; the encrypted and authenticated paths rely on the mail library | Before the first production deployment |
| The trace of a request has one span, the request itself: database calls are not traced. The demonstration receives the trace; no test in `cargo test` does | First issue that adds a traced database call |
| The demonstration needs Python 3 on the machine that runs it | Accepted: it uses only the standard library |
| SQL is checked at run time, not at compile time (`sqlx::query!` with the offline cache is not set up). Every query is exercised by an integration test instead | A dedicated issue, not yet scheduled |
| Continuous integration actions are pinned by tag, not by commit SHA | Hardening pass (threat Threat-General-15) |

## Design system

Specified in [the design system](../design/design-system.md) and [the control plane](../design/control-plane.md), outside the milestone plan; the React components are built with the admin console (Epic 12).

| Piece | Status | What exists |
|---|---|---|
| Specification | Done | Foundations, components, security interaction patterns, control plane structure, console requirements (`Requirement-Console-…`), [Decision 0016](../decisions/0016-design-system.md) |
| Tokens and styles | Done | `frontend/design-system/tokens.css`, `components.css` and `shell.css`: dark and light themes, density, reduced motion, forced colors |
| Showcase | Done | Static pages in `frontend/design-system/showcase/`: the security posture screen with working level 2 and level 3 confirmations, step-up, secret reveal and command palette, plus a component gallery |
| Fonts | Done for the hosted pages | IBM Plex Sans is bundled with `auth-ui` from the `@fontsource/ibm-plex-sans` package and served by `hodor-server`. The showcase still loads its fonts from Google Fonts, which the shipped frontends must not do |
| React components and action catalog | Not started | Epic 12 |
| Contrast checks in a token build | Not started | Planned with the React components. The hosted pages are measured by the accessibility checker of the browser tests, which found and fixed one pair: text on the accent in the light theme |

## Defects found after merging

Defects that reached `develop` and were fixed later, kept here so that the record of what went wrong is not lost.

| Defect | Introduced | Found by | Fixed |
|---|---|---|---|
| Locking an attempt counter could fail with an internal error when a successful sign-in cleared the same counter at the same moment. The store created the row and then locked it in two statements, and the clear could delete it in between | Issue-22 | A full-suite run, in which the test that submits one sign-in eight times at once failed intermittently | Issue-24: one statement now creates, locks and returns the row; a test runs both operations against each other |

## Where the implementation departs from the design

Each departure is reflected in the page that specifies the topic. They are collected here for a reader who knows the original design.

| Topic | Design said | What was built | Recorded in |
|---|---|---|---|
| Metrics backend and transport | OTLP plus a Prometheus endpoint | OTLP push to VictoriaMetrics, no scrape endpoint | [Decision 0015](../decisions/0015-observability-stack.md) |
| Container images | One image per binary | One image with the three binaries | [deployment](../operations/deployment.md#artifacts) |
| TLS trust for the database client | Not specified | Operating system trust store, not bundled roots | [local setup](../development/local-setup.md) and `Cargo.toml` |
| Outbox delivery | A handler registry with per-handler idempotency | Delivery is atomic per event: all handlers for an event commit together with the "delivered" mark | [Decision 0003](../decisions/0003-context-communication.md) |
| `UnitOfWork` | Port named, shape open | A trait object that adapters downcast to reach their transaction | [overview](../architecture/overview.md#cross-cutting-concerns) |
| Email delivery | An event handler in the worker that reacts to events of other contexts | A queue of its own: the context that wants a message sent puts it in the queue inside its own transaction, and the worker delivers from the queue. An event must never carry a link that is as good as a token, and the queue can erase a message's contents once it is sent | [the notification context](../architecture/contexts/notification.md#how-a-message-gets-sent) |
| Audit records | Written in the same transaction as the change; columns for the target, the outcome, the client and the address | Written by the worker in the transaction that marks the event delivered, shortly after the change; the details are the event's contents, and target, outcome, client and address are not separate columns yet | [the audit context](../architecture/contexts/audit.md#how-a-record-comes-to-exist) |
| The OpenAPI document | Generated from the code | Written by hand and kept next to the code that serves it; a test checks that it and the routes agree | [the administration interface](../api/admin-api.md) |
| Authorization of the administration interface | The native engine behind the engine contract | A direct check of fixed roles; the engine contract comes with policies in Phase 5 | [the authorization context](../architecture/contexts/authorization.md) |
| The files of the hosted pages | Shipped in the image; how the server finds them was open | Built into a directory of the image that `HODOR_PAGES_DIRECTORY` names, not compiled into the binary, so that the Rust workspace builds and tests without Node.js | [the hosted pages](../architecture/hosted-pages.md#how-the-pages-are-served) |
| Navigation inside the hosted pages | A single-page application | One application, but going from page to page is an ordinary navigation of the browser: no router, nothing kept from the page before | [the hosted pages](../architecture/hosted-pages.md#where-the-code-is) |
| Tenant lookup for HTTP | Middleware in `protocol-http` | Same, through a `TenantResolver` trait that the composition root implements, so `protocol-http` depends on no adapter | [overview](../architecture/overview.md#cross-cutting-concerns) |
