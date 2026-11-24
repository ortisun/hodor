# Changelog

Every release of Hodor, newest first. The rules for versions and releases are in [the conventions](docs/development/conventions.md#releases).

## [Unreleased]

### Added

- Groups of users in a tenant, with groups inside groups, no cycles and a depth the tenant chooses with `hodor-cli tenant group-depth`.
- Organizations inside a tenant, with a tree of units and departments up to ten levels deep, and people as members of several organizations, each in some of its units.
- The administration interface manages groups, organizations, their units and members, and invitations, under four new permissions: `groups:read`, `groups:write`, `organizations:read` and `organizations:write`. `hodor-cli group` and `hodor-cli organization` do the same from the command line, and the admin console from its new screens of groups and organizations. A user's screen in the console shows their groups and organizations.
- Roles given to a group, held by every member of the group and of the groups inside it, and roles given in an organization, which count only for its members and only when the question names it. `GET /groups/{group_id}/role-assignments` lists a group's roles, and `hodor-cli role assign` takes `--group` and `--organization`.
- A client names the organization a person signs in for with `organization`. Only a member gets a code, and every token of the grant carries the organization as `org_id`, until the person leaves it. The scope `groups` puts the identifiers of the person's groups, the nested ones included, in the access token and at UserInfo.
- Invitations to an organization by email. The person accepts from the link: with a new account and a password if the address has none, or signed in as the account that has it.
- A SCIM 2.0 server at `/t/{slug}/scim/v2`, so that a directory such as Entra ID or Okta, or a human resources system, creates, reads, replaces and lists a tenant's people and groups, with the enterprise extension, filters, sorting and pages. A tenant opens it by registering a resource server with the audience `urn:hodor:scim` and the scope `scim`, and gives the directory a client allowed that scope. Addresses set through SCIM count as verified. What SCIM changes is in the audit log with the directory's client as the actor. Changing through `PATCH`, bulk requests and deleting people come later.
- SCIM clients change people and groups with `PATCH`, send up to 100 changes at once to `/Bulk`, and guard their changes with versions: `If-Match` refuses a change for a version that is no longer the resource's.
- When a directory deprovisions a person, with `DELETE` or `active: false`, the tenant's policy decides whether they are deactivated or deleted, and their sessions and tokens stop working at once. The policy is set with `hodor-cli tenant scim-deprovisioning` or `PUT /scim-deprovisioning` of the administration interface, and is `deactivate` unless changed.
- Service accounts and agents: principals of a tenant that are not people, each with a name and the people who own it. They never sign in. A client of the client credentials grant can act as one: its tokens then name it in `sub` and say `principal_kind`, and the roles assigned to it count in the Authorization API. Disabling or deleting one stops its tokens at once, at introspection, UserInfo and the Authorization API, and its clients get no new ones. The administration interface manages them under `/service-accounts` and `/agents` with two new permissions, `workloads:read` and `workloads:write`, and so does `hodor-cli service-account` and `hodor-cli agent`; `principal` binds a client to one. Clients without one work as before.
- Webhooks. A tenant registers up to 20 endpoints and subscribes each to the events it wants, such as `identity.user_created` or `session.started`. The worker sends each event to its endpoints, signed as [Standard Webhooks](https://www.standardwebhooks.com/) say, so any of their libraries checks it. It keeps trying with longer and longer waits, sets a delivery aside after 8 attempts, and delivers it again when asked. The secret is shown once and can be rotated with an overlap during which both secrets sign. An address that leads to a private network is refused when it is registered and again whenever it is called. The administration interface has nine new operations under `webhooks:read` and `webhooks:write`; the worker has new settings, `HODOR_WEBHOOK_*`, and needs `HODOR_SECRET_KEYS` to send.

- Hodor can sit behind load balancers and web servers and still count each client apart. Name them in `HODOR_TRUSTED_PROXIES` and Hodor reads the client address they forward in `X-Forwarded-For`, or in `Forwarded` with `HODOR_FORWARDED_HEADER`. The limits on sign-in attempts, sessions and the audit log then use that address. A forwarded header from anyone else is ignored. The Docker installation trusts its own web server, and the chart has `trustedProxies` and `forwardedHeader`.
- The worker removes what stopped being useful: ended sessions, used and expired links, delivered messages, expired codes, revoked grants and refresh tokens, withdrawn consents, and more. Each kind is kept for a while after it stops being useful, 7 days for sessions and 30 for messages, for example, and `HODOR_CLEANUP_RETENTION_DAYS` changes how long. The audit log is never touched.
- Each release publishes its image, `ghcr.io/ortisun/hodor:<version>`, for `linux/amd64` and `linux/arm64`, and its Helm chart, `oci://ghcr.io/ortisun/charts/hodor`. Both are signed with `cosign`, and the image carries its software bill of materials. The installation pages say how to check the signatures. The chart now uses the published image unless `image.repository` says otherwise.

### Fixed

- A link to the console's screens of applications, clients and authorization, or a reload of one, answered with not found; the server now answers every screen the console has with its page.

## [0.2.0] - 2026-11-23

A pre-release that lets applications ask Hodor who someone is, and whether they may do something. It holds the three parts [Decision 0023](docs/decisions/0023-what-0.2.0-holds.md) set for it: the OAuth 2.x authorization server and OpenID Provider ([Milestone 3](docs/product/epics.md#milestone-3-applications-ask-hodor-who-someone-is)), multi-factor authentication with passkeys and step-up ([Milestone 4](docs/product/epics.md#milestone-4-strong-authentication)), and the authorization engine with Open Policy Agent ([Milestone 5](docs/product/epics.md#milestone-5-the-authorization-engine)). Each part is cut to what makes it whole; what each leaves to its phase is in that decision.

**0.2.0 is not ready to hold real accounts.** What stands in the way, besides what 0.1.0 listed and still holds:

- no limit on the number of requests to the token, revocation, introspection and authorization endpoints, nor to the Authorization API;
- no cross-origin headers, so an application running in a browser cannot call the token endpoint or UserInfo;
- the OpenID conformance plans pass in continuous integration, but Hodor is not certified: four tests wait for a person to review their screenshots, and nobody of the OpenID Foundation has seen the results;
- request objects, the `claims` parameter, pairwise subjects and back-channel logout are not supported;
- no physical security key and no authenticator built into a device were tried; WebAuthn and passkeys were tested with software and virtual authenticators;
- the journeys of the authorization endpoint, consent, logout and step-up, and the console's new screens, were not tried by hand in a browser;
- no application and no Open Policy Agent instance of the world has talked to Hodor yet; the demonstrations and the conformance suite stand in for them.

The [progress](docs/product/progress.md) page lists every known gap, with "Before Milestone 3 is used anywhere real".

### Added

**Applications ask Hodor who someone is**

- **Signing keys per tenant**, kept sealed, rotated by the worker on a schedule and published as a key set at `/t/{slug}/oauth2/jwks`, with the next key published a day before it signs and the old one kept until its tokens expire. `hodor-cli keys list|rotate|revoke` and the administration interface.
- **Applications, clients and resource servers**: confidential and public clients, redirect addresses compared exactly, client secrets shown once and kept as hashes, keys for `private_key_jwt`, resource servers with their scopes. Managed through the administration interface, `hodor-cli application|client|resource-server` and the console.
- **The authorization endpoint** with PKCE, one-use authorization codes and a sign-in in the middle when there is no session; **the token endpoint** with the four client authentication methods and access tokens as JWT (RFC 9068); **refresh tokens** that rotate on every use, whose reuse ends their family; **client credentials**.
- **The OpenID Provider**: ID tokens signed with ES256 or, per client, RS256; UserInfo; discovery and the authorization server metadata; `nonce`, `prompt`, `max_age`, `login_hint`, `ui_locales`; `acr` and `amr` (RFC 8176).
- **Consent** for third-party applications, on a page of the hosted pages, kept with its history and withdrawn by the person or an administrator, which ends the grants it allowed.
- **Logout initiated by the relying party**, with registered addresses to return to and a confirmation when the request does not name the browser's session.
- **Revocation and introspection** (RFC 7009 and RFC 7662), with a register of the access tokens issued, so that a revoked grant or family makes its access tokens inactive.
- **The OpenID conformance suite in continuous integration**: the Basic OpenID Provider and Config OpenID Provider plans of the OpenID Foundation's suite run against the image on every pull request ([conformance](docs/operations/conformance.md)).
- **The demonstration of Milestone 3**, `deploy/demo/applications.py`, run in continuous integration: a third-party application registered with the command-line tool, the consent page, the ID token and UserInfo, a refresh token whose reuse ends its family, a token a client gets for itself, revocation and introspection, a rotated key, and a client, a code and a token of one tenant refused by another.

**Strong authentication**

- **Authenticator applications (TOTP)** as a second factor, with the secret sealed and every code good once; **recovery codes**, ten per person, each good once; **WebAuthn security keys**, checked by Hodor's own code ([Decision 0024](docs/decisions/0024-webauthn-checks.md)); **passkeys** that sign a person in alone, without an identifier or a password.
- **A tenant policy that requires a second factor**, `hodor-cli tenant second-factor`.
- **Assurance levels and step-up**: a tenant names the `acr` levels applications ask for, single-factor, multi-factor and phishing-resistant; an application asks with `acr_values` or `max_age`, and a person signed in is asked only for what their session lacks. Tokens say the level reached. Set the levels with `hodor-cli tenant assurance-levels` or the administration interface.
- **A person manages their own factors** on `/account/security`, after proving themselves again; an administrator removes a person's factors through the administration interface and the console.
- **The demonstration of Milestone 4**, `deploy/demo/strong_authentication.py`, run in continuous integration: an authenticator application, recovery codes, a tenant that requires a second factor, a passkey alone, a step-up asked for by an application, and an administrator removing a person's factors.

**The authorization engine**

- **The engine contract**: one engine answers for each resource server of a tenant, a failing engine never answers allow, and the tenant always comes from the caller's credential.
- **Native role-based access control**: permissions per resource server, roles with hierarchy and composites, assignments to users and clients for the tenant or an application. The fixed roles of the administration interface became roles of this engine, unchanged.
- **Conditions in Common Expression Language** on the permissions of a role, checked and bounded when the role is saved ([Decision 0025](docs/decisions/0025-condition-language.md)).
- **The Authorization API**: `evaluate`, `batch` and `simulate` under `/t/{slug}/api/v1/authorization/`, called with access tokens, the explanation only for callers allowed to see it.
- **Open Policy Agent as an engine**, over its Data API, with a circuit breaker and every failure an indeterminate answer; **signed bundles** pulled by each instance with a credential of its own; **the policy lifecycle**: versions validated and tested with the `opa` binary in a sandbox of the worker ([Decision 0026](docs/decisions/0026-policy-checks-in-a-sandbox.md)), simulated, published and rolled back with `hodor-cli policy draft|validate|test|simulate|publish|rollback|status`; a decision from an instance that runs an older revision five minutes after a new one is published is `indeterminate`.
- **The record of decisions**, for both engines, per tenant full, sampled or deny-only, masked by path and kept for a number of days, partitioned by day.
- **Managing authorization through the administration interface and the command line**: the permissions of a resource server, roles with their inclusions and conditions, who holds them, which engine answers for each resource server, and policy versions drafted, checked, tested and simulated, under the new permissions `roles:read|write`, `bindings:read|write` and `policies:read|write`. `hodor-cli authorization permission|role|assign|revoke|bind|unbind|bindings`. Publishing and rolling back a policy stay commands of the operator, who alone holds the key that signs bundles.
- **An Authorization screen in the admin console**: the tenant's roles with their conditions, changed as text and checked by the server; the engine of each resource server and removing a binding; what is published for Open Policy Agent and whether every instance runs it; the latest decisions. A person's and a client's roles are on their pages, and can be taken away.
- **The demonstration of Milestone 5**, `deploy/demo/authorization.py`, run in continuous integration after the other four: roles given to a person and a client, decisions asked for with a token, a condition that changes the answer, a resource server answered by Open Policy Agent with policies published, simulated and rolled back, a stopped instance whose answer is never allow, and the record of decisions.

### Changed

- **Secrets are kept under a data key of their tenant**, a key version of the keys context, and the keys of `HODOR_SECRET_KEYS` only wrap keys. After upgrading from 0.1.0, run `hodor-cli secrets reseal` once: it moves the secrets 0.1.0 kept and then refuses their old format. Until it runs, they open as before.
- **`hodor-cli policy-agent publish` is gone.** Bundles are published only from tested policy versions, with `hodor-cli policy publish`.
- **The image holds the `opa` binary**, 46 MB, pinned by checksum; the chart gives the worker 512 MiB of memory instead of 256 MiB.

### Fixed

- **Building the image where other branches were built.** The shared cargo cache of the image's build compared modification times and could build code of another checkout; the build now marks the workspace's files as changed first.

## [0.1.0] - 2026-11-22

The first release, a pre-release: the walking skeleton of [Milestone 1](docs/product/epics.md#milestone-1-walking-skeleton) and signing in with external identities, [Milestone 2](docs/product/epics.md#milestone-2-signing-in-with-external-identities). Hodor lets people into a tenant; it does not yet let applications ask Hodor who someone is.

0.2.0 comes when three more parts are built: the OAuth 2.x authorization server and OpenID Provider, multi-factor authentication with passkeys and step-up, and the authorization engine with Open Policy Agent. These same contents were first published as `v1.0.0` by mistake, before those parts; that tag and release were withdrawn the same day, before any image or chart was published.

**0.1.0 is not ready to hold real accounts.** What stands in the way:

- the development stack's passwords and keys are written in the repository, and it speaks plain HTTP: see [before anything real](docs/operations/quick-start.md#before-anything-real);
- behind a load balancer every person shares one limit of attempts, since a forwarded address is not trusted yet;
- SAML has not been reviewed by anyone outside the project, which [Decision 0019](docs/decisions/0019-saml-signature-verification.md) makes a condition for production;
- no connector has been tried against the real provider, and LDAP was tried against OpenLDAP only;
- sessions, verification tokens, sign-ins, attempt counters and message records that expired are never removed;
- no image and no chart are published: both are built from a checkout of the tag.

The [progress](docs/product/progress.md) page lists every known gap.

### Added

- **Tenants**, each isolated in the database by row-level security, created and managed with `hodor-cli`, resolved from the address of every request.
- **Users and passwords**: registration and password recovery through a link sent by email, Argon2id hashing under a limit of memory and concurrency, sign-in in steps driven by a flow engine, lockout per identifier and per address.
- **Sessions** tied to the browser that started them, with signing out and ending one's other sessions.
- **The hosted pages**, one React application served by `hodor-server` under a strict Content Security Policy, in English and Brazilian Portuguese, tested in a browser for accessibility.
- **The administration interface**, under fixed roles, with its OpenAPI description; the first administrator is made with `hodor-cli admin bootstrap`. **The admin console** on the administrator's Hodor session.
- **The audit log**: every event of a tenant recorded in a chain of hashes, written by `hodor-worker` from a transactional outbox, and checked with `hodor-cli audit verify`.
- **Email** through a queue that the worker delivers over SMTP, with retries.
- **Signing in with external identities**: any OpenID Connect provider, with recipes for Google, Microsoft Entra ID and Keycloak; GitHub; LDAP directories; and SAML identity providers, with Hodor as the service provider. An external identity is never let into an existing account because of its email address.
- **SAML checked behind a narrow profile of Hodor's own** with `xml-sec`: a corpus of more than sixty attacks, each refused for its own reason; responses checked as they arrive, with only the answer kept; a receipt that ties the finish of a sign-in to the browser that carried the response.
- **Secrets kept encrypted at rest** with AES-256-GCM, bound to their tenant and purpose, with keys that can be changed.
- **One guarded client for outbound requests**: public addresses only, no redirects, limits on size and time.
- **Telemetry** over OpenTelemetry: traces to VictoriaTraces, metrics to VictoriaMetrics.
- **A Compose stack for development** with a development OpenID Connect provider, an LDAP directory and a SAML identity provider, all of which let anyone sign in as anyone; **installation packages** for Docker and Kubernetes.
- **Two test environments** on one machine, each seeded with a tenant, a person and an administrator: the stack in Docker with the three development providers, and Hodor installed by its chart on a Kubernetes cluster in Docker.
- **Two demonstrations**, one per milestone, run in continuous integration against the image.
- **The documentation site**, published from `docs/` at <https://ortisun.github.io/hodor/>.

[Unreleased]: https://github.com/ortisun/hodor/compare/v0.2.0...develop
[0.2.0]: https://github.com/ortisun/hodor/releases/tag/v0.2.0
[0.1.0]: https://github.com/ortisun/hodor/releases/tag/v0.1.0
