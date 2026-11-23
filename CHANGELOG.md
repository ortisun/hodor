# Changelog

Every release of Hodor, newest first. The rules for versions and releases are in [the conventions](docs/development/conventions.md#releases).

## [Unreleased]

### Added

- **Assurance levels and step-up**: a tenant names the `acr` levels applications ask for, single-factor, multi-factor and phishing-resistant; an application asks with `acr_values` or `max_age`, and a person signed in is asked only for what their session lacks. Tokens say the level reached. Set the levels with `hodor-cli tenant assurance-levels` or the administration interface.

### Changed

- **Secrets are kept under a data key of their tenant**, a key version of the keys context, and the keys of `HODOR_SECRET_KEYS` only wrap keys. After upgrading from 0.1.0, run `hodor-cli secrets reseal` once: it moves the secrets 0.1.0 kept and then refuses their old format. Until it runs, they open as before.

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

[Unreleased]: https://github.com/ortisun/hodor/compare/v0.1.0...develop
[0.1.0]: https://github.com/ortisun/hodor/releases/tag/v0.1.0
