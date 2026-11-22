---
title: Home
description: Identity, authentication and authorization for many tenants, written in Rust.
hide:
  - navigation
  - toc
---

<div class="hodor-hero" markdown>

![The Hodor logo: someone braced against a heavy wooden door, holding it shut](images/logo/hodor.png)
{ .hodor-hero-logo }

# Hodor

Identity, authentication and authorization for many tenants, written in Rust. One server knows who people are and lets them in; each customer, product or environment gets a **tenant** of its own, with its own users, sign-in page, identity providers and audit log.

[Start the quick-start](operations/quick-start.md){ .md-button .md-button--primary }
[See the examples](examples/README.md){ .md-button }
[Read the architecture](architecture/overview.md){ .md-button }

</div>

## Where to begin

<div class="grid cards" markdown>

-   :material-rocket-launch-outline: **Quick-start**

    ---

    From a clean checkout to a person signed in to a tenant, on one machine, with Docker and nothing else.

    [:octicons-arrow-right-24: Run Hodor locally](operations/quick-start.md)

-   :material-account-key-outline: **Examples**

    ---

    A tenant and its first administrator, sign-in through OpenID Connect, GitHub, SAML and LDAP, and the administration interface with `curl`.

    [:octicons-arrow-right-24: Work through the examples](examples/README.md)

-   :material-sitemap-outline: **Architecture**

    ---

    A modular monolith of bounded contexts, tenants kept apart by row-level security, and every decision recorded with its reasons.

    [:octicons-arrow-right-24: Read the overview](architecture/overview.md)

-   :material-api: **Interfaces**

    ---

    The interaction interface the sign-in pages call, the administration interface, and its OpenAPI document.

    [:octicons-arrow-right-24: Browse the interfaces](api/api-spec.md)

-   :material-shield-lock-outline: **Security**

    ---

    The threat model, outbound requests, secrets at rest, and the responses a SAML service provider must refuse.

    [:octicons-arrow-right-24: Read the threat model](security/threat-model.md)

-   :material-map-marker-path: **Product**

    ---

    Requirements, the roadmap in phases, the epics, and what is built today.

    [:octicons-arrow-right-24: See the progress](product/progress.md)

</div>

## What Hodor does today

Hodor lets people **into** a tenant. It does not yet let applications **ask** Hodor who someone is: the OAuth authorization server and the OpenID Provider are the next phase. [Progress](product/progress.md) tracks every issue.

| Capability | Status |
|---|---|
| Tenants, each isolated in the database by row-level security | Built |
| Registration and password recovery, decided by who reads the mailbox | Built |
| Sign-in with an email address and a password, with lockout on repeated failures | Built |
| Sign-in through an OpenID Connect provider, GitHub, an LDAP directory or a SAML identity provider | Built |
| Administration interface with an OpenAPI document, the command-line tool, and the admin console | Built |
| Audit log, chained with SHA-256 so that a changed record is found | Built |
| OAuth 2.x authorization server and OpenID Provider | Planned: Phase 2 |
| Multi-factor authentication, passkeys, step-up | Planned: Phase 4 |
| Authorization engine with policies, Open Policy Agent | Planned: Phase 5 |

The [roadmap](product/roadmap.md) has the phases and the order they are built in.

<figure markdown>
  ![The hosted sign-in page of the tenant acme: an email address or username, then a choice of the development identity provider or the company directory](images/sign-in.png){ .hodor-screenshot width="380" }
  <figcaption>The sign-in page of the tenant <code>acme</code> on the development stack.</figcaption>
</figure>

## How this documentation is kept

Every page of this site is a file in [`docs/`](https://github.com/ortisun/hodor/tree/develop/docs) of the repository, written before the code that follows it. When the code and a page disagree, one of them is a bug. The [working conventions](development/conventions.md) say how the pages are written, and [the documentation site](development/documentation-site.md) how this site is built from them.
