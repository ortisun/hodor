# Releases

A release is a version of Hodor on the branch `main`, marked with the tag `v<version>`. It is prepared on a branch `release/<version>` cut from `develop`, as the [conventions](../development/conventions.md#branches) say, and it carries one number everywhere: the three binaries, the Helm chart and the image an installation is told to run.

This page says what each release contains. What has been built since the last one is in [progress](progress.md).

## 1.0.0

Released on November 22, 2026. The first release.

### What the number means

1.0.0 is the first version put on `main`, numbered so at the owner's request. It is **not** the stage the [product requirements](product-requirements.md#9-release-criteria) call general availability, nor the ones before it: by those criteria Hodor has not reached Alpha, which waits for the OAuth authorization server and the OpenID Provider of Phase 2.

Read the number as "the first version with a name", and read [what stands between it and real accounts](#what-it-is-not-ready-for) before relying on it.

### What it contains

Hodor lets people into a tenant. It does not yet let applications ask Hodor who someone is.

| Area | In this release |
|---|---|
| Tenants | Each tenant isolated in the database by row-level security, addressed by its slug in the path, with a system tenant for the operators of the installation |
| Accounts | Registration and password recovery, decided by who reads the mailbox; sign-in with an email address and a password, with lockout on repeated failures; sessions, sign-out, ending one's other sessions |
| External identities | Sign-in through an OpenID Connect provider, GitHub, an LDAP directory and a SAML identity provider, with the secrets of providers encrypted at rest |
| Administration | The administration interface over HTTP, with its OpenAPI document; the command-line tool; the admin console in the browser, for users, audit records and identity providers |
| Audit | Every event recorded once, in a log chained with SHA-256 so that a changed record is found |
| Messages and telemetry | Email in English and Brazilian Portuguese; logs, metrics and traces over OpenTelemetry |
| Installation | [With Docker](../operations/install-with-docker.md) on one machine and [on Kubernetes](../operations/install-on-kubernetes.md) with a Helm chart, both without a secret of their own |
| Documentation | Published at <https://ortisun.github.io/hodor/> from `docs/`, with a quick-start and worked examples |

The [readme](https://github.com/ortisun/hodor#where-it-stands) lists the same capabilities beside the ones that are planned, and [progress](progress.md) has every issue.

### What it is not ready for

| Gap | Where it is written |
|---|---|
| Applications cannot sign people in through Hodor: no OAuth authorization server, no OpenID Provider | [Roadmap](roadmap.md), Phase 2 |
| No multi-factor authentication, no passkeys | [Roadmap](roadmap.md), Phase 4 |
| SAML sign-in has had no security review from outside the project, which [Decision 0019](../decisions/0019-saml-signature-verification.md) makes a condition for production; no connector has been tried against the real provider it is written for | [Progress](progress.md#before-milestone-2-is-used-anywhere-real) |
| Behind a web server, which every installation needs for HTTPS, everyone shares one limit on sign-in attempts | [Progress](progress.md#known-gaps-in-what-is-done) |
| No image and no chart are published: both are built from a checkout | [Progress](progress.md#installation-packages) |
| The other known gaps of what is built | [Progress](progress.md#known-gaps-in-what-is-done) |

### Upgrading

There is no earlier release to upgrade from. An installation started from `develop` before this release is brought to it like any upgrade: the migrations it has not seen are applied when the new image starts.
