# Decision 0051: Every certification plan runs in continuous integration, a core set on each pull request and all of them every night and before each release; certification is asked for against a public deployment the owner runs, one batch per version

Status: Proposed (requested by the project owner, who asked for every OpenID certification profile)

## Context

Continuous integration runs five plans of the [OpenID conformance suite](../operations/conformance.md) on every pull request: 75 tests in about 30 minutes. This plan adds every OpenID Provider profile the OpenID Foundation certifies: Implicit, Hybrid, Dynamic, Form Post for three flows, third-party initiated login, four logout profiles run once per response type, and later FAPI 1.0 Advanced in eight variants, FAPI 2.0 in seven and FAPI-CIBA in four. Run one after the other, they would take many hours on every pull request.

Certification itself is a separate act ([how certification is obtained](../operations/certification.md)). The Foundation accepts results only from its hosted suite, `www.certification.openid.net`, which must reach the deployment over the internet. The full logs are published with the certification, client credentials and keys included. The Certification of Conformance is signed by a person who works for the implementer. Each programme has its fee, and the open-source fee waiver, as the Executive Committee updated it on 2026-10-29, allows one waiver per project and year, for all the profiles of a specification submitted at once, and asks US$100 for any later request within the year ([the policy](https://openid.net/certification/open-source-project-certification-policy/)).

## Decision

### What runs, and when

| When | What runs | Why |
|---|---|---|
| Every pull request into `develop` | The core set: Basic, Config, RP-Initiated with Back-Channel logout, Dynamic with `code`, and FAPI 2.0 Security Profile with one variant once it exists | Catches what breaks most profiles, within about 45 minutes |
| A pull request labelled `conformance: full`, every night on `develop`, and every pull request into `main` | Every plan of every profile Hodor claims, in every variant the [target](../operations/conformance.md#the-target) names | A release is never cut with a profile failing |

- **Each plan runs in a job of its own**, in a matrix, against its own stack started from the same image, so that the plans run side by side and a failure names its plan. The image is built once and shared between the jobs.
- **`deploy/conformance/expected.json` stays the one list of allowed results**, per plan and variant now, each with its reason. A test that ends otherwise fails its job.
- **The nightly run opens an issue** when it fails, naming the plans and tests, so that nobody has to look for it.
- **The pull request into `main` is the gate**: the release rules already wait for continuous integration to be green on its head ([releases](../development/conventions.md#releases)).

### Certification is asked for per version, in one batch per specification

- **The project prepares; the owner asks.** The project keeps `deploy/certification/`: the configuration of a public deployment and a script that makes, through `hodor-cli`, the tenants and clients the hosted suite's plans need, with throwaway credentials. The runbook is [how certification is obtained](../operations/certification.md). The owner runs the deployment, runs the plans on the hosted suite, signs the declaration and submits.
- **One batch per specification, when a version is released.** 0.5.0 is submitted with every OpenID Connect and logout profile at once, as the waiver asks. 0.6.0 is submitted with FAPI 1.0 Advanced, FAPI 2.0 and FAPI-CIBA at once. Whether the FAPI programmes fall under the same yearly waiver as OpenID Connect is asked of the Foundation before 0.6.0 is submitted.
- **What is certified is a deployment of a version.** The version string of the declaration is Hodor's version, and a deployment is one issuer per tenant; a later version is certified again only when the owner chooses, as the Foundation does not require it.
- **Nothing real is in the certification deployment.** Its tenants, clients and keys exist for the run, are disabled and revoked before the logs are published, and the deployment is taken down or reset afterwards.

## Consequences

- A change that breaks a profile is caught on its pull request for the core set, and within a night otherwise. Running every plan costs build minutes every night, paid for with the confidence that a release passes them all.
- A matrix of stacks needs runners that hold several stacks at once; the jobs are sized to fit the free runners, one stack each.
- Certification costs the owner time and, without the waiver, money: for a member US$700 for OpenID Connect and US$1,000 each for FAPI 1, FAPI 2 and FAPI-CIBA; for a non-member US$3,500 and US$5,000 each ([fees](https://openid.net/certification/fees/)).
- The published logs show how the deployment was configured. That is the point of them; nothing in them may still work when they are published.

## Alternatives considered

- **Every plan on every pull request.** Nothing slips through for a night. Set aside: hours per pull request would make every change wait, and most changes touch no plan.
- **Running the plans only before a release.** Cheapest. Set aside: a failure found then is weeks old and hard to place.
- **A permanent public certification deployment, running the hosted suite on a schedule.** Results always current. Set aside: it is a public system with credentials in published logs, to run and pay for between certifications; the local suite is the same code and runs in continuous integration.
- **Submitting each profile as it passes.** Earlier listings. Set aside: the waiver covers one batch per specification and year; each later request costs a fee.
