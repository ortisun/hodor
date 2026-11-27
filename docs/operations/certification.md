# How certification is obtained

Passing the [OpenID conformance suite](conformance.md) in continuous integration is not a certification. A certification is a declaration, signed by a person who works for the implementer, that one deployment conforms to one or more profiles, with the logs of the hosted suite as evidence, listed by the OpenID Foundation once it accepts them. This page says how that is done for Hodor, what the project prepares, and what only the owner can do. [Decision 0051](../decisions/0051-conformance-runs-and-certification.md) says when.

Nothing on this page has been done yet. It was checked against the Foundation's pages in November 2026; read them again before relying on it, since the Foundation may change its fees and rules at any time.

## What the Foundation asks

- **Self-certification.** The Foundation's model is "a formal declaration by an entity that its identified deployment … conforms" to a profile, and "any online deployment of a product or service that implements a conformance profile" may be certified ([the frequently asked questions](https://openid.net/certification/what-is-self-certification-faq/)).
- **The hosted suite.** Results count only from the suite at `www.certification.openid.net`, whose version the declaration names ([submission rules](https://openid.net/certification/fapi_op_submission/)). The suite there must reach the deployment over the internet, with TLS. Its address for outbound calls is published on the Foundation's testing pages; a firewall in front of the deployment must let it in.
- **Every test finished, none failed.** "Certification of a profile requires that you have 'PASSED', 'REVIEW', 'WARNING' or 'SKIPPED' results for all tests in the profile. You cannot certify with any FAILED or INTERRUPTED results" ([OpenID Provider testing](https://openid.net/certification/connect_op_testing/)). A test that asks for review holds screenshots a person must look at before submitting.
- **Each flow, each response type.** Form Post must be run for each of Basic, Implicit and Hybrid the provider supports, and the logout profiles once for each response type it supports ([logout testing](https://openid.net/certification/connect_op_logout_testing/)). A logout submission holds RP-Initiated and at least one of Session, Front-Channel and Back-Channel.
- **The logs are published.** "The full supplied log files will be published as part of a successful certification and these may contain client credentials, private keys … it is strongly recommended to deactivate clients and revoke keys prior to submitting" ([submission rules](https://openid.net/certification/fapi_op_submission/)).
- **One package per profile.** The suite's "Publish for certification" button makes, for each plan, a zip with the logs; the Certification of Conformance ([the form](https://openid.net/wordpress-content/uploads/2021/07/OpenID-Certification-of-Conformance.pdf)) goes with it. A version string is always required, and the profile is named as the Foundation's tables name it, such as "Basic OP", not by the plan's name.
- **The declaration is signed by a person of the implementer.** It "can be signed by any authorized person who actually works for the implementer", by hand or electronically, "cannot be signed by third parties, e.g by an external consultant" ([submission rules](https://openid.net/certification/fapi_op_submission/)).
- **How it is sent** ([how to submit](https://openid.net/how-to-submit-your-certification-request/)):
  1. Pay, or ask for the fee waiver, at the Foundation's certification page, to get a payment code.
  2. Submit at `submissions.openid.net`, with the zips attached.
  3. The signer receives a DocuSign message, "Declaration of Conformance signing". The request "can not be processed until the document(s) have been signed".
  4. The Foundation lists the certification once it approves it.
- **A certification does not expire.** Its date is part of it ([the frequently asked questions](https://openid.net/certification/what-is-self-certification-faq/)). A different endpoint is a different deployment. If the deployment changes and no longer conforms, the implementer corrects it and updates the declaration, or revokes it ([the Certification of Conformance](https://openid.net/wordpress-content/uploads/2021/07/OpenID-Certification-of-Conformance.pdf), item 2). A new version of Hodor does not have to be certified again; certifying it is a choice.

## What it costs

From [the fees](https://openid.net/certification/fees/), in United States dollars:

| Programme | Member of the Foundation | Not a member | What one fee covers |
|---|---|---|---|
| OpenID Connect | 700 | 3,500 | One deployment, "to as many profiles as they choose within a calendar year"; an OpenID Provider and a relying party pay apart |
| FAPI 1 | 1,000 | 5,000 | Every FAPI 1 profile of one deployment |
| FAPI 2 | 1,000 | 5,000 | Every FAPI 2 profile of one deployment |
| FAPI-CIBA | 1,000 | 5,000 | Every combination of poll and ping with mutual TLS and `private_key_jwt` |

**The open-source fee waiver** ([the policy](https://openid.net/certification/open-source-project-certification-policy/), "updated by the OpenID Foundation Executive Committee on October 29, 2026"):

- the person or organization asking "must be an OpenID Foundation member in good standing";
- they "must assert that none of the primary maintainers of the open source project are being compensated for their work on the project". A maintainer employed elsewhere and working on the project as a volunteer still qualifies;
- they "must be affiliated with or responsible for the deployment being certified";
- there is "one waiver per project annually", for "self-certifying once for each specification you supported (OP & RP)", submitting "all relevant profiles of that specification at once"; "any subsequent requests for the project within 1 year requires payment of $100 open source fee";
- each request is judged case by case, "not all open source projects will qualify", and projects that can afford the fee are asked to pay it. Requests go to `certification@oidf.org`.

The Foundation's frequently asked questions still describe the waiver of June 2021 as giving certifications at no cost; the policy page is the current one.

## Who does what

| Step | The owner | The project |
|---|---|---|
| A host name and a public deployment with TLS, reachable by the hosted suite | Owns the name, pays for and runs the host | Keeps `deploy/certification/`: the stack, the web server's settings (TLS 1.2 and 1.3, the cipher suites FAPI asks for, client certificates requested and forwarded for the FAPI profiles) |
| The tenants and clients each plan needs | Runs the script | Keeps the script, which makes them through `hodor-cli` with throwaway credentials, and prints the configuration to paste into the hosted suite |
| An account on the hosted suite and the runs | Signs in with Google or GitLab, runs each plan, looks at every review screenshot | Keeps, for each plan, the variants to choose and the results expected, in [the target](conformance.md#the-target) and `deploy/conformance/expected.json` |
| Membership of the Foundation and the waiver, or the fee | Joins, asks for the waiver, or pays | — |
| The Certification of Conformance | Fills it in and signs it through DocuSign, as the person responsible | Drafts the fields: implementer, deployment, version, profiles, suite version |
| Before the logs are published | Disables the clients and revokes the keys used | The script does both, on request |
| Submitting | Submits at `submissions.openid.net` | — |
| Afterwards | Takes the deployment down or resets it | Links the listing from the [conformance page](conformance.md) and the changelog |

## When

[Decision 0051](../decisions/0051-conformance-runs-and-certification.md): one batch for every OpenID Connect and logout profile when 0.5.0 is released, and one for FAPI 1.0 Advanced, FAPI 2.0 and FAPI-CIBA when 0.6.0 is. Whether the second batch falls under the same yearly waiver is asked of the Foundation first.

## What could not be confirmed

- No page of the Foundation says in so many words that the deployment must be public; it follows from results counting only from the hosted suite.
- Whether the fee for OpenID Connect covers the logout profiles: they are profiles of OpenID Connect, and the fee covers "as many profiles as they choose", but the page does not name them.
- Whether one yearly waiver covers both OpenID Connect and the FAPI programmes, or each is a specification of its own.
