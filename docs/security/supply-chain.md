# Supply chain: what Hodor is built from, and how it is checked

Hodor is built from code that other people wrote: Rust crates, the npm packages of the pages and consoles, and the GitHub Actions that build and test it. Any of them could be changed by someone who should not change it, or carry a license Hodor cannot ship. This page says what is checked, by what, and when. It answers Threat-General-15 of [the threat model](threat-model.md).

Every check below runs in continuous integration on every pull request. A pull request is merged only when they pass.

## Rust crates

| Check | Tool | Fails when |
|---|---|---|
| Known vulnerabilities | `cargo deny check` | A crate in `Cargo.lock` has an advisory of the RustSec database that is not answered in `deny.toml` |
| Licenses | `cargo deny check` | A crate's license is not in the allowed list of `deny.toml` |
| Where crates come from | `cargo deny check` | A crate comes from anywhere but crates.io |
| Unused crates | `cargo machete` | A crate is named in a `Cargo.toml` and never used |
| The exact versions | `--locked` on every build | `Cargo.lock` does not match the manifests |

## npm packages

Three applications are built with npm: the hosted pages (`frontend/auth-ui`), the admin console (`frontend/admin-console`) and the design system showcase (`frontend/design-system/showcase`). The OpenID conformance runner in `deploy/conformance` also uses npm, but only in continuous integration, and it never ships.

| Check | Tool | Fails when |
|---|---|---|
| Known vulnerabilities | `npm audit --audit-level=high` | A package has an advisory of high or critical severity |
| Licenses | `.github/scripts/supply_chain.py licenses` | A package's license is not allowed, as the next section says |
| The exact versions | `npm ci` | `package-lock.json` does not match `package.json` |

### Which licenses are allowed

A package is either **shipped** or a **tool**. Shipped packages end up in what Hodor gives people: the code of the pages and consoles, and the fonts they carry. Tools build, test and check that code, and never leave the machine they run on. `package-lock.json` marks tools as `dev`.

| Kind | Allowed licenses |
|---|---|
| Shipped | The licenses `deny.toml` allows for crates: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD, Zlib, Unicode-3.0. Also OFL-1.1, the license of the bundled fonts, which allows them to be shipped with software |
| Tool | Everything allowed for shipped packages, and also MPL-2.0, BlueOak-1.0.0, MIT-0, CC0-1.0 and CC-BY-4.0. These apply to files Hodor never ships, so their conditions on distribution never come into play |

A package without a license, or one whose license is an expression the script cannot read, fails the check. Adding a license to either list is a change to this page and to the script, in the same pull request.

## GitHub Actions

An action is code that runs in continuous integration with access to the repository. A tag such as `v4` can be moved by whoever controls the action's repository, and every run after that runs the new code.

- **Every action is named by the commit it runs**, such as `actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0`. The comment says which release that commit is. A commit cannot be moved.
- **`.github/scripts/supply_chain.py actions` fails** when a workflow names an action by anything but a full commit, a local action (`./…`) excepted.
- **Dependabot keeps them current.** Once a week it proposes a pull request that moves an action to the commit of its newest release, with the comment changed to match. Its pull requests go through the same checks as any other.

## What a release publishes

From 0.3.0, pushing the tag of a release, such as `v0.3.0`, runs the workflow `.github/workflows/release.yml`. It publishes these, all on the GitHub container registry, readable by anyone:

| What | Where |
|---|---|
| The image, for `linux/amd64` and `linux/arm64` | `ghcr.io/ortisun/hodor:<version>`, such as `ghcr.io/ortisun/hodor:0.3.0` |
| From 0.4.0, the image of [`hodor-ext-authz`](../operations/hodor-ext-authz.md), for the same architectures | `ghcr.io/ortisun/hodor-ext-authz:<version>` |
| The Helm chart, as an OCI artifact | `oci://ghcr.io/ortisun/charts/hodor`, version `<version>` |

How the image is made and published:

- **Each architecture is built on a machine of its own architecture.** The two builds are then joined under one tag, so `docker pull` takes the right one.
- **The image carries its software bill of materials and its provenance**, as attestations next to it in the registry. The bill of materials lists every package in the image. The provenance says which workflow built it, from which commit.
- **The image and the chart are signed by the workflow, with no key kept anywhere.** [Sigstore](https://www.sigstore.dev/)'s `cosign` signs with a certificate made for this one run, which names the workflow and the tag. The signature is recorded in Sigstore's public transparency log, so a signature made in secret cannot pass.
- **The workflow refuses to publish a tag that differs from the version of the chart and of the binaries**, as continuous integration already refuses a chart whose version differs from the binaries'.

To check what you pulled before you run it:

```bash
cosign verify ghcr.io/ortisun/hodor:0.3.0 \
  --certificate-identity-regexp '^https://github[.]com/ortisun/hodor/[.]github/workflows/release[.]yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The chart is checked the same way, at `ghcr.io/ortisun/charts/hodor:0.3.0`, and from 0.4.0 the image of `hodor-ext-authz`, at `ghcr.io/ortisun/hodor-ext-authz:<version>`. Both images are built, joined and signed by the same jobs, each from its own Dockerfile.

A pull request that changes the workflow or the Dockerfile runs the same builds for both architectures, and publishes and signs nothing. A broken release is then found before the tag, not after.

## Not checked yet

| What | When |
|---|---|
| The base images of the Dockerfile, named by tag rather than by digest. Dependabot does not update them | When a base image changes under a tag and breaks a build, or before 1.0.0 |
| Versions before 0.3.0 | They were never published. Build them from their tag |
