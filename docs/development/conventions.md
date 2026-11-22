# Working conventions

These are the rules everyone working on Hodor follows, people and coding agents alike. When a new rule is agreed, it is written here first.

## 1. Documentation comes first

`docs/` is the source of truth for Hodor. The code follows the documentation, never the other way round.

- **Before changing code, change the document.** A new feature, a changed behavior, a new rule or a reversed decision starts as an edit to the page that specifies it. The implementation is then written to match.
- **If the code and the document disagree, one of them is a bug.** Decide which, fix the document first if it is the one that is wrong, then fix the code.
- **A decision that constrains the design gets a decision record** in [`docs/decisions/`](../decisions/README.md). Changing your mind means a new decision record that supersedes the old one.
- **Everything lives in `docs/`**: specifications, architecture, diagrams, protocols, operations, conventions and progress. Pull request descriptions and commit messages explain a change; they are not where knowledge is kept.

In practice a piece of work is two steps, in this order:

1. A documentation change that describes what will be built, reviewed and merged on its own or as the first commit of the pull request.
2. The code that implements it.

## 2. How the documentation is written

The documentation is written for a person who is new to the project and has no one to ask.

- Plain, direct prose. Say what the thing is before explaining how it works.
- One topic per page, and one place for each fact. Link instead of repeating.
- Tables for things that are compared or enumerated; prose for reasoning.
- Diagrams are Mermaid, kept in the page next to the text they illustrate.
- Define a term where it first appears. The shared vocabulary is in the [domain model](../architecture/domain-model.md#ubiquitous-language).
- English throughout.
- No status that goes stale silently: progress is recorded in [one place](../product/progress.md) and updated with every merge.

## 3. Words, not abbreviations

Documentation and code comments are written in whole words. A reader should never have to look up what a letter or a short code stands for.

- **No letter codes.** Write `Rule`, `Test`, `Requirement`, `Threat`, `Issue`, `Epic`, `Milestone`. Never `R`, `T`, or a prefix made of initials.
- **No abbreviations of ordinary terms.** Write "identity provider", "relying party", "row-level security", "multi-factor authentication", "single sign-on", "role-based access control", "policy decision point", "user interface", "identifier", "continuous integration". Write them every time, not only on first use.
- **Identifiers are made of words.** They read the same in a table, a commit message and a test name.

| Kind | Form | Example |
|---|---|---|
| Requirement | `Requirement-<Area>-<number>` | `Requirement-Tenancy-01`, `Requirement-Security-03` |
| Threat | `Threat-<Area>-<number>` | `Threat-OAuth-02`, `Threat-Tenancy-01` |
| Issue | `Issue-<number>` | `Issue-07` |
| Epic | `Epic <number>` | `Epic 9` |
| Decision record | `Decision <number>` | `Decision 0005` |
| Priority | A word | `Blocker`, `Expected`, `Optional` |

- **Diagrams follow the same rule.** Participants and nodes are named with words (`Browser`, `Authentication`, `PolicyAgent`), in what the reader sees and in the diagram source.
- **Comments in code follow the same rule.** The names of types, functions and variables follow normal Rust naming, which already prefers whole words.

### Names that stay as they are

Some names are the actual name of a standard, protocol, format or product. Nobody calls them by their expansion, and the expansion would hide what is meant. These are kept:

| Group | Names |
|---|---|
| Protocols and standards | OAuth, SAML, SCIM, LDAP, RADIUS, HTTP, HTTPS, TLS, DNS, SMTP, SMS, OTLP, PKCE, DPoP, TOTP, HOTP, WebAuthn, XACML, FAPI |
| Formats and data | JSON, NDJSON, XML, YAML, HTML, CSS, SVG, PNG, OKLCH, SQL, URL, URI, UUID, JWT, JWK, JWKS, JWS, JOSE, COSE, UTC, UTF-8 |
| Cryptography | RSA, SHA, HMAC, AES, GCM, ECDSA, EdDSA, PKCS, FIPS, and algorithm identifiers such as ES256 |
| Attack classes | CSRF, SSRF, XSS, XXE |
| Products, projects and organizations | PostgreSQL, Redis, OpenTelemetry, VictoriaMetrics, Kubernetes, Helm, OWASP, STRIDE, C4, RFC numbers, NIST, IBM, Entra ID |
| Everyday technical words | API, CPU, IP address, README |
| Published titles | The title of a specification is quoted as published, for example "OpenID Connect RP-Initiated Logout" |
| Language tags | `en`, `pt-BR` |

Anything outside this table is written out. When in doubt, write it out. If a new name deserves to be kept, add it to the table in the same change.

## 4. How the documentation is organized

| Folder | What belongs there |
|---|---|
| [`product/`](../product/product-requirements.md) | Why Hodor exists and what it must do: Product requirements, requirements, roadmap, epics, progress |
| [`architecture/`](../architecture/overview.md) | How it is built: structure, domain model, crates, data, tenancy, authorization, plugins, testing, and the critical review |
| [`architecture/contexts/`](../architecture/contexts/tenant.md) | One page per bounded context: its rules, data and operations, written before the context is built |
| [`design/`](../design/design-system.md) | How it looks and behaves for people: the design system and the consoles' structure |
| [`protocols/`](../protocols/sequences.md) | How it behaves on the wire: sequences and lifecycles |
| [`api/`](../api/api-spec.md) | The HTTP surfaces and their conventions |
| [`security/`](../security/threat-model.md) | Threat models and security analysis |
| [`operations/`](../operations/deployment.md) | Running it: deployment, configuration, observability, backup |
| [`development/`](local-setup.md) | Working on it: these conventions, the local setup and the documentation site |
| [`examples/`](../examples/README.md) | Worked examples on the development stack, each run as written against the code |
| [`decisions/`](../decisions/README.md) | Decisions and their reasons |
| `images/` | Screenshots and pictures that pages link to, taken from the development stack. A picture never replaces text: what it shows is also written out |

[`docs/README.md`](../README.md) is the index. A page that is not linked from it does not exist as far as a reader is concerned, so a new page is added to the index in the same change, and to the navigation of [the documentation site](documentation-site.md#adding-a-page).

## 5. Git

### Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<optional scope>): <subject in the imperative, lower case, no period>

<body: what changed and why, wrapped at 72 columns>

Refs: Issue-<number>
```

| Type | Use for |
|---|---|
| `feat` | New behavior |
| `fix` | A bug fix |
| `docs` | Documentation only |
| `test` | Tests only |
| `refactor` | Restructuring without behavior change |
| `perf` | A performance improvement |
| `ci` | Pipeline changes |
| `build` | Build system and dependencies |
| `chore` | Everything else that does not touch behavior |

Scopes are crate or area names: `kernel`, `postgres`, `http`, `outbox`, `oauth`.

**No co-author trailers.** Commits carry no `Co-Authored-By` line, and pull request descriptions carry no tool-attribution footer.

### Branches

Branching follows Gitflow.

| Branch | Purpose | Cut from | Merges into |
|---|---|---|---|
| `main` | Released versions | — | — |
| `develop` | Integration of finished work | `main` | `main` through a release branch |
| `feature/<name>` | One piece of work | `develop` | `develop` |
| `release/<version>` | Stabilizing a release | `develop` | `main` and `develop` |
| `hotfix/<name>` | An urgent fix to a release | `main` | `main` and `develop` |

### Pull requests

- One issue per pull request, small enough to review in one sitting.
- The title is the Conventional Commits subject, because pull requests are squash-merged and the title becomes the commit on `develop`.
- The description says what changed, what a reviewer should look at, and how it was verified. It states plainly anything that was not verified.
- A pull request is merged only when continuous integration is green.

### Releases

- **Versions follow Semantic Versioning.** Before 1.0.0, versions are `0.<minor>.<patch>`, and a minor version may break what came before; the changelog says what breaks. From 1.0.0 on, a change that breaks what came before raises the major version.
- **1.0.0 waits for three parts.** The owner chose to release 1.0.0 once the OAuth 2.x authorization server and OpenID Provider, multi-factor authentication with passkeys and step-up, and the authorization engine with Open Policy Agent are built. Until then every release is a 0.x version.
- **One version for everything that ships.** It is the `version` of the Cargo workspace, which every crate and application takes, the version of the container image, and the `version` and `appVersion` of the Helm chart; continuous integration fails when the chart and the workspace differ. The page applications are built into the image and carry no version of their own.
- **The changelog is `CHANGELOG.md`**, in the form of [Keep a Changelog](https://keepachangelog.com/): one section per version, newest first, with what was added, changed, fixed and removed, in words a person running Hodor understands. What is built and not yet released is under *Unreleased*, at the top; a pull request that changes what a person running Hodor sees adds its line there. Cutting a release turns *Unreleased* into the section of its version.
- **A release says what it is not ready for.** When it cannot hold real accounts, its section of the changelog and its notes say what stands in the way, from the [progress](../product/progress.md) page, and it is published as a pre-release.
- **A release is named by its tag alone**, `v<version>`, such as `v0.1.0`: the name of the published release and the message of the tag are the same, without the product's name.

A release is cut in these steps:

1. Turn *Unreleased* in `CHANGELOG.md` into the section of the version, with its date, and set the version, through a pull request into `develop`.
2. Cut `release/<version>` from `develop`. Only fixes go into it from then on.
3. Open a pull request from `release/<version>` into `main`. It is merged with a **merge commit**, not squashed, so that `main` and `develop` keep one history, and only when continuous integration is green on its head.
4. Tag the merge commit on `main` as `v<version>`, an annotated tag whose message is `v<version>`, and publish a release named `v<version>` from that tag, with its section of the changelog as notes.
5. Merge `release/<version>` back into `develop` with a pull request and a merge commit, if the release branch received any commit, as it does when the version is set on it.

## 6. Definition of done

A change is done when:

1. The documentation describes it, and was updated before the code.
2. The business rules have tests, and the tests pass.
3. `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo deny check` and `cargo machete` pass.
4. The dependency rules in [crates.md](../architecture/crates.md) hold (checked by the architecture test).
5. Tenant isolation holds for any new table or port (checked by the schema rules and the contract tests).
6. Nothing sensitive can reach a log, a trace or an error message.
7. [Progress](../product/progress.md) is updated.

The full list for features is in section 27 of the specification and is reflected in the [testing strategy](../architecture/testing.md).
