# Working conventions

These are the rules everyone working on Hodor follows, people and coding agents alike. When a new rule is agreed, it is written here first.

## 1. Documentation comes first

`docs/` is the source of truth for Hodor. The code follows the documentation, never the other way round.

- **Before changing code, change the document.** A new feature, a changed behavior, a new rule or a reversed decision starts as an edit to the page that specifies it. The implementation is then written to match.
- **If the code and the document disagree, one of them is a bug.** Decide which, fix the document first if it is the one that is wrong, then fix the code.
- **A decision that constrains the design gets an ADR** in [`docs/adr/`](../adr/README.md). Changing your mind means a new ADR that supersedes the old one.
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

## 3. How the documentation is organized

| Folder | What belongs there |
|---|---|
| [`product/`](../product/prd.md) | Why Hodor exists and what it must do: PRD, requirements, roadmap, epics, progress |
| [`architecture/`](../architecture/overview.md) | How it is built: structure, domain model, crates, data, tenancy, authorization, plugins, testing, and the critical review |
| [`protocols/`](../protocols/sequences.md) | How it behaves on the wire: sequences and lifecycles |
| [`api/`](../api/api-spec.md) | The HTTP surfaces and their conventions |
| [`security/`](../security/threat-model.md) | Threat models and security analysis |
| [`operations/`](../operations/deployment.md) | Running it: deployment, configuration, observability, backup |
| [`development/`](local-setup.md) | Working on it: these conventions and the local setup |
| [`adr/`](../adr/README.md) | Decisions and their reasons |

[`docs/README.md`](../README.md) is the index. A page that is not linked from it does not exist as far as a reader is concerned, so a new page is added to the index in the same change.

## 4. Git

### Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<optional scope>): <subject in the imperative, lower case, no period>

<body: what changed and why, wrapped at 72 columns>

Refs: <issue id>
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
- A pull request is merged only when CI is green.

## 5. Definition of done

A change is done when:

1. The documentation describes it, and was updated before the code.
2. The business rules have tests, and the tests pass.
3. `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo deny check` and `cargo machete` pass.
4. The dependency rules in [crates.md](../architecture/crates.md) hold (checked by the architecture test).
5. Tenant isolation holds for any new table or port (checked by the schema rules and the contract tests).
6. Nothing sensitive can reach a log, a trace or an error message.
7. [Progress](../product/progress.md) is updated.

The full list for features is in section 27 of the specification and is reflected in the [testing strategy](../architecture/testing.md).
