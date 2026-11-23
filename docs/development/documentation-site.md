# The documentation site

The pages of `docs/` are also published as a website, <https://ortisun.github.io/hodor/>, with navigation, search, light and dark modes, and diagrams drawn. This page says how the site is made from `docs/`, how to see it on your machine, and how it is published. Why it is made this way is [Decision 0021](../decisions/0021-documentation-site.md).

`docs/` stays the source of truth, read by people on GitHub as before. The site adds nothing that a page needs: it is another way to read the same files.

## How it is made

The site is built by [MkDocs](https://www.mkdocs.org/) with the [Material](https://squidfunk.github.io/mkdocs-material/) theme, from the pages in `docs/` where they are. Nothing is copied into another folder and no page is changed by the build.

| What | Where | What it is |
|---|---|---|
| The pages | `docs/` | Every page of the site, except the two below |
| The configuration | `site/mkdocs.yml` | The site's name and address, the theme, the Markdown extensions, the version of Mermaid that draws the diagrams, and the navigation: which page goes in which tab and in what order |
| Pages of the site alone | `site/pages/` | The home page, and the page that shows the OpenAPI document. They hold no fact of their own: they point at the pages of `docs/` |
| The build hooks | `site/hooks.py` | Adds the pages of `site/pages/`, publishes the OpenAPI documents of the administration interface and of the Authorization API from `crates/protocol-http/openapi/`, and moves `docs/README.md`, the documentation map, from the root of the site to `/map/`, since the home page takes the root |
| Colors | `site/overrides/` | The Hodor colors over the theme, and the layout of the home page |
| The logo | `docs/images/logo/` | `hodor.png`, someone holding a heavy door shut against what pushes from outside, which is what the name means; it opens the readme and the home page. `hodor-icon.png` is the same picture on a square, 128 pixels wide, for the header of the site and the icon of the browser tab |
| The tools, at exact versions | `site/requirements.txt` | Every Python package of the build, at one version, with the hashes of its files. `site/requirements.in` names the packages asked for directly |
| The workflow | `.github/workflows/documentation-site.yml` | Builds the site on every pull request and publishes it from `develop` |

### What a page may use

A page is written for GitHub first and must read well there. These work in both places, and are what the pages use today:

- Tables, fenced code with a language, footnotes and links between pages by relative path, such as `[the tenant context](../architecture/contexts/tenant.md#command-line-tool)`.
- Mermaid diagrams in a fence marked `mermaid`.
- Links to anchors as GitHub makes them: the heading in lower case, with spaces turned into hyphens. The site makes its anchors the same way.

The theme also offers admonitions, tabs and grids. GitHub shows them as plain text, so the pages of `docs/` do not use them; the home page in `site/pages/` does.

### Adding a page

A new page in `docs/` is added in the same change to [the documentation map](../README.md), as the [conventions](conventions.md#4-how-the-documentation-is-organized) say, and to the `nav` of `site/mkdocs.yml`, in the tab where a reader would look for it. The build fails on a page that is missing from the navigation, and on a link or an anchor that leads nowhere.

## Seeing the site on your machine

You need Python 3.13 or newer; continuous integration uses 3.13. From the root of the repository, make an environment for the site and install the tools at their pinned versions:

```bash
python3 -m venv site/.venv
```

```bash
site/.venv/bin/pip install --require-hashes -r site/requirements.txt
```

Serve the site at <http://127.0.0.1:8000/hodor/>. It is rebuilt when a page changes:

```bash
site/.venv/bin/mkdocs serve -f site/mkdocs.yml
```

Build it as continuous integration does, failing on any warning:

```bash
site/.venv/bin/mkdocs build -f site/mkdocs.yml --strict
```

The site is written to `site/build/`. `site/.venv` and `site/build` are ignored by git.

The theme prints a notice that it reaches its end of life in May 2027. [Decision 0021](../decisions/0021-documentation-site.md#consequences) says what is done about it. Setting `NO_MKDOCS_2_WARNING=1` hides the notice.

## Changing a tool's version

The versions are chosen by resolving `site/requirements.in` as the package index stood on a given date, so that the same command gives the same answer later. With [uv](https://docs.astral.sh/uv/):

```bash
uv pip compile site/requirements.in --universal --python-version 3.13 --exclude-newer 2026-11-07 --generate-hashes --no-header -o site/requirements.txt
```

Move the date forward to take newer versions, and keep it at least two weeks behind the day of the change, so that a release that is withdrawn soon after it appears is not taken. Build the site with `--strict` before committing.

## How it is published

The workflow `.github/workflows/documentation-site.yml` runs on every pull request that changes `docs/`, `site/`, the OpenAPI document or the workflow itself, and on every push to `develop`.

| When | What it does |
|---|---|
| A pull request | Builds the site with `--strict` and keeps it as an artifact of the run, `documentation-site`, for seven days. Download it to look at the site a change produces |
| A push to `develop` | Builds the site the same way and publishes it on GitHub Pages |
| By hand, from the Actions tab | The same as a push, for the branch it is run on, when that branch may publish |

The site is published from `develop`, not `main`, because the documentation is written before the code and `develop` is where the two meet; `main` receives releases. The address is <https://ortisun.github.io/hodor/>.

Publishing needs two settings of the repository, made once by its owner:

1. **Settings → Pages → Build and deployment → Source: GitHub Actions.** Until this is set, the publishing job fails and the build job still passes.
2. **Settings → Environments → `github-pages` → Deployment branches**: `develop` must be allowed. GitHub creates the environment when Pages is turned on, and may allow only the default branch, `main`, at first.
