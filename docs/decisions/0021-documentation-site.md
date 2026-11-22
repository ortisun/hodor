# Decision 0021: The documentation site is built from `docs/` with MkDocs and Material, and published on GitHub Pages from `develop`

Status: Proposed (the site was requested by the project owner; the choices here wait for their review)

## Context

Everything known about Hodor is in `docs/`: more than sixty pages, with Mermaid diagrams, written before the code and read on GitHub. A newcomer reading them on GitHub has no search, no navigation between sections and no single place to start. The owner asked for a documentation site, published on GitHub Pages, with a home page, a quick-start, worked examples and the reference sections that `docs/` already has.

What the site must respect:

- **`docs/` stays the source of truth** ([conventions](../development/conventions.md#1-documentation-comes-first)). The site reads the pages where they are; it must not need a copy, a second version or a change to how they are written. A page must still read well on GitHub.
- **Relative links between pages and links to anchors work in both places.** The pages hold hundreds of them, written for GitHub.
- **Mermaid diagrams are drawn.**
- **The build is reproducible**, as the rest of the repository is: tools at exact versions, actions pinned to a commit.
- **A broken link fails the build**, so the site cannot rot quietly.

## Decision

- **The site is built by MkDocs 1.6 with the Material theme**, configured in `site/mkdocs.yml` with `docs_dir: ../docs`. MkDocs reads Markdown files as GitHub does, resolves relative links between them, and checks every link and anchor; `--strict` turns what it finds into a failure. Material gives navigation in tabs, search, light and dark modes, Mermaid, and a copy button on code.
- **Anchors are made as GitHub makes them** (`pymdownx.slugs.slugify` in lower case), so that a link written for GitHub reaches the same heading on the site.
- **Only two pages exist for the site alone**, in `site/pages/`: the home page, which points at the pages of `docs/`, and the page that shows the OpenAPI document of the administration interface with Swagger UI, which sends no requests. A build hook adds them, publishes the OpenAPI document from where the code keeps it, and moves the documentation map, `docs/README.md`, from the root of the site to `/map/`.
- **The Python packages are pinned with their hashes** in `site/requirements.txt`, resolved as the package index stood on a stated date, and installed with `--require-hashes`.
- **The workflow builds the site on every pull request that touches it, and publishes it from `develop`** with the official Pages actions, pinned to commits. `develop` is where the documentation and the code meet; `main` receives releases and has had none yet.

How the site is built and published is in [the documentation site](../development/documentation-site.md).

## Consequences

- A reader gets search, navigation and drawn diagrams; a writer keeps writing Markdown for GitHub, and adds each new page to the navigation of `site/mkdocs.yml`.
- A link or an anchor that leads nowhere, anywhere in `docs/`, fails the pull request that introduces it.
- **Material for MkDocs reaches its end of life on May 5, 2027**; until then it receives critical fixes and security updates. Its successor, [Zensical](https://zensical.org/), is built by the same team and reads the same `mkdocs.yml`. Zensical 0.1.3, tried on this site in November 2026, built the pages but ran neither the build hook nor the Swagger UI plugin, and did not report a missing page. The site moves to Zensical when it does those three things, and before May 2027 in any case. Until then the build prints a notice about it, which `NO_MKDOCS_2_WARNING=1` hides.
- The site's search and pages are static files: no server, no account and no cookie, and no font service: the theme uses the reader's system fonts. The one thing fetched from elsewhere is Mermaid, at one exact version, from the public content delivery network `unpkg.com`; without it the pages read the same and the diagrams show as their source.
- The OpenAPI page shows the document as the code has it on `develop`, which the server's test keeps equal to the routes.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Zensical now | Version 0.1.3 runs no hooks and no plugins and lets a missing page pass. The site would lose the OpenAPI page, the home page at the root and the check of the navigation |
| Astro with Starlight | Maintained and fast, and the repository already uses Node.js. But every page would need front matter with its title, and links ending in `.md` would need a plugin to be rewritten; the pages would change for the site's sake |
| Docusaurus | The same objections as Starlight, and a React application to maintain for static text |
| GitHub's own rendering, with no site | No search, no navigation between sections, and no home page for a newcomer |
| A copy of `docs/` made for the site | Two versions of every fact, which the conventions forbid |
