"""Build hooks of the documentation site.

The site is built from `docs/` as people write it, without copying or changing a page. Three things are added
or moved at build time, and only here:

* The pages that exist for the site alone, in `site/pages/`: the home page and the pages that show the
  OpenAPI documents. They are added as if they were in `docs/`.
* The OpenAPI documents of the administration interface and of the Authorization API,
  `crates/protocol-http/openapi/admin-v1.json` and `authorization-v1.json`, which the code keeps next to the routes
  they describe. They are published at `api/admin-v1.json` and `api/authorization-v1.json`.
* `docs/README.md`, the documentation map. GitHub shows it as the front page of the folder; on the site the
  home page takes the root, so the map moves to `map/`. Links to it keep working, because MkDocs resolves
  links by the source file.

See docs/development/documentation-site.md.
"""

from __future__ import annotations

import os
from pathlib import Path

from mkdocs.config.defaults import MkDocsConfig
from mkdocs.structure.files import File, Files

SITE = Path(__file__).resolve().parent
REPOSITORY = SITE.parent
SITE_PAGES = SITE / "pages"
OPENAPI_DIRECTORY = REPOSITORY / "crates" / "protocol-http" / "openapi"
OPENAPI_DOCUMENTS = ("admin-v1.json", "authorization-v1.json")


def on_files(files: Files, config: MkDocsConfig) -> Files:
    documentation_map = files.get_file_from_path("README.md")
    if documentation_map is None:
        raise RuntimeError("docs/README.md, the documentation map, is missing")
    documentation_map.dest_uri = "map/index.html"
    documentation_map.url = "map/"
    documentation_map.abs_dest_path = os.path.join(config.site_dir, "map", "index.html")

    for path in sorted(SITE_PAGES.rglob("*")):
        if path.is_file():
            source = path.relative_to(SITE_PAGES).as_posix()
            files.append(File.generated(config, source, abs_src_path=str(path)))

    for document in OPENAPI_DOCUMENTS:
        files.append(File.generated(config, f"api/{document}", abs_src_path=str(OPENAPI_DIRECTORY / document)))
    return files
