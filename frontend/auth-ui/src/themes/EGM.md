# themes

## Overview

The Astryx themes of the hosted pages. There is one, `hodor`, and no source
file directly in this directory. The generated `../astryx-themes.ts` records
it as `{"themes":{"hodor":"./src/themes"},"defaultThemeSlug":"hodor"}` and
imports its compiled module and stylesheet.

## Subdirectories & Boundaries

- hodor: [./hodor/EGM.md](./hodor/EGM.md) - the Hodor theme. `hodorTheme.ts`
  is the source; `npm run theme` compiles it into `hodor.css`, `hodor.js` and
  their `.d.ts` declarations. The hosted pages, `frontend/admin-console` and
  `frontend/design-system/showcase` (the last two through the `@hodor-theme`
  alias) all load the compiled files.
