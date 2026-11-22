# showcase

## Overview

The design system showcase (package description: a control plane screen plus a
gallery, built on Astryx with the Hodor theme, never shipped). It is a React
and Vite application with only static sample data, used to see the Hodor theme
from `frontend/auth-ui/src/themes/hodor` applied to Astryx components. The
application is in [src](./src/EGM.md).

## Interface

- `package.json:scripts` - `dev` (`vite`), `build` (`tsc --noEmit && vite
  build`), `typecheck` (`tsc --noEmit`). There is no `test` or `lint` script.
- `package.json:dependencies` - `@astryxdesign/core`,
  `@astryxdesign/theme-neutral`, `@fontsource/ibm-plex-mono`,
  `@fontsource/ibm-plex-sans`, `@stylexjs/stylex`, `lucide-react`, `react`,
  `react-dom`.
- `vite.config.ts` - `const theme = fileURLToPath(new
  URL("../../auth-ui/src/themes/hodor", import.meta.url))` and
  `resolve.alias: { "@hodor-theme": theme }`, so `src/App.tsx` imports
  `hodorTheme` from `@hodor-theme/hodor.js` and `src/main.tsx` imports
  `@hodor-theme/hodor.css` from `frontend/auth-ui/src/themes/hodor`.
  The comment above `theme` says the theme lives with the hosted pages until
  a second frontend is started (`docs/design/design-system.md`, section 10).
  `resolve.dedupe` keeps one copy of `react`, `react-dom`,
  `@astryxdesign/core`, `@astryxdesign/theme-neutral` and `@stylexjs/stylex`.
  The development server uses port 4174 with `fs.allow` set to this directory
  and the theme directory; the build writes `dist` without source maps.
- `index.html` - the `#root` mount, `/src/main.tsx`, `robots: noindex`.
- Subdirectory: [src](./src/EGM.md) - the shell, the security posture screen,
  the gallery, the confirmation dialogs and the shared pieces.

## Invariants

- The theme is not a package dependency: it is reached only through the
  `@hodor-theme` alias, so `frontend/auth-ui/src/themes/hodor` must exist two
  levels up from this package.
- Nothing here talks to a server; the showcase is a sketch, not part of the
  product.

## Side Effects

- `npm run build` empties and writes `dist`.
- `npm run dev` listens on port 4174.

## Verification

- Run from `frontend/design-system/showcase`: `npm run typecheck` and
  `npm run build`. There is no test script.
