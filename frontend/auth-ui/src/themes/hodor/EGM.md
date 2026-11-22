# hodor (theme)

## Overview

The Hodor theme for the Astryx design system: Astryx's neutral theme with
Hodor's own palette, type and corner radii. `hodorTheme.ts` is the only
hand-written source here; `npm run theme` (`astryx theme build
src/themes/hodor/hodorTheme.ts`, from `frontend/auth-ui/package.json`)
compiles it into the static stylesheet and module beside it, which are what
the pages load. The `hodorTheme.ts` header gives the reason: the Content
Security Policy allows no style to be made in the browser. The specification
is `docs/design/design-system.md`, section 3 (cited in `hodorTheme.ts`).

Three frontends use these files. The hosted pages load them through the
generated `../../astryx-themes.ts`; `frontend/admin-console` and
`frontend/design-system/showcase` reach this directory through an
`@hodor-theme` alias in their `vite.config.ts` and import
`@hodor-theme/hodor.js` and `@hodor-theme/hodor.css` (see
`frontend/admin-console/EGM.md` and `frontend/design-system/showcase/EGM.md`).

## Interface

- `hodorTheme.ts:hodorTheme` (source) - `defineTheme({ name: "hodor",
  extends: neutralTheme, ... })` from `@astryxdesign/core/theme` and
  `@astryxdesign/theme-neutral`:
  - `palette: themePalette({...})` - accent `#007b92` ("Signal"), neutral
    `#737b84` ("Ink"), success `#137d41`, warning `#a06604`, danger
    `#c22826`, info `#3a65b8`, and `recipe: "astryx-oklch-v2"`.
  - `typography` - `scale: { base: 14, ratio: 1.2 }`; body and heading family
    `IBM Plex Sans` with the fallbacks `system-ui, -apple-system, 'Segoe UI',
    sans-serif`.
  - `tokens` - `--radius-inner: 4px`, `--radius-element: 6px`,
    `--radius-container: 10px`.
- `hodorTheme.doc.mjs` (source) - default export of an Astryx `ThemeDoc`:
  `type: 'theme'`, `name: 'hodor'`, `displayName: 'Hodor'`, a description,
  `maintained: true`.
- `hodor.js` (generated) - `export const hodorTheme` (`name: 'hodor'`,
  `__built: true`, the compiled `tokens` such as `--font-size-*`) and
  `export { themeIcons }`, taken from `neutralTheme["icons"]`. Its header
  says to import `./hodor.css` alongside it.
- `hodor.css` (generated) - declares `@layer reset, astryx-base,
  astryx-theme;` and scopes its rules with `@scope
  ([data-astryx-theme="hodor"]) to ([data-astryx-theme])`.
- `hodor.d.ts` (generated) - `export declare const hodorTheme: DefinedTheme`
  and `export declare const themeIcons: IconRegistry`; references
  `hodor.variants.d.ts`.
- `hodor.variants.d.ts` (generated) - augments `@astryxdesign/core/Badge`
  `BadgeVariantMap` with `'gray'` and `@astryxdesign/core/ProgressBar`
  `ProgressBarVariantMap` with `'disabled'`.
- `hodor.css.d.ts` (generated) - `export {};`, so the stylesheet can be
  imported from TypeScript.

## Invariants

- `hodor.css`, `hodor.js`, `hodor.d.ts`, `hodor.variants.d.ts` and
  `hodor.css.d.ts` each start with an `@generated` header ("by `astryx theme
  build` ... do not edit manually") naming `Source: src/themes/hodor/hodorTheme.ts`,
  `@astryxdesign/cli@0.7.17` and `@astryxdesign/core@0.7.17`. Change
  `hodorTheme.ts` and rebuild; never edit the outputs.
- `npm run theme-check` (`astryx theme build ... --check`) checks the
  committed outputs against the source; `frontend/auth-ui/eslint.config.js`
  excludes `src/themes/hodor/hodor.*` from linting because they are written by
  `npm run theme`.
- The palette `recipe` is pinned to `astryx-oklch-v2` so that an upgrade of
  Astryx does not move the shades (comment in `hodorTheme.ts`).
- Other frontends depend on the paths `hodor.js` and `hodor.css` in this
  directory through their `@hodor-theme` alias; moving or renaming them
  breaks `frontend/admin-console` and `frontend/design-system/showcase`.

## Side Effects

- None at run time beyond the styles `hodor.css` adds wherever it is
  imported. `npm run theme` rewrites the generated files here and
  `src/astryx-themes.ts`.

## Verification

- Run from `frontend/auth-ui`: `npm run theme-check`, then `npm run
  typecheck`.
