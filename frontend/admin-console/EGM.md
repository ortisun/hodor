# admin-console

## Overview

The administration console of Hodor (package `hodor-admin-console`): a React
and Vite single-page application, built on Astryx with the Hodor theme from
`frontend/auth-ui/src/themes/hodor`, that a tenant's administrators use to
manage users, sessions and identity providers and to read the audit log. It is
served under `/t/{tenant}/console` and talks only to the console interface
under `/t/{tenant}/console/api` (and to `/t/{tenant}/interaction/session` to
sign out). This directory holds its build, lint and type configuration; the
application is in [src](./src/EGM.md).

## Interface

- `package.json:scripts` - `dev` (`vite`), `build` (`tsc --noEmit && vite
  build`), `typecheck` (`tsc --noEmit`), `lint` (`eslint .`), `test`
  (`vitest run`).
- `vite.config.ts` - `base` is `/admin-console/`; builds to `dist` with no
  inlined assets, no module-preload polyfill and no source maps. The alias
  `@hodor-theme` points to `../auth-ui/src/themes/hodor`, and `resolve.dedupe`
  keeps one copy of `react`, `react-dom`, `@astryxdesign/core`,
  `@astryxdesign/theme-neutral` and `@stylexjs/stylex`.
- `vite.config.ts` development server - port 4175; proxies
  `^/t/[^/]+/(console/api|interaction|account)` and `^/auth-ui/` to
  `HODOR_URL` (default `http://localhost:8080`); the `hodor-console-addresses`
  middleware serves `/admin-console/index.html` for any `/t/{tenant}/console`
  address outside `/console/api`.
- `vite.config.ts` plugin `hodor-layer-rules` - appends Astryx's
  `slideRulesCss()` to `src/layer-rules.css` whenever Vite transforms that
  file, in development and in the build.
- `vite.config.ts:test` - Vitest with jsdom, `src/**/*.test.{ts,tsx}`, setup
  file `src/setup.ts`.
- `index.html` - the `#root` mount, `/src/main.tsx`, `robots: noindex`, and the
  meta `astryx-layer-slide-rules` (`static`) that tells Astryx its layer rules
  are already in the style sheets.
- Subdirectory: [src](./src/EGM.md) - the application, its client of the
  console interface, addresses, action catalog, copy, parts and screens.

## Invariants

- Content Security Policy: `eslint.config.js` makes the JSX attributes
  `dangerouslySetInnerHTML` and `style` lint errors, and `vite.config.ts` sets
  `assetsInlineLimit: 0` and moves Astryx's layer rules into a style sheet, so
  the built console needs no inline style or script.
- The theme is not a package dependency: it is reached only through the
  `@hodor-theme` alias in `vite.config.ts` (declared for TypeScript in
  `src/hodor-theme.d.ts`), so `frontend/auth-ui/src/themes/hodor` must exist
  beside this package.

## Side Effects

- `npm run build` empties and writes `dist`.
- `npm run dev` listens on port 4175 and forwards console interface,
  interaction, account and `/auth-ui/` requests to `HODOR_URL`.

## Verification

- Run from `frontend/admin-console`: `npm test`, `npm run typecheck`,
  `npm run lint`.
