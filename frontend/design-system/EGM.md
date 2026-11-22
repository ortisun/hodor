# design-system

## Overview

This directory holds no source of its own. Its one package is the showcase, a
static application that renders Astryx components and Hodor-specific pieces
under the Hodor theme, which lives in `frontend/auth-ui/src/themes/hodor`.

## Subdirectories & Boundaries

- showcase: [./showcase/EGM.md](./showcase/EGM.md) - a never-shipped React and
  Vite application (security posture screen and component gallery) that
  imports the Hodor theme through the `@hodor-theme` alias, uses only static
  sample data, and is verified with `npm run typecheck` and `npm run build`
  (no test script).
