# showcase/src

## Overview

The source of the design system showcase: a security posture screen sketched as
a control plane, and a gallery of the Astryx components and Hodor-specific
pieces under the Hodor theme. Everything shown is static sample data; nothing
is fetched.

## Interface

- `main.tsx` - imports the IBM Plex fonts, Astryx `reset.css` and `astryx.css`,
  `@hodor-theme/hodor.css` and `showcase.css`, and renders `App` on `#root`.
- `App.tsx:App` - holds the mode (starts `dark`) and renders
  `<Theme theme={hodorTheme} mode={mode}>` (with `hodorTheme` imported from
  `@hodor-theme/hodor.js`), `LayerProvider` and `Shell`.
- `App.tsx:Shell` - an app shell with top bar (tenant, session clock,
  `ModeToggle`), a side navigation from `navigation`, a command palette from
  `commands` (mod+k), and `ControlPlane` or `Gallery` for the `Screen`
  `posture` or `gallery`; only those two navigation entries change the screen.
- `App.tsx:useSessionClock`, `IDLE_SECONDS` (900) - a remaining-session clock
  as `m:ss`; `ModeContext`, `ModeToggle` switch dark and light.
- `ControlPlane.tsx:ControlPlane({ open })` - the security posture screen:
  score, metrics, filterable findings, live activity, break-glass accounts and
  a pending policy change with a diff; `open(name)` opens a dialog.
- `Gallery.tsx:Gallery` - sections for color tokens, status and severity,
  typography, actions, inputs, feedback, data tables, the dangerous action
  ladder (levels 0 to 4), and secrets and identifiers.
- `dialogs.tsx:Confirmation({ name, onDone })` with `DialogName`
  (`rotate`, `revoke`, `secret`, `publish`) - picks `RotateKey`,
  `RevokeSessions`, `NewSecret` or `PublishPolicy`.
- `parts.tsx` - `Overline`, `Code`, `Severity` with `SeverityLevel`, `Ladder`,
  `Score`, `Spark`, `Fact`, `Facts`, `Diff` with `DiffLine`, `Decision`,
  `Identifier`, `HoldButton`.
- `hodor-theme.d.ts` - declares `@hodor-theme/hodor.js` (`hodorTheme:
  DefinedTheme`) and `@hodor-theme/hodor.css`; the alias is resolved by
  `../vite.config.ts`.
- `showcase.css` styles the Hodor-specific `hodor-*` classes using theme tokens
  only.

## Invariants

- No `fetch` or other network or storage call exists in this directory; all
  data is module-level constants (for example `ControlPlane.tsx:findings`,
  `Gallery.tsx:records`, `dialogs.tsx:SECRET`).
- `parts.tsx:HoldButton` confirms only after a continuous hold of
  `HOLD_MILLISECONDS` (1500) started by pointer down or a non-repeated Space or
  Enter; releasing, leaving or losing focus cancels it; when disabled it only
  sets `aria-disabled`.
- `dialogs.tsx:RotateKey` needs `tenant-signing` typed and then a simulated
  passkey step; `RevokeSessions` needs `ana.mendes` typed and then the hold;
  `NewSecret` is a required dialog whose Close stays disabled until the
  "stored" checkbox is ticked; `PublishPolicy` finishes at once.
- `dialogs.tsx` dismissal and Cancel call `onDone()` with no message, and
  `App.tsx:Shell` shows a toast only when a message is given.
- `ControlPlane.tsx:ControlPlane` adds no simulated activity when
  `(prefers-reduced-motion: reduce)` matches, and keeps at most 5 events.

## Side Effects

- Timers: `App.tsx:useSessionClock` ticks every second and resets on window
  `pointerdown` and `keydown`; `ControlPlane.tsx:ControlPlane` adds an event
  every 9 seconds until its samples run out; `parts.tsx:HoldButton` sets a
  timeout while held. All are cleared on unmount.
- Clipboard: `parts.tsx:Identifier` and `dialogs.tsx:NewSecret` copy through
  `useClipboard` from `@astryxdesign/core/hooks`.
- Toasts through `useToast` in `App.tsx:Shell` and `Gallery.tsx:Gallery`.
- `App.tsx:Shell` registers the mod+k hotkey.

## Verification

- Run from `frontend/design-system/showcase`: `npm run typecheck` and
  `npm run build`. The package has no test script.
