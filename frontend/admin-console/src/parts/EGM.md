# parts

## Overview

The pieces the screens of the administration console share: the confirmation
dialog that follows the dangerous action ladder, the display of a long
identifier, and the loading state of anything fetched from the console
interface. They are built on `@astryxdesign/core` components.

## Interface

- `Confirm.tsx:Confirm` - a form dialog (width 520) for an action of
  `../actions.ts:ACTIONS`. Props: `action`, `title`, `confirmLabel`, `typed`
  (optional text the person must type), `ready` (default `true`),
  `isDestructive` (default `true`, chooses the `destructive` or `primary`
  button), `onConfirm` (returns a promise), `onClose`, `text`, `children`. The
  header shows a `Ladder`; a failure shows as an error banner.
- `Confirm.tsx:Ladder` - four step marks filled up to the action's level, with
  `text.level(level)` and `text.levelFriction[level]`.
- `Confirm.tsx:Consequence` - one list item, `what` beside a strong `value`.
- `Identifier.tsx:shortened(value)` - values of 14 characters or fewer
  unchanged; longer ones as the first 8 characters, an ellipsis and the last 4.
- `Identifier.tsx:Identifier` - shows a value whole or shortened, with the full
  value as its title and a button that copies it.
- `ShownOnce.tsx:ShownOnce` - a form dialog (width 560) with a client's new
  secret, a warning that it is shown this once, a copy button and
  `text.secretKept`, which calls `onClose`. Props: `secret`, `onClose`, `text`.
  The secret is in an element with `data-testid="shown-once"`.
- `Loaded.tsx:Loading<T>` - `loading`, `failed` with a `Failure`, or `loaded`
  with a value.
- `Loaded.tsx:useLoaded(load)` - returns `[state, again, replace]`.
- `Loaded.tsx:asFailure(thrown)` - `thrown` if it is a `Failure`, otherwise
  `new Failure(null, 500)`.
- `Loaded.tsx:Waiting` - a spinner labelled `text.loading`.
- `Loaded.tsx:Failed` - an error banner titled `describe(failure, text)`, with
  a try-again button only when `again` is given.

## Invariants

- `Confirm.tsx:Confirm` asks for typing only when
  `ACTIONS[action].level >= 2` and `typed` is given; the action is allowed only
  when `ready` is true and, if typing is asked for, the trimmed input equals
  `typed` exactly.
- `Confirm.tsx:Confirm` cancels form submission, so Enter never confirms; only
  the button does, and it is disabled while busy or not allowed.
- `Confirm.tsx:Confirm` keeps the dialog open and shows the failure when
  `onConfirm` throws; when it succeeds the dialog does not close itself, the
  caller closes it.
- `Loaded.tsx:useLoaded` starts in `loading`, settles to `loaded` or `failed`
  (through `asFailure`), drops results from runs that are no longer current,
  and loads again when `load` changes or `again()` is called; `again()` goes
  back to `loading` first. `replace(value)` sets `loaded` without a request.

## Side Effects

- `Identifier.tsx:Identifier` writes the full value to the clipboard through
  `useClipboard` from `@astryxdesign/core/hooks`.
- `Loaded.tsx:useLoaded` calls the caller's `load()` on mount and on each
  reload; the request itself is whatever `load` does (a `Client` method from
  `../client.ts`).
- `Confirm.tsx:Confirm` calls `onConfirm()` on the allowed confirm button and
  `onClose()` on cancel or when the dialog closes.

## Verification

- Run from `frontend/admin-console`: `npm test` (Vitest; these parts are
  exercised through `App.test.tsx`).
