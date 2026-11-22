# parts

## Overview

The building blocks every hosted page is made of: the frame, form, fields,
buttons, notices and text. Each one wraps an Astryx component from
`@astryxdesign/core` with the choices the pages share (large sizes, full
width, accessible roles). None of them talk to the server.

## Interface

- `Frame.tsx:Frame({ tenant, title, text, children })` - a `main.auth-page`
  holding a `section.auth-card` labelled by its heading, an Astryx `Card` with
  the line `{text.organization}: {tenant}` and an `h1` (`Heading level={1}`,
  `tabIndex={-1}`, class `auth-title`).
- `Form.tsx:Form({ onSubmit, children })` - `<form method="post" noValidate>`
  with its children in a `VStack`.
- `Field.tsx:Field({ label, hint, error, name, type, autoComplete, autoFocus,
  verbatim, value, onChange })` - an Astryx `TextInput` (`size="lg"`,
  `width="100%"`); `hint` becomes its description and `error` its detached
  error status. `type` is `"text" | "email" | "password"`, default `"text"`.
- `Field.tsx:PasswordField({ text, ...field })` - a verbatim `Field` plus a
  `CheckboxInput` labelled `text.showPassword` that switches the field
  between `password` and `text`.
- `Submit.tsx:Submit({ label, busy, text })` - the primary submit `Button`;
  while `busy` its label is `text.working` and it shows loading.
- `Submit.tsx:Action({ label, variant, busy, onClick })` - a non-submit
  `Button`, `variant` `"primary" | "secondary" | "ghost"` (default
  `"secondary"`).
- `Notice.tsx:Notice({ kind, children })` - an Astryx `Banner`; `kind`
  `"danger" | "success" | "info"` maps to status `error` / `success` /
  `info`.
- `Words.tsx:Words({ quiet, announced, children })` - a paragraph (`Text
  as="p"`), secondary color when `quiet`, `role="status"` when `announced`.
- `Words.tsx:PageLink({ href, children })` - an Astryx `Link` with
  `hasUnderline`.
- `Words.tsx:Ways({ children })` - a `VStack as="ul"` with class `auth-ways`,
  for the other places a person may go.

## Invariants

- `Frame` focuses its heading whenever `title` or `tenant` changes, so that a
  screen reader announces the new page state (comment on `Frame`).
- `Form` sets `noValidate`: what was typed is checked by the server, which
  answers in the person's language (comment on `Form`).
- `Notice` with `kind="danger"` has `role="alert"`, so failures are announced
  at once; other kinds have `role="status"`.
- `Field` with `verbatim` turns off auto-capitalization, auto-correction and
  spell checking; `PasswordField` is always verbatim.
- Inside text, a `PageLink` is underlined: it is told apart by more than its
  color (comment on `PageLink`).
- No part sets an inline `style` attribute; `frontend/auth-ui/eslint.config.js`
  makes `style` and `dangerouslySetInnerHTML` lint errors.

## Side Effects

- `Frame` sets `document.title` to `` `${title} · ${tenant}` `` and moves
  keyboard focus to its heading.
- `PasswordField` keeps whether the password is shown in local React state.

## Verification

- Run from `frontend/auth-ui`: `npm test` (the parts are exercised by
  `../pages/pages.test.tsx`), `npm run typecheck`, `npm run lint`.
