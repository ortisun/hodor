# screens

## Overview

The screens of the administration console: users and one user, identity
providers and one provider, and the audit log. Each screen loads what it shows
through a method of `../client.ts:Client`, gates every button that changes
something with `../actions.ts:may`, and sends dangerous actions through
`../parts/Confirm.tsx:Confirm`. Screens see values, never addresses of the
console interface.

## Interface

- `shared.tsx:ScreenProps` - what every screen receives: `client`, `me`,
  `text`, `go(screen)` (open another screen in this tab), `path(screen)` (its
  address, for links) and `say(message)` (announce that something was done).
- `shared.tsx:Page` - the frame of a screen: `title`, optional `lead`,
  `above` (breadcrumbs), `actions`, `children`.
- `UsersScreen.tsx:UsersScreen` - the user table, loaded with
  `client.listUsers()`; "load more" calls `client.listUsers(nextCursor)`.
  "Create user" (gated by `may(..., "createUser")`) opens `CreateUser`, which
  calls `client.createUser(email, name)`.
- `UsersScreen.tsx:nameOf`, `UsersScreen.tsx:StatusBadge` - a user's list name
  (display name, then primary identifier, then `text.unnamed`) and status badge.
- `UserScreen.tsx:UserScreen` - one user, loaded with `client.getUser(id)`;
  sessions loaded with `client.listSessions(id)`. "Suspend user"
  (`suspendUser`) calls `client.suspendUser(id, reason)`; "End session"
  (`endSession`) calls `client.endSession(sessionId)`; both go through
  `Confirm`.
- `ProvidersScreen.tsx:ProvidersScreen` - the identity provider table, loaded
  with `client.listProviders()`; "Add provider" (`addProvider`) opens
  `ProviderForm`, which calls `client.addProvider(added)`.
- `ProvidersScreen.tsx:ProviderStatus` - a badge, success when `enabled`.
- `ProviderScreen.tsx:ProviderScreen` - one provider, loaded with
  `client.getProvider(id)`. All its buttons are gated by `changeProvider`:
  change settings (`client.changeProvider`), replace the client secret
  (`Confirm` with `replaceClientSecret`, `client.replaceClientSecret`), disable
  (`Confirm` with `disableProvider`, `client.disableProvider`) and enable
  (`Confirm` with `enableProvider`, `client.enableProvider`).
- `ProviderForm.tsx:ProviderForm` - the dialog to add a provider or change one;
  `ProviderForm.tsx:scopesOf` splits typed scopes on whitespace, and
  `DEFAULT_SCOPES` is `"openid email profile"`.
- `AuditScreen.tsx:AuditScreen` - the audit record table, loaded with
  `client.listAuditRecords()`; "load more" passes `nextCursor`; a record opens
  a read-only dialog with its details, previous hash and hash.

## Invariants

- A button that changes something renders only when
  `may(me.permissions, action)` holds; `AuditScreen` changes nothing and has no
  gates.
- `UserScreen.tsx:UserScreen` lists sessions only when `me.permissions`
  includes `sessions:read`, and offers "Suspend user" only for an `active` user
  who is not `me.user.id`. Suspending needs a non-empty reason and, being level
  2, the typed primary identifier value (or the user identifier when there is
  none).
- `ProviderScreen.tsx:ProviderScreen` offers change settings and replace secret
  only when `provider.kind` is `openid_connect`; for other kinds a person with
  the change permission sees a banner saying the provider is managed
  elsewhere. Disabling, at level 2, needs the provider alias typed.
- `ProviderForm.tsx:ProviderForm` sends, when changing, only the fields that
  differ and is disabled until one does; when adding, alias, display name,
  issuer, client identifier and secret must all be non-empty. The secret field
  is cleared after a successful submit and never shown again.
- `UsersScreen.tsx:CreateUser` is a level 0 form, its own confirmation; the
  codes `identity.identifier_taken` and `identity.email_invalid` show on the
  email field.
- Lists with "load more" (users, audit) do nothing while busy or when
  `nextCursor` is `null`; the provider and session lists are not paged.
- A plain primary click on a link calls `go`; a click with meta, control or
  shift, or another button, keeps the browser's own navigation to `path()`.

## Side Effects

- Each screen requests its data on mount through `../parts/Loaded.tsx:useLoaded`.
- After a change succeeds the screen calls `say(...)` and then: creating a
  user or adding a provider calls `go` to the new one; suspending a user or
  changing, disabling or enabling a provider replaces the shown value with the
  answer; suspending a user and ending a session reload the sessions; replacing
  a secret reloads the provider.
- `ProviderScreen.tsx` clears the typed secret whenever a dialog closes.

## Verification

- Run from `frontend/admin-console`: `npm test` (Vitest; the screens are
  exercised through `App.test.tsx`).
