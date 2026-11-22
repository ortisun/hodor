# pages

## Overview

The hosted pages a person sees: sign-in, asking for a registration or
recovery link, finishing a registration or a password reset, the account
page, and the page an identity provider sends the person back to. Each page
is a React component given `PageProps`. It talks to the server only through
the `Client` of `../client.ts`, moves between pages only through `go` and
`leave`, and builds its screens from [parts](../parts/EGM.md) and words from
[messages](../messages/EGM.md). `../App.tsx` chooses the page from the
address.

## Interface

- `shared.ts:PageProps` - `{ tenant, client: Client, text: Messages, go(page,
  notice?), leave(url), path(page) }`.
- `shared.ts:asFailure(thrown): Failure` - a thrown `Failure` as is, anything
  else as `new Failure(null, 500)`.
- `SignInPage.tsx:SignInPage({ ...PageProps, notice })` - on mount calls
  `client.providers()` and `findOut`: `client.session()` (someone signed in
  means `go("account")`), then `client.currentSignIn()`, else
  `client.startSignIn()`. It renders the form for the step the server names:
  - `identifier` - `client.submitIdentifier`, plus one `Action` per offered
    provider (`text.continueWith(displayName)`). A provider with
    `isDirectory` shows a username and password form here that calls
    `client.signInWithDirectory(alias, identifier, password)`; any other
    calls `client.chooseProvider(alias)` and passes the answer to `leave`.
  - `password` - `client.submitPassword`, with a hidden read-only `username`
    input for password managers.
  - `totp` - `client.submitTotp`, one field (`text.totpLabel`, hint
    `text.totpHint`) with `autocomplete="one-time-code"` and
    `inputmode="numeric"`, and "use another address".
  - `webauthn` - a button that asks `client.webAuthnOptions()`, then the
    authenticator through `askAuthenticator`, and sends its answer with
    `client.submitWebAuthn`. When the authenticator gives no answer nothing
    is sent and `text.securityKeyNoAnswer` is shown; a browser without
    WebAuthn is told `text.securityKeyUnavailable`.
  - Any other step - `text.unknownStep` and "start again".
  - Answer `completed` means `go("account")`; `failed` shows `signInEnded`;
    `rejected` shows `rejected` and `attemptsLeft`. "Start again" and "use
    another address" call `client.abandonSignIn()` and start a new sign-in.
  - It shows the notices `registered`, `password-changed`, `signed-out`
    (success) and `provider-refused`, `provider-cancelled` (danger), and links
    to `recover` and `register`.
- `AskPage.tsx:AskPage({ ...PageProps, purpose })` - `purpose`
  `"registration" | "recovery"`; one email field that calls
  `client.askToRegister(email, text.locale)` or `client.askToRecover(email,
  text.locale)`, then shows `checkMailboxTitle` with "ask again" and a link
  back to sign-in.
- `FinishPage.tsx:FinishPage({ ...PageProps, purpose, token })` - with no
  token, or after `authentication.verification_token_invalid`, shows
  `linkInvalidTitle` and a link to ask for a new one. Otherwise it shows a
  new-password field (and an optional display name for registration) and
  calls `client.completeRegistration(token, password, displayName)` or
  `client.resetPassword(token, password)`, then `go("sign-in", "registered" |
  "password-changed")`. Field failures go through `fieldProblem` to the
  matching field.
- `AccountPage.tsx:AccountPage(PageProps)` - `client.session()`: none means
  `go("sign-in")`; else it shows `signedInSince` (the `signedInAt` time
  formatted with `Intl.DateTimeFormat` in `text.locale`) and a sign-out
  `Action` that calls `client.signOut()` and `go("sign-in", "signed-out")`.
- `ComingBackPage.tsx:ComingBackPage({ ...PageProps, provider, answer })` -
  from the `ProviderAnswer`: with `binding === "saml"` it needs `state` and
  `receipt`; otherwise any `error`, or a missing `code` or `state`, means
  `go("sign-in", "provider-cancelled")`. It then calls
  `client.currentSignIn()` (a `null` answer means `provider-refused`) and
  `client.finishWithProvider(provider, state, { code } | { receipt })`;
  `completed` means `go("account")`, anything else `go("sign-in",
  "provider-refused")`.

## Invariants

- The pages decide nothing about authentication: `SignInPage` shows the form
  for the step the server names, and `ComingBackPage` only presents what
  arrived to the server (comments on both components).
- `SignInPage` error codes: `GONE` (`authentication.transaction_not_found`,
  `authentication.transaction_not_active`) starts a new sign-in and shows
  `signInExpired`; `OUT_OF_STEP` (`authentication.unexpected_step`,
  `authentication.transaction_modified_concurrently`,
  `request.csrf_token_invalid`) asks the server again where the sign-in
  stands. The typed password is cleared after every answer.
- `ComingBackPage` sends the person back to sign-in with `provider-refused`
  on statuses 404, 409 and 422, and shows the failure on any other.
- `AskPage` shows the same "check your mailbox" answer whatever the address
  (comment on `AskPage`); an empty address sends nothing.
- `AccountPage` treats a 401 on sign-out as already signed out.
- Every action ignores a second click while `busy`. Effects ignore answers
  that arrive after the component is gone (the `current` flag).
- Failures are shown only through `describe` or `fieldProblem`, never as the
  server's text.

## Side Effects

- Requests to the interaction interface through `Client` (see
  [src](../EGM.md) for the endpoints).
- Navigation of the whole browser through `go` and `leave`
  (`window.location.assign` in `../main.tsx`); `leave` goes to an identity
  provider's address.
- Through `Frame`, every page sets `document.title` and moves focus to its
  heading.

## Verification

- Run from `frontend/auth-ui`: `npm test` (Vitest with jsdom; includes
  `pages.test.tsx`, which drives the pages against the scripted client of
  `../testing.ts`), `npm run typecheck`, `npm run lint`.
