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
  else as `new Failure(null, 500)`. `shared.ts:grouped(secret)` writes the
  key of an authenticator application in groups of four, for `SecurityPage`
  and `SignInPage`.
- `SignInLinkPage.tsx:SignInLinkPage({ ...PageProps, token })` - the page a
  link to sign in opens. Without a token it says `text.signInLinkRefused` and
  asks nothing. Otherwise `client.currentSignIn()`: `null` shows
  `text.signInLinkElsewhere` and sends nothing; else
  `client.submitEmailLink(token)`, `completed` goes to `continueTo` or
  `account`, `pending` to `sign-in`, anything else, `404`, `409` and `422`
  show `text.signInLinkRefused`; other failures are described.
- `SignInPage.tsx:SignInPage({ ...PageProps, notice, signInAgain?,
  loginHint? })` - the identifier field starts with `loginHint`. On mount calls
  `client.providers()` and `findOut`: `client.session()` (someone signed in
  means `go("account")`), then `client.currentSignIn()`, else
  `client.startSignIn()`. It renders the form for the step the server names:
  - `identifier` - `client.submitIdentifier`, with
    `autocomplete="username webauthn"`; in a browser with WebAuthn, an
    `Action` `text.signInWithPasskey` that asks `client.passkeyOptions()`, then
    the authenticator, and sends the answer with `client.submitPasskey`
    (no answer shows `text.passkeyNoAnswer` and sends nothing); where
    `conditionalMediationAvailable()`, a conditional request that offers the
    browser's passkeys in the field, aborted when the step is left, the
    identifier is submitted or the button is pressed; plus one `Action` per
    offered provider (`text.continueWith(displayName)`). When
    `client.alternatives()` names `email_code` or `email_link`, an `Action`
    `text.emailMeACode` or `text.emailMeALink` asks
    `client.askByEmail(method, identifier, text.locale)` (nothing typed shows
    `text.typeAddressFirst` and sends nothing; the passkey offer is stopped
    first, and the request is sent once: asking keeps nothing in the
    sign-in, so the server never refuses it for the passkey request, and a
    second request would send a second message);
    then, while the step stays `identifier`, a code form
    (`text.emailCodeLabel`, `autocomplete="one-time-code"`) that calls
    `client.submitEmailCode`, or the notice `text.emailLinkSent`, each with a
    way to ask again and to use another address. A provider with
    `isDirectory` shows a username and password form here that calls
    `client.signInWithDirectory(alias, identifier, password)`; any other
    calls `client.chooseProvider(alias)` and passes the answer to `leave`.
  - `password` - `client.submitPassword`, with a hidden read-only `username`
    input for password managers.
  - `totp` - `client.submitTotp`, one field (`text.totpLabel`, hint
    `text.totpHint`) with `autocomplete="one-time-code"` and
    `inputmode="numeric"`, "use a recovery code instead" and "use another
    address". "Use a recovery code instead" shows, in its place, one field
    (`text.recoveryCodeLabel`, hint `text.recoveryCodeHint`) with
    `autocomplete="off"`, no numeric keyboard and no capitals or corrections,
    sent with `client.submitRecoveryCode`, and "use the code of your
    application instead" to go back; a rejection keeps the recovery code
    form. "Start again" returns to the code of the application. After each
    switch the field shown takes the focus, in a task of its own once the
    press has been handled (`switches`, `codeField`): `autoFocus` alone
    leaves it on the button.
  - `webauthn` - a button that asks `client.webAuthnOptions()`, then the
    authenticator through `askAuthenticator`, and sends its answer with
    `client.submitWebAuthn`. When the authenticator gives no answer nothing
    is sent and `text.securityKeyNoAnswer` is shown; a browser without
    WebAuthn is told `text.securityKeyUnavailable`. It also offers "use a
    recovery code instead", the same recovery code form, with "use the
    security key instead" to go back.
  - `enrollment` - `text.enrollLead`, then what `client.enrollmentKinds()`
    lists, read when the step is shown: an `Action` `text.setUpApplication`
    that calls `client.beginApplicationEnrollment()` and shows the `QrCode`
    of its `uri`, the secret `grouped`, one code field (`text.totpLabel`,
    `autocomplete="one-time-code"`) sent with
    `client.finishApplicationEnrollment`, `text.confirmAndSignIn` and
    `text.chooseAnotherWay` back to the choice (a rejection keeps the QR
    code); in a browser with WebAuthn, a key name field and `Action`s
    `text.addSecurityKey` and `text.addPasskey` that call
    `client.beginKeyEnrollment(passkey)`, `askToCreate`, and
    `client.finishKeyEnrollment(registration, name)` (no answer shows
    `text.keyNoAnswer` and sends nothing; a blank name is
    `text.defaultKeyName` or `text.defaultPasskeyName`); nothing offered shows
    `text.nothingToSetUp`; and "use another address". No way to go on without
    a factor.
  - An answer with `recoveryCodes` shows only them (`text.codesTitle`,
    `text.codesLead`), until `text.codesKept` is pressed; the answer then goes
    on as any other (`keeping`).
  - Any other step - `text.unknownStep` and "start again".
  - Answer `completed` means `go("account")`; `failed` shows `signInEnded`;
    `rejected` shows `rejected` and `attemptsLeft`. "Start again" and "use
    another address" call `client.abandonSignIn()` and start a new sign-in.
  - It shows the notices `registered`, `password-changed`, `signed-out`
    (success) and `provider-refused`, `provider-cancelled` (danger), and links
    to `recover` and `register`.
- `AskPage.tsx:AskPage({ ...PageProps, purpose, forApplication? })` - `purpose`
  `"registration" | "recovery"`; one email field that calls
  `client.askToRegister(email, text.locale)` or `client.askToRecover(email,
  text.locale)`, then shows `checkMailboxTitle` with "ask again" and a link
  back to sign-in. With `forApplication` (an application's `prompt=create`,
  Issue-125) a registration page also shows `registerForApplication`, and
  both its links to sign in carry `?continue=authorization`.
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
  formatted with `Intl.DateTimeFormat` in `text.locale`), the applications
  the person let in from `client.consents()`, each with a "withdraw" `Action`
  that calls `client.withdrawConsent(clientId)` and says so
  (`consentWithdrawn`), a link to the
  security page, and a sign-out `Action` that calls
  `client.signOut()` and `go("sign-in", "signed-out")`.
- `ConsentPage.tsx:ConsentPage(PageProps)` - `client.session()`: none means
  `go("sign-in")`; then `client.consentQuestion()`: none is the "nothing to
  answer" frame with a link to the account page. Otherwise the heading
  names the application (`consentTitle`), one line per scope (OpenID
  Connect scopes worded by the page, a resource server's scope by its
  description and name, as text), `consentOffline` when offline access is
  asked, and the two `Action`s "allow" (primary, first) and "deny".
  `client.answerConsent(decision)` answers where to go, given to `leave`;
  a 404 shows the "nothing to answer" frame.
- `SignOutPage.tsx:SignOutPage(PageProps)` - the question an application's
  logout asks. `client.session()`: none means `leave` to
  `/t/{tenant}/oauth2/logout/finish` at once; else it shows
  `signOutQuestion(tenant)` with a primary `signOut` `Action` (calls
  `client.signOut()`, then `leave` to the finish; a 401 counts as signed
  out) and `staySignedIn` (`go("account")`). It never learns the return
  address: the server keeps it.
- `SecurityPage.tsx:SecurityPage({ ...PageProps, reauthenticate })` -
  `client.session()` (none means `go("sign-in")`), then `client.factors()`.
  Changes are offered only while `recentSignInUntil` is in the future;
  otherwise a notice and a "sign in again" `Action` that calls
  `reauthenticate`. Views: the overview; setting up an application (`QrCode`
  of `uri`, the secret in groups of four, a code field); the recovery codes
  shown once, until "I have kept them"; a confirmation before removing the
  application or a key, or generating new codes; renaming a key in place.
  `authentication.recent_sign_in_required` from any change goes back to the
  overview with the sign-in-again notice. Adding a key goes through
  `askToCreate` (`webauthn.ts`) and `client.finishKey`.
- `ComingBackPage.tsx:ComingBackPage({ ...PageProps, provider, answer })` -
  from the `ProviderAnswer`: with `binding === "saml"` it needs `state` and
  `receipt`; otherwise any `error`, or a missing `code` or `state`, means
  `go("sign-in", "provider-cancelled")`. It then calls
  `client.currentSignIn()` (a `null` answer means `provider-refused`) and
  `client.finishWithProvider(provider, state, { code } | { receipt })`;
  `completed` means `go("account")` (or `leave(continueTo)`), `pending`, a
  second factor asked next, `go("sign-in")` with no notice, anything else
  `go("sign-in", "provider-refused")`.

## Invariants

- The pages decide nothing about authentication: `SignInPage` shows the form
  for the step the server names, and `ComingBackPage` only presents what
  arrived to the server (comments on both components).
- `SignInPage` error codes: `GONE` (`authentication.transaction_not_found`,
  `authentication.transaction_not_active`) starts a new sign-in and shows
  `signInExpired`; `OUT_OF_STEP` (`authentication.unexpected_step`,
  `authentication.transaction_modified_concurrently`,
  `request.csrf_token_invalid`) asks the server again where the sign-in
  stands; `authentication.enrollment_not_needed` starts a new sign-in and
  shows `text.enrollmentNotNeeded`. The typed password is cleared after every
  answer.
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
