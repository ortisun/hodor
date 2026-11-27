# src (hosted pages application)

## Overview

The React application behind Hodor's hosted pages. `main.tsx` reads the
tenant and the page from the address, picks the person's language, and
renders `App` inside the Hodor theme. `App` shows the page the address names.
`client.ts` is the only code that knows the paths, headers and answer shapes
of the interaction interface (see `docs/api/interaction-api.md`, cited in
its header); the pages see plain values.

## Interface

- `main.tsx` (entry, loaded by `../index.html`) - imports the IBM Plex Sans
  font files, `@astryxdesign/core/reset.css`, `@astryxdesign/core/astryx.css`
  and `auth-ui.css`. When `#root` exists and `placeOf(location.pathname)` is
  not `null`, it picks the language with `chooseMessages` from
  `uiLocalesOf(location.search)` followed by `navigator.languages`, sets
  `document.documentElement.lang`, reads `noticeOf`, `providerAnswerOf`,
  `tokenOf`, `continuesAuthorization` and `loginHintOf`, and renders `<Theme
  theme={themes[defaultThemeSlug]} mode="light"><App .../></Theme>` with
  `client={new Client(place.tenant)}`, `go` (`window.location.assign(pathOf(...))`)
  and `leave` (`window.location.assign(url)`).
- `App.tsx:App(AppProps)` - `AppProps` is `{ place, client, text, notice,
  token, go, leave, providerAnswer, signInAgain?, forApplication?,
  loginHint?, afterSignIn?, reauthenticate? }`; `signInAgain`, `loginHint`
  and `afterSignIn` go to `SignInPage`, `forApplication` (from
  `continuesAuthorization`) to the registration `AskPage`; `main.tsx` sets `signInAgain`, `afterSignIn` and
  `reauthenticate` from `continuationOf(location.search)` and
  `signInAgainPath`. It renders `sign-in` as `SignInPage`,
  `register` / `recover` as `AskPage`, `complete-registration` /
  `reset-password` as `FinishPage`, `account` as `AccountPage`, `sign-out`
  as `SignOutPage`, `security` as `SecurityPage`, `profile` as
  `ProfilePage`, `sign-in-link` as
  `SignInLinkPage` (`main.tsx` reads the token and takes the fragment out of
  the address for it),
  `provider-callback` as `ComingBackPage`, and anything else as a "page not
  found" frame with a link to sign-in.
- `address.ts`:
  - `PAGES` / `PageName` - `sign-in`, `register`, `complete-registration`,
    `recover`, `reset-password`, `consent`, `account`, `sign-out`,
    `security`, `profile`, `accept-invitation`, `sign-in-link`.
  - `continuationOf(search)` - `"authorization"`, `"security"` or `null`, from
    `?continue=`; `signInAgainPath(tenant)` is
    `/t/{tenant}/account/sign-in?continue=security`.
  - `NOTICES` / `NoticeName` - `registered`, `password-changed`, `signed-out`,
    `provider-refused`, `provider-cancelled`.
  - `Place` - `{ tenant, page: PageName | "provider-callback" | null,
    provider? }`.
  - `placeOf(pathname): Place | null` - understands
    `/t/{tenant}/account[/{page}]` and
    `/t/{tenant}/account/providers/{alias}/callback`; a tenant is
    `[a-z0-9][a-z0-9-]{1,62}`, a provider alias `[a-z0-9][a-z0-9-]{1,31}`.
  - `pathOf(tenant, page, notice?)` - `/t/{tenant}/account` or
    `/t/{tenant}/account/{page}`, with `?notice={notice}` when given.
  - `noticeOf(search)` - the `notice` query parameter if it is in `NOTICES`.
  - `continuesAuthorization(search)` - whether `continue=authorization`.
  - `loginHintOf(search)` - `login_hint`, or `null` when missing, blank or
    longer than 255 characters.
  - `uiLocalesOf(search)` - the tags of `ui_locales`, separated by spaces, in
    their order.
  - `tokenOf(hash)` - the `token` of the fragment if it matches
    `^[0-9a-f]{16,128}$`.
  - `ProviderAnswer` / `providerAnswerOf(search)` - `code`, `state`, `error`,
    `binding` (`"saml"` or `null`) and `receipt` from the query string.
- `client.ts`:
  - `Failure` - `code` (the problem document's `code`), `status` (`0` when
    unreachable), `requestId`, `retryAfterSeconds`, `detail` (the problem's
    English `detail`, which names what was wrong and never a typed value);
    getter `unreachable`.
  - Types `SignInStatus` (`pending | rejected | failed | completed`),
    `SignInAnswer` (`status`, `step`, `attemptsLeft`, `continueTo?`, and
    `recoveryCodes?` when the answer holds a non-empty `recovery_codes`),
    `EnrollmentKind` (`authenticator_application | security_key | passkey`), `OfferedProvider`
    (`alias`, `displayName`, `isDirectory` when `kind === "ldap"`), `Session`
    (`userId`, `sessionId`, `signedInAt`, `expiresAt`).
  - `CLAIM_FIELDS` / `ClaimField` - the seventeen fields of a person's
    standard claims the pages edit: `given_name`, `middle_name`,
    `family_name`, `nickname`, `gender`, `birthdate`, `zoneinfo`, `profile`,
    `picture`, `website`, `phone_number`, and the parts of the address as
    `address.formatted`, `address.street_address`, `address.locality`,
    `address.region`, `address.postal_code`, `address.country`.
  - `Profile` - `displayName`, `claims` (a text for every `ClaimField`, empty
    when the person has no value) and `phoneNumberVerified`.
  - `Client(tenant, fetch?)` - base path `/t/{tenant}/interaction`; methods
    and the requests they send:

    | Method | Request |
    | --- | --- |
    | `session()` | `GET /session` (401 gives `null`) |
    | `signOut()` | `DELETE /session` |
    | `currentSignIn()` | `GET /sign-in` (404 gives `null`) |
    | `startSignIn()` | `POST /sign-in` |
    | `abandonSignIn()` | `DELETE /sign-in` |
    | `providers()` | `GET /sign-in/providers` |
    | `chooseProvider(alias)` | `POST /sign-in/providers/{alias}` |
    | `signInWithDirectory(alias, identifier, password)` | `POST /sign-in/providers/{alias}/password` |
    | `finishWithProvider(alias, state, { code } or { receipt })` | `POST /sign-in/providers/{alias}/callback` |
    | `submitIdentifier(identifier)` | `POST /sign-in/steps/identifier` |
    | `submitPassword(password)` | `POST /sign-in/steps/password` |
    | `submitTotp(code)` | `POST /sign-in/steps/totp` |
    | `webAuthnOptions()` | `POST /sign-in/steps/webauthn/options` (answers `public_key`) |
    | `submitWebAuthn(answer)` | `POST /sign-in/steps/webauthn` |
    | `submitRecoveryCode(code)` | `POST /sign-in/steps/recovery_code` |
    | `consentQuestion()` | `GET /consent` (404 gives `null`; answers a `ConsentQuestion` of `AskedScope`s, with `registered`, the `SelfDescription` of a client that registered itself, each address kept only when it is HTTPS) |
    | `answerConsent("allow" or "deny")` | `POST /consent` (answers `continue`, refused unless it is an address of the tenant's authorization endpoint) |
    | `consents()` | `GET /consents` (answers `GivenConsent`s) |
    | `withdrawConsent(clientId)` | `DELETE /consents/{clientId}` (404 is not an error) |
    | `profile()` | `GET /profile` (answers a `Profile`) |
    | `saveProfile(displayName, claims)` | `PUT /profile` `{ display_name?, claims }` (answers the `Profile` kept) |
    | `passkeyOptions()` | `POST /sign-in/steps/passkey/options` (answers `public_key`) |
    | `submitPasskey(answer)` | `POST /sign-in/steps/passkey` |
    | `alternatives()` | `GET /sign-in/alternatives` (answers the keys) |
    | `askByEmail("code" or "link", email, locale)` | `POST /sign-in/steps/email_code/send` or `/email_link/send` |
    | `submitEmailCode(code)` | `POST /sign-in/steps/email_code` |
    | `submitEmailLink(token)` | `POST /sign-in/steps/email_link` |
    | `enrollmentKinds()` | `GET /sign-in/steps/enrollment/kinds` (the known kinds listed, in their order) |
    | `beginApplicationEnrollment()` | `POST /sign-in/steps/enrollment/options` `{ "kind": "authenticator_application" }` (answers an `Enrollment`) |
    | `beginKeyEnrollment(passkey)` | `POST /sign-in/steps/enrollment/options` `{ "kind": "passkey" }` or `"security_key"` (answers `public_key`) |
    | `finishApplicationEnrollment(code)` | `POST /sign-in/steps/enrollment` `{ "code" }` |
    | `finishKeyEnrollment(registration, name)` | `POST /sign-in/steps/enrollment` with the registration and the name, left out when blank |
    | `askToRegister(email, locale)` | `POST /registration` |
    | `completeRegistration(token, password, displayName)` | `POST /registration/complete` |
    | `askToRecover(email, locale)` | `POST /recovery` |
    | `resetPassword(token, password)` | `POST /recovery/complete` |

- `webauthn.ts` - `toBase64url`, `fromBase64url`, `requestOptions(options)`
  (the interface's options as `navigator.credentials.get` takes them),
  `answerOf(credential)`, `webAuthnAvailable()`,
  `conditionalMediationAvailable()`, and
  `askAuthenticator(options, credentials?, { mediation?, signal? })`, which
  answers `null` when the authenticator gave no answer or the request was
  abandoned.
- `astryx-themes.ts` (generated by `astryx theme`) - `themes` (`{ hodor }`),
  `ThemeSlug`, `defaultThemeSlug = "hodor"`; imports
  `./themes/hodor/hodor.js` and `./themes/hodor/hodor.css`.
- `auth-ui.css` - page layout only (`.auth-page`, `.auth-card`,
  `.auth-title`, `.auth-ways`, `.auth-hidden`, `.auth-divider`, and
  `.auth-fieldset`, a group of fields whose legend reads as a heading,
  without a frame), using theme tokens only.
- `testing.ts` (unit test support) - `json`, `problem` (a problem document
  with `type: urn:hodor:error:{code}` and `request_id: "request-1"`),
  `empty`, and `scripted(script)`, which returns a `Client` of tenant `acme`
  whose requests are answered in order from `script` and records each
  `Sent` request, including its `X-CSRF-Token`.
- `door.svg` - the icon `../index.html` links.
- Subdirectories:
  - [messages](./messages/EGM.md) - the English and Portuguese catalogs,
    `chooseMessages`, `describe`, `fieldProblem`.
  - [pages](./pages/EGM.md) - `SignInPage`, `AskPage`, `FinishPage`,
    `AccountPage`, `ProfilePage`, `SignOutPage`, `ComingBackPage`,
    `PageProps`.
  - [parts](./parts/EGM.md) - `Frame`, `Form`, `Field`, `PasswordField`,
    `Submit`, `Action`, `Notice`, `Words`, `PageLink`, `Ways`.
  - [themes](./themes/EGM.md) - the Hodor theme source and its compiled
    files.

## Invariants

- The tenant comes from the address and from nothing else (`address.ts`
  header); `main.tsx` renders nothing at an address `placeOf` does not
  understand.
- The link token travels in the fragment (`#token=`), which a browser never
  sends to a server (`tokenOf`).
- `Client` keeps the server's `csrf_token` from any successful answer and
  sends it as `X-CSRF-Token` on every request other than `GET`. It forgets
  the token on `startSignIn`, `signOut`, `abandonSignIn`, and on a sign-in
  answer of `failed` or `completed`.
- Every request is sent with `Accept: application/json`, `credentials:
  "same-origin"`, `cache: "no-store"` and `redirect: "error"`. A network
  error becomes `Failure(null, 0)`; a non-success status becomes a `Failure`
  carrying `code`, `request_id` (or the `X-Request-Id` header), a positive
  `Retry-After` and `detail`.
- `chooseProvider` accepts only an `http://` or `https://` redirect address;
  anything else is a `Failure`. An answer with an unknown sign-in `status`,
  or a session missing a field, is also a `Failure`.
- `abandonSignIn` does not fail on a client-error status (a sign-in already
  gone); it does fail when unreachable or on a status of 500 or more.
- `completeRegistration` sends `display_name` only when the trimmed name is
  not empty.
- `saveProfile` replaces the whole profile: it trims every field and sends
  only those not empty, so a field left empty removes the claim; it sends
  `address` as an object of its parts only when one part has a value,
  `display_name` only when not empty, and never `phone_number_verified`,
  which is the server's to say.
- What a provider sent back and any `notice` are taken out of the address
  with `history.replaceState` once read (`main.tsx`), so the code stays out
  of the browser history and a reload does not repeat the notice.

## Side Effects

- HTTP requests to `/t/{tenant}/interaction/...` on the page's own origin
  (`client.ts`), with the browser's cookies (`credentials: "same-origin"`).
- `main.tsx` writes `document.documentElement.lang`, rewrites the address
  with `history.replaceState`, and navigates with `window.location.assign`.

## Verification

- Run from `frontend/auth-ui`: `npm test` (Vitest with jsdom, files
  `src/**/*.test.{ts,tsx}`), `npm run typecheck`, `npm run lint`.
