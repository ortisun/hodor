# messages

## Overview

Everything the hosted pages say, in English and in Brazilian Portuguese, and
the choice of words for each failure a request can end in. The pages never
show the server's own `detail` text: they map a failure's `code` to their own
words (comment on `index.ts:describe`).

## Interface

- `en.ts:en` - the English catalog (`locale: "en"`). Most entries are
  strings, for example `signInTitle`, `identifierLabel`, `passwordLabel`,
  `registerTitle`, `emailLabel`, `sendLink`, `checkMailboxTitle`,
  `newPasswordLabel`, `createAccount`, `noticeRegistered`, `unreachable`,
  `somethingWentWrong`. Some are functions: `signingInAs(identifier)`,
  `attemptsLeft(count)`, `checkMailbox(email)`, `signedInSince(moment)`,
  `continueWith(provider)`, `directoryIdentifierLabel(directory)`,
  `tryAgainInSeconds(seconds)`, `tryAgainInMinutes(minutes)`,
  `requestIdentifier(identifier)`. The profile page has `profileLink`,
  `profileTitle`, `profileLead`, the headings `profileNamesHeading`,
  `profileAboutHeading`, `profilePagesHeading`, `profilePhoneHeading` and
  `profileAddressHeading`, `profileSave`, `profileSaved`, `phoneVerified`,
  `phoneNotVerified`, and the functions `claimLabel(field)` (the label of a
  claim of `CLAIM_FIELDS`, the field's own name when unknown),
  `claimHint(field)` (how to write `birthdate`, `zoneinfo`, the three
  addresses and `phone_number`, `null` for the others) and
  `claimInvalid(label)`.
- `en.ts:Messages` - `typeof en`, the shape every language must have.
- `pt-BR.ts:ptBR` - the Brazilian Portuguese catalog (`locale: "pt-BR"`),
  typed as `Messages`, with the same keys as `en`.
- `index.ts`:
  - `LANGUAGES` - `[en, ptBR]`.
  - `chooseMessages(preferred: readonly string[]): Messages` - the first
    preferred language tag that matches a catalog's `locale` exactly (case
    ignored), or failing that by its primary subtag; `en` otherwise.
  - `FieldProblem` - `{ field: "password" | "displayName"; message }`.
  - `fieldProblem(failure, text): FieldProblem | null` - maps
    `credential.password_too_short`, `credential.password_too_long`,
    `credential.password_is_own_name`, `credential.password_reused` to the
    password field and `identity.display_name_invalid` to the display name
    field; `null` for any other code.
  - `describe(failure, text): string` - `unreachable` when the server could
    not be reached; `authentication.too_many_attempts` gives `tooManyAttempts`
    plus a wait (`tryAgainLater` without a `Retry-After`, seconds below 60,
    minutes otherwise, rounded up); `authentication.registration_closed`,
    `authentication.verification_token_invalid` and
    `credential.hashing_overloaded` have their own words; anything else is
    `somethingWentWrong`, followed by `requestIdentifier(requestId)` when the
    failure carries one.
  - Re-exports `type Messages`.

## Invariants

- `ptBR` is declared `: Messages`, so the type checker refuses a Portuguese
  catalog that lacks a key of `en` or gives one the wrong shape.
- `chooseMessages` always returns a catalog; English is the fallback.
- The server's `detail` is never shown; only `code`, `status`, `requestId` and
  `retryAfterSeconds` of `Failure` (`../client.ts`) decide the words. The
  profile page uses the first word of a `detail` only to know which field to
  mark (see [pages](../pages/EGM.md)).

## Side Effects

- None. Pure data and functions.

## Verification

- Run from `frontend/auth-ui`: `npm test` (Vitest, includes
  `messages.test.ts`) and `npm run typecheck`.
