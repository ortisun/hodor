# messages

## Overview

The copy of the administration console in every language it has, and the
helpers that turn values into text for a person: choosing a language,
describing a failure, formatting a time. Screens never hold literal text; they
read it from a `Messages` object.

## Interface

- `index.ts:LANGUAGES` - the languages the console has, in order: `[en, ptBR]`.
- `index.ts:chooseMessages(preferred)` - returns the `Messages` for the first
  preferred language tag the console has (`main.tsx` passes
  `navigator.languages`).
- `index.ts:describe(failure, text)` - the text to show for a `Failure` from
  `../client.ts`.
- `index.ts:moment(written, text)` - a time written by the server, formatted
  for the language of `text`.
- `index.ts:named(names, name)` - `names[name]`, or `name` itself when the key
  is missing.
- `index.ts:lifetime(seconds, text)` - a lifetime in the largest whole unit:
  `text.days` when it divides into days, then `text.hours`, else
  `text.minutes` rounded.
- `en.ts:en` - the English copy, `locale: "en"`; `en.ts:Messages` is
  `typeof en` and is re-exported by `index.ts`.
- `en.ts:en` groups - plain keys (`locale`, `product`, `console`, `loading`,
  `scope`, `navigation`, `tenant`), then comment-marked groups for who may be
  here, the frame, navigation, failures, users, one user, the ladder, audit,
  identity providers, applications, resource servers, clients, groups and
  organizations alike, groups, organizations, the page of a user, a secret
  shown once, service accounts and agents, API keys, webhooks and trust
  domains; lookup tables `roles`, `status`, `kinds`, `providerStatus`,
  `providerKinds`, `clientTypes`, `clientTypeHints`, `methods`,
  `methodHints`, `grants`, `memberKinds`, `unitKinds`, `messageLanguages`,
  `trustDomainSources`, `trustDomainSourceHints`, `bundleFailures`,
  `valueInvalid` and the list
  `levelFriction`; text-building functions such as `noAccess`, `sessionUntil`,
  `userCreated`, `typeToConfirm` and `requestIdentifier`. The page of a user has
  `standardClaims`, `noStandardClaims` and `claimLabel(claim)`, the label of
  a standard claim or of a part of the address (`address.locality` and the
  others), the claim's own name when unknown.
- `pt-BR.ts:ptBR` - the Brazilian Portuguese copy, `locale: "pt-BR"`, declared
  as `Messages`.

## Invariants

- `pt-BR.ts:ptBR` is typed `Messages`, so it must have exactly the keys of
  `en`; a missing or extra key is a type error. The inner keys of the lookup
  tables (`roles`, `status`, `valueInvalid` and the rest) are typed
  `Record<string, string>` and are not checked by the type;
  `messages.test.ts` checks that every language has the same keys in each,
  and that every refusal of trust domains and of a client's workload
  identity is said in words in every language.
- `index.ts:chooseMessages` lowercases each preferred tag and tries, for that
  tag, an exact match on `locale` and then a match on the primary subtag (the
  part before the first `-`) before moving to the next tag; so `pt-PT` picks
  `ptBR`, and an earlier tag always wins over a later one. With no match it
  returns `en`.
- `index.ts:describe` returns `text.unreachable` whenever `failure.status` is
  `0`. Otherwise it maps known problem codes (for example `admin.forbidden`,
  `identity.identifier_taken`, `identity.email_invalid`,
  `identity.user_not_found`, `identity.invalid_transition`,
  `federation.provider_not_found`, `federation.alias_taken`,
  `federation.too_many_providers`, `federation.not_configured`,
  `federation.provider_modified_concurrently`, `identity.group_cycle`,
  `identity.group_nesting_too_deep`, `identity.unit_not_empty` and the other
  codes of groups and organizations, of workloads and webhooks, and
  `keys.trust_domain_not_found`, `keys.trust_domain_name_taken`,
  `keys.too_many_trust_domains`, `keys.trust_domain_changed`,
  `oauth.client_spiffe_id_taken` and `oauth.client_linkerd_identity_taken`)
  to their text, then tries
  `text.valueInvalid[code]`, and falls back to `somethingWrong` followed by
  `requestIdentifier(requestId)` when the failure carries a request identifier.
  No HTTP status other than `0` is looked at.
- `index.ts:moment` returns the original string when it does not parse as a
  date, and otherwise formats with
  `Intl.DateTimeFormat(text.locale, { dateStyle: "medium", timeStyle: "short" })`.
- `en.ts:levelFriction` has entries for levels 0 to 2 only.

## Side Effects

- None. Every export is a constant or a pure function.

## Verification

- Run from `frontend/admin-console`: `npm test` (Vitest; `messages.test.ts`
  covers this directory).
