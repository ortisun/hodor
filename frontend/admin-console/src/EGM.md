# admin-console/src

## Overview

The source of the administration console, a React application served under
`/t/{tenant}/console`. The tenant is part of every address and a tab never
changes tenant on its own. `client.ts` is the only place that knows the paths,
headers and answer shapes of the console interface; `address.ts` maps browser
addresses to screens; `actions.ts` is the catalog of actions that change
something, with their ladder level and permission. `App.tsx` decides what a
person sees from who they are (`Client.me`).

## Interface

- `main.tsx:Console` - the root: creates `new Client(tenant)`, picks the copy
  with `chooseMessages(navigator.languages)`, and renders
  `Theme(theme=hodorTheme, mode)`, `LayerProvider` and `App`. The module mounts
  it on `#root` only when `placeOf(window.location.pathname)` is not `null`.
- `App.tsx:App`, `App.tsx:AppProps`, `App.tsx:Mode` - loads `client.me()` and
  shows a spinner, a failure with try again, a no-access notice linking to
  `accountPath(tenant)`, or the frame (top bar, side navigation filtered by
  permission, command palette on mod+k, and the current screen).
- `App.tsx:needsOf` - the permission a screen needs: `audit` needs
  `audit:read`; `providers` and `provider` need `identity-providers:read`;
  `applications`, `application` and `client` need `applications:read`;
  `groups` and `group` need `groups:read`; `organizations` and `organization`
  need `organizations:read`; the others need `users:read`.
- `address.ts` - `Screen` (`home`, `users`, `user`, `audit`, `providers`,
  `provider`, `applications`, `application`, `client`, `authorization`,
  `groups`, `group`, `organizations`, `organization`), `Place`, `placeOf(pathname)`, `pathOf(tenant, screen)`,
  `isIdentifier(text)`, `signInPath(tenant)` (`/t/{tenant}/account/sign-in`)
  and `accountPath(tenant)` (`/t/{tenant}/account`). Console addresses are
  `/t/{tenant}/console`, `.../users`, `.../users/{id}`, `.../audit`,
  `.../identity-providers`, `.../identity-providers/{id}`, `.../applications`,
  `.../applications/{id}`, `.../clients/{id}`, `.../authorization`,
  `.../groups`, `.../groups/{id}`, `.../organizations` and
  `.../organizations/{id}`.
- `actions.ts:ACTIONS`, `ActionName`, `Level`, `Action`, `may(permissions,
  action)` - `createUser` (level 0, `users:write`); `endSession` (1,
  `sessions:revoke`); `suspendUser` (2, `users:write`); `addProvider`,
  `changeProvider`, `replaceClientSecret`, `enableProvider` (1,
  `identity-providers:write`); `disableProvider` (2,
  `identity-providers:write`); `addApplication`, `changeApplication`,
  `enableApplication`, `addClient`, `changeClient`, `changeResourceServer`,
  `addKey`, `removeKey`, `enableClient` (1, `applications:write`);
  `disableApplication`, `rotateSecret`, `revokeSecret`, `disableClient` (2,
  `applications:write`); `createGroup` (0), `changeGroup`, `addGroupMember`,
  `removeGroupMember` (1), `deleteGroup` (2), all `groups:write`;
  `createOrganization`, `createUnit` (0), `changeOrganization`, `changeUnit`,
  `putOrganizationMember`, `removeOrganizationMember`, `invite`,
  `withdrawInvitation` (1), `deleteOrganization`, `deleteUnit` (2), all
  `organizations:write`.
- `client.ts:Client` - every request goes to `/t/{tenant}/console/api{path}`,
  except sign-out, which uses `/t/{tenant}/interaction{path}`:

  | Method | Request |
  | --- | --- |
  | `me()` | `GET /me` |
  | `signOut()` | `DELETE /session` (interaction) |
  | `listUsers(cursor)` | `GET /users?limit=50[&cursor=]` |
  | `getUser(id)` | `GET /users/{id}` |
  | `createUser(email, displayName)` | `POST /users` |
  | `suspendUser(id, reason)` | `POST /users/{id}:suspend` |
  | `listSessions(userId)` | `GET /users/{id}/sessions` |
  | `endSession(sessionId)` | `DELETE /sessions/{id}` |
  | `listProviders()` | `GET /identity-providers` |
  | `getProvider(id)` | `GET /identity-providers/{id}` |
  | `addProvider(added)` | `POST /identity-providers` |
  | `changeProvider(id, change)` | `PATCH /identity-providers/{id}` |
  | `replaceClientSecret(id, secret)` | `PUT /identity-providers/{id}/client-secret` |
  | `disableProvider(id)` | `POST /identity-providers/{id}:disable` |
  | `enableProvider(id)` | `POST /identity-providers/{id}:enable` |
  | `listApplications()` | `GET /applications` |
  | `getApplication(id)` | `GET /applications/{id}` |
  | `addApplication(settings)` | `POST /applications` |
  | `changeApplication(id, settings)` | `PATCH /applications/{id}` |
  | `disableApplication(id)`, `enableApplication(id)` | `POST /applications/{id}:disable`, `:enable` |
  | `listClients(applicationId)` | `GET /applications/{id}/clients` |
  | `addClient(applicationId, type, settings)` | `POST /applications/{id}/clients`; returns the client and `client_secret` when given |
  | `getClient(id)` | `GET /clients/{id}` |
  | `changeClient(id, settings)` | `PATCH /clients/{id}` |
  | `disableClient(id)`, `enableClient(id)` | `POST /clients/{id}:disable`, `:enable` |
  | `rotateSecret(id)` | `POST /clients/{id}/secrets` with `{}` |
  | `revokeSecret(id, secretId)` | `DELETE /clients/{id}/secrets/{secretId}` |
  | `addKey(id, jwk)` | `POST /clients/{id}/keys` |
  | `removeKey(id, kid)` | `DELETE /clients/{id}/keys/{kid}`, the `kid` percent-encoded |
  | `listResourceServers()` | `GET /resource-servers` |
  | `addResourceServer(applicationId, audience, name, scopes)` | `POST /resource-servers` |
  | `changeResourceServer(id, name, scopes)` | `PATCH /resource-servers/{id}` |
  | `listAuditRecords(cursor)` | `GET /audit-records?limit=50[&cursor=]` |
  | `listGroups(cursor)` | `GET /groups?limit=50[&cursor=]` |
  | `getGroup(id)`, `createGroup(settings)`, `changeGroup(id, settings)`, `deleteGroup(id)` | `GET /groups/{id}`, `POST /groups`, `PATCH /groups/{id}`, `DELETE /groups/{id}`; an empty description is not sent |
  | `listGroupMembers(id, cursor)` | `GET /groups/{id}/members?limit=50[&cursor=]` |
  | `addGroupMember(id, member)`, `removeGroupMember(id, member)` | `POST /groups/{id}/members`, `POST /groups/{id}/members:remove` with `{ kind, id }` |
  | `groupsOfUser(userId)` | `GET /users/{id}/groups` |
  | `listOrganizations(cursor)` | `GET /organizations?limit=50[&cursor=]` |
  | `getOrganization(id)`, `createOrganization(settings)`, `changeOrganization(id, settings)`, `deleteOrganization(id)` | `GET /organizations/{id}`, `POST /organizations`, `PATCH /organizations/{id}`, `DELETE /organizations/{id}` |
  | `listUnits(id)`, `createUnit(id, settings)`, `changeUnit(id, unitId, settings)`, `deleteUnit(id, unitId)` | `GET` and `POST /organizations/{id}/units`, `PUT` and `DELETE /organizations/{id}/units/{unitId}` |
  | `listOrganizationMembers(id, cursor)` | `GET /organizations/{id}/members?limit=50[&cursor=]` |
  | `putOrganizationMember(id, userId, unitIds)`, `removeOrganizationMember(id, userId)` | `PUT` and `DELETE /organizations/{id}/members/{userId}` |
  | `listInvitations(id)`, `invite(id, email, unitIds, locale)`, `withdrawInvitation(id, invitationId)` | `GET` and `POST /organizations/{id}/invitations`, `DELETE /organizations/{id}/invitations/{invitationId}`; the answer to `POST` holds nothing |
  | `organizationsOfUser(userId)` | `GET /users/{id}/organizations` |

- `client.ts` types - `Failure` (`code`, `status`, `requestId`, `signedOut`),
  `Permission`, `Identifier`, `User`, `Me`, `Session`, `AuditRecord`,
  `Provider`, `NewProvider`, `ProviderChange`, `Application`,
  `ApplicationSettings`, `TokenPolicy`, `ApplicationClient` (an OAuth client:
  the name `Client` is this class), `ClientSettings`, `CreatedClient`,
  `NewSecret`, `Scope`, `ResourceServer`, `Page<T>`, `Named` (with `Group`
  and `Organization`), `NamedSettings`, `GroupMember`, `GroupOfUser`, `Unit`,
  `UnitKind`, `UnitSettings`, `OrganizationMember`, `OrganizationOfUser`,
  `Invitation` (never a link or a secret).
- `hodor-theme.d.ts` - declares the modules `@hodor-theme/hodor.js`
  (`hodorTheme: DefinedTheme`) and `@hodor-theme/hodor.css`; the alias is
  resolved by `../vite.config.ts`.
- `testing.ts`, `setup.ts` - test support only: a scripted `fetch` behind a
  `Client` for tenant `acme`, answer builders, and a `HTMLDialogElement` stand-in
  for the test environment.
- `console.css` styles what the console draws beyond Astryx using theme tokens
  only; `layer-rules.css` receives Astryx's layer placement rules from the
  `hodor-layer-rules` plugin of `../vite.config.ts`.
- Subdirectories: [messages](./messages/EGM.md) (copy in English and Brazilian
  Portuguese, failure text), [parts](./parts/EGM.md) (confirmation dialog,
  identifier, loading state, a secret shown once), [screens](./screens/EGM.md)
  (users, one user, groups, one group, organizations, one organization,
  identity providers, one provider, applications, one application, one
  client, authorization, audit).

## Invariants

- `client.ts:Client.#send` sends `credentials: "same-origin"`,
  `cache: "no-store"` and `redirect: "error"`, and adds the cross-site request
  forgery token as `X-CSRF-Token` on every non-`GET` request once `me()` has
  stored `csrf_token`; `signOut()` clears it.
- `client.ts:Client.#send` turns a network error into `Failure(null, 0)` and a
  non-success answer into `Failure(code, status, request_id or X-Request-Id)`;
  an answer missing a required field becomes `Failure(null, 502)`.
- `client.ts:Client.me` returns `null` on a 401 (`Failure.signedOut`), and
  `App.tsx:App` then leaves for `signInPath(tenant)`. Other failures show the
  failure banner.
- `App.tsx:Frame` renders a screen only when `me.permissions` holds
  `needsOf(screen)`; a forbidden screen shows the same not-found page as an
  unknown address. `home` goes to the first allowed entry in the order users,
  groups, organizations, identity providers, applications, authorization,
  audit. A person with no allowed entry sees only the
  no-access notice.
- `App.tsx:Frame` signs out by calling `client.signOut()` and always leaves for
  the sign-in page afterwards, even when sign-out fails.
- `address.ts:placeOf` accepts tenants matching `^[a-z0-9][a-z0-9-]*$` and
  identifiers of the eight-four-four-four-twelve hexadecimal shape, lowercased.
- `main.tsx:Console` reloads the page when back or forward lands on another
  tenant or outside the console.

## Side Effects

- Network: every `Client` method calls `fetch` as listed above.
- `main.tsx` reads and writes `window.localStorage` key `hodor-console-mode`
  (dark unless it holds `light`; storage errors ignored), sets
  `document.documentElement.lang`, calls `window.history.pushState` in `go`,
  `window.location.assign` in `leave`, and listens for `popstate`.
- `App.tsx:App` sets `document.title`; `App.tsx:Frame` registers the mod+k
  hotkey and shows toasts when a screen calls `say`.
- `main.tsx` imports global CSS: IBM Plex fonts, Astryx `reset.css` and
  `astryx.css`, `@hodor-theme/hodor.css`, `layer-rules.css`, `console.css`.

## Verification

- Run from `frontend/admin-console`: `npm test` (Vitest: `App.test.tsx`,
  `address.test.ts`, `client.test.ts`, `messages/messages.test.ts`),
  `npm run typecheck`, `npm run lint`.
