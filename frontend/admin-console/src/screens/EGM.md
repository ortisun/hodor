# screens

## Overview

The screens of the administration console: users and one user, groups and
one group, organizations and one organization, service accounts and agents
and one of each with its API keys, identity providers and one provider,
applications, one application with its clients and resource server, one
client, the trust domains and one trust domain, webhook endpoints and one
endpoint with its deliveries, and the audit log. Each screen loads what it shows
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
- `shared.tsx:follow(event, go, screen)` - a plain primary click calls `go`;
  one with meta, control or shift, or another button, is left to the browser.
- `names.tsx:NameOf` - a user, group or organization named by identifier: a
  link to its screen showing its name once `client.getUser`, `getGroup` or
  `getOrganization` answers, or the shortened identifier until then or on
  failure. Without `users:read`, `groups:read` or `organizations:read` it
  shows `../parts/Identifier.tsx:Identifier` and asks for nothing.
- `NamedList.tsx:NamedList` - the table of groups or organizations, a page at
  a time, with "load more", and the creating `NamedForm`, then `go` to the new
  one. `GroupsScreen.tsx:GroupsScreen` (`client.listGroups`,
  `client.createGroup`, `createGroup`) and
  `OrganizationsScreen.tsx:OrganizationsScreen` (`client.listOrganizations`,
  `client.createOrganization`, `createOrganization`) configure it.
- `NamedForm.tsx:NamedForm` - name and optional description; when changing,
  disabled until something differs, and says `identifierKept`. A name taken or
  invalid shows on the name field.
- `GroupScreen.tsx:GroupScreen` - one group (`client.getGroup`) and its direct
  members a page at a time (`client.listGroupMembers`). Change (`NamedForm`,
  `changeGroup`), delete (`Confirm` `deleteGroup`, the name typed, then `go`
  to `groups`), add a member (`AddMember`, `addGroupMember`: kind and
  identifier, refused without asking the server when not an identifier), take
  one out (`Confirm` `removeGroupMember`).
- `OrganizationForms.tsx:treeOf` - units in tree order, siblings by name, with
  their depth and path (`Engineering / Platform`); a unit whose parent is
  unknown is at the top. `UnitForm` (name, kind, parent; changing excludes the
  unit and every unit below it from the parents), `MemberForm` (user
  identifier when putting, and units), `InviteForm` (address, units, language
  of the message).
- `OrganizationScreen.tsx:OrganizationScreen` - one organization
  (`client.getOrganization`), its units (`client.listUnits`, indented by
  `data-depth` on `.console-unit`), members a page at a time
  (`client.listOrganizationMembers`) and pending invitations
  (`client.listInvitations`), each loaded on its own. Change, delete (the name
  typed), create, change or delete a unit (the unit's name typed), put a member
  or change their units (`client.putOrganizationMember`), take one out,
  invite (`client.invite`) and withdraw (`client.withdrawInvitation`).
- `UserMemberships.tsx:UserGroups`, `UserOrganizations` - on `UserScreen`, with
  `groups:read` the user's groups (`client.groupsOfUser`), direct or through
  another; with `organizations:read` their organizations
  (`client.organizationsOfUser`) and units, named from `client.listUnits` of
  each organization with units.
- `WorkloadForm.tsx:WorkloadForm` - a service account's or an agent's name
  and owners, one user identifier a line (`linesOf`), refused without asking
  the server when one is not an identifier; `createWorkload` (level 0) or
  `changeWorkload` (level 1, says `workloadKept`). `ofKind(kind, pair)` picks
  the copy of one kind from a pair.
- `WorkloadsScreen.tsx:WorkloadsScreen` - with `kind` `service_account` or
  `agent`, the table a page at a time (`client.listWorkloads(kind, cursor)`),
  with status and the number of owners, and the creating `WorkloadForm`
  (`client.createWorkload`), then `go` to the new one (`screenOf`).
- `WorkloadScreen.tsx:WorkloadScreen` - one workload (`client.getWorkload`):
  its owners by `NameOf`, its API keys (`ApiKeys`), the roles it holds
  (`RoleAssignments` of kind `user`, with `roles:read`). Change
  (`WorkloadForm`), disable (`Confirm` `disableWorkload`, the name typed),
  enable (`enableWorkload`), delete (`deleteWorkload`, the name typed, then
  `go` to the list).
- `ApiKeys.tsx:ApiKeys` - a workload's keys, newest first
  (`client.listApiKeys`), each with `hodor_ak_…` and its last four
  characters, its scopes, status, expiry and last use. `ApiKeyForm` (name,
  scopes one a line, an optional application identifier, a lifetime of 1 to
  365 days, 90 unless changed) calls `client.createApiKey`; a key that works
  and was not replaced is rotated (`Confirm` `rotateApiKey`,
  `client.rotateApiKey`) and revoked (`Confirm` `revokeApiKey`, the key's name
  typed). A new key goes to `../parts/ShownOnce.tsx:ShownOnce` and is
  forgotten when it closes. Making a key is offered only for an active
  workload.
- `WebhookForms.tsx:EndpointForm`, `SubscriptionsForm` - an endpoint's
  address, description and event types, and replacing its event types. The
  catalog comes from `client.listEventTypes`; each type is a checkbox, in the
  groups of the webhooks context (`groupOf`), and the chosen ones are sent in
  the catalog's order.
- `WebhooksScreen.tsx:WebhooksScreen` - the endpoints a page at a time
  (`client.listEndpoints`), and `EndpointForm` (`registerEndpoint`,
  `client.registerEndpoint`); the secret is shown by `ShownOnce`, then `go` to
  the endpoint.
- `WebhookScreen.tsx:WebhookScreen` - one endpoint (`client.getEndpoint`): its
  settings and event types, its secrets in force, and its deliveries a page at
  a time (`client.listDeliveries(id, status, cursor)`) filtered by status.
  Change the event types (`SubscriptionsForm`, `client.replaceSubscriptions`),
  rotate the secret (`Confirm` `rotateEndpointSecret`, the address typed; the
  new secret by `ShownOnce`), remove it (`removeEndpoint`, the address typed,
  then `go` to `webhooks`), deliver a set-aside delivery again (`Confirm`
  `redeliver`, `client.redeliver`). `DeliveryBadge` is a delivery's status.
- `TrustDomainForm.tsx:TrustDomainForm` - adds a trust domain (`current`
  `null`: name, `addTrustDomain`, level 1) or replaces the source of one (no
  name, which never changes; `replaceTrustDomain`, level 1). The source is a
  `RadioList` of `bundle_endpoint` (an address), `uploaded` (the bundle in a
  text area, refused with `text.bundleNotJson` without asking the server when
  it is not JSON) and `mesh` (nothing more); `submit(name, settings)` gets a
  `TrustDomainSettings`. It says the consequence before its button, and
  replacing a `mesh` trust domain with `mesh` is not offered.
- `TrustDomainsScreen.tsx:TrustDomainsScreen` - the trust domains a page at a
  time (`client.listTrustDomains`), each with its name as a link, its
  source, `BundleStatus` and when the bundle changed, or that the mesh checks
  its workloads, and its last refresh: when it was fetched, since when and
  why it fails, when it is fetched next; replaced by hand for `uploaded`,
  nothing to fetch for `mesh`. "Add trust domain" (`addTrustDomain`) opens
  `TrustDomainForm` (`client.addTrustDomain`), then `go` to the new one.
- `TrustDomainsScreen.tsx:BundleStatus` - a badge: no bundle (`mesh`), fetching
  fails (a refresh with `failingSince`), or in force.
  `TrustDomainsScreen.tsx:bundleFailure(code, text)` - the code of why a fetch
  fails, in words from `text.bundleFailures`, or the code itself when unknown.
- `TrustDomainScreen.tsx:TrustDomainScreen` - one trust domain
  (`client.getTrustDomain`): its identifier, name, source with its sentence,
  bundle endpoint address; the bundle in force summarized (sequence number,
  refresh hint by `lifetime`, how many authorities for X509-SVIDs and for
  JWT-SVIDs, when it changed), or `text.meshLead` for `mesh`; for a bundle
  endpoint, its refresh (last fetch that read, next fetch, and while failing
  since when and why). Replace the source (`TrustDomainForm`,
  `client.replaceTrustDomain`, the answer replaces the shown value) and
  remove it (`Confirm` `removeTrustDomain`, the name typed, then `go` to
  `trustDomains`), both gated by `may(..., "replaceTrustDomain")`.
- `names.tsx:PrincipalOf` - on `ClientScreen`, the workload a client acts as:
  asked as a service account, then as an agent, and shown as a link with its
  name; without `workloads:read`, the identifier.
- `UsersScreen.tsx:nameOf`, `UsersScreen.tsx:StatusBadge` - a user's list name
  (display name, then primary identifier, then `text.unnamed`) and status badge.
- `AuthorizationScreen.tsx:AuthorizationScreen` - the tenant's authorization at `/authorization`: roles (`client.listRoles`, with the resource servers to find a role's by audience), each changed in `RoleEditor` with its permissions written one a line as `name` or `name if condition` (`permissionLines`, `readPermissionLines`) and saved with `client.defineRole`; bindings (`client.listBindings`, removed with `client.unbind` behind `Confirm` `unbind`); the policy status (`client.policyStatus`; publishing is the command line's); the latest decisions (`client.listDecisions`, filtered by effect). Each part only with its read permission.
- `RoleAssignments.tsx:RoleAssignments` - the roles a user or a client holds (`client.listAssignments`), each taken away with `client.revokeAssignment` behind `Confirm` `revokeRole`, the role's name typed; shown on `UserScreen` and `ClientScreen` with `roles:read`.
- `UserScreen.tsx:UserScreen` - one user, loaded with `client.getUser(id)`;
  sessions loaded with `client.listSessions(id)`. "Suspend user"
  (`suspendUser`) calls `client.suspendUser(id, reason)`; "End session"
  (`endSession`) calls `client.endSession(sessionId)`; both go through
  `Confirm`. With `credentials:read` it shows the user's factors from
  `client.listFactors(id)`; with `credentials:write` (`removeFactor`, level 2,
  the typed primary identifier) it removes the application, a key or the
  recovery codes, and the dialog says when it is the last second factor and
  that no session ends. A card `standardClaims` lists the person's standard
  claims that have a value, each labelled `text.claimLabel(claim)`, the
  telephone number with a badge `verified` or `notVerified`; with none it
  says `noStandardClaims`. The console shows them and does not change them.
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
- `ApplicationsScreen.tsx:ApplicationsScreen` - the application table, loaded
  with `client.listApplications()`; "Register application" (`addApplication`)
  opens `ApplicationForm`, which calls `client.addApplication(settings)`, then
  `go` to the new application.
- `ApplicationForm.tsx:ApplicationForm` - name and first party; says before its
  button whether people will be asked for consent (`consentSkipped`,
  `consentAsked`). When changing, it is disabled until something differs.
- `ApplicationScreen.tsx:ApplicationScreen` - one application, its clients and
  its resource server, loaded together with `client.getApplication(id)`,
  `client.listClients(id)` and `client.listResourceServers()` (the one whose
  `applicationId` is this one). Change (`changeApplication`), disable (`Confirm`
  with `disableApplication`, the name typed), enable (`enableApplication`),
  create a client (`ClientForm`, `client.addClient`) and register or change the
  resource server (`ResourceServerForm`).
- `ClientForm.tsx:ClientForm` - name, type (only when creating), method (a
  `RadioList` of the seven confidential methods, each with its sentence from
  `text.methodHints`; not for a public client), grants (`client_credentials`
  not offered to a public client), redirect addresses one per line
  (`linesOf`), addresses after signing out one per line, the front-channel
  logout address (`text.frontchannelLogoutUriHint`; left empty it is
  `null`) with, once one is written, a `Switch` for
  `frontchannelLogoutSessionRequired`, scopes separated by spaces, and
  whether access tokens are
  bound to the certificate (a `Switch`, not for `linkerd_identity`). A method
  of a workload's identity (`spiffe_jwt`, `spiffe_x509`, `tls_client_auth`,
  `linkerd_identity`) asks for the service account's identifier, refused with
  `text.principalNotAnIdentifier` without asking the server when it has not
  the shape of one, and for the identity it takes: the SPIFFE identifier, the
  Linkerd identity, or for `tls_client_auth` one of the two chosen with a
  `SegmentedControl`; it offers only `client_credentials` and no redirect
  address, and sends empty ones and no front-channel logout address.
  `submit(type, settings)` returns a promise;
  a failure it throws is shown and the form stays open.
- `ResourceServerForm.tsx:ResourceServerForm` - audience (fixed when changing),
  name and scopes one per line as `name description` (`definedScopesOf`,
  `writtenScopes`).
- `ClientScreen.tsx:ClientScreen` - one client, loaded with
  `client.getClient(id)`: its identifier whole, settings (with the SPIFFE
  identifier or the Linkerd identity when it has one, its front-channel
  logout address when it has one, with `text.frontchannelLogoutUriHint`
  beside it, and whether its access tokens are bound to a certificate),
  token lifetimes
  (`lifetime`), secrets by identifier and expiry, keys for `private_key_jwt`.
  Change (`ClientForm`, `client.changeClient`), give a new secret (`Confirm`
  with `rotateSecret`, the name typed, `client.rotateSecret`), end a secret
  (`revokeSecret`, the name typed), add a key (`KeyForm`, `client.addKey`),
  remove a key (`removeKey`), disable (`disableClient`, the name typed) and
  enable (`enableClient`).
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
- A client's secret is shown only by `../parts/ShownOnce.tsx:ShownOnce`, right
  after the answer that made it (creating a client with a secret method, giving
  a new secret), and is dropped from state when that dialog closes. Creating a
  client with a secret goes to the client's page only after the dialog closes.
- `ClientScreen.tsx:KeyForm` refuses text that is not JSON with
  `text.keyNotJson` without asking the server, as `TrustDomainForm` refuses a
  bundle with `text.bundleNotJson`.
- A trust domain's keys are never shown: the client keeps only how many
  elements of each `use` its bundle holds.
- `ProviderForm.tsx:ProviderForm` sends, when changing, only the fields that
  differ and is disabled until one does; when adding, alias, display name,
  issuer, client identifier and secret must all be non-empty. The secret field
  is cleared after a successful submit and never shown again.
- `UsersScreen.tsx:CreateUser` is a level 0 form, its own confirmation; the
  codes `identity.identifier_taken` and `identity.email_invalid` show on the
  email field.
- An invitation shows its address, units and expiry only; no link or secret
  is ever read from an answer.
- Lists with "load more" (users, audit, groups, organizations, the members of
  a group or an organization, workloads, endpoints, deliveries, trust
  domains) do nothing while busy or when
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
