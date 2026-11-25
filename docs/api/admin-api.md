# The administration interface

The administration interface is how the people who run a tenant, and the programs they write, manage it: its users, their sessions, its audit log, its identity providers and its keys. It is the first part of the Admin API outlined in the [API specification](api-spec.md#admin-api); this page specifies what is built.

All paths are relative to the tenant: `https://{host}/t/{slug}/api/v1/admin`. Requests and responses are JSON and follow the [conventions for the JSON APIs](api-spec.md#conventions-for-the-json-apis). Errors are problem documents.

The same interface is described for programs in an OpenAPI document, served at `GET /api/v1/admin/openapi.json` without authentication. The document and this page must say the same thing; a test checks that every route the server answers is in the document and that every route in the document is answered.

## Who may call it

Every request carries, in the `Authorization` header, a person's [access token](../architecture/contexts/credential.md#access-tokens) or a workload's [API key](../architecture/contexts/credential.md#api-keys):

```
Authorization: Bearer hodor_at_3f9c…
Authorization: Bearer hodor_ak_7d02…
```

A request is answered only if all of these hold, checked in this order:

1. **The token or the key is good in this tenant**: well formed, known here, not expired, not revoked. One of another tenant is not known here.
2. **Its holder may act.** A token's user may sign in: a suspended user's tokens stop working, and only a person may sign in, so a token of a [service account or an agent](#service-accounts-and-agents) is never good here. A key's holder is a service account or an agent that is active: disabling it stops its keys.
3. **It may do what the route needs**, in this tenant ([authorization](../architecture/contexts/authorization.md)). A token's user holds a role with the route's permission. A key holds the permission among its scopes **and** its holder holds a role with it.

| Failing | Status | Code | Says |
|---|---|---|---|
| 1 or 2 | `401`, with `WWW-Authenticate: Bearer` | `admin.not_authenticated` | The same thing in every case: nothing presented, a malformed token or key, an unknown, expired or revoked one, another tenant's, or one whose holder may not act |
| 3 | `403` | `admin.forbidden` | That the token or key is good and may not do this |

What a key does is in the audit log with its holder as the actor.

The check comes before anything else. A request that is refused learns nothing about what it asked for: not whether a user exists, not whether a body was valid.

There are no cookies on this interface, so there is nothing for another site to forge and no CSRF token. The [admin console](../architecture/admin-console.md) reaches the same routes through the [console interface](console-interface.md), which recognizes a person by their session.

### The first administrator

Nobody can be given a role through this interface yet, so the first administrator of a tenant is made from outside it, by someone who can run commands against the installation:

```
hodor-cli admin bootstrap --tenant acme --email ana@example.com
```

The command:

1. Finds the user with that address in the tenant, or creates one, active and without a password.
2. Gives the user the `tenant_administrator` role, if they do not hold it already.
3. Issues an access token for the user and prints it, once.

```
user 0193f1c2-… ana@example.com
role tenant_administrator
token hodor_at_3f9c…
expires 2026-11-21T15:03:11Z
```

The token lives for one hour unless `--token-minutes` says otherwise, from 1 to 43200, which is 30 days. It works in its own tenant and in no other.

The command can be run again, for the same person or another: each run issues a new token and leaves earlier ones as they are. It is also the way back in when every administrator has lost access. Whoever can run it can already read and change the database, so it grants nothing they did not have; what it does is recorded in the audit log like everything else, with Hodor itself as the actor.

It needs `HODOR_DATABASE_URL`, like the tenant commands.

## Routes

| Method and path | Permission | Purpose |
|---|---|---|
| `POST /users` | `users:write` | Create a user |
| `GET /users` | `users:read` | List users |
| `GET /users/{user_id}` | `users:read` | Read one user |
| `POST /users/{user_id}:suspend` | `users:write` | Suspend a user |
| `GET /users/{user_id}/sessions` | `sessions:read` | List a user's active sessions |
| `GET /users/{user_id}/factors` | `credentials:read` | List a user's second factors and how many recovery codes are left |
| `DELETE /users/{user_id}/factors/authenticator-application` | `credentials:write` | Remove a user's authenticator application |
| `DELETE /users/{user_id}/factors/keys/{key_id}` | `credentials:write` | Remove one of a user's security keys or passkeys |
| `DELETE /users/{user_id}/factors/recovery-codes` | `credentials:write` | Remove a user's recovery codes |
| `DELETE /sessions/{session_id}` | `sessions:revoke` | End a session |
| `GET /users/{user_id}/consents` | `users:read` | List the consents a user gave that stand |
| `DELETE /users/{user_id}/consents/{client_id}` | `users:write` | Withdraw a user's consent for a client |
| `GET /audit-records` | `audit:read` | Read the audit log |
| `GET /identity-providers` | `identity-providers:read` | List the tenant's identity providers |
| `POST /identity-providers` | `identity-providers:write` | Add an identity provider |
| `GET /identity-providers/{provider_id}` | `identity-providers:read` | Read one identity provider |
| `PATCH /identity-providers/{provider_id}` | `identity-providers:write` | Change an identity provider's settings |
| `PUT /identity-providers/{provider_id}/client-secret` | `identity-providers:write` | Replace its client secret |
| `POST /identity-providers/{provider_id}:disable` | `identity-providers:write` | Stop it from signing people in |
| `POST /identity-providers/{provider_id}:enable` | `identity-providers:write` | Let it sign people in again |
| `GET /keys/{key_set}` | `keys:read` | List the versions of a key set: `sig` or `data` |
| `POST /keys/{key_set}:rotate` | `keys:write` | Activate a new signing version at once |
| `POST /keys/{key_set}/versions/{version_id}:revoke` | `keys:write` | Revoke a version, with a reason |
| `GET /trust-domains` | `keys:read` | List the tenant's trust domains, with their bundles |
| `POST /trust-domains` | `keys:write` | Add a trust domain: its bundle, its bundle endpoint, or the mesh |
| `GET /trust-domains/{trust_domain_id}` | `keys:read` | Read one trust domain |
| `PUT /trust-domains/{trust_domain_id}` | `keys:write` | Replace its source and bundle |
| `DELETE /trust-domains/{trust_domain_id}` | `keys:write` | Remove it |
| `GET /applications` | `applications:read` | List the tenant's applications |
| `POST /applications` | `applications:write` | Register an application |
| `GET /applications/{application_id}` | `applications:read` | Read one application |
| `PATCH /applications/{application_id}` | `applications:write` | Change its name or whether it is first party |
| `POST /applications/{application_id}:disable` | `applications:write` | Stop its clients from getting tokens |
| `POST /applications/{application_id}:enable` | `applications:write` | Let its clients get tokens again |
| `GET /applications/{application_id}/clients` | `applications:read` | List an application's clients |
| `POST /applications/{application_id}/clients` | `applications:write` | Create a client of an application |
| `GET /clients/{client_id}` | `applications:read` | Read one client |
| `PATCH /clients/{client_id}` | `applications:write` | Change a client's settings |
| `POST /clients/{client_id}:disable` | `applications:write` | Stop a client from getting tokens |
| `POST /clients/{client_id}:enable` | `applications:write` | Let a client get tokens again |
| `POST /clients/{client_id}/secrets` | `applications:write` | Give a client a new secret |
| `DELETE /clients/{client_id}/secrets/{secret_id}` | `applications:write` | End one of its secrets at once |
| `POST /clients/{client_id}/keys` | `applications:write` | Add a public key for `private_key_jwt` |
| `DELETE /clients/{client_id}/keys/{key_id}` | `applications:write` | Remove one of its keys |
| `GET /clients/{client_id}/claim-mappers` | `applications:read` | List a client's claim mappers |
| `POST /clients/{client_id}/claim-mappers` | `applications:write` | Add a claim mapper to a client |
| `GET /clients/{client_id}/claim-mappers/{claim_mapper_id}` | `applications:read` | Read one claim mapper |
| `PUT /clients/{client_id}/claim-mappers/{claim_mapper_id}` | `applications:write` | Replace a claim mapper |
| `DELETE /clients/{client_id}/claim-mappers/{claim_mapper_id}` | `applications:write` | Delete a claim mapper |
| `GET /resource-servers` | `applications:read` | List the tenant's resource servers |
| `POST /resource-servers` | `applications:write` | Register the resource server of an application |
| `GET /resource-servers/{resource_server_id}` | `applications:read` | Read one resource server |
| `PATCH /resource-servers/{resource_server_id}` | `applications:write` | Change its name or its scopes |
| `GET /scim-deprovisioning` | `users:read` | Read the tenant's SCIM deprovisioning policy |
| `PUT /scim-deprovisioning` | `users:write` | Set it |
| `GET /email-sign-in` | `users:read` | Read whether people of the tenant may sign in with a code or a link by email |
| `PUT /email-sign-in` | `users:write` | Set it |
| `GET /assurance-levels` | `assurance-levels:read` | Read the tenant's assurance levels |
| `PUT /assurance-levels` | `assurance-levels:write` | Replace the tenant's assurance levels |
| `GET /decision-log` | `decisions:read` | Read the settings of the record of decisions |
| `PUT /decision-log` | `decision-log:write` | Replace the settings of the record of decisions |
| `GET /decisions` | `decisions:read` | List recorded decisions, newest first |
| `GET /resource-servers/{resource_server_id}/permissions` | `roles:read` | List the permissions of a resource server |
| `PUT /resource-servers/{resource_server_id}/permissions/{permission}` | `roles:write` | Declare a permission, or describe it again |
| `DELETE /resource-servers/{resource_server_id}/permissions/{permission}` | `roles:write` | Remove a permission, and remove it from every role |
| `GET /roles` | `roles:read` | List the tenant's roles |
| `GET /resource-servers/{resource_server_id}/roles/{role}` | `roles:read` | Read one role |
| `PUT /resource-servers/{resource_server_id}/roles/{role}` | `roles:write` | Define a role, or replace it |
| `DELETE /resource-servers/{resource_server_id}/roles/{role}` | `roles:write` | Remove a role that no other role includes |
| `GET /users/{user_id}/role-assignments` | `roles:read` | List the roles a user holds |
| `GET /clients/{client_id}/role-assignments` | `roles:read` | List the roles a client holds |
| `GET /groups/{group_id}/role-assignments` | `roles:read` | List the roles a group holds |
| `POST /role-assignments` | `roles:write` | Give a role to a user or a client |
| `POST /role-assignments:revoke` | `roles:write` | Take a role away |
| `GET /resource-servers/{resource_server_id}/access-entries` | `access-entries:read` | List the entries of a resource server's access control lists, oldest first |
| `POST /resource-servers/{resource_server_id}/access-entries` | `access-entries:write` | Grant a principal a permission on one resource |
| `GET /access-entries/{entry_id}` | `access-entries:read` | Read one entry |
| `DELETE /access-entries/{entry_id}` | `access-entries:write` | Remove an entry |
| `GET /bindings` | `bindings:read` | List which engine answers for each resource server |
| `GET /resource-servers/{resource_server_id}/binding` | `bindings:read` | Read a resource server's binding |
| `PUT /resource-servers/{resource_server_id}/binding` | `bindings:write` | Bind a resource server to an engine, or change the binding |
| `DELETE /resource-servers/{resource_server_id}/binding` | `bindings:write` | Remove the binding: everything is denied afterwards |
| `GET /policy-versions` | `policies:read` | List the latest policy versions |
| `POST /policy-versions` | `policies:write` | Draft a policy version |
| `GET /policy-versions/{number}` | `policies:read` | Read a version with its files and report |
| `POST /policy-versions/{number}:validate` | `policies:write` | Ask for a draft to be checked |
| `POST /policy-versions/{number}:test` | `policies:write` | Ask for a checked version's tests to be run |
| `POST /policy-versions/{number}/simulations` | `policies:write` | Ask for a version to be simulated on given inputs |
| `GET /policy-simulations/{simulation_id}` | `policies:read` | Read a simulation and its answers |
| `GET /policy-status` | `policies:read` | Read what is published and what each instance runs |
| `GET /groups` | `groups:read` | List the tenant's groups |
| `POST /groups` | `groups:write` | Create a group |
| `GET /groups/{group_id}` | `groups:read` | Read one group |
| `PATCH /groups/{group_id}` | `groups:write` | Change its name or description |
| `DELETE /groups/{group_id}` | `groups:write` | Delete it, with every membership it is part of |
| `GET /groups/{group_id}/members` | `groups:read` | List its direct members, users first |
| `POST /groups/{group_id}/members` | `groups:write` | Add a user or a group |
| `POST /groups/{group_id}/members:remove` | `groups:write` | Take a user or a group out |
| `GET /users/{user_id}/groups` | `groups:read` | List the groups a user is in, directly or through others |
| `GET /organizations` | `organizations:read` | List the tenant's organizations |
| `POST /organizations` | `organizations:write` | Create an organization |
| `GET /organizations/{organization_id}` | `organizations:read` | Read one organization |
| `PATCH /organizations/{organization_id}` | `organizations:write` | Change its name or description |
| `DELETE /organizations/{organization_id}` | `organizations:write` | Delete it, with its units, members and invitations |
| `GET /organizations/{organization_id}/units` | `organizations:read` | List its units, each with its parent |
| `POST /organizations/{organization_id}/units` | `organizations:write` | Create a unit |
| `PUT /organizations/{organization_id}/units/{unit_id}` | `organizations:write` | Rename a unit, change its kind, or move it |
| `DELETE /organizations/{organization_id}/units/{unit_id}` | `organizations:write` | Delete a unit with no unit below it |
| `GET /organizations/{organization_id}/members` | `organizations:read` | List its members with their units |
| `PUT /organizations/{organization_id}/members/{user_id}` | `organizations:write` | Make a user a member, or replace the units of a member |
| `DELETE /organizations/{organization_id}/members/{user_id}` | `organizations:write` | Take a user out |
| `GET /organizations/{organization_id}/invitations` | `organizations:read` | List its pending invitations |
| `POST /organizations/{organization_id}/invitations` | `organizations:write` | Invite an email address |
| `DELETE /organizations/{organization_id}/invitations/{invitation_id}` | `organizations:write` | Withdraw a pending invitation |
| `GET /users/{user_id}/organizations` | `organizations:read` | List the organizations a user is in, with their units |
| `GET /service-accounts` | `workloads:read` | List the tenant's service accounts |
| `POST /service-accounts` | `workloads:write` | Create a service account |
| `GET /service-accounts/{service_account_id}` | `workloads:read` | Read one service account |
| `PATCH /service-accounts/{service_account_id}` | `workloads:write` | Rename it, or replace its owners |
| `POST /service-accounts/{service_account_id}:disable` | `workloads:write` | Disable it: its clients get no tokens and its tokens stop at once |
| `POST /service-accounts/{service_account_id}:enable` | `workloads:write` | Enable it again |
| `DELETE /service-accounts/{service_account_id}` | `workloads:write` | Delete it |
| `GET /agents` | `workloads:read` | List the tenant's agents |
| `POST /agents` | `workloads:write` | Create an agent |
| `GET /agents/{agent_id}` | `workloads:read` | Read one agent |
| `PATCH /agents/{agent_id}` | `workloads:write` | Rename it, or replace its owners |
| `POST /agents/{agent_id}:disable` | `workloads:write` | Disable it: its clients get no tokens and its tokens stop at once |
| `POST /agents/{agent_id}:enable` | `workloads:write` | Enable it again |
| `DELETE /agents/{agent_id}` | `workloads:write` | Delete it |
| `GET /webhook-event-types` | `webhooks:read` | List the event types an endpoint can be subscribed to |
| `GET /webhook-endpoints` | `webhooks:read` | List the tenant's webhook endpoints |
| `POST /webhook-endpoints` | `webhooks:write` | Register an endpoint, and see its secret once |
| `GET /webhook-endpoints/{endpoint_id}` | `webhooks:read` | Read one endpoint |
| `DELETE /webhook-endpoints/{endpoint_id}` | `webhooks:write` | Remove it, with its secrets and deliveries |
| `PUT /webhook-endpoints/{endpoint_id}/subscriptions` | `webhooks:write` | Replace the event types it receives |
| `POST /webhook-endpoints/{endpoint_id}:rotate-secret` | `webhooks:write` | Give it a new secret, seen once; the previous one keeps signing for an overlap |
| `GET /webhook-deliveries` | `webhooks:read` | List deliveries, newest first, of one endpoint or all, of one status or all |
| `POST /webhook-deliveries/{delivery_id}:redeliver` | `webhooks:write` | Deliver a set-aside delivery again |
| `GET /service-accounts/{service_account_id}/api-keys` | `workloads:read` | List the service account's API keys, never the keys themselves |
| `POST /service-accounts/{service_account_id}/api-keys` | `workloads:write` | Make an API key for it, shown once |
| `POST /service-accounts/{service_account_id}/api-keys/{api_key_id}:rotate` | `workloads:write` | Replace a key with a new one, shown once; the old one keeps working for an overlap |
| `DELETE /service-accounts/{service_account_id}/api-keys/{api_key_id}` | `workloads:write` | Revoke a key at once |
| `GET /agents/{agent_id}/api-keys` | `workloads:read` | List the agent's API keys, never the keys themselves |
| `POST /agents/{agent_id}/api-keys` | `workloads:write` | Make an API key for it, shown once |
| `POST /agents/{agent_id}/api-keys/{api_key_id}:rotate` | `workloads:write` | Replace a key with a new one, shown once; the old one keeps working for an overlap |
| `DELETE /agents/{agent_id}/api-keys/{api_key_id}` | `workloads:write` | Revoke a key at once |

### A user

```json
{
  "id": "0193f1c2-…",
  "kind": "human",
  "status": "active",
  "status_reason": null,
  "display_name": "Ana Silva",
  "locale": "pt-BR",
  "identifiers": [
    { "id": "0193f1c3-…", "kind": "email", "value": "ana@example.com", "verified": true, "primary": true }
  ],
  "created_at": "2026-11-20T14:03:11Z",
  "updated_at": "2026-11-20T14:03:11Z"
}
```

### Creating a user

`POST /users` with:

```json
{ "email": "ana@example.com", "display_name": "Ana Silva", "locale": "pt-BR" }
```

`display_name` and `locale` are optional. The answer is `201` with the user.

The user is created active, with the address not yet verified and without a password. The person chooses a password by [recovering it](interaction-api.md#registering-and-recovering-a-password), which also verifies the address. An administrator never knows or sets anyone's password.

An address that already has an account is refused with `409` and `identity.identifier_taken`. This interface may say so: its caller is allowed to see the tenant's users.

### Listing users

`GET /users?limit=50&cursor=…` answers with users in the order they were created, oldest first:

```json
{ "items": [ … ], "next_cursor": "0193f1c2-…" }
```

`limit` is 50 unless given, and at most 200. `next_cursor` is absent on the last page; otherwise it is passed back as `cursor` to get the next one. A cursor that is not one this interface gave out is refused with `422`.

### Suspending a user

`POST /users/{user_id}:suspend` with `{ "reason": "left the company" }` answers `200` with the user. A suspended user cannot sign in, and their sessions end with the next request each one makes. A reason is required. Suspending a user who is not active is refused with `409`.

### Sessions

`GET /users/{user_id}/sessions` answers with the user's active sessions, newest first, as [a person sees their own](interaction-api.md#listing-sessions) but without `current`:

```json
{ "items": [ { "session_id": "…", "started_at": "…", "last_activity_at": "…", "expires_at": "…", "address": "…", "description": "…" } ] }
```

`DELETE /sessions/{session_id}` ends a session: `204`. A session that does not exist is `404` with `session.not_found`; ending one that has already ended changes nothing and answers `204`.

### A user's factors

`GET /users/{user_id}/factors` answers with what [the person sees of their own](interaction-api.md#listing-them), without `recent_sign_in_until`:

```json
{
  "authenticator_application": { "in_use": true },
  "keys": [ { "id": "0193f1d1-…", "name": "Blue key", "passkey": false, "created_at": "…", "last_used_at": null } ],
  "recovery_codes": { "remaining": 8 },
  "second_factor_required": true
}
```

It never holds a secret, a public key or a code. An administrator removes a factor for a person who lost it:

- `DELETE /users/{user_id}/factors/authenticator-application`: `204`, or `404` with `credential.totp_not_found` when none is in use;
- `DELETE /users/{user_id}/factors/keys/{key_id}`: `204`, or `404` with `credential.webauthn_credential_not_found`;
- `DELETE /users/{user_id}/factors/recovery-codes`: `204`, or `404` with `credential.recovery_codes_not_found` when the user has none.

The tenant's second factor policy does not refuse an administrator's removal, and removing a factor ends none of the user's sessions; [the authentication context](../architecture/contexts/authentication.md#what-an-administrator-may-do) says why. When the last second factor goes, the user's recovery codes go with it. A user that does not exist is `404` with `identity.user_not_found`. Each removal is in the audit log with the administrator as the actor.

### Consents

`GET /users/{user_id}/consents` answers with the consents the user gave that stand and have not expired, as [a person sees their own](interaction-api.md#the-persons-consents):

```json
{ "items": [ { "client_id": "…", "application": "Billing", "scopes": ["openid", "invoices:read"], "given_at": "…", "expires_at": "…" } ] }
```

`DELETE /users/{user_id}/consents/{client_id}` withdraws it: `204`, and every active grant of the user for that client is revoked ([withdrawing a consent](../architecture/contexts/oauth.md#withdrawing-a-consent)). A user who does not exist, or a consent the user does not have or that was withdrawn already, is `404`: `identity.user_not_found` or `oauth.consent_not_found`. The audit log records it as withdrawn by an administrator.

### The audit log

`GET /audit-records?limit=50&cursor=…` answers with the tenant's [audit records](../architecture/contexts/audit.md) in the order they were recorded, oldest first:

```json
{
  "items": [
    {
      "sequence": 42,
      "action": "identity.user_suspended",
      "occurred_at": "2026-11-20T14:03:11.482913Z",
      "recorded_at": "2026-11-20T14:03:11.731002Z",
      "actor": { "kind": "user", "id": "0193f1c2-…" },
      "correlation_id": "0193f1d0-…",
      "details": { "user_id": "0193f1c4-…", "reason": "left the company" },
      "previous_hash": "9a41…",
      "hash": "c07e…"
    }
  ],
  "next_cursor": "42"
}
```

The cursor is the sequence of the last record returned. Hashes are written in hexadecimal, so that a reader can check the chain for themselves.

What an administrator does through this interface is itself recorded: the actor of those records is the token's user.

### Identity providers

The rules behind these operations are in [the federation context](../architecture/contexts/federation.md#identity-providers).

An identity provider:

```json
{
  "id": "0193f1c2-…",
  "alias": "google",
  "kind": "openid_connect",
  "display_name": "Google",
  "issuer": "https://accounts.google.com",
  "client_id": "1234.apps.googleusercontent.com",
  "scopes": ["openid", "email", "profile"],
  "creates_users": true,
  "trusts_email": false,
  "status": "enabled",
  "callback_address": "https://auth.example.com/t/acme/account/providers/google/callback",
  "created_at": "2026-11-21T14:03:11Z",
  "updated_at": "2026-11-21T14:03:11Z"
}
```

`callback_address` is the address to register at the provider as the place it sends people back to. It is `null` for a directory, which nobody leaves for.

A provider of the kind `ldap`, a [directory](../architecture/contexts/federation.md#signing-in-through-a-directory), also has `directory`; every other kind has it `null`:

```json
"directory": {
  "base": "ou=people,dc=example,dc=com",
  "filter": "(uid={identifier})",
  "subject_attribute": "entryUUID",
  "email_attribute": "mail",
  "name_attribute": "cn"
}
```

For a directory, `issuer` is its address (`ldaps://host`), `client_id` is the name Hodor binds with to search, and `client_secret` is that name's password.

A provider of the kind `saml`, a [SAML identity provider](../architecture/contexts/federation.md#signing-in-through-a-saml-identity-provider), also has `saml`, and `metadata_address`; every other kind has them `null`:

```json
"saml": {
  "single_sign_on_address": "https://login.example.com/sso/saml",
  "certificate": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----",
  "email_attribute": "email",
  "name_attribute": "name"
},
"metadata_address": "https://auth.example.com/t/acme/interaction/sign-in/providers/corp/saml/metadata"
```

For a SAML provider, `issuer` is the identity provider's entity identifier, `client_id` is empty and there is no client secret. `metadata_address` is what to give the identity provider: Hodor's entity identifier and where responses are posted. `callback_address` is `null`.

**The client secret is never part of an answer.** It is given when a provider is added and when the secret is replaced, and after that no operation returns it.

`POST /identity-providers` with:

```json
{
  "alias": "google",
  "display_name": "Google",
  "issuer": "https://accounts.google.com",
  "client_id": "1234.apps.googleusercontent.com",
  "client_secret": "…",
  "scopes": ["openid", "email", "profile"],
  "creates_users": true
}
```

`kind` is `openid_connect` unless given; the others are `github`, for which `issuer` may be left out, `ldap`, which needs `directory` with at least `base` and `filter`, and `saml`, which needs `saml` with at least `single_sign_on_address` and `certificate` and takes neither `client_id` nor `client_secret`. The attribute names are `entryUUID`, `mail` and `cn` for a directory, `email` and `name` for a SAML provider, unless given. A certificate that cannot be used is refused with `422` and `federation.saml_invalid`; the problem's `detail` names the reason, such as `key_too_short`. A directory whose host and port are not on the installation's list is refused with `403` and `federation.directory_not_allowed`. `scopes`, `creates_users` and `trusts_email` are optional. The answer is `201` with the provider, enabled.

`trusts_email` is a statement about the provider that is easy to get wrong; read [what it means](../architecture/contexts/federation.md#when-a-provider-does-not-say-whether-it-vouches) before setting it.

`PATCH /identity-providers/{provider_id}` takes any of `display_name`, `issuer`, `client_id`, `scopes`, `creates_users`, `trusts_email`, for a directory `directory` with any of its fields, and for a SAML provider `saml` with any of its fields, such as a new `certificate` when the identity provider changes its keys; what is left out stays as it is. Neither the alias nor the kind can be changed: the alias is part of the callback address, and another kind is another provider. The answer is `200` with the provider.

`PUT /identity-providers/{provider_id}/client-secret` with `{ "client_secret": "…" }` answers `204`. A SAML provider has no secret: `422` with `federation.client_secret_invalid`.

`POST /identity-providers/{provider_id}:disable` and `:enable` take no body and answer `200` with the provider. A disabled provider is not offered on the sign-in page and signs nobody in; the people it let in keep their accounts and their links.

`GET /identity-providers` answers `{ "items": [ … ] }`, ordered by alias. A tenant has at most 20, so the list has no pages.

| Situation | Status | Code |
|---|---|---|
| A value breaks its rule | `422` | The federation context's code, such as `federation.issuer_invalid` |
| The alias is taken | `409` | `federation.alias_taken` |
| The tenant already has 20 providers | `409` | `federation.too_many_providers` |
| No such provider in this tenant | `404` | `federation.provider_not_found` |
| Someone else changed the provider at the same moment | `409` | `federation.provider_modified_concurrently` |
| The server has no keys to keep secrets with (`HODOR_SECRET_KEYS`) | `503` | `federation.not_configured` |

### Keys

The rules behind these operations are in [the keys context](../architecture/contexts/keys.md). Keys rotate by themselves on a schedule; these routes are for looking at them and for an operator who will not wait.

A key version:

```json
{
  "id": "0193f1c2-…",
  "key_use": "sig",
  "algorithm": "ES256",
  "state": "active",
  "provider": "local",
  "created_at": "2026-11-21T14:03:11Z",
  "activated_at": "2026-11-21T14:03:11Z",
  "retiring_at": null,
  "retire_after": null,
  "retired_at": null,
  "revoked_at": null,
  "revocation_reason": null
}
```

The `id` is the key identifier, `kid`, of the version in [the published key set](../architecture/contexts/keys.md#the-published-key-set). **Nothing of the key itself is part of an answer**, not even the public key: that is what the published key set is for.

`GET /keys/{key_set}` answers `{ "items": [ … ] }`, newest first, for `sig` or `data`. Revoked and retired versions are listed too: they are kept so that every signature can be traced to its key.

`POST /keys/sig:rotate` takes an optional body, `{ "algorithm": "ES256" }`, ES256 unless given, RS256 or PS256 otherwise. A pending version of that algorithm is activated, or a new one made and activated. The version it replaces starts retiring with the installation's overlap. The answer is `200` with the activated version. Only the signing key set rotates this way: `data` is refused with `422` and `keys.rotation_not_offered`.

`POST /keys/{key_set}/versions/{version_id}:revoke` with `{ "reason": "…" }`, 1 to 200 characters, answers `200` with the version, revoked. A signing version leaves the published key set at once. Revoking a revoked version changes nothing. To replace a key that is no longer trusted, rotate first and revoke the version that was replaced: revoking the active version first leaves the tenant signing nothing until the next pass of the rotation job.

| Situation | Status | Code |
|---|---|---|
| A key set other than `sig` or `data` | `404` | `keys.key_set_not_found` |
| No such version in this key set | `404` | `keys.version_not_found` |
| An algorithm that is not ES256, RS256 or PS256 | `422` | `keys.algorithm_unsuitable` |
| A reason that is empty or too long | `422` | `keys.reason_invalid` |
| Two activations at the same moment | `409` | `keys.activation_conflict` |
| The server has no keys to keep secrets with (`HODOR_SECRET_KEYS`) | `503` | `keys.not_configured` |

### Trust domains

The SPIFFE trust domains a tenant trusts, specified in [the keys context](../architecture/contexts/keys.md#trust-domains). A trust domain is answered as:

```json
{
  "id": "0193f3a0-…",
  "name": "prod.example.com",
  "source": "bundle_endpoint",
  "bundle_endpoint_url": "https://spire.example.com/bundle",
  "bundle": {
    "spiffe_sequence": 12,
    "spiffe_refresh_hint": 300,
    "keys": [
      { "use": "x509-svid", "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "x5c": ["MIIB…"] },
      { "use": "jwt-svid", "kty": "EC", "crv": "P-256", "kid": "…", "x": "…", "y": "…" }
    ]
  },
  "bundle_changed_at": "…",
  "refresh": {
    "fetched_at": "…",
    "next_at": "…",
    "failing_since": null,
    "last_error": null
  },
  "created_at": "…",
  "updated_at": "…"
}
```

`bundle_endpoint_url` and `refresh` are present only for the source `bundle_endpoint`; `bundle` and `bundle_changed_at` are absent for `mesh`. The bundle is the one in force, as Hodor keeps it: only the elements it kept, with their members in order. `refresh.failing_since` and `refresh.last_error` say, while fetching fails, since when and the code of the last reason; the bundle in force is then still the last one that read.

`POST /trust-domains` takes the name and one source:

```json
{ "name": "prod.example.com", "source": "uploaded", "bundle": { "keys": [ … ] } }
{ "name": "prod.example.com", "source": "bundle_endpoint", "bundle_endpoint_url": "https://spire.example.com/bundle" }
{ "name": "cluster.local", "source": "mesh" }
```

and answers `201` with the trust domain. A bundle endpoint is fetched before anything is stored. `PUT /trust-domains/{trust_domain_id}` takes the same body without `name`, which cannot change, and answers `200` with the trust domain; a refusal leaves it as it was. `DELETE` answers `204`. `GET /trust-domains` answers a page of `{ "items": [ … ], "next_cursor": … }` in the order of their identifiers.

| Situation | Status | Code |
|---|---|---|
| No trust domain of that identifier | `404` | `keys.trust_domain_not_found` |
| A name the tenant has already | `409` | `keys.trust_domain_name_taken` |
| A fifty-first trust domain | `409` | `keys.too_many_trust_domains` |
| The trust domain changed while it was being changed | `409` | `keys.trust_domain_changed` |
| A name that breaks its rule, or a source that is not one of the three or comes without what it needs | `422` | `keys.trust_domain_name_invalid`, `keys.trust_domain_source_invalid` |
| A bundle that does not read | `422` | `keys.trust_bundle_invalid` |
| A bundle endpoint that is not an HTTPS address of at most 1000 characters | `422` | `keys.bundle_endpoint_invalid` |
| A bundle endpoint that leads somewhere that may not be called, or resolves to nothing | `422` | `keys.bundle_endpoint_forbidden`, `keys.bundle_endpoint_unresolvable` |
| A bundle endpoint that did not answer a bundle: no answer in 10 seconds, a status other than 2xx, a redirect, or more than 64 kibibytes | `422` | `keys.bundle_endpoint_unreachable` |

### Applications, clients and resource servers

The rules behind these operations are in [the OAuth context](../architecture/contexts/oauth.md): what an application is, [what a client may be](../architecture/contexts/oauth.md#what-a-client-may-be), [redirect addresses](../architecture/contexts/oauth.md#redirect-addresses), [secrets](../architecture/contexts/oauth.md#secrets), [keys](../architecture/contexts/oauth.md#keys) and [resource servers](../architecture/contexts/oauth.md#resource-servers). This interface translates them and adds none of its own.

An application:

```json
{
  "id": "0193f1c2-…",
  "name": "Billing",
  "first_party": true,
  "status": "enabled",
  "created_at": "2026-11-22T14:03:11Z",
  "updated_at": "2026-11-22T14:03:11Z"
}
```

`POST /applications` with `{ "name": "Billing", "first_party": true }` answers `201` with the application, enabled. `first_party` is required: whether a person is asked for consent follows from it, so it is never assumed. Until consent exists, only the clients of a first-party application are answered by the authorization endpoint ([the OAuth context](../architecture/contexts/oauth.md#checking-the-request)).

`PATCH /applications/{application_id}` takes `name`, `first_party` or both; what is left out stays as it is. `POST /applications/{application_id}:disable` and `:enable` take no body and answer `200` with the application. `GET /applications` answers `{ "items": [ … ] }`, oldest first; a tenant has at most 100, so the list has no pages.

A client:

```json
{
  "id": "0193f1d0-…",
  "application_id": "0193f1c2-…",
  "name": "Billing web site",
  "type": "confidential",
  "authentication_method": "client_secret_basic",
  "grant_types": ["authorization_code", "refresh_token"],
  "redirect_uris": ["https://billing.example.com/callback"],
  "post_logout_redirect_uris": ["https://billing.example.com/signed-out"],
  "allowed_scopes": ["openid", "email", "invoices:read"],
  "require_pkce": true,
  "id_token_signed_response_alg": "ES256",
  "backchannel_logout_uri": "https://billing.example.com/backchannel-logout",
  "backchannel_logout_session_required": false,
  "subject_type": "public",
  "sector_identifier_uri": null,
  "principal": null,
  "exchange_rules": [],
  "spiffe_id": null,
  "linkerd_identity": null,
  "token_policy": {
    "access_token_seconds": 300,
    "id_token_seconds": 300,
    "refresh_token_seconds": 2592000,
    "refresh_idle_seconds": 604800
  },
  "secrets": [
    { "id": "0193f1d1-…", "created_at": "2026-11-22T14:03:11Z", "expires_at": "2027-11-22T14:03:11Z" }
  ],
  "keys": [],
  "status": "enabled",
  "created_at": "2026-11-22T14:03:11Z",
  "updated_at": "2026-11-22T14:03:11Z"
}
```

`id` is the `client_id` the client sends. `secrets` lists the secrets that exist, by identifier and expiry, never the secret or its hash. `keys` lists the public keys, each as `{ "kid": "…", "jwk": { … }, "added_at": "…" }`. `spiffe_id` is the SPIFFE identifier of a client using `spiffe_jwt`, `null` for any other.

`POST /applications/{application_id}/clients` with:

```json
{
  "name": "Billing web site",
  "type": "confidential",
  "grant_types": ["authorization_code", "refresh_token"],
  "redirect_uris": ["https://billing.example.com/callback"],
  "allowed_scopes": ["openid", "email", "invoices:read"]
}
```

`name`, `type` and `grant_types` are required. `authentication_method` is `client_secret_basic` for a confidential client and `none` for a public one unless given; `redirect_uris`, `post_logout_redirect_uris` and `allowed_scopes` are empty, `require_pkce` is `true`, `id_token_signed_response_alg` is `ES256` (or `RS256`; how its ID tokens are signed), `backchannel_logout_uri` is `null` and `backchannel_logout_session_required` `false`, and `token_policy` is the default of the OAuth context unless given, and `token_policy` may give any of its four fields. `principal`, the identifier of a service account or an agent, binds the client to it ([clients that act as a workload](../architecture/contexts/oauth.md#clients-that-act-as-a-workload)); it is `null` unless given, and a client with one has `client_credentials` and, for an agent, may have `urn:ietf:params:oauth:grant-type:token-exchange` besides. `exchange_rules`, a list of `{ "subject_audience": "…", "audience": "…" }`, is the [token exchange](../architecture/contexts/oauth.md#token-exchange) policy of an agent's client with that grant, and is empty otherwise. `spiffe_id`, `null` unless given, is the one SPIFFE identifier of a client using `spiffe_jwt`, such as `spiffe://cluster.local/ns/payroll/sa/nightly-export`, whose JWT-SVIDs then prove who the client is ([the SPIFFE identifier of a client](../architecture/contexts/oauth.md#the-spiffe-identifier-of-a-client)), or using `spiffe_x509`, whose X509-SVID a trusted proxy forwards ([an identity forwarded by a proxy](../architecture/contexts/oauth.md#an-identity-forwarded-by-a-proxy)): it is required with those methods, allowed with `tls_client_auth` and refused with any other, and the client's `principal` must then be a service account. An identifier that does not follow the SPIFFE rules, or ends in `/*`, is refused with `oauth.client_spiffe_id_invalid`, and one already bound to another client of the tenant with `oauth.client_spiffe_id_taken`. `linkerd_identity`, `null` unless given, is the one Linkerd identity of a client using `linkerd_identity`, such as `web.shop.serviceaccount.identity.linkerd.cluster.local`, which Linkerd's proxy forwards: it is required with that method, allowed with `tls_client_auth` and refused with any other, the client's `principal` must then be a service account, one that does not read is refused with `oauth.client_linkerd_identity_invalid`, and one already bound to another client of the tenant with `oauth.client_linkerd_identity_taken`. A client using `tls_client_auth` has exactly one of the two, and is refused with `oauth.client_spiffe_id_invalid` otherwise. These methods are for a confidential client, which then has no secret. `backchannel_logout_uri` is where Hodor sends a logout token when a session the client signed a person in with ends ([back-channel logout](../architecture/contexts/oauth.md#back-channel-logout)): an HTTPS address, only for a client with `authorization_code`, and checked when it is given as [a webhook endpoint's address](../architecture/contexts/oauth.md#the-back-channel-logout-address) is: one that leads to a private network is refused with `oauth.client_backchannel_logout_uri_forbidden`, a name that resolves to nothing with `oauth.client_backchannel_logout_uri_unresolvable`, and one that is not HTTPS or cannot be read with `oauth.client_backchannel_logout_uri_invalid`. `backchannel_logout_session_required` may be `true` only with an address; Hodor puts `sid` in every logout token whatever it says. `subject_type` is `public` unless given, or `pairwise`, only for a client with `authorization_code`, otherwise `oauth.client_subject_type_invalid`: a pairwise client knows each person by an identifier of its sector alone, in its ID tokens, access tokens, UserInfo, introspection and logout tokens ([pairwise subject identifiers](../architecture/contexts/oauth.md#pairwise-subject-identifiers)). Its sector is the host of `sector_identifier_uri` when it has one, or the one host of its redirect addresses; with redirect addresses of several hosts, or a private-use scheme, it needs `sector_identifier_uri`, otherwise `oauth.client_sector_identifier_uri_required`. `sector_identifier_uri`, `null` unless given and only for a pairwise client, is an HTTPS address that Hodor fetches when it is set, which must answer a JSON array holding every redirect address of the client ([the sector identifier address](../architecture/contexts/oauth.md#the-sector-identifier-address)): one that leads to a private network is refused with `oauth.client_sector_identifier_uri_forbidden`, a name that resolves to nothing with `oauth.client_sector_identifier_uri_unresolvable`, one that does not answer in time, answers another status or too much with `oauth.client_sector_identifier_uri_unreachable`, an answer that is not a JSON array of strings with `oauth.client_sector_identifier_uri_document_invalid`, a redirect address missing from it with `oauth.client_sector_identifier_uri_mismatch`, and an address that is not HTTPS or cannot be read with `oauth.client_sector_identifier_uri_invalid`. `secret_lifetime_days`, from 1 to 730, is how long the first secret lives; 365 unless given. The answer is `201` with the client. **A client with a secret method also has `client_secret` in this answer, once**: the secret itself, which no other answer holds and which Hodor cannot show again.

`PATCH /clients/{client_id}` takes any of `name`, `authentication_method`, `grant_types`, `redirect_uris`, `post_logout_redirect_uris`, `allowed_scopes`, `require_pkce`, `id_token_signed_response_alg`, `backchannel_logout_uri`, which `null` removes, `backchannel_logout_session_required`, `subject_type`, `sector_identifier_uri`, which `null` removes, `token_policy` (with any of its fields), `principal`, which `null` removes, `exchange_rules`, which replaces the list, and `spiffe_id` and `linkerd_identity`, which `null` removes; what is left out stays as it is, except that giving one identity removes the other, and the result is checked against every rule at once. The sector identifier address is fetched again when the change gives the client a new address, new redirect addresses or the pairwise subject type while it has one. **Changing `subject_type`, `sector_identifier_uri` or the host of the redirect addresses of a pairwise client changes the identifier by which it knows every person from then on.** The type and the application never change. Moving away from a secret method drops the client's secrets, moving away from `private_key_jwt` drops its keys, and moving to a method that does not take the client's `spiffe_id` or `linkerd_identity` drops it. The answer is `200` with the client.

`POST /clients/{client_id}/secrets` with `{ "lifetime_days": 365, "keep_previous_days": 7 }` makes a new secret. Both fields are optional: the new secret lives 365 days and the newest previous one keeps working 7 more days unless given; `keep_previous_days` is 0 to 30, and 0 ends it at once. Every older secret ends at once. The answer is `201` with `{ "id": "…", "client_secret": "hodor_cs_…", "created_at": "…", "expires_at": "…" }`, once. A client without a secret method is refused with `422` and `oauth.client_secret_not_allowed`.

`DELETE /clients/{client_id}/secrets/{secret_id}` ends one secret at once and answers `204`.

`POST /clients/{client_id}/keys` with `{ "jwk": { "kty": "EC", "crv": "P-256", "kid": "2026-11", "x": "…", "y": "…" } }` adds a public key to a client using `private_key_jwt` and answers `201` with the client. A key with a private part is refused with `422` and `oauth.client_key_invalid`, and nothing is kept. `DELETE /clients/{client_id}/keys/{key_id}` removes the key with that `kid`, written in the path with percent-encoding where it needs it, and answers `204`.

`POST /clients/{client_id}:disable` and `:enable` take no body and answer `200` with the client. `GET /applications/{application_id}/clients` answers `{ "items": [ … ] }`, oldest first; an application has at most 20.

A resource server:

```json
{
  "id": "0193f1e0-…",
  "application_id": "0193f1c2-…",
  "audience": "https://api.billing.example.com",
  "name": "Billing interface",
  "scopes": [
    { "name": "invoices:read", "description": "Read your invoices" }
  ],
  "created_at": "2026-11-22T14:03:11Z",
  "updated_at": "2026-11-22T14:03:11Z"
}
```

`POST /resource-servers` with `application_id`, `audience`, `name` and `scopes` answers `201` with it. `PATCH /resource-servers/{resource_server_id}` takes `name`, `scopes` or both; `scopes` replaces the whole list. The audience never changes, since tokens already issued name it. `GET /resource-servers` answers `{ "items": [ … ] }`, oldest first.

| Situation | Status | Code |
|---|---|---|
| A value breaks its rule | `422` | The OAuth context's code, such as `oauth.client_redirect_uri_invalid` or `oauth.client_authentication_method_invalid`; a key for a client that does not use `private_key_jwt` is `oauth.client_key_not_allowed`; a principal that is not a service account or an agent of the tenant, or a deleted one, or not an agent with the token exchange grant, or not a service account with `spiffe_jwt`, `tls_client_auth`, `spiffe_x509` or `linkerd_identity`, is `oauth.client_principal_invalid`; a SPIFFE identifier that breaks its rules, or one given with a method that does not take it or missing with one that needs it, and a client using `tls_client_auth` with both identities or neither, is `oauth.client_spiffe_id_invalid`; a Linkerd identity that does not read, given with a method that does not take it or missing with `linkerd_identity`, is `oauth.client_linkerd_identity_invalid`; exchange rules that break their rules are `oauth.client_exchange_rules_invalid`; and one given with another grant than `client_credentials` is `oauth.client_grants_invalid` |
| The tenant already has 100 applications, or the application 20 clients | `409` | `oauth.too_many_applications`, `oauth.too_many_clients` |
| The audience is taken, or the application already has a resource server | `409` | `oauth.audience_taken`, `oauth.application_has_resource_server` |
| A `kid` the client already has, or a sixth key | `409` | `oauth.client_key_taken`, `oauth.client_too_many_keys` |
| A SPIFFE identifier or a Linkerd identity another client of the tenant is bound to | `409` | `oauth.client_spiffe_id_taken`, `oauth.client_linkerd_identity_taken` |
| No such application, client, secret, key or resource server in this tenant | `404` | `oauth.application_not_found`, `oauth.client_not_found`, `oauth.client_secret_not_found`, `oauth.client_key_not_found`, `oauth.resource_server_not_found` |
| Someone else changed it at the same moment | `409` | `oauth.application_modified_concurrently`, `oauth.client_modified_concurrently`, `oauth.resource_server_modified_concurrently` |

What an administrator does here is in the audit log, through [the events of the OAuth context](../architecture/contexts/oauth.md#events), which never carry a secret or its hash.

### Claim mappers

A claim mapper adds one claim to the tokens of one client. What it may read, the names it may not use and the bound on what a client's mappers add to a token are in [claim mappers](../architecture/contexts/oauth.md#claim-mappers), which this interface translates.

```json
{
  "id": "0193f1f0-…",
  "client_id": "0193f1d0-…",
  "claim": "finance_member",
  "targets": ["id_token", "access_token"],
  "scope": null,
  "source": { "kind": "group_member", "group_id": "0193f0a0-…" },
  "created_at": "2026-11-25T14:03:11Z",
  "updated_at": "2026-11-25T14:03:11Z"
}
```

`source` is one of:

| `kind` | Other members |
|---|---|
| `attribute` | `attribute`: `display_name`, `username`, `email`, `email_verified` or `locale` |
| `groups` | None |
| `group_member` | `group_id`: a group of the tenant |
| `organization` | `attribute`: `id` or `name` |
| `constant` | `value`: any JSON value but `null`, at most 1024 bytes |

`POST /clients/{client_id}/claim-mappers` with `claim`, `targets`, `source` and, optionally, `scope` answers `201` with the mapper. `PUT /clients/{client_id}/claim-mappers/{claim_mapper_id}` takes the same body and replaces the mapper; the result is checked against every rule again, with the client's other mappers. `GET /clients/{client_id}/claim-mappers` answers `{ "items": [ … ] }`, by claim name; a client has at most 20. `DELETE /clients/{client_id}/claim-mappers/{claim_mapper_id}` answers `204`.

| Situation | Status | Code |
|---|---|---|
| A value breaks its rule, a name is reserved, or a group is not one of the tenant's | `422` | `oauth.claim_mapper_name_invalid`, `oauth.claim_mapper_name_reserved`, `oauth.claim_mapper_targets_invalid`, `oauth.claim_mapper_source_invalid`, `oauth.claim_mapper_scope_not_allowed`, `oauth.claim_mapper_group_unknown` |
| The mappers of the client would add more than 4096 bytes to one target in the worst case | `422` | `oauth.claim_mapper_token_too_large` |
| Another mapper of the client has the claim, or the client has 20 | `409` | `oauth.claim_mapper_name_taken`, `oauth.claim_mappers_too_many` |
| No such client or mapper in this tenant, or a mapper of another client | `404` | `oauth.client_not_found`, `oauth.claim_mapper_not_found` |
| Someone else changed the mapper at the same moment | `409` | `oauth.claim_mapper_modified_concurrently` |

### Assurance levels

The levels an application names in `acr_values`, and which every token names in `acr` ([the tenant context](../architecture/contexts/tenant.md#assurance-levels)):

```json
{
  "levels": [
    { "acr": "urn:hodor:acr:single-factor", "requirement": "single_factor" },
    { "acr": "urn:hodor:acr:mfa", "requirement": "multi_factor" },
    { "acr": "urn:example:phishing-resistant", "requirement": "phishing_resistant" }
  ]
}
```

`GET /assurance-levels` answers the levels in force, weakest first. `PUT /assurance-levels` takes the same document and replaces them all; the answer is `200` with the levels as they are now, weakest first. A change applies to requests that arrive after it, and is recorded as `tenant.settings_changed`.

| Situation | Status | Code |
|---|---|---|
| No level, more than three, a name that is empty, longer than 255 characters or holds a space or a character outside printable ASCII, or two levels with the same name or the same requirement | `422` | `tenant.settings_invalid` |
| A requirement other than `single_factor`, `multi_factor` and `phishing_resistant`, or a body that is not that document | `422` | `request.body_invalid` |

### SCIM deprovisioning

The tenant's [SCIM deprovisioning policy](../architecture/contexts/tenant.md#scim-deprovisioning-policy): what a SCIM client's `DELETE` or `active: false` does to a person.

```json
{ "deprovisioning": "deactivate" }
```

`GET /scim-deprovisioning` answers the policy in force, `deactivate` when none was set. `PUT /scim-deprovisioning` takes the same document and answers it as it is now; a change applies to requests that arrive after it, and is recorded as `tenant.settings_changed`. Any value other than `deactivate` and `delete`, or another body, is `422` with `request.body_invalid`.

### Email sign-in

The tenant's [email sign-in policy](../architecture/contexts/tenant.md#email-sign-in-policy): whether people may sign in with a code, or with a link, sent to their address.

```json
{ "code": true, "link": false }
```

`GET /email-sign-in` answers the policy in force, both `false` when none was set. `PUT /email-sign-in` takes the same document, both fields required, and answers it as it is now; a change applies to requests that arrive after it, and is recorded as `tenant.settings_changed`. Another body is `422` with `request.body_invalid`.

### The record of decisions

The settings of [the record of decisions](../architecture/contexts/authorization.md#the-record-of-decisions):

```json
{
  "mode": "sampled",
  "allow_sample_percent": 10,
  "masks": ["subject.attributes.email", "resource.attributes.*"],
  "retention_days": 30
}
```

`GET /decision-log` answers the settings in force, the defaults when none were set. `PUT /decision-log` replaces them all and answers them as they are now. `allow_sample_percent` is given with `sampled` and only then. A change applies to decisions made after it, and is recorded as `authorization.decision_log_changed`.

| Situation | Status | Code |
|---|---|---|
| A share outside 1 to 99, a share without `sampled` or `sampled` without one, more than 32 masks, a mask that is not one of the paths the record accepts, or a retention outside 1 to 400 days | `422` | `authorization.decision_log_invalid` |
| A mode other than `full`, `sampled`, `deny_only` and `off`, or a body that is not that document | `422` | `request.body_invalid` |

`GET /decisions?from=…&to=…&effect=deny&namespace=…&subject_kind=user&subject_id=…&limit=50&cursor=…` answers the tenant's records newest first. Every filter is optional; `from` and `to` are RFC 3339 times, `from` included and `to` excluded. The cursor continues after the last record of the page.

```json
{
  "items": [
    {
      "decision_id": "0193f2a0-…",
      "namespace": "https://api.example.com",
      "subject": { "kind": "user", "id": "0193f1c4-…" },
      "action": "read",
      "resource": { "type": "document", "id": "42" },
      "effect": "deny",
      "reason": "no_matching_role",
      "engine": "native",
      "policy_version": "7",
      "decided_at": "2026-11-23T03:10:11.482913Z",
      "duration_microseconds": 412,
      "input": { "subject": { "attributes": { "status": "active" } }, "resource": { "attributes": {} } },
      "masked": ["subject.attributes.email"]
    }
  ],
  "next_cursor": "…"
}
```

A filter that cannot be read is answered `422` with `request.query_invalid`.

### Roles and their permissions

Specified in [native role-based access control](../architecture/contexts/authorization.md#native-role-based-access-control). A resource server is named in the path by its identifier; its audience is the namespace of its permissions and roles. `hodor:admin` cannot be reached through these routes: Hodor's own roles are built in.

`PUT /resource-servers/{resource_server_id}/permissions/{permission}` takes `{ "description": "Read a document" }` and answers the permission. `{permission}` is `resource:action`, such as `document:read`.

`PUT /resource-servers/{resource_server_id}/roles/{role}` takes the whole role and answers it:

```json
{
  "description": "Edits documents during office hours",
  "permissions": [
    { "name": "document:read" },
    { "name": "document:write", "condition": "context.time.matches('T(0[89]|1[0-7]):')" }
  ],
  "includes": [{ "namespace": "https://api.example.com", "name": "reader" }]
}
```

An included role of the same resource server makes a hierarchy, one of another a composite. A condition is checked when the role is saved: one that does not compile answers `authorization.condition_invalid`, one that is too costly `authorization.condition_too_costly`, both `422` with the permission in the detail.

`POST /role-assignments` gives a role; `POST /role-assignments:revoke` takes the same body without the times and takes it away:

```json
{
  "principal": { "kind": "client", "id": "0193f1c4-…" },
  "role": { "namespace": "https://api.example.com", "name": "editor" },
  "application_id": "0193f0aa-…",
  "valid_from": "2026-12-01T00:00:00Z",
  "valid_until": "2027-01-01T00:00:00Z"
}
```

`principal.kind` is `user`, `client` or `group`. In place of `application_id`, `organization_id` scopes the assignment to an organization; giving both is refused with `authorization.scope_invalid`. Without either the role applies to the whole tenant. `GET /groups/{group_id}/role-assignments` lists the roles a group holds, under `roles:read`. Revoking a role that was not held answers `404` with `authorization.assignment_not_found`.

| Situation | Status | Code |
|---|---|---|
| No resource server of that identifier | `404` | `oauth.resource_server_not_found` |
| A permission or role name that is not one | `422` | `authorization.permission_invalid`, `authorization.role_name_invalid` |
| A role that includes a role leading back to it | `422` | `authorization.role_cycle` |
| A role that holds a permission its resource server does not declare | `422` | `authorization.permission_not_declared` |
| Removing a role another role includes | `409` | `authorization.role_in_use` |
| Giving a role that does not exist | `422` | `authorization.role_not_found` |

### Access control lists

Specified in [access control lists](../architecture/contexts/authorization.md#access-control-lists). The resource server is named in the path by its identifier; its audience is the namespace of the entry. An entry is answered as:

```json
{
  "id": "0193f3a1-…",
  "namespace": "https://api.example.com",
  "permission": "document:read",
  "resource_kind": "document",
  "resource_id": "d-42",
  "principal": { "kind": "group", "id": "0193f2a0-…" },
  "granted_at": "2026-11-24T14:03:11Z"
}
```

`POST /resource-servers/{resource_server_id}/access-entries` takes `{ "permission": "document:read", "resource_id": "d-42", "principal": { "kind": "group", "id": "0193f2a0-…" } }` and answers `201` with the new entry. When the principal already has that permission on that resource, it answers `200` with the entry that exists, and nothing changes. `principal.kind` is `user`, `client` or `group`; a service account or an agent is a `user`. The principal must be of the tenant, as for [a role assignment](#roles-and-their-permissions).

`GET /resource-servers/{resource_server_id}/access-entries` answers `{ "items": [ … ], "next_cursor": … }`, oldest first, a page at a time with `limit` and `cursor`. The query may also hold `resource_kind`, `resource_id`, and `principal_kind` with `principal_id`, each narrowing the list. `DELETE /access-entries/{entry_id}` answers `204`.

| Situation | Status | Code |
|---|---|---|
| No resource server of that identifier | `404` | `oauth.resource_server_not_found` |
| No entry of that identifier in the tenant | `404` | `authorization.access_entry_not_found` |
| A principal that is not of the tenant | `404` | `identity.user_not_found`, `oauth.client_not_found`, `identity.group_not_found` |
| A permission that is not one, or that the resource server does not declare | `422` | `authorization.permission_invalid`, `authorization.permission_not_declared` |
| A resource identifier that is empty, longer than 255 characters or holds a control character | `422` | `authorization.resource_invalid` |
| A principal kind that is not one of the three | `422` | `authorization.principal_kind_invalid` |
| A query whose principal has a kind without an identifier, or the other way round, or a cursor this interface did not give | `422` | `request.query_invalid` |

What an administrator does here is in the audit log, through [the events of access control lists](../architecture/contexts/authorization.md#events-of-access-control-lists).

### Bindings

`PUT /resource-servers/{resource_server_id}/binding` takes and answers [a binding](../architecture/contexts/authorization.md#bindings):

```json
{
  "engine": "native",
  "time_limit_milliseconds": 200,
  "sensitive": false,
  "fail_open_actions": [],
  "trust_asserted": false
}
```

The engine is `native` or `open_policy_agent`. An action that fails open is allowed when the engine fails, and is recorded each time: the console asks for it to be confirmed. An unknown engine answers `422` with `authorization.unknown_engine`.

### Policies for Open Policy Agent

Specified in [the policy lifecycle](../architecture/contexts/authorization.md#the-policy-lifecycle). Versions written through these routes are the tenant's own, and run only in an instance of the tenant's own.

`POST /policy-versions` takes the files of a version, each with its path in the tenant's tree and its text:

```json
{ "files": [{ "path": "resource_servers/r…/policy.rego", "contents": "package hodor.tenants.t….resource_servers.r…\n…" }] }
```

`:validate` and `:test` answer at once with the version waiting; the worker checks it, and the version's `state` and `report` say how it went. `POST /policy-versions/{number}/simulations` takes `{ "resource_server_id": "…", "inputs": [ … ] }`, at most 100 inputs, and answers the simulation waiting; `GET /policy-simulations/{simulation_id}` answers its results once the worker has run it.

**Publishing and rolling back are not routes.** A published bundle is signed with the installation's bundle signing key, which only `hodor-cli policy publish` and `hodor-cli policy rollback` hold: the server never holds it ([Decision 0026](../decisions/0026-policy-checks-in-a-sandbox.md)). `GET /policy-status` shows what was published and, per instance that should run it, whether it does.

Registering and disabling Open Policy Agent instances is likewise the operator's, with `hodor-cli policy-agent instance`: an instance may serve every tenant.

### Groups

Specified in [groups](../architecture/contexts/identity.md#groups). A group is answered as:

```json
{ "id": "0193f2a0-…", "name": "finance", "description": "Who pays the bills", "created_at": "…", "updated_at": "…" }
```

`POST /groups` and `PATCH /groups/{group_id}` take `{ "name": "…", "description": "…" }`; `PATCH` replaces both, and a missing description removes it. A member is named as `{ "kind": "user", "id": "…" }` or `{ "kind": "group", "id": "…" }`, in the body of `POST /groups/{group_id}/members` and `POST /groups/{group_id}/members:remove`, and in the list of members. `GET /users/{user_id}/groups` answers `{ "items": [{ "id": "…", "direct": true }] }`, where `direct` says the user is a member of that group and not only through another.

| Situation | Status | Code |
|---|---|---|
| No group of that identifier | `404` | `identity.group_not_found` |
| A member that is not a user or a group of the tenant, or a Deleted user | `404` | `identity.user_not_found`, `identity.group_not_found` |
| A name another group has | `409` | `identity.group_name_taken` |
| A group that would be inside itself, or deeper than the tenant allows | `409` | `identity.group_cycle`, `identity.group_nesting_too_deep` |
| A name or a description that breaks a rule | `422` | `identity.group_name_invalid`, `identity.group_description_invalid` |

### Organizations

Specified in [organizations](../architecture/contexts/identity.md#organizations). An organization is answered as a group is. A unit:

```json
{ "id": "0193f2b1-…", "parent_id": null, "name": "Engineering", "kind": "department", "created_at": "…", "updated_at": "…" }
```

`POST /organizations/{organization_id}/units` takes `{ "parent_id": null, "name": "…", "kind": "unit" }`, and `PUT /organizations/{organization_id}/units/{unit_id}` the same, replacing all three: a new `parent_id` moves the unit and what is below it.

`PUT /organizations/{organization_id}/members/{user_id}` takes `{ "unit_ids": ["…"] }`. It makes the user a member with those units, or replaces the units of a member, and answers the membership: `{ "user_id": "…", "unit_ids": ["…"], "added_at": "…" }`.

`POST /organizations/{organization_id}/invitations` takes `{ "email": "ana@example.com", "unit_ids": [], "locale": "pt-BR" }`, sends the message, and answers `202` with nothing in it: the link is in the message only. `GET` on the same path lists pending invitations as `{ "id": "…", "email": "…", "unit_ids": [], "created_at": "…", "expires_at": "…" }`. The address is shown to an administrator, who typed it.

| Situation | Status | Code |
|---|---|---|
| No organization, unit or member of that identifier | `404` | `identity.organization_not_found`, `identity.unit_not_found`, `identity.membership_not_found` |
| No pending invitation of that identifier | `404` | `identity.invitation_invalid` |
| A user that is not one of the tenant, or a Deleted user | `404` | `identity.user_not_found` |
| A name another organization, or a unit with the same parent, has | `409` | `identity.organization_name_taken`, `identity.unit_name_taken` |
| A unit put under itself, or past ten levels | `409` | `identity.unit_cycle`, `identity.unit_tree_too_deep` |
| A unit with units below it | `409` | `identity.unit_not_empty` |
| A name, a description, a kind or an address that breaks a rule | `422` | `identity.organization_name_invalid`, `identity.group_description_invalid`, `identity.unit_kind_invalid`, `identity.email_invalid` |

### Service accounts and agents

Specified in [service accounts and agents](../architecture/contexts/identity.md#service-accounts-and-agents). Both are answered alike, each under its own path; an identifier of the other kind, of a person or of a deleted workload is `404` there. A service account:

```json
{
  "id": "0193f2c0-…",
  "kind": "service_account",
  "name": "Nightly billing export",
  "status": "active",
  "owners": ["0193f1c2-…"],
  "created_at": "2026-11-24T14:03:11Z",
  "updated_at": "2026-11-24T14:03:11Z"
}
```

`status` is `active` or `disabled`. `owners` are the identifiers of the people responsible for it, in the order they became owners.

`POST /service-accounts` and `POST /agents` take `{ "name": "Nightly billing export", "owners": ["0193f1c2-…"] }`, both required, and answer `201` with it, active. `PATCH` takes `name`, `owners` or both; `owners` replaces the whole list. `:disable` and `:enable` take no body and answer `200` with it. `DELETE` answers `204`. `GET /service-accounts` and `GET /agents` answer `{ "items": [ … ], "next_cursor": … }`, oldest first, a page at a time as users are.

A workload holds roles and is in groups as a user is: `GET /users/{user_id}/role-assignments`, `POST /role-assignments` with `{ "principal": { "kind": "user", "id": "…" } }`, and `POST /groups/{group_id}/members` name it by its identifier. Its credentials are clients of an application, created with `principal` ([applications, clients and resource servers](#applications-clients-and-resource-servers)).

| Situation | Status | Code |
|---|---|---|
| No workload of that kind and identifier, or a deleted one | `404` | `identity.workload_not_found` |
| An owner that is not a user of the tenant, or a Deleted one | `404` | `identity.user_not_found` |
| An owner that is not a person | `422` | `identity.workload_owner_invalid` |
| No owner, or more than 10 | `422` | `identity.workload_owner_required`, `identity.too_many_workload_owners` |
| A name that is empty or longer than 200 characters | `422` | `identity.display_name_invalid` |
| Someone else changed it at the same moment | `409` | `identity.user_modified_concurrently` |

What an administrator does here is in the audit log, through [the events of the identity context](../architecture/contexts/identity.md#events), and the tokens that disabling or deleting revoked through `oauth.access_token_revoked`.
### Webhooks

Specified in [the webhooks context](../architecture/contexts/webhooks.md). An endpoint is answered as:

```json
{
  "id": "0193f2c4-…",
  "url": "https://hooks.example.com/hodor",
  "description": "Our directory",
  "event_types": ["identity.user_created", "session.revoked"],
  "secrets": [{ "created_at": "…", "expires_at": null }, { "created_at": "…", "expires_at": "…" }],
  "created_at": "…",
  "updated_at": "…"
}
```

`secrets` says which secrets sign now, newest first, and until when; never the secrets themselves. `POST /webhook-endpoints` takes `{ "url": "…", "description": "…", "event_types": ["…"] }` and answers `201` with `{ "endpoint": { … }, "secret": "whsec_…" }`. `POST /webhook-endpoints/{endpoint_id}:rotate-secret` takes `{ "overlap_hours": 24 }`, or no body for the default of 24, and answers the same shape with the new secret. These two answers are the only places a secret is ever shown, and they carry `Cache-Control: no-store`. `PUT /webhook-endpoints/{endpoint_id}/subscriptions` takes `{ "event_types": ["…"] }` and answers the endpoint. `GET /webhook-event-types` answers `{ "items": ["identity.user_created", …] }`, the catalog.

`GET /webhook-deliveries` takes `endpoint_id` and `status` (`pending`, `delivered` or `set_aside`) in its query, besides `limit` and `cursor`. A delivery is answered without its body:

```json
{
  "id": "0193f2d0-…",
  "endpoint_id": "0193f2c4-…",
  "event_id": "0193f2cf-…",
  "event_type": "session.started",
  "status": "set_aside",
  "attempts": 8,
  "next_attempt_at": null,
  "last_response_status": 503,
  "last_error": "the endpoint answered 503",
  "created_at": "…",
  "finished_at": "…"
}
```

`next_attempt_at` is set only while a delivery is pending. `POST /webhook-deliveries/{delivery_id}:redeliver` puts a set-aside delivery back to pending, due at once, and answers it.

| Situation | Status | Code |
|---|---|---|
| No endpoint or delivery of that identifier | `404` | `webhooks.endpoint_not_found`, `webhooks.delivery_not_found` |
| A twenty-first endpoint | `409` | `webhooks.too_many_endpoints` |
| Delivering again a delivery that is not set aside | `409` | `webhooks.delivery_not_set_aside` |
| The endpoint changed while it was being changed | `409` | `webhooks.endpoint_changed` |
| An address that is not HTTPS, cannot be read, or is too long | `422` | `webhooks.endpoint_address_invalid` |
| An address that leads somewhere that may not be called, or resolves to nothing | `422` | `webhooks.endpoint_address_forbidden`, `webhooks.endpoint_address_unresolvable` |
| An event type that is not in the catalog, or a description or an overlap that breaks its rule | `422` | `webhooks.event_type_unknown`, `webhooks.description_invalid`, `webhooks.overlap_invalid` |
| A status in the query that is not one of the three, or an endpoint that is not an identifier | `422` | `request.query_invalid` |
| The installation has no keys to seal secrets with | `503` | `webhooks.not_configured` |

#### API keys

Specified in [API keys](../architecture/contexts/credential.md#api-keys). A key, as every answer writes it:

```json
{
  "id": "0193f2d0-…",
  "name": "Nightly export on the build server",
  "hint": "…7c1e",
  "scopes": ["users:read", "authz:evaluate"],
  "application_id": "0193f1c2-…",
  "status": "active",
  "created_at": "2026-11-24T14:03:11Z",
  "expires_at": "2027-02-22T14:03:11Z",
  "last_used_at": null,
  "revoked_at": null,
  "replaced_by": null
}
```

`status` is `active`, `expired` or `revoked`. `hint` is the last four characters of the key, so that a person can tell which key a program holds.

`POST …/api-keys` takes `{ "name": "…", "scopes": ["…"], "application_id": "…", "lifetime_days": 90 }`; `application_id` is needed with a scope of the Authorization API and refused without one, and `lifetime_days`, 1 to 365, is 90 unless given. The answer is `201` with the key and, **once**, `api_key`: the key itself, which no other answer holds and which Hodor cannot show again.

`POST …/api-keys/{api_key_id}:rotate` takes `{ "lifetime_days": 90, "keep_previous_days": 7 }`, both optional, `keep_previous_days` from 0 to 30. The answer is `201` with the new key and its `api_key`, once. `DELETE …/api-keys/{api_key_id}` revokes the key and answers `204`. `GET …/api-keys` answers `{ "items": [ … ] }`, newest first.

| Situation | Status | Code |
|---|---|---|
| No workload of that kind and identifier, or no key of it with that identifier | `404` | `identity.workload_not_found`, `credential.api_key_not_found` |
| A scope that is not a permission of this interface or a scope of the Authorization API | `422` | `authorization.scope_unknown` |
| A scope of the Authorization API without an application, or an application without one | `422` | `authorization.scope_needs_application`, `authorization.application_without_scope` |
| An application that is not one of the tenant | `422` | `credential.api_key_application_invalid` |
| A name, a lifetime or an overlap that breaks its rule | `422` | `credential.api_key_name_invalid`, `credential.api_key_lifetime_invalid`, `credential.api_key_overlap_invalid` |
| The workload already holds 10 keys that work | `409` | `credential.too_many_api_keys` |
| Rotating a key that was replaced, revoked or expired | `409` | `credential.api_key_not_rotatable` |

## Not built yet

| Item | Planned in |
|---|---|
| Everything else in the [outline of the Admin API](api-spec.md#admin-api) | The phase of each area |
| OAuth access tokens with scopes, in place of the access token of this version | Phase 2 |
| `ETag` and `If-Match`, `Idempotency-Key`, filtering and sorting, rate-limit headers | Phase 2, with the rest of the conventions |
| Reactivating a user, changing a user, removing a user | Phase 2 |
