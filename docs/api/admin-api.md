# The administration interface

The administration interface is how the people who run a tenant, and the programs they write, manage it: its users, their sessions, its audit log, its identity providers and its keys. It is the first part of the Admin API outlined in the [API specification](api-spec.md#admin-api); this page specifies what is built.

All paths are relative to the tenant: `https://{host}/t/{slug}/api/v1/admin`. Requests and responses are JSON and follow the [conventions for the JSON APIs](api-spec.md#conventions-for-the-json-apis). Errors are problem documents.

The same interface is described for programs in an OpenAPI document, served at `GET /api/v1/admin/openapi.json` without authentication. The document and this page must say the same thing; a test checks that every route the server answers is in the document and that every route in the document is answered.

## Who may call it

Every request carries an [access token](../architecture/contexts/credential.md#access-tokens) in the `Authorization` header:

```
Authorization: Bearer hodor_at_3f9c…
```

A request is answered only if all of these hold, checked in this order:

1. **The token is good in this tenant**: well formed, known here, not expired, not revoked. A token of another tenant is not known here.
2. **Its user may sign in.** A suspended user's tokens stop working.
3. **The user holds a role with the permission the route needs**, in this tenant ([authorization](../architecture/contexts/authorization.md)).

| Failing | Status | Code | Says |
|---|---|---|---|
| 1 or 2 | `401`, with `WWW-Authenticate: Bearer` | `admin.not_authenticated` | The same thing in every case: no token, a malformed one, an unknown, expired or revoked one, another tenant's, or one whose user may not sign in |
| 3 | `403` | `admin.forbidden` | That the token is good and its user may not do this |

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
| `DELETE /sessions/{session_id}` | `sessions:revoke` | End a session |
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

## Not built yet

| Item | Planned in |
|---|---|
| Everything else in the [outline of the Admin API](api-spec.md#admin-api) | The phase of each area |
| OAuth access tokens with scopes, in place of the access token of this version | Phase 2 |
| `ETag` and `If-Match`, `Idempotency-Key`, filtering and sorting, rate-limit headers | Phase 2, with the rest of the conventions |
| Reactivating a user, changing a user, removing a user | Phase 2 |
