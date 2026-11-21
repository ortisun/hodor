# The administration interface

The administration interface is how the people who run a tenant, and the programs they write, manage it: its users, their sessions and its audit log. It is the first part of the Admin API outlined in the [API specification](api-spec.md#admin-api); this page specifies what is built.

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

## Not built yet

| Item | Planned in |
|---|---|
| Everything else in the [outline of the Admin API](api-spec.md#admin-api) | The phase of each area |
| OAuth access tokens with scopes, in place of the access token of this version | Phase 2 |
| `ETag` and `If-Match`, `Idempotency-Key`, filtering and sorting, rate-limit headers | Phase 2, with the rest of the conventions |
| Reactivating a user, changing a user, removing a user | Phase 2 |
