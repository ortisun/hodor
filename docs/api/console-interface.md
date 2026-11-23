# The console interface

The console interface is what the [admin console](../architecture/admin-console.md) calls. It is the backend-for-frontend of [Decision 0011](../decisions/0011-frontends-bff.md), in the form [Decision 0020](../decisions/0020-console-on-the-hodor-session.md) gives it until Hodor issues tokens. It is for that one application: programs use the [administration interface](admin-api.md).

All paths are relative to the tenant: `https://{host}/t/{slug}/console/api`. Requests and responses are JSON and follow the [conventions for the JSON APIs](api-spec.md#conventions-for-the-json-apis). Errors are problem documents.

## Who may call it

A request is answered only if all of these hold, checked in this order, before anything else is done with it:

1. **It comes from this origin**, if it changes something. A request that names another origin is refused.
2. **It carries a session of this tenant** in the session cookie the [hosted pages](../architecture/hosted-pages.md) set at sign-in: known here, not expired, not ended.
3. **The sign-in is less than 12 hours old.** This holds whatever the tenant's own session lifetimes are.
4. **Its user may sign in.**
5. **It carries the session's CSRF token** in `X-CSRF-Token`, if it changes something. The token is the one `GET /interaction/session` and `GET /me` give.
6. **The user holds a role with the permission the route needs**, in this tenant.

| Failing | Status | Code |
|---|---|---|
| 1 | `403` | `request.cross_origin` |
| 2, 3 or 4 | `401` | `console.not_authenticated`, the same in every case |
| 5 | `403` | `request.csrf_token_invalid` |
| 6 | `403` | `admin.forbidden` |

A request that is refused learns nothing about what it asked for, as on the administration interface.

## Routes

### Who is asking

`GET /me` needs a session and no permission. It answers with the person, what they may do, and the CSRF token of their session:

```json
{
  "user": { "id": "0193f1c2-…", "display_name": "Ana Silva", "identifiers": [ … ] },
  "roles": ["tenant_administrator"],
  "permissions": ["users:read", "users:write", "sessions:read", "sessions:revoke", "audit:read", "…"],
  "signed_in_at": "2026-11-21T14:03:11Z",
  "console_until": "2026-11-22T02:03:11Z",
  "csrf_token": "9a41…"
}
```

`user` is [a user](admin-api.md#a-user). `console_until` is when the console stops answering for this sign-in: 12 hours after it, or the session's own end if that comes first. A person with no role gets an empty `roles` and `permissions`; the console tells them they have no access here.

### Everything else

Every route of the [administration interface](admin-api.md#routes) exists here at the same path, with the same permission, body and answer:

| Method and path | Permission |
|---|---|
| `POST /users` | `users:write` |
| `GET /users` | `users:read` |
| `GET /users/{user_id}` | `users:read` |
| `POST /users/{user_id}:suspend` | `users:write` |
| `GET /users/{user_id}/sessions` | `sessions:read` |
| `DELETE /sessions/{session_id}` | `sessions:revoke` |
| `GET /audit-records` | `audit:read` |
| `GET /identity-providers` | `identity-providers:read` |
| `POST /identity-providers` | `identity-providers:write` |
| `GET /identity-providers/{provider_id}` | `identity-providers:read` |
| `PATCH /identity-providers/{provider_id}` | `identity-providers:write` |
| `PUT /identity-providers/{provider_id}/client-secret` | `identity-providers:write` |
| `POST /identity-providers/{provider_id}:disable` | `identity-providers:write` |
| `POST /identity-providers/{provider_id}:enable` | `identity-providers:write` |
| `GET /applications` | `applications:read` |
| `POST /applications` | `applications:write` |
| `GET /applications/{application_id}` | `applications:read` |
| `PATCH /applications/{application_id}` | `applications:write` |
| `POST /applications/{application_id}:disable` | `applications:write` |
| `POST /applications/{application_id}:enable` | `applications:write` |
| `GET /applications/{application_id}/clients` | `applications:read` |
| `POST /applications/{application_id}/clients` | `applications:write` |
| `GET /clients/{client_id}` | `applications:read` |
| `PATCH /clients/{client_id}` | `applications:write` |
| `POST /clients/{client_id}:disable` | `applications:write` |
| `POST /clients/{client_id}:enable` | `applications:write` |
| `POST /clients/{client_id}/secrets` | `applications:write` |
| `DELETE /clients/{client_id}/secrets/{secret_id}` | `applications:write` |
| `POST /clients/{client_id}/keys` | `applications:write` |
| `DELETE /clients/{client_id}/keys/{key_id}` | `applications:write` |
| `GET /resource-servers` | `applications:read` |
| `POST /resource-servers` | `applications:write` |
| `GET /resource-servers/{resource_server_id}` | `applications:read` |
| `PATCH /resource-servers/{resource_server_id}` | `applications:write` |
| `GET /assurance-levels` | `assurance-levels:read` |
| `PUT /assurance-levels` | `assurance-levels:write` |

The two interfaces are answered by the same handlers and the same table of permissions; a route added to one is added to the other. The OpenAPI document is not served here: this interface has one client, which ships with the server.

What an administrator does through the console is recorded in the audit log with their user as the actor, exactly as through the administration interface.
