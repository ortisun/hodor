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
| `GET /resource-servers` | `applications:read` | List the tenant's resource servers |
| `POST /resource-servers` | `applications:write` | Register the resource server of an application |
| `GET /resource-servers/{resource_server_id}` | `applications:read` | Read one resource server |
| `PATCH /resource-servers/{resource_server_id}` | `applications:write` | Change its name or its scopes |
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
| `POST /role-assignments` | `roles:write` | Give a role to a user or a client |
| `POST /role-assignments:revoke` | `roles:write` | Take a role away |
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

`id` is the `client_id` the client sends. `secrets` lists the secrets that exist, by identifier and expiry, never the secret or its hash. `keys` lists the public keys, each as `{ "kid": "…", "jwk": { … }, "added_at": "…" }`.

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

`name`, `type` and `grant_types` are required. `authentication_method` is `client_secret_basic` for a confidential client and `none` for a public one unless given; `redirect_uris`, `post_logout_redirect_uris` and `allowed_scopes` are empty, `require_pkce` is `true`, `id_token_signed_response_alg` is `ES256` (or `RS256`; how its ID tokens are signed) and `token_policy` is the default of the OAuth context unless given, and `token_policy` may give any of its four fields. `secret_lifetime_days`, from 1 to 730, is how long the first secret lives; 365 unless given. The answer is `201` with the client. **A client with a secret method also has `client_secret` in this answer, once**: the secret itself, which no other answer holds and which Hodor cannot show again.

`PATCH /clients/{client_id}` takes any of `name`, `authentication_method`, `grant_types`, `redirect_uris`, `post_logout_redirect_uris`, `allowed_scopes`, `require_pkce`, `id_token_signed_response_alg` and `token_policy` (with any of its fields); what is left out stays as it is, and the result is checked against every rule at once. The type and the application never change. Moving away from a secret method drops the client's secrets, and moving away from `private_key_jwt` drops its keys. The answer is `200` with the client.

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
| A value breaks its rule | `422` | The OAuth context's code, such as `oauth.client_redirect_uri_invalid` or `oauth.client_authentication_method_invalid`; a key for a client that does not use `private_key_jwt` is `oauth.client_key_not_allowed` |
| The tenant already has 100 applications, or the application 20 clients | `409` | `oauth.too_many_applications`, `oauth.too_many_clients` |
| The audience is taken, or the application already has a resource server | `409` | `oauth.audience_taken`, `oauth.application_has_resource_server` |
| A `kid` the client already has, or a sixth key | `409` | `oauth.client_key_taken`, `oauth.client_too_many_keys` |
| No such application, client, secret, key or resource server in this tenant | `404` | `oauth.application_not_found`, `oauth.client_not_found`, `oauth.client_secret_not_found`, `oauth.client_key_not_found`, `oauth.resource_server_not_found` |
| Someone else changed it at the same moment | `409` | `oauth.application_modified_concurrently`, `oauth.client_modified_concurrently`, `oauth.resource_server_modified_concurrently` |

What an administrator does here is in the audit log, through [the events of the OAuth context](../architecture/contexts/oauth.md#events), which never carry a secret or its hash.

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

Without `application_id` the role applies to the whole tenant. Revoking a role that was not held answers `404` with `authorization.assignment_not_found`.

| Situation | Status | Code |
|---|---|---|
| No resource server of that identifier | `404` | `oauth.resource_server_not_found` |
| A permission or role name that is not one | `422` | `authorization.permission_invalid`, `authorization.role_name_invalid` |
| A role that includes a role leading back to it | `422` | `authorization.role_cycle` |
| A role that holds a permission its resource server does not declare | `422` | `authorization.permission_not_declared` |
| Removing a role another role includes | `409` | `authorization.role_in_use` |
| Giving a role that does not exist | `422` | `authorization.role_not_found` |

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

## Not built yet

| Item | Planned in |
|---|---|
| Everything else in the [outline of the Admin API](api-spec.md#admin-api) | The phase of each area |
| OAuth access tokens with scopes, in place of the access token of this version | Phase 2 |
| `ETag` and `If-Match`, `Idempotency-Key`, filtering and sorting, rate-limit headers | Phase 2, with the rest of the conventions |
| Reactivating a user, changing a user, removing a user | Phase 2 |
