# API specification

This document is the contract outline: the conventions and the map of surfaces. What is built of each surface has a page of its own: [the interaction interface](interaction-api.md) and [the administration interface](admin-api.md).

The administration interface also has a machine-readable OpenAPI 3.1 document, written by hand, kept next to the code that serves it and served by it. A test holds the document and the routes together.

## Surfaces

All paths are relative to the tenant base: `https://{host}/t/{tenant}` or the tenant's own domain.

| Surface | Base path | Audience | Authentication |
|---|---|---|---|
| OAuth / OpenID Connect | `/oauth2`, `/.well-known` | Clients, relying parties | Per protocol |
| Interaction API | `/interaction` | `auth-ui` only | Interaction cookie + CSRF token |
| Federation callbacks | `/federation` | External identity providers via the browser | `state` |
| Account API | `/api/v1/account` | `account-console`, first-party apps | Session (backend-for-frontend) or access token with `account:*` scopes |
| Admin API | `/api/v1/admin` | `admin-console`, automation, Terraform | Access token with `admin:*` scopes; role-based access control on every route |
| Authorization API | `/api/v1/authorization` | Applications (policy enforcement points) | Access token with `authz:*` scopes |
| SCIM | `/scim/v2` | Provisioning clients | Bearer token bound to a SCIM integration |
| SAML | `/saml` | SAML peers | Per protocol |
| Open Policy Agent service API | `/opa` | Open Policy Agent instances | Per-instance bearer token or mTLS |
| Platform API | `https://{host}/platform/v1` | Platform operators | Token from the `system` tenant with `platform:*` scopes |
| Operations | `/livez`, `/readyz`, `/startupz`, `/metrics` | Infrastructure | Separate listener, not internet-facing |

## Conventions for the JSON APIs

| Topic | Rule |
|---|---|
| Versioning | Major version in the path (`/api/v1`). Additive changes do not bump it. A breaking change ships as `/api/v2` with an overlap period |
| Media type | `application/json`; UTF-8; `snake_case` field names |
| Identifiers | UUID strings; type is implied by the path, not a prefix |
| Timestamps | RFC 3339, UTC |
| Errors | RFC 9457 `application/problem+json` with `type`, `title`, `status`, `detail`, `instance`, plus `code` (stable machine code), `request_id` and `errors[]` for field validation |
| Pagination | Cursor based: `?limit=` (default 50, max 200) and `?cursor=`; response has `items` and `next_cursor`. No offset pagination |
| Filtering and sorting | `?filter[field]=value`, `?sort=field,-other`; only documented fields |
| Concurrency | `ETag` on resources; `If-Match` required on `PUT`, `PATCH` and `DELETE` of mutable aggregates; `412` on mismatch |
| Idempotency | `Idempotency-Key` header accepted on every `POST` that creates; same key and body returns the stored response for 24 h |
| Partial update | `PATCH` with JSON Merge Patch (RFC 7396) |
| Secrets | Write-only. Generated secrets are returned once, at creation; never readable afterwards |
| Rate limiting | `429` with `Retry-After`; `RateLimit-*` headers |
| Tracing | `traceparent` honored and returned; `X-Request-Id` on every response |
| Long operations | `202 Accepted` with a `Location` to an operation resource (tenant deletion, imports, bundle builds) |

OAuth endpoints follow their RFCs instead: form-encoded requests and the `error` / `error_description` JSON format.

## OAuth 2.x and OpenID Connect

The paths are relative to the tenant, `https://{host}/t/{slug}`, whose issuer is `{HODOR_PUBLIC_URL}/t/{slug}`. The authorization endpoint, the token endpoint and the OpenID Provider are specified in [the OAuth context](../architecture/contexts/oauth.md#authorization-endpoint).

| Method and path | Purpose | Standard |
|---|---|---|
| `GET /.well-known/openid-configuration` | Provider metadata (built: [discovery](../architecture/contexts/oauth.md#discovery)) | OpenID Connect Discovery |
| `GET /.well-known/oauth-authorization-server` | Authorization server metadata, the same document (built) | RFC 8414 |
| `GET /oauth2/jwks` | Public signing keys (built: [the published key set](../architecture/contexts/keys.md#the-published-key-set)) | RFC 7517 |
| `GET, POST /oauth2/authorize` | Authorization endpoint | RFC 6749, OpenID Connect Core |
| `GET /oauth2/authorize/resume` | Where the hosted pages send the browser after a sign-in, to go on with the pending authorization request ([the OAuth context](../architecture/contexts/oauth.md#signing-in-and-coming-back)) | — |
| `POST /oauth2/par` | Pushed authorization request | RFC 9126 |
| `POST /oauth2/token` | Token endpoint: `authorization_code` (built: [the token endpoint](../architecture/contexts/oauth.md#token-endpoint-and-client-authentication)), `refresh_token`, `client_credentials`, `urn:ietf:params:oauth:grant-type:device_code`, `…:token-exchange`, `…:jwt-bearer` | RFC 6749, 8628, 8693, 7523 |
| `POST /oauth2/revoke` | Revocation | RFC 7009 |
| `POST /oauth2/introspect` | Introspection | RFC 7662 |
| `GET, POST /oauth2/userinfo` | UserInfo (built: [UserInfo](../architecture/contexts/oauth.md#userinfo)) | OpenID Connect Core |
| `POST /oauth2/device_authorization` | Device authorization | RFC 8628 |
| `GET /oauth2/device` | User code entry page | RFC 8628 |
| `GET, POST /oauth2/logout` | Logout initiated by the relying party | OpenID Connect RP-Initiated Logout |
| `POST /oauth2/register`, `GET, PUT, DELETE /oauth2/register/{client_id}` | Dynamic client registration and management | RFC 7591, 7592 |

Advertised in metadata and enforced: `response_types_supported: ["code"]`, `code_challenge_methods_supported: ["S256"]`, `authorization_response_iss_parameter_supported: true`, `id_token_signing_alg_values_supported` starting with `ES256` and `RS256`.

## Interaction API

Used only by the hosted login user interface. It exposes the flow engine as a step machine, so the user interface never encodes flow logic.

The part that is built, signing in with an identifier and a password, is specified in full in [the interaction interface](interaction-api.md). The table below is the outline of everything this interface will cover.

| Method and path | Purpose |
|---|---|
| `GET /interaction/{id}` | Current state: step to render, options, branding, locale, client display data |
| `POST /interaction/{id}/steps/{step}` | Submit the current step (`identifier`, `password`, `totp`, `webauthn`, `otp`, `recovery_code`, `idp`, `terms`) |
| `POST /interaction/{id}/webauthn/options` | Challenge for a WebAuthn ceremony |
| `POST /interaction/{id}/consent` | Grant or deny scopes |
| `POST /interaction/{id}/cancel` | Abort; returns the client an `access_denied` error |
| `POST /interaction/registration`, `POST /interaction/recovery` | Start registration or recovery flows |
| `GET /federation/callback/{provider}` (also `POST` for form-post providers) | Return from an external identity provider |

Every response has the same shape: `{ "status": "pending" | "completed" | "failed", "step": {...}, "redirect": "..." }`. Errors do not reveal whether an account exists.

## Account API

| Resource | Operations |
|---|---|
| `/account/profile` | `GET`, `PATCH` |
| `/account/identifiers` | List, add, verify, set primary, remove |
| `/account/password` | `PUT` (requires current password or recent authentication) |
| `/account/credentials` | List; enroll and remove TOTP, passkeys, recovery codes |
| `/account/sessions` | List, revoke one, revoke all others |
| `/account/devices` | List and remove trusted devices |
| `/account/identities` | List linked external identities; start link; unlink (not the last sign-in method) |
| `/account/consents` | List and revoke |
| `/account/login-history` | List |
| `/account/export` | Request and download a personal data export |
| `/account` | `DELETE`: request account deletion |

Sensitive operations require recent authentication; a stale session gets `401` with a `step_up_required` problem carrying the `acr` and `max_age` to request.

## Admin API

Standard collection and item routes (`GET` list, `POST`, `GET`, `PATCH`, `DELETE`) unless noted.

| Area | Resources | Notable actions |
|---|---|---|
| Tenant | `/admin/tenant`, `/admin/tenant/settings`, `/admin/tenant/domains`, `/admin/tenant/branding` | `POST /domains/{id}/verify` |
| Users | `/admin/users`, `/users/{id}/identifiers`, `/users/{id}/credentials`, `/users/{id}/sessions`, `/users/{id}/identities`, `/users/{id}/roles`, `/users/{id}/groups` | `POST /users/{id}:suspend`, `:reactivate`, `:reset-password`, `:revoke-sessions`; `POST /users:import`, `:export` |
| Groups | `/admin/groups`, `/groups/{id}/members` | — |
| Organizations | `/admin/organizations`, `/organizations/{id}/units`, `/members`, `/invitations` | `POST /invitations/{id}:resend` |
| Applications | `/admin/applications`, `/applications/{id}/clients`, `/clients/{id}/secrets`, `/clients/{id}/claim-mappers`, `/resource-servers`, `/resource-servers/{id}/scopes` | `POST /clients/{id}/secrets` returns the secret once; `POST /secrets/{id}:revoke` |
| Service accounts and agents | `/admin/service-accounts`, `/admin/agents` | Credential issuance, rotation, disable |
| Identity providers | `/admin/identity-providers`, `/admin/routing-rules` | `POST /identity-providers/{id}:test`, `:deactivate` |
| Authentication | `/admin/auth-flows`, `/auth-flows/{id}/versions` | `POST /versions/{v}:validate`, `:simulate`, `:publish` |
| Authorization | `/admin/roles`, `/permissions`, `/role-assignments`, `/acl`, `/relation-tuples`, `/policies`, `/policies/{id}/versions`, `/bundles`, `/engine-bindings`, `/decision-logs` | `POST /versions/{v}:validate`, `:test`, `:simulate`, `:publish`; `POST /policies/{id}:rollback` |
| Keys | `/admin/keys/{set}` | `POST /keys/{set}:rotate`, `POST /keys/{set}/versions/{kid}:revoke` (built: [the administration interface](admin-api.md#keys)) |
| Sessions | `/admin/sessions` | `DELETE`, `POST /sessions:revoke-all` |
| Audit | `/admin/audit-records` (read-only) | `POST /audit-records:export` |
| Security posture | `/admin/posture` (read-only summary), `/admin/posture/findings`, `/findings/{id}/acceptances` | `POST /posture:evaluate`; an acceptance carries a reason and an expiry ([control plane](../design/control-plane.md#security-posture)) |
| Integrations | `/admin/webhooks`, `/admin/scim-integrations`, `/admin/plugins` | `POST /webhooks/{id}:test` |

Custom actions use the `:verb` suffix so that they never collide with resource identifiers.

## Authorization API

```http
POST /t/acme/api/v1/authorization/evaluate
Authorization: Bearer <token with authz:evaluate>
Content-Type: application/json

{
  "subject": { "type": "user", "id": "0193f1c2-..." },
  "asserted": { "roles": ["finance-manager"] },
  "resource": {
    "type": "invoice",
    "id": "invoice-456",
    "attributes": { "amount": 5000, "owner_id": "0193f1c2-..." }
  },
  "action": "approve",
  "context": { "environment": "production" }
}
```

```json
{
  "decision": "ALLOW",
  "decision_id": "0193f1c9-...",
  "evaluated_at": "2026-11-20T14:03:11Z",
  "engine": "opa",
  "policy_version": "rev-42",
  "reason": "policy_matched"
}
```

Differences from the example in the specification: there is no `tenant_id` in the body (the tenant is the URL's), and roles sent by the caller go under `asserted` so that policy can distinguish them from roles Hodor resolved. `/batch` takes `{ "requests": [...] }` and returns `{ "results": [...] }` in the same order, each item either a decision or a problem object. `/simulate` adds `"against": { "policy_version": "draft" }`.

## SCIM 2.0

`/scim/v2/Users`, `/Groups`, `/Bulk`, `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`, per RFC 7643 and RFC 7644, including `PATCH`, `filter`, `startIndex`/`count` pagination and the Enterprise User extension. Deprovisioning (`active: false` or `DELETE`) suspends or deletes according to the integration's policy.

## SAML 2.0

| Path | Purpose |
|---|---|
| `GET /saml/idp/metadata` | Identity provider metadata |
| `GET, POST /saml/idp/sso` | Single sign-on (Redirect and POST bindings) |
| `GET, POST /saml/idp/slo` | Single logout |
| `GET /saml/sp/{provider}/metadata` | Service provider metadata for a brokered identity provider |
| `POST /saml/sp/{provider}/acs` | Assertion consumer service |
| `GET, POST /saml/sp/{provider}/slo` | Single logout |

## Open Policy Agent service API

| Path | Called by Open Policy Agent to |
|---|---|
| `GET /opa/bundles/{name}` | Download the bundle (`ETag` / `If-None-Match`) |
| `POST /opa/logs` | Upload decision log batches |
| `POST /opa/status` | Report bundle activation and health |

## Platform API

`/platform/v1/tenants` (create, list, suspend, reactivate, delete), `/platform/v1/operations/{id}`, `/platform/v1/support-grants`, `/platform/v1/system/health`, `/platform/v1/system/config`.

## Webhooks (outbound)

Events are delivered as `POST` with a JSON envelope `{ id, type, tenant_id, occurred_at, data }`, signed with HMAC-SHA-256 over timestamp and body in a `Hodor-Signature` header, retried with exponential backoff, and moved to a dead-letter list after the last attempt. Receivers deduplicate on `id`.
