# The interaction interface

The interaction interface is how a browser signs in. It is what the hosted sign-in pages call; nothing else should. It exposes the [authentication context](../architecture/contexts/authentication.md) as a small state machine over HTTP: the pages ask which step comes next and submit what the person typed, and never decide anything themselves.

All paths are relative to the tenant: `https://{host}/t/{slug}`. Requests and responses are JSON. Errors are problem documents, as everywhere ([conventions](api-spec.md#conventions-for-the-json-apis)).

## Signing in

| Method and path | Purpose |
|---|---|
| `POST /interaction/sign-in` | Start a sign-in |
| `GET /interaction/sign-in` | Ask where the current sign-in stands, for example after the page was reloaded |
| `POST /interaction/sign-in/steps/identifier` | Submit the login identifier |
| `POST /interaction/sign-in/steps/password` | Submit the password |
| `DELETE /interaction/sign-in` | Abandon the sign-in |
| `GET /interaction/session` | Say who is signed in |

Signing out and the person's sessions are under [the session](#routes-for-a-signed-in-person). Registration and password recovery have [their own section](#registering-and-recovering-a-password).

### What a sign-in response looks like

Every response about a sign-in has the same shape:

```json
{
  "status": "pending",
  "step": "password",
  "csrf_token": "9f2c…"
}
```

| Field | Present | Meaning |
|---|---|---|
| `status` | Always | `pending`, `rejected`, `failed` or `completed` |
| `step` | When `pending` or `rejected` | The step the pages should ask for next |
| `attempts_left` | When `rejected` | How many more rejections this sign-in tolerates |
| `csrf_token` | When `pending` or `rejected` | The value to send back in the `X-CSRF-Token` header |

| Status | HTTP status | What the pages do |
|---|---|---|
| `pending` | `200`, or `201` when the sign-in was just started | Show the form for `step` |
| `rejected` | `200` | Show the same form again with a generic "that did not work" message |
| `failed` | `200` | The sign-in is over; offer to start again |
| `completed` | `200` | The person is signed in; the session cookie has been set |

A rejection is a normal answer, not an error: the request was understood and the sign-in simply did not advance. Nothing in it says why, and it is the same whether the password was wrong, the identifier belongs to nobody, or the user may not sign in.

### Request bodies

| Step | Body |
|---|---|
| `identifier` | `{ "identifier": "ana@example.com" }` |
| `password` | `{ "password": "…" }` |

Submitting a step other than the one the sign-in is waiting for is an error (`422`, `authentication.unexpected_step`), and changes nothing.

### Errors

| Situation | Status | Code |
|---|---|---|
| No sign-in in progress for this browser, or it expired, or it was already used | `404` | `authentication.transaction_not_found` |
| The sign-in has ended | `409` | `authentication.transaction_not_active` |
| Another request advanced the sign-in at the same moment | `409` | `authentication.transaction_modified_concurrently` |
| The wrong step was submitted | `422` | `authentication.unexpected_step` |
| Attempts are being limited | `429`, with `Retry-After` | `authentication.too_many_attempts` |
| The server is too busy to check a password | `503`, with `Retry-After` when known | `credential.hashing_overloaded` |
| The CSRF token is missing or wrong | `403` | `request.csrf_token_invalid` |
| The request comes from another site | `403` | `request.cross_origin` |
| The body is not JSON of the expected shape | `400`, `415` or `422` | — |

## How a sign-in is tied to one browser

A sign-in belongs to the browser that started it. Nobody else can continue it, even knowing its identifier.

- Starting a sign-in creates a random secret of 256 bits. The server keeps only its SHA-256 hash, with the sign-in.
- The browser receives the sign-in's identifier and the secret together in a cookie. The cookie cannot be read by scripts, and is only sent back to the interaction paths of this tenant.
- Every later request about the sign-in must carry that cookie. A request without it, or with a secret that does not match, is answered exactly as if the sign-in did not exist.
- The identifier of a sign-in never appears in an address or in a response body.

### The sign-in cookie

| Attribute | Value | Why |
|---|---|---|
| Name | `__Secure-hodor_signin` | The prefix makes browsers refuse it over an insecure connection |
| Value | The sign-in's identifier and its secret | |
| `HttpOnly` | Yes | Scripts cannot read it |
| `Secure` | Yes | Never sent in clear text |
| `SameSite` | `Strict` | Not sent on requests that another site starts |
| `Path` | `/t/{slug}/interaction` | Sent to this tenant's interaction interface only |
| `Max-Age` | 600 seconds | A sign-in lasts ten minutes |

It is removed when the sign-in completes, fails or is abandoned.

## Protection against requests forged by another site

A page on another site must not be able to make a person's browser act on their sign-in. Three independent measures stand in the way; any one of them is enough.

1. **The cookie is `SameSite=Strict`**, so a browser does not attach it to a request another site starts.
2. **Every request that changes something must carry a CSRF token** in the `X-CSRF-Token` header. The token is derived from the sign-in's secret and returned in the response body, which only a page from this origin can read. A request without it, or with a wrong one, is refused with `403`.
3. **A request that names another origin is refused.** If the browser sends an `Origin` header and it is not this server's own, the answer is `403`.

Bodies must be JSON, which a plain cross-site form cannot send.

Starting a sign-in is the one changing request that carries no CSRF token, since there is no sign-in yet to derive one from. It is covered by the origin check, and a forged start does no harm: it gives the browser a fresh sign-in that nobody has typed anything into.

## The session

When a sign-in completes, the response sets the session cookie and the browser is signed in to the tenant.

### The session cookie

| Attribute | Value | Why |
|---|---|---|
| Name | `__Secure-hodor_session` | |
| Value | The [session token](../architecture/contexts/session.md#the-token) | |
| `HttpOnly` | Yes | Scripts cannot read it |
| `Secure` | Yes | Never sent in clear text |
| `SameSite` | `Lax` | Sent when the person follows a link to the tenant, not on requests another site makes in the background |
| `Path` | `/t/{slug}` | Sent to this tenant only |
| `Max-Age` | The session's absolute timeout | The browser forgets it when the session can no longer be valid |

The cookie holds nothing but the token. Whether the session is still valid is decided on the server every time, never by the cookie's age.

On a host that serves several tenants by path, cookies are separated by `Path`, which is a convenience and not a security boundary between tenants; see [multi-tenancy](../architecture/multi-tenancy.md#shared-host-caveat). On a tenant's own host the cookies use the stricter `__Host-` prefix. That variant comes with custom domains in Phase 3.

### Routes for a signed-in person

| Method and path | Purpose |
|---|---|
| `GET /interaction/session` | Say who is signed in |
| `DELETE /interaction/session` | Sign out of this browser |
| `GET /interaction/sessions` | List the person's sessions |
| `DELETE /interaction/sessions/{session_id}` | End one of the person's sessions |
| `DELETE /interaction/sessions` | End all of the person's sessions except this one |

Every one of them needs a valid session cookie. Without one the answer is `401` with `session.not_authenticated`, whatever the reason: no cookie, an unknown token, an expired or a revoked session.

### `GET /interaction/session`

Answers who is signed in:

```json
{
  "user_id": "0193f1c2-…",
  "session_id": "0193f1c9-…",
  "signed_in_at": "2026-11-20T14:03:11Z",
  "assurance": "single_factor",
  "methods": ["password"],
  "expires_at": "2026-11-20T14:33:11Z",
  "csrf_token": "5b1e…"
}
```

`expires_at` is the moment the session ends if it is not used again. `csrf_token` is the value to send back in the `X-CSRF-Token` header of the requests below that change something.

### Signing out

`DELETE /interaction/session` ends the session this browser holds and removes the session cookie. The answer is `204`.

The session is ended on the server, not merely forgotten by the browser: a copy of the token made earlier stops working at the same moment. The next request with it gets `401`.

Signing out ends one session. The person's sessions in other browsers continue.

### Listing sessions

`GET /interaction/sessions` answers with the person's active sessions, newest first:

```json
{
  "sessions": [
    {
      "session_id": "0193f1c9-…",
      "current": true,
      "started_at": "2026-11-20T14:03:11Z",
      "last_activity_at": "2026-11-20T14:20:00Z",
      "expires_at": "2026-11-20T14:50:00Z",
      "address": "203.0.113.9",
      "description": "Mozilla/5.0 …"
    }
  ]
}
```

`current` marks the session of the browser that asks. `address` and `description` are what was seen when the session started, so that the person can recognize their own devices and notice one that is not theirs. A session's token never appears, in this list or anywhere else.

### Ending other sessions

`DELETE /interaction/sessions/{session_id}` ends one session of the person: `204`. A session that is not theirs, does not exist or has already ended is answered with `404` and `session.not_found`, all three in the same way, so that one person cannot learn about another's sessions. Ending the current session this way is the same as signing out, and removes the cookie.

`DELETE /interaction/sessions` ends every session of the person except the current one: `200` with `{ "ended": 2 }`.

### Protection for these requests

The three `DELETE` requests change something, so each must carry the CSRF token from `GET /interaction/session` in the `X-CSRF-Token` header. The token is derived from the session token, and only a page from this origin can read it. A request without it, or with a wrong one, is refused with `403` and `request.csrf_token_invalid`, and changes nothing. The origin check applies as everywhere.

The session cookie is `SameSite=Lax`, which already keeps a browser from attaching it to a `DELETE` another site starts. The token is a second, independent measure.

## Registering and recovering a password

These requests are made by a person who is not signed in and has no sign-in in progress. The rules behind them are in [the authentication context](../architecture/contexts/authentication.md#registration-and-password-recovery).

| Method and path | Body | Answer |
|---|---|---|
| `POST /interaction/registration` | `{ "email": "ana@example.com", "locale": "pt-BR" }` | `202`, always the same |
| `POST /interaction/registration/complete` | `{ "token": "…", "password": "…", "display_name": "Ana" }` | `204` |
| `POST /interaction/recovery` | `{ "email": "ana@example.com", "locale": "pt-BR" }` | `202`, always the same |
| `POST /interaction/recovery/complete` | `{ "token": "…", "password": "…" }` | `204` |

`locale` and `display_name` are optional.

A `202` means "if there is something to send, it was sent". Its body is `{ "status": "accepted" }` whether the address has an account, has none or is not an address at all. The pages show one message for every case: "check your mailbox".

| Situation | Status | Code |
|---|---|---|
| The tenant does not accept registrations | `403` | `authentication.registration_closed` |
| Too many requests about this address or from this address | `429`, with `Retry-After` | `authentication.too_many_attempts` |
| The token is unknown, used, replaced or expired | `404` | `authentication.verification_token_invalid` |
| The password is not acceptable. The token stays good | `422` | the credential context's code, for example `credential.password_too_short` |
| The server is too busy to hash a password | `503` | `credential.hashing_overloaded` |

These requests carry no cookie and no CSRF token: there is nothing of the person's in the browser yet for another site to abuse. A request that names another origin is still refused, and bodies must be JSON. A forged request can do no more than cause a message to be sent to an address, which the limits above bound.

Neither completion signs the person in. The pages send them to sign in.

## Where requests come from

The address recorded for a sign-in, and used to limit attempts, is the address of the connection the server sees. Behind a load balancer that is the load balancer's address, which would make every person share one attempt limit. Trusting a forwarded address from named proxies is not built yet; until it is, Hodor must be reached directly or the address limit must be understood as shared.

## Not built yet

| Item | Planned in |
|---|---|
| The pages themselves | Issue-31 |
| Trusting a forwarded client address from named proxies | Before any deployment behind a load balancer |
| Limiting requests per address on these paths, beyond the attempt limits of the password step | Later in Phase 1 |
| The `__Host-` cookie variant for a tenant's own host | Phase 3 |
