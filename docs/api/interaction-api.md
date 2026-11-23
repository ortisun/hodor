# The interaction interface

The interaction interface is how a browser signs in. It is what [the hosted pages](../architecture/hosted-pages.md) call; nothing else should. It exposes the [authentication context](../architecture/contexts/authentication.md) as a small state machine over HTTP: the pages ask which step comes next and submit what the person typed, and never decide anything themselves.

All paths are relative to the tenant: `https://{host}/t/{slug}`. Requests and responses are JSON. Errors are problem documents, as everywhere ([conventions](api-spec.md#conventions-for-the-json-apis)).

## Signing in

| Method and path | Purpose |
|---|---|
| `POST /interaction/sign-in` | Start a sign-in |
| `GET /interaction/sign-in` | Ask where the current sign-in stands, for example after the page was reloaded |
| `POST /interaction/sign-in/steps/identifier` | Submit the login identifier |
| `POST /interaction/sign-in/steps/password` | Submit the password |
| `POST /interaction/sign-in/steps/totp` | Submit a code of the person's authenticator application |
| `POST /interaction/sign-in/steps/webauthn/options` | Ask for the challenge of the WebAuthn step |
| `POST /interaction/sign-in/steps/webauthn` | Submit what the authenticator answered |
| `POST /interaction/sign-in/steps/recovery_code` | Submit one of the person's recovery codes, while the sign-in waits for the `webauthn` or the `totp` step |
| `POST /interaction/sign-in/steps/passkey/options` | Ask for the challenge of signing in with a passkey |
| `POST /interaction/sign-in/steps/passkey` | Submit what the passkey answered, in place of the identifier and the password |
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
| `continue` | When `completed`, and the browser holds a pending [authorization request](../architecture/contexts/oauth.md#signing-in-and-coming-back) of this tenant | The address of Hodor's own to go to next, `/t/{slug}/oauth2/authorize/resume`, instead of the account page |

| Status | HTTP status | What the pages do |
|---|---|---|
| `pending` | `200`, or `201` when the sign-in was just started | Show the form for `step` |
| `rejected` | `200` | Show the same form again with a generic "that did not work" message |
| `failed` | `200` | The sign-in is over; offer to start again |
| `completed` | `200` | The person is signed in; the session cookie has been set. The pages go to `continue` when the answer has it, and to the account page otherwise |

A rejection is a normal answer, not an error: the request was understood and the sign-in simply did not advance. Nothing in it says why, and it is the same whether the password was wrong, the identifier belongs to nobody, or the user may not sign in. For the `totp` step it is the same whether the code was wrong, already used or not six digits.

The `totp` step comes after the password only for a person who has an authenticator application in use ([the built-in flow](../architecture/contexts/authentication.md#the-built-in-flow)). The answer to the password then names `totp` as the next step instead of completing.

While the sign-in waits for `webauthn` or for `totp`, a recovery code can be submitted in its place: `recovery_code` is a [substitute](../architecture/contexts/authentication.md#substitutes) of both steps. The answer has the same shape. When the recovery code is rejected, `step` is still the step it stood in for; the rejection is the same whether the code was wrong, already used, from an earlier set or not a code at all.

### Request bodies

| Step | Body |
|---|---|
| `identifier` | `{ "identifier": "ana@example.com" }` |
| `password` | `{ "password": "…" }` |
| `totp` | `{ "code": "123456" }` |
| `webauthn` | `{ "credential_id": "…", "client_data": "…", "authenticator_data": "…", "signature": "…", "user_handle": "…" }`, each the bytes the authenticator gave, in base64url without padding. `user_handle` may be left out or `null` |
| `recovery_code` | `{ "code": "7K2M-QX9D-4HVN-R8TA" }` |
| `passkey` | The same as `webauthn`, and `user_handle` is needed: an answer without it is a rejection |

Submitting a step other than the one the sign-in is waiting for, or than one of its substitutes, is an error (`422`, `authentication.unexpected_step`), and changes nothing.

### The WebAuthn step

The `webauthn` step needs a challenge before it can be submitted, so the pages ask for one first. `POST /interaction/sign-in/steps/webauthn/options`, with the CSRF token and no body, answers `200`:

```json
{
  "public_key": {
    "challenge": "q3Fv…",
    "rpId": "id.example.com",
    "allowCredentials": [
      { "type": "public-key", "id": "AbC1…", "transports": ["usb", "nfc"] }
    ],
    "userVerification": "discouraged",
    "timeout": 300000
  }
}
```

`public_key` is the `PublicKeyCredentialRequestOptionsJSON` of the WebAuthn specification: every byte string in base64url without padding. The pages turn it into what `navigator.credentials.get` takes, and send the answer to `POST /interaction/sign-in/steps/webauthn`. Asking again replaces the challenge; submitting uses it up, whatever the answer.

| Situation | Status | Code |
|---|---|---|
| The sign-in is not waiting for the `webauthn` step | `422` | `authentication.unexpected_step` |

A wrong answer, a value that is not base64url, an answer to another challenge, from another credential or from another site is a rejection like a wrong password: `200` with `"status": "rejected"`.

### Signing in with a passkey

A passkey takes the place of the identifier and the password, as an [alternative](../architecture/contexts/authentication.md#the-passkey-alternative): only while the sign-in is waiting for the `identifier` step. `POST /interaction/sign-in/steps/passkey/options`, with the CSRF token and no body, answers `200` with options that name no credential and require user verification:

```json
{
  "public_key": {
    "challenge": "c0Fq…",
    "rpId": "id.example.com",
    "allowCredentials": [],
    "userVerification": "required",
    "timeout": 300000
  }
}
```

The pages pass them to `navigator.credentials.get`, either when the person presses "sign in with a passkey" or as a conditional request that lets the browser offer passkeys in the identifier field, and send the answer to `POST /interaction/sign-in/steps/passkey`. The answer to it is `completed` when the passkey is accepted, since a passkey is multi-factor and nothing more is asked. Asking again replaces the challenge; submitting the passkey or the identifier uses it up.

| Situation | Status | Code |
|---|---|---|
| The sign-in has gone past the `identifier` step | `422` | `authentication.unexpected_step` |
| Attempts from this address are being limited | `429`, with `Retry-After` | `authentication.too_many_attempts` |

A wrong answer, an answer without a user handle or without user verification, a passkey of another tenant or of a user who may not sign in is a rejection: `200` with `"status": "rejected"`, and the sign-in goes on waiting for the identifier.

### Errors

| Situation | Status | Code |
|---|---|---|
| No sign-in in progress for this browser, or it expired, or it was already used | `404` | `authentication.transaction_not_found` |
| The sign-in has ended | `409` | `authentication.transaction_not_active` |
| Another request advanced the sign-in at the same moment | `409` | `authentication.transaction_modified_concurrently` |
| The wrong step was submitted | `422` | `authentication.unexpected_step` |
| Attempts are being limited, on the password or the code | `429`, with `Retry-After` | `authentication.too_many_attempts` |
| The server is too busy to check a password | `503`, with `Retry-After` when known | `credential.hashing_overloaded` |
| The CSRF token is missing or wrong | `403` | `request.csrf_token_invalid` |
| The request comes from another site | `403` | `request.cross_origin` |
| The body is not JSON of the expected shape | `400`, `415` or `422` | — |

### Signing in through an identity provider

A tenant may offer [identity providers](../architecture/contexts/federation.md#signing-in-through-a-provider). A person who chooses one leaves for the provider and comes back to a page of Hodor, which finishes the sign-in.

| Method and path | Purpose |
|---|---|
| `GET /interaction/sign-in/providers` | The providers the tenant offers |
| `POST /interaction/sign-in/providers/{alias}` | Choose a provider for the current sign-in |
| `POST /interaction/sign-in/providers/{alias}/callback` | Finish, with what the provider sent back |
| `POST /interaction/sign-in/providers/{alias}/password` | Sign in through a directory, with an identifier and a password |
| `POST /interaction/sign-in/providers/{alias}/saml` | Where a SAML identity provider posts its response |
| `GET /interaction/sign-in/providers/{alias}/saml/metadata` | Hodor's metadata for a SAML identity provider |

`GET /interaction/sign-in/providers` needs no sign-in and answers with what the sign-in page shows, enabled providers only:

```json
{ "providers": [ { "alias": "google", "display_name": "Google", "kind": "openid_connect" } ] }
```

`POST /interaction/sign-in/providers/{alias}` needs the sign-in cookie and the CSRF token. It answers `200` with the address to send the browser to:

```json
{ "redirect": "https://accounts.example.com/authorize?response_type=code&…" }
```

The provider sends the person back to `/t/{slug}/account/providers/{alias}/callback`, a page. The page sends what arrived in its address to `POST /interaction/sign-in/providers/{alias}/callback`, with the sign-in cookie and the CSRF token:

```json
{ "code": "…", "state": "…" }
```

The answer has [the shape of every sign-in response](#what-a-sign-in-response-looks-like): `completed` with the session cookie set, or `rejected`, in the same words whatever the reason.

A provider in the list carries its `kind`. For one of the kind `ldap`, a [directory](../architecture/contexts/federation.md#signing-in-through-a-directory), nobody leaves: the page asks for an identifier and a password and sends them to `POST /interaction/sign-in/providers/{alias}/password`, with the sign-in cookie and the CSRF token:

```json
{ "identifier": "ana", "password": "…" }
```

The answer has the shape of every sign-in response. Attempts are limited as for a password of Hodor's own (`429`, `authentication.too_many_attempts`).

#### SAML identity providers

For a provider of the kind `saml`, choosing it answers with the identity provider's single sign-on address carrying the request, as for any provider. The identity provider then makes the browser post its response, from its own site, to `POST /interaction/sign-in/providers/{alias}/saml`, form-encoded with `SAMLResponse` and `RelayState`. That route [is different](../architecture/contexts/federation.md#when-the-response-arrives):

- It is the one changing request that comes from another site: it needs no cookie, no CSRF token, and its `Origin` is not checked. It changes nothing but the pending authorization whose state hashes to `RelayState`, and only once: it claims that pending authorization with the hash of a new random **receipt**, if nobody claimed it before, [checks the response](../architecture/contexts/federation.md#checking-the-response) against its request, and keeps only the answer there (who the person is, or why the response was refused). Of several responses posted at once, only the one that claimed it is checked. The response itself is not stored. A body that is not base64, or a relay state no pending authorization has, is not checked at all.
- Its body is at most 768 kibibytes, form-encoded; the response in it at most 384.
- It answers `303 See Other` to `/t/{slug}/account/providers/{alias}/callback?binding=saml&state={RelayState}&receipt={receipt}`, whether or not a pending authorization was found, and without `state` and `receipt` when the relay state is not a plain token of at most 80 characters. An alias that is not an alias is `404`, as is any alias when the server has no keys to keep secrets with; a failure of storage is `500`.

The page then finishes as for any provider, with `POST /interaction/sign-in/providers/{alias}/callback`, the sign-in cookie and the CSRF token, and the state and the receipt from its address:

```json
{ "state": "…", "receipt": "…" }
```

Only then is the answer used: the person is signed in, or the reason it was refused is recorded. The receipt shows that the browser finishing is the one that carried the response: see [why](../architecture/contexts/federation.md#when-the-response-arrives).

`GET /interaction/sign-in/providers/{alias}/saml/metadata` needs no sign-in and answers with Hodor's metadata for that provider, `application/samlmetadata+xml`, for an administrator to give the identity provider. A provider of another kind, or none, is `404`.

| Situation | Status | Code |
|---|---|---|
| The tenant has no enabled provider with this alias | `404` | `federation.provider_not_found` |
| Finishing, when the sign-in has already had a step satisfied: a sign-in is completed by its steps or through a provider, never by part of each | `422` | `authentication.unexpected_step` |
| The provider cannot be reached or describes itself wrongly | `503` | `federation.provider_unavailable` |
| The server has no keys to keep secrets with (`HODOR_SECRET_KEYS`) | No provider is offered, and each of these routes answers `404` with `federation.provider_not_found` | |

### A step-up

When an application asks for more than the session has, the [authorization endpoint](../architecture/contexts/oauth.md#assurance-and-step-up) starts a [step-up](../architecture/contexts/authentication.md#step-up) itself: it gives the browser the sign-in cookie of the step-up and sends it to the sign-in page. The page finds the step-up with `GET /interaction/sign-in`, as it finds any sign-in in progress, and shows the step it names: the WebAuthn step, the code of the application, or the password when only the identifier is still known. The steps are submitted to the same routes as any sign-in.

Nothing starts a step-up through this interface: `POST /interaction/sign-in` always starts a new sign-in, from the first step, and replaces the cookie of a step-up in progress. When a step-up completes, the answer is the answer of a completed sign-in: the session cookie carries the session's new token, and `continue` names the authorization endpoint's resume address.

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

The route a SAML identity provider posts its response to is outside all three, because another site is the one that sends it. It can do nothing but keep a response, once, on the pending authorization its relay state names; the response is read only when this origin's page finishes the sign-in with the cookie and the token ([above](#saml-identity-providers)).

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
| `POST /interaction/webauthn/registrations` | Begin registering a WebAuthn credential |
| `POST /interaction/webauthn/registrations/{registration_id}` | Finish registering it |
| `GET /interaction/factors` | List the person's factors |
| `POST /interaction/factors/authenticator-application` | Begin enrolling an authenticator application |
| `POST /interaction/factors/authenticator-application/confirmation` | Confirm it with a code |
| `DELETE /interaction/factors/authenticator-application` | Remove the authenticator application |
| `PATCH /interaction/factors/keys/{key_id}` | Rename a security key or a passkey |
| `DELETE /interaction/factors/keys/{key_id}` | Remove a security key or a passkey |
| `POST /interaction/factors/recovery-codes` | Generate a new set of recovery codes |

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

`assurance` is `single_factor`, `multi_factor` or `phishing_resistant` ([what a sign-in must reach](../architecture/contexts/authentication.md#what-a-sign-in-must-reach)); after a [step-up](#a-step-up) it is what the raised session reached. `expires_at` is the moment the session ends if it is not used again. `csrf_token` is the value to send back in the `X-CSRF-Token` header of the requests below that change something.

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

### Registering a WebAuthn credential

A signed-in person registers a security key or a platform authenticator in two requests. Both change something and carry the session's CSRF token.

`POST /interaction/webauthn/registrations`, with no body or with `{ "passkey": false }`, registers a security key, and with `{ "passkey": true }` a [passkey](../architecture/contexts/credential.md#passkeys). It needs [a recent sign-in](#a-recent-sign-in). It answers `201`:

```json
{
  "registration_id": "0193f1d0-…",
  "public_key": {
    "rp": { "id": "id.example.com", "name": "Hodor" },
    "user": { "id": "AZPx…", "name": "ana@example.com", "displayName": "Ana" },
    "challenge": "Zm9v…",
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 },
      { "type": "public-key", "alg": -257 }
    ],
    "timeout": 300000,
    "excludeCredentials": [],
    "authenticatorSelection": { "residentKey": "preferred", "userVerification": "discouraged" },
    "attestation": "none",
    "extensions": { "credProps": true }
  }
}
```

`public_key` is the `PublicKeyCredentialCreationOptionsJSON` of the WebAuthn specification. The registration can be finished within five minutes, once. For a passkey, `authenticatorSelection` is `{ "residentKey": "required", "userVerification": "required" }`, and `displayName` is followed by the tenant's name in brackets.

`POST /interaction/webauthn/registrations/{registration_id}` with what `navigator.credentials.create` answered:

```json
{
  "client_data": "eyJ0…",
  "attestation_object": "o2Nm…",
  "transports": ["usb"],
  "discoverable": true,
  "name": "Blue key"
}
```

`client_data` and `attestation_object` are base64url without padding. `transports` is what `getTransports()` gave, `discoverable` what the `credProps` extension said, and either may be left out. `name` may be left out too, and is then `Security key`. The answer is `201` with the credential:

```json
{ "id": "0193f1d1-…", "name": "Blue key", "created_at": "2026-11-20T14:05:00Z" }
```

When this is the person's first second factor and they have no unused recovery code, the answer also holds a new set, once: `"recovery_codes": ["7K2M-QX9D-4HVN-R8TA", …]`. Otherwise `recovery_codes` is absent.

| Situation | Status | Code |
|---|---|---|
| The registration is unknown, another person's, already used or older than five minutes | `404` | `credential.webauthn_registration_not_found` |
| The answer fails a check of [registration](../architecture/contexts/credential.md#registering-a-credential) | `422` | `credential.webauthn_registration_refused` |
| The tenant already has this credential | `409` | `credential.webauthn_credential_exists` |

A registration that fails is used up anyway: the person asks again.

### Managing one's factors

These routes are what [the person's own pages](../architecture/hosted-pages.md#a-persons-own-factors) use. The rules behind them are in [the authentication context](../architecture/contexts/authentication.md#a-persons-own-factors).

#### A recent sign-in

Every request below that changes something, and beginning a WebAuthn registration, needs a session signed in to at most five minutes before. Confirming an authenticator application and finishing a WebAuthn registration do not: they finish what was begun with one. Without a recent sign-in the answer is:

| Situation | Status | Code |
|---|---|---|
| The session was signed in to more than five minutes ago | `403` | `authentication.recent_sign_in_required` |

The pages then send the person to sign in again and bring them back.

#### Listing them

`GET /interaction/factors` answers:

```json
{
  "authenticator_application": { "in_use": true },
  "keys": [
    {
      "id": "0193f1d1-…",
      "name": "Blue key",
      "passkey": false,
      "created_at": "2026-11-20T14:05:00Z",
      "last_used_at": "2026-11-21T09:12:40Z"
    }
  ],
  "recovery_codes": { "remaining": 8 },
  "second_factor_required": false,
  "recent_sign_in_until": "2026-11-21T09:17:40Z"
}
```

| Field | Meaning |
|---|---|
| `authenticator_application` | Whether an application is in use; `null` when the installation offers none, because it cannot keep secrets |
| `keys` | Security keys and passkeys, oldest first. `passkey` is whether the credential is discoverable; `last_used_at` is `null` until it is used |
| `recovery_codes.remaining` | How many unused recovery codes the person has |
| `second_factor_required` | Whether the tenant requires a second factor, so that removing the last one is refused |
| `recent_sign_in_until` | Until when changes are allowed without signing in again; `null` when they are not allowed now |

#### The authenticator application

`POST /interaction/factors/authenticator-application`, with no body, begins enrolling one and answers `201`, once:

```json
{
  "secret": "JBSWY3DPEHPK3PXP…",
  "uri": "otpauth://totp/Acme:ana%40example.com?secret=JBSW…&issuer=Acme&algorithm=SHA1&digits=6&period=30"
}
```

The pages show `uri` as a QR code and `secret` as text, for an application that cannot scan. `POST /interaction/factors/authenticator-application/confirmation` with `{ "code": "123456" }` puts the application in use: `200` with `{}`, or with `recovery_codes` as for a first WebAuthn credential. `DELETE /interaction/factors/authenticator-application` removes it: `204`.

#### Keys

`PATCH /interaction/factors/keys/{key_id}` with `{ "name": "Office key" }` answers `200` with the key, as listed. `DELETE /interaction/factors/keys/{key_id}` answers `204`.

#### Recovery codes

`POST /interaction/factors/recovery-codes`, with no body, makes a new set in place of the old one and answers `201`, once: `{ "recovery_codes": ["7K2M-QX9D-4HVN-R8TA", …] }`.

#### Errors

| Situation | Status | Code |
|---|---|---|
| The installation offers no authenticator application | `404` | `credential.totp_unavailable` |
| No enrollment waits to be confirmed, or it waited more than ten minutes | `404` | `credential.totp_enrollment_not_found` |
| The code is not the one the application shows | `422` | `credential.totp_code_wrong` |
| The key is not the person's, or does not exist | `404` | `credential.webauthn_credential_not_found` |
| The name is empty, longer than 64 characters or holds control characters | `422` | `credential.webauthn_name_invalid` |
| Removing the last second factor while the tenant requires one | `422` | `authentication.last_second_factor` |
| Generating recovery codes without a second factor | `422` | `authentication.second_factor_missing` |
| Another set of recovery codes was generated at the same moment | `409` | `credential.recovery_codes_conflict` |

### Protection for these requests

The `DELETE`, `PATCH` and `POST` requests above change something, so each must carry the CSRF token from `GET /interaction/session` in the `X-CSRF-Token` header. The token is derived from the session token, and only a page from this origin can read it. A request without it, or with a wrong one, is refused with `403` and `request.csrf_token_invalid`, and changes nothing. The origin check applies as everywhere.

The session cookie is `SameSite=Lax`, which already keeps a browser from attaching it to a `DELETE` another site starts. The token is a second, independent measure. The bodies are JSON, which a plain cross-site form cannot send.

## Consent

When a third-party application asks for access a person has not agreed to, the authorization endpoint keeps the request and sends the browser to the consent page ([the OAuth context](../architecture/contexts/oauth.md#consent)). These routes are what that page and the account page use.

| Method and path | Purpose |
|---|---|
| `GET /interaction/consent` | What the waiting request asks for, to show it |
| `POST /interaction/consent` | The person's answer |
| `GET /interaction/consents` | The person's consents that stand |
| `DELETE /interaction/consents/{client_id}` | Withdraw one |

Each needs a valid session cookie, and is answered `401` with `session.not_authenticated` without one. The two that change something need the session's CSRF token in `X-CSRF-Token`, from `GET /interaction/session`, and pass the origin check, as [for a signed-in person](#protection-for-these-requests).

### What the request asks for

`GET /interaction/consent` reads the `__Secure-hodor_authorization` cookie. When it names a request that waits for consent, for this browser and for the session of this browser, the answer is:

```json
{
  "application": "Billing",
  "scopes": [
    { "scope": "openid", "kind": "openid" },
    { "scope": "email", "kind": "openid" },
    { "scope": "invoices:read", "kind": "resource", "description": "Read your invoices", "resource_server": "Invoices" }
  ],
  "offline_access": false,
  "csrf_token": "5b1e…"
}
```

- `kind` `openid` is a scope of OpenID Connect, which the page words in the person's language by its name;
- `kind` `resource` is a scope of a resource server, with the description and the resource server's name as the tenant's administrator wrote them;
- `offline_access` says the application asks to keep access when the person is not there. It is not repeated in `scopes`.

Without the cookie, with a request that does not wait for consent, that is another browser's, another session's or already answered, the answer is `404` with `oauth.consent_request_not_found`, in the same way for every reason.

### The answer

`POST /interaction/consent` with `{ "decision": "allow" }` or `{ "decision": "deny" }`. The request must be the one `GET` describes. The answer is recorded once; it is `200` with:

```json
{ "continue": "/t/acme/oauth2/authorize/resume" }
```

The page goes there, and the authorization endpoint answers the application: with a code after `allow`, with `access_denied` after `deny`. A request that was answered already, or none, is `404` with `oauth.consent_request_not_found`; a body that is not one of the two is `422` with `request.body_invalid`.

### The person's consents

`GET /interaction/consents` lists the consents of the person that stand and have not expired, the most recently given first:

```json
{
  "consents": [
    {
      "client_id": "0193f1d0-…",
      "application": "Billing",
      "scopes": ["openid", "email", "invoices:read"],
      "given_at": "2026-11-20T14:03:11Z",
      "expires_at": "2027-11-20T14:03:11Z"
    }
  ]
}
```

`DELETE /interaction/consents/{client_id}` withdraws the person's consent for that client and revokes the grants made under it: `204`. A consent the person does not have, of another person, or already withdrawn, is `404` with `oauth.consent_not_found`, all alike, so that a person learns nothing about another's.

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
| Trusting a forwarded client address from named proxies | Before any deployment behind a load balancer |
| Limiting requests per address on these paths, beyond the attempt limits of the password step | Later in Phase 1 |
| The `__Host-` cookie variant for a tenant's own host | Phase 3 |
| The history of a person's consents in the account pages | The account console, Phase 2 |
