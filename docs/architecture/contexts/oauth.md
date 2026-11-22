# The OAuth context

The `oauth` context makes Hodor an OAuth 2.x authorization server and an OpenID Provider. It owns the applications a tenant registers, the clients through which they ask for tokens, the resource servers those tokens are for, and, in later issues, the codes, grants, tokens and consents of [Milestone 3](../../product/epics.md#milestone-3-applications-ask-hodor-who-someone-is).

It does not sign anyone in. When a request needs a person, it hands the request to the `authentication` context and takes the session that comes back. The two contexts do not depend on each other: the HTTP layer joins them ([crates.md](../crates.md)).

This page specifies what Issue-53 builds: applications, clients and resource servers, and the rules they keep; what Issue-55 builds: the authorization endpoint, grants and authorization codes; and what Issue-56 builds: the token endpoint, client authentication and access tokens. The other endpoints, the other tokens and consent are added by Issue-57 to Issue-62, under the headings at the end of this page.

## Applications

An application is what a tenant's administrator registers: a web site, a mobile application, a service. It is the unit people recognize. It groups the clients that ask for tokens on its behalf, and it may expose one resource server.

| Field | Meaning |
|---|---|
| Identifier | An `ApplicationId` |
| Name | Shown to people, for example on the consent page. 1 to 100 characters, without control characters; spaces at either end are removed |
| First party | Whether the application belongs to whoever runs the tenant. A first-party application is not asked for consent (Issue-62) |
| Status | `enabled` or `disabled`. The clients of a disabled application get no tokens |

A tenant has at most 100 applications.

## Clients

A client is what talks to Hodor's endpoints. Its identifier is the `client_id` of OAuth.

| Field | Meaning |
|---|---|
| Identifier | A `ClientId`. Written as a UUID, it is the `client_id` the client sends. It is not a secret |
| Application | The application it belongs to. It never changes |
| Name | For administrators. Same rule as an application's name |
| Type | `confidential`: it runs where it can keep a secret, such as a server. `public`: it runs where it cannot, such as a browser or a mobile application. Chosen when the client is created and never changed |
| Authentication method | How it proves who it is at the token endpoint: `client_secret_basic`, `client_secret_post`, `private_key_jwt` or `none` |
| Grants | What it may ask for: `authorization_code`, `refresh_token`, `client_credentials` |
| Redirect addresses | Where the authorization endpoint may send a person back to. At most 10 |
| Scopes | The scopes it may ask for. At most 50 |
| PKCE | Whether it must send a code challenge. Always for a public client; on by default for a confidential one |
| Token policy | How long its tokens live |
| Secrets | Its secrets, kept only as hashes. Only with `client_secret_basic` or `client_secret_post` |
| Keys | Its public keys, for `private_key_jwt`. Only with that method |
| Status | `enabled` or `disabled`. A disabled client gets no tokens |

An application has at most 20 clients.

### What a client may be

Every change to a client is checked against all of these at once; a change that breaks one changes nothing.

- **A public client has no secret and cannot be given one.** Its authentication method is `none`, it has no keys, and it always uses PKCE.
- **A confidential client proves who it is.** Its method is `client_secret_basic`, `client_secret_post` or `private_key_jwt`, never `none`.
- **`client_credentials` is for confidential clients only**, since that grant is the client acting as itself.
- **`refresh_token` comes with `authorization_code`.** A refresh token is only ever issued with tokens from a code.
- **A client with `authorization_code` has at least one redirect address, and one without it has none.**
- **A client has at least one grant.**
- **Switching the authentication method drops what the old one used.** A client that moves away from a secret method loses its secrets, and one that moves away from `private_key_jwt` loses its keys.

### Redirect addresses

A redirect address is where a person's browser is sent with a code. Sending a code to the wrong place hands it to whoever is there, so the rules are strict:

- **Compared by exact equality only.** The address an authorization request names must be, character for character, one that is registered. No prefix, no pattern, no normalization, not even the port of a loopback address. [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) recommends this.
- **HTTPS**, with a host, without a name and password, a fragment or a `*`.
- **Plain HTTP only to a loopback address written as an address**, `127.0.0.1` or `[::1]`, for an application on the person's own machine ([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252#section-7.3)). The name `localhost` is not accepted, since it can resolve elsewhere.
- **A private-use scheme only for a public client**, written as a reversed domain name that has a dot in it, such as `com.example.app:/callback` ([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252#section-7.1)).
- At most 2000 characters, all of them printable ASCII without spaces.

An address is kept exactly as it was given.

### Scopes a client may ask for

A scope is written as OAuth writes it: 1 to 128 characters, printable ASCII without spaces, double quotes or backslashes. The list is kept in the order given, without repeats. Whether a resource server or OpenID Connect defines it is checked when it is asked for (Issue-55 and Issue-59), not here.

### Secrets

A secret is what a confidential client using `client_secret_basic` or `client_secret_post` proves who it is with.

- **It is made by Hodor**: `hodor_cs_` followed by 64 hexadecimal characters, from 32 random bytes of the operating system. The beginning lets tools that look for leaked secrets recognize one.
- **It is shown once**, when it is made, and stored nowhere. Hodor keeps its SHA-256 hash ([Decision 0004](../../decisions/0004-token-formats.md)): with 256 bits of randomness there is nothing to guess, so a slow hash would add nothing.
- **Every secret expires**, after 1 to 730 days; 365 unless the administrator chooses.
- **Rotation keeps the newest previous secret for a while.** Making a new secret keeps the one made just before it working for 0 to 30 days more, so that the client can be changed over without stopping. Every older secret stops at once. A client therefore has at most two secrets that work.
- **A secret can be revoked**, and it stops at once.
- A client gets its first secret when it is created with a secret method.

A presented secret is checked by computing its hash and comparing it, in constant time, with each secret of the client that has not expired. A value that does not have the shape of a secret matches nothing and nothing is computed for it.

### Keys

A client using `private_key_jwt` proves who it is by signing an assertion with its own private key ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)). Hodor keeps the public key as a JSON Web Key:

- `kid` is required, 1 to 128 printable characters, unique among the client's keys;
- `kty` is `EC` with `crv` `P-256` or `P-384`, `RSA` with a modulus of at least 2048 bits, or `OKP` with `crv` `Ed25519`;
- `use`, if present, is `sig`; `alg`, if present, fits the key: `ES256`, `ES384`, `RS256`, `PS256` or `EdDSA`;
- **no private part**: a key with `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` or `k` is refused, so that a private key pasted by mistake is never kept;
- at most 5 keys per client.

Checking an assertion against these keys is Issue-56.

### Token policy

| Setting | Allowed | Default |
|---|---|---|
| Access token lifetime | 1 minute to 1 hour | 5 minutes ([Decision 0004](../../decisions/0004-token-formats.md)) |
| ID token lifetime | 1 minute to 1 hour | 5 minutes |
| Refresh token lifetime | 1 hour to 365 days; the most a refresh token family can live | 30 days |
| Refresh token idle time | 1 hour up to the refresh token lifetime; how long a refresh token lasts unused | 7 days |

## Resource servers

A resource server is an interface that accepts Hodor's access tokens. Its identifier is the audience of those tokens and the `resource` a client names in a request ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)).

| Field | Meaning |
|---|---|
| Identifier | A `ResourceServerId` |
| Application | The application that exposes it; an application has at most one resource server. Never changes |
| Audience | An absolute address, `https://…` or `urn:…`, without a fragment, at most 255 printable characters. Unique in the tenant and never changed, since tokens already issued name it |
| Name | For administrators and the consent page. Same rule as an application's name |
| Scopes | What it defines, each with a name and a description of up to 200 characters. At most 100 |

A scope name follows the rule of [scopes a client may ask for](#scopes-a-client-may-ask-for), is unique within the resource server and is none of the names OpenID Connect defines: `openid`, `profile`, `email`, `address`, `phone`, `offline_access`.

## Operations

| Use case | What it does |
|---|---|
| Create, change, enable and disable an application | Name and first party; the status |
| Create a client | Checks the settings against [what a client may be](#what-a-client-may-be); a confidential client with a secret method gets its first secret, returned once |
| Change a client | Replaces its settings, all checked again |
| Rotate a client's secret | Makes a new secret, returned once, and shortens or ends the old ones as [the rules](#secrets) say |
| Revoke a client's secret | Ends one secret at once |
| Add and remove a client's key | Only for `private_key_jwt` |
| Enable and disable a client | |
| Create and change a resource server | Name and scopes; the audience is fixed |
| Read and list | An application, the tenant's applications, a client, an application's clients, a resource server by identifier or by audience, the tenant's resource servers |

Changes use optimistic locking: a change made from a copy someone else has changed since is refused with a conflict, and nothing is stored.

Administrators reach these use cases through [the administration interface](../../api/admin-api.md#applications-clients-and-resource-servers), the console's applications screens ([the admin console](../admin-console.md#screens)) and `hodor-cli application`, `hodor-cli client` and `hodor-cli resource-server` (Issue-54). They need the permissions `applications:read` and `applications:write` ([the authorization context](authorization.md#permissions)).

### The command-line tool

For an operator who can reach the database, as for tenants and identity providers. The commands need `HODOR_DATABASE_URL` and name the tenant by its slug; what they do is in the audit log with Hodor itself as the actor.

| Command | What it does |
|---|---|
| `hodor-cli application add --tenant acme --name Billing [--first-party]` | Registers an application, enabled; third party unless `--first-party` is given. Prints its identifier |
| `hodor-cli application list --tenant acme` | One line per application: identifier, status, first or third party, name |
| `hodor-cli application disable --tenant acme --id …`, `enable` | |
| `hodor-cli client add --tenant acme --application … --name … --type confidential --grant authorization_code --redirect-uri https://… --scope openid` | Creates a client. `--grant`, `--redirect-uri` and `--scope` are given once per value; `--method` chooses the authentication method and `--secret-days` the lifetime of the first secret. Prints the `client_id` and, for a client with a secret method, the secret, once |
| `hodor-cli client list --tenant acme --application …` | One line per client: `client_id`, status, type, authentication method, name |
| `hodor-cli client rotate-secret --tenant acme --id … [--lifetime-days 365] [--keep-previous-days 7]` | Gives a client a new secret and prints it, once |
| `hodor-cli client disable --tenant acme --id …`, `enable` | |
| `hodor-cli resource-server add --tenant acme --application … --audience https://api.example.com --name … --scope 'invoices:read=Read your invoices'` | Registers the resource server of an application; `--scope` is given once per scope, as its name, `=` and its description |
| `hodor-cli resource-server list --tenant acme` | One line per resource server: identifier, audience, name, scopes |

Changing a client's settings, ending one secret and managing keys are done through the administration interface or the console.

### Events

| Event type | When |
|---|---|
| `oauth.application_created`, `oauth.application_changed` | An application was registered or changed; carry its identifier and name |
| `oauth.application_enabled`, `oauth.application_disabled` | |
| `oauth.client_created`, `oauth.client_changed` | Carry the client, its application and its type |
| `oauth.client_enabled`, `oauth.client_disabled` | |
| `oauth.client_secret_issued`, `oauth.client_secret_revoked` | Carry the client and the secret's identifier, and when it expires; never the secret or its hash |
| `oauth.client_key_added`, `oauth.client_key_removed` | Carry the client and the `kid` |
| `oauth.resource_server_created`, `oauth.resource_server_changed` | Carry the resource server and its audience |

### Ports

| Port | Purpose |
|---|---|
| `ApplicationStore` | Store, change and load applications |
| `ClientStore` | Store, change and load clients with their secrets and keys |
| `ResourceServerStore` | Store, change and load resource servers; find one by audience |
| `Digest` | SHA-256, from the kernel |
| `RandomSource` | The random bytes of a secret, from the kernel |

## Storage

Every table is a tenant table under row-level security, in the schema `oauth`. References between them include the tenant, so a row can only name a row of its own tenant.

### `oauth.application`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `id` | `uuid` | Primary key |
| `name` | `text` | |
| `first_party` | `boolean` | |
| `status` | `text` | `enabled` or `disabled` |
| `created_at`, `updated_at` | `timestamptz` | |
| `version` | `integer` | For optimistic locking |

### `oauth.client`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `id` | `uuid` | Primary key |
| `application_id` | `uuid` | References `oauth.application` |
| `name`, `client_type`, `authentication_method`, `status` | `text` | A check constraint keeps a public client on `none` |
| `grant_types`, `redirect_uris`, `allowed_scopes` | `text[]` | Redirect addresses are compared byte for byte (`COLLATE "C"`) |
| `require_pkce` | `boolean` | A check constraint keeps it true for a public client |
| `access_token_seconds`, `id_token_seconds`, `refresh_token_seconds`, `refresh_idle_seconds` | `integer` | The token policy |
| `created_at`, `updated_at` | `timestamptz` | |
| `version` | `integer` | For optimistic locking; secrets and keys are stored with the client under the same version |

### `oauth.client_secret`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `client_id`, `id` | `uuid` | Primary key; the client is referenced and its secrets go with it |
| `secret_hash` | `bytea` | SHA-256 of the secret; 32 bytes, unique in the tenant |
| `created_at`, `expires_at` | `timestamptz` | |

A revoked or replaced secret is deleted: there is nothing to keep about a secret that no longer works.

### `oauth.client_key`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `client_id` | `uuid` | The client is referenced and its keys go with it |
| `key_id` | `text` | The `kid`; primary key with the tenant and the client |
| `jwk` | `jsonb` | The public key; a check constraint refuses one with a private part |
| `position` | `integer` | The order the keys were added in |
| `added_at` | `timestamptz` | |

### `oauth.resource_server` and `oauth.resource_server_scope`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `id` | `uuid` | Primary key |
| `application_id` | `uuid` | References `oauth.application`; unique in the tenant |
| `audience` | `text` | Unique in the tenant, compared byte for byte |
| `name` | `text` | |
| `created_at`, `updated_at`, `version` | | As for applications |

`oauth.resource_server_scope` holds `tenant_id`, `resource_server_id`, `name` and `description`, with the tenant, the resource server and the name as primary key, in the order they were given (`position`).

## Authorization endpoint

Issue-55. The authorization endpoint is where a client sends a person's browser to ask for an authorization code ([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1)). It is at `/t/{slug}/oauth2/authorize` and answers `GET` with the parameters in the query, and `POST` with them in a form (`application/x-www-form-urlencoded`); a `POST` with another body is answered with Hodor's own page, `oauth.authorization_form_expected`. A browser does not send the session cookie with a form another site posts (the cookie is `SameSite=Lax`), so a request by `POST` always has the person sign in. Its sequence is [sequence 2](../../protocols/sequences.md#2-oauth-20-authorization-code-with-pkce).

The **issuer** of the tenant is `{HODOR_PUBLIC_URL}/t/{slug}`, without a slash at the end. Every successful answer and every error sent back to a client carries it as `iss` ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)), so that a client talking to several servers knows which one answered. Discovery (Issue-59) advertises the same value.

### Checking the request

Nothing is shown and nothing is stored until the request has been checked. The checks are made in this order, and the first that fails decides the answer.

**First, whether the request may be answered at its redirect address at all.** Until the client and its redirect address are known to be genuine, an error is never sent to the address the request names, because that address could be anyone's ([RFC 6749, section 4.1.2.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1)). These failures are answered with a page of Hodor's own, status `400`, that says the request cannot be answered and names the reason by its code:

| Failure | Code |
|---|---|
| `client_id` missing, given twice, or not the identifier of a client of this tenant | `oauth.authorization_client_unknown` |
| The client or its application is disabled | `oauth.authorization_client_unknown` |
| The client may not use the authorization code (it has no redirect address) | `oauth.authorization_client_unknown` |
| `redirect_uri` missing or given twice | `oauth.authorization_redirect_uri_missing` |
| `redirect_uri` is not, character for character, one of the client's redirect addresses | `oauth.authorization_redirect_uri_unregistered` |

`redirect_uri` is required even when the client has only one redirect address. OpenID Connect requires it, and requiring it always leaves one rule instead of two.

A client of another tenant is unknown here: the client is looked up only in the tenant the address names.

**Then, everything else, answered at the redirect address.** From here on, an error is sent back by redirecting the browser to the redirect address with `error`, `error_description`, `state` when the request had one, and `iss`:

| Failure | `error` |
|---|---|
| A parameter other than `resource` is given more than once | `invalid_request` |
| `request` is given: request objects are not supported | `request_not_supported` |
| `request_uri` is given: request objects are not supported | `request_uri_not_supported` |
| `response_mode` is given and is not `query` | `invalid_request` |
| `response_type` is missing | `invalid_request` |
| `response_type` is anything but `code` | `unsupported_response_type` |
| `code_challenge` is missing for a client that requires PKCE (every public client, and a confidential one unless an administrator turned it off) | `invalid_request` |
| `code_challenge_method` is missing or is not `S256`. `plain` is refused: a challenge without a method means `plain` ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636#section-4.3)) | `invalid_request` |
| `code_challenge` is not 43 characters of base64url without padding, the length of a SHA-256 digest | `invalid_request` |
| `state` or `nonce` is longer than 1024 characters or holds characters outside printable ASCII | `invalid_request` |
| `prompt` holds a value other than `none`, `login`, `consent` and `select_account`, or `none` with another | `invalid_request` |
| `max_age` is not a whole number of seconds from 0 to 31 536 000 | `invalid_request` |
| `login_hint`, `ui_locales` or `acr_values` is longer than 255 characters | `invalid_request` |
| `scope` is missing or empty, holds a scope the client may not ask for, or a scope that neither OpenID Connect nor a resource server of the request defines | `invalid_scope` |
| More than 10 `resource` values; a `resource` that is not an absolute address without a fragment; or one that is not the audience of a resource server of this tenant ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)) | `invalid_target` |
| The client belongs to an application that is not first party | `access_denied` |

**The resource servers of a request.** When the request names resources, they are the resource servers whose audiences it names, and every scope that is not one of OpenID Connect's must be defined by one of them. When it names none, they are the resource servers of the tenant that define the scopes asked for. The resource servers become the audiences of the tokens issued from the code (Issue-56).

**Only first-party applications until consent exists.** Consent is Issue-62. Until then, a person would be giving a third-party application access to their account without being asked, so the clients of an application that is not first party are refused with `access_denied`. The administrator of a tenant decides which applications are first party.

Parameters this issue does not use are kept with the request for the issues that do: `nonce` (Issue-59), `acr_values` (Issue-69), `login_hint` and `ui_locales` (Issue-59). Parameters the endpoint does not know are ignored, as RFC 6749 requires.

### Whether the person must sign in

A checked request needs a person signed in to the tenant. The session cookie of the browser is looked up as for every route of the tenant, and the request decides whether that session is enough:

| Situation | What happens |
|---|---|
| No valid session, and `prompt` holds `none` | Error `login_required` at the redirect address |
| A valid session older than `max_age`, and `prompt` holds `none` | Error `login_required` |
| A valid session, `prompt` neither `login` nor `select_account`, and not older than `max_age` when it is given | A code is issued at once |
| No valid session; or `prompt` holds `login` or `select_account`; or the session is older than `max_age` | The person signs in, then the request goes on |

`select_account` is treated as `login`: a browser holds one session per tenant, so the only way to choose another account is to sign in as it. `consent` asks for nothing more until consent exists.

### Signing in and coming back

When the person must sign in, the request is kept and the browser is sent to the hosted pages.

1. The checked request is stored as a **pending authorization request**, for ten minutes, the life of a sign-in. It is bound to the browser exactly as a sign-in is: Hodor makes a random secret of 256 bits, stores only its SHA-256 hash with the request, and gives the browser the request's identifier and the secret in a cookie.
2. The browser is redirected to `/t/{slug}/account/sign-in?continue=authorization`. That address tells the sign-in page to start a sign-in even when the browser is signed in already, since the request asked for a new one.
3. The person signs in with any way the tenant offers, an identity provider included. When the sign-in completes, the interaction interface sees the cookie and adds `"continue": "/t/{slug}/oauth2/authorize/resume"` to its answer ([the interaction interface](../../api/interaction-api.md#what-a-sign-in-response-looks-like)). The page goes there instead of to the account page.
4. `GET /t/{slug}/oauth2/authorize/resume` reads the cookie, takes the pending request, which can therefore be resumed once, and removes the cookie. Without the cookie, with a wrong secret or after ten minutes, it answers with Hodor's own error page, `oauth.authorization_request_not_found`.
5. The session is checked again against the request. A request that asked for a new sign-in (`prompt=login` or `select_account`, or `max_age` that the old session did not meet) needs a session that signed in after the request arrived. When the session is enough, a code is issued; when it is not, because the person did not sign in again, the answer is `access_denied` at the redirect address.

The cookie:

| Attribute | Value | Why |
|---|---|---|
| Name | `__Secure-hodor_authorization` | |
| Value | The pending request's identifier and its secret | |
| `HttpOnly`, `Secure` | Yes | As for the other cookies |
| `SameSite` | `Strict` | It is only ever needed by requests Hodor's own pages make |
| `Path` | `/t/{slug}` | Sent to the interaction interface, which adds `continue`, and to the resume address |
| `Max-Age` | 600 seconds | |

A browser has one pending authorization request per tenant at a time: a new one replaces the cookie of the one before, which then cannot be resumed.

### The authorization code

When the person is signed in and the session is enough, a **grant** and an **authorization code** are made.

- **The grant** records that this person let this client act for them, with the scopes and audiences of the request and the session it was made in. It is what the refresh tokens of Issue-57 belong to, and it can be revoked; revoking it ends whatever was issued from it.
- **The code** is 32 random bytes from the operating system, written as base64url without padding. Hodor keeps only its SHA-256 hash ([Decision 0004](../../decisions/0004-token-formats.md)), with the grant, the client, the redirect address, the code challenge, the scopes, the audiences, the `nonce`, the session, the user, when they signed in and with which methods. It lives **60 seconds**.
- The browser is redirected to the redirect address with `code`, `state` when the request had one, and `iss`. The redirect address keeps its own query, and the parameters are added after it.

Every answer of the endpoint, a redirect included, carries `Cache-Control: no-store`, so that no code or error is kept by a cache.

### Redeeming a code

The token endpoint (Issue-56) redeems a code. The rules are the context's, so that the token endpoint only translates them:

- the code is found by the hash of what was presented; an unknown code, a code of another tenant and a code past its 60 seconds are all refused alike;
- it must be presented by the client it was issued to, with the same redirect address;
- with a code challenge, the verifier must be 43 to 128 characters of `A`–`Z`, `a`–`z`, `0`–`9`, `-`, `.`, `_` and `~`, and the base64url of its SHA-256 must equal the challenge; without one, a verifier is refused, so that a client cannot be made to skip PKCE by an attacker who removed the challenge ([RFC 9700](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1));
- **a code is redeemed once.** Marking it redeemed is one conditional change in storage, so two redemptions at the same moment cannot both win. **A second redemption, by anyone, revokes the grant**, and with it everything issued from it ([RFC 6749, section 4.1.2](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2)).

A refusal of any kind is one answer to the client, `invalid_grant`; the reason is in Hodor's own logs and events only.

### Events

| Event type | When |
|---|---|
| `oauth.authorization_code_issued` | A code was issued; carries the client, the grant and the user, never the code or its hash |
| `oauth.grant_revoked` | A grant was revoked; carries the grant, the client and the reason, such as `code_reused` |

### Ports

| Port | Purpose |
|---|---|
| `AuthorizationRequestStore` | Store a pending authorization request; load one by its identifier; remove it only if it is still there, so that it is resumed once |
| `GrantStore` | Store a grant; load one; store its revocation |
| `AuthorizationCodeStore` | Store a code; find one by its hash; mark it redeemed only if it was not |

### Storage

| Table | Holds |
|---|---|
| `oauth.authorization_request` | `tenant_id`, `id`, `secret_hash` (32 bytes), `client_id`, the checked request as `request` (`jsonb`), `received_at`, `expires_at` |
| `oauth.authorization_grant` | `tenant_id`, `id`, `client_id`, `user_id`, `session_id`, `scopes`, `audiences`, `status` (`active` or `revoked`), `created_at`, `revoked_at`, `revocation_reason` |
| `oauth.authorization_code` | `tenant_id`, `code_hash` (32 bytes, the key), `grant_id`, `client_id`, `redirect_uri`, `scopes`, `audiences`, `code_challenge`, `nonce`, `session_id`, `user_id`, `signed_in_at`, `methods`, `issued_at`, `expires_at`, `redeemed_at` |

All three are tenant tables under row-level security. The request and the code reference their client, and the code its grant, with the tenant in the reference. A pending request and a code hold the hash of a secret, never the secret.

## Token endpoint and client authentication

Issue-56 builds the token endpoint, the four ways a client proves who it is there, and the access token issued for a code. Refresh tokens and client credentials are Issue-57; the ID token is Issue-59. The endpoint is at `/t/{slug}/oauth2/token` and answers `POST` with a form (`application/x-www-form-urlencoded`) only ([RFC 6749, section 3.2](https://www.rfc-editor.org/rfc/rfc6749#section-3.2)).

### The request

- Any other method is answered `405`; a body that is not a form is `invalid_request`.
- A body larger than 64 kibibytes is refused, as for every request.
- A parameter given more than once is `invalid_request`, since the specification forbids it.
- `grant_type` is required:
  - missing: `invalid_request`;
  - `authorization_code`: built here;
  - `refresh_token` and `client_credentials`: answered `unsupported_grant_type` until Issue-57;
  - anything else: `unsupported_grant_type`.

### How a client proves who it is

A client proves who it is in exactly one of four ways, and it must be the one it was registered with:

| Method | What the request carries |
|---|---|
| `client_secret_basic` | `Authorization: Basic` with the client identifier and the secret, each form-encoded before the pair is base64-encoded ([RFC 6749, section 2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1)) |
| `client_secret_post` | `client_id` and `client_secret` in the form |
| `private_key_jwt` | `client_assertion_type` `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion`, a JSON Web Token the client signed with its private key ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)); `client_id` may be added and must then name the same client |
| `none` | `client_id` alone, for a public client, which proves nothing and is held to PKCE instead |

The checks, in order:

1. **One method only.** A request that carries more than one is `invalid_request`: for example, both a `Basic` header and a `client_secret`, or both a secret and an assertion. `Authorization` with a scheme other than `Basic` is `invalid_request` too.
2. **The client exists and may get tokens.** It must be a client of this tenant, enabled, with its application enabled. Otherwise the answer is `invalid_client`.
3. **The method is the client's.** A client registered with `client_secret_basic` that sends its secret in the form is refused, and so is a confidential client that sends only its identifier. The answer is `invalid_client`.
4. **The proof holds.**
   - A secret is checked as [secrets](#secrets) says.
   - An assertion is checked as the next section says.

An `invalid_client` is answered with status `401`. When the client used `Basic`, the answer also carries `WWW-Authenticate: Basic realm="{issuer}"`, as RFC 6749 requires. Every other error is answered with status `400`. The client is told only the error, never which check failed; the reason is in Hodor's logs.

### Checking a client assertion

An assertion is a compact JSON Web Signature of at most 8 kibibytes. When the form carries no `client_id`, the assertion's `iss` is read first, only to know whose keys to check it with. It is then checked as follows, and nothing else it says is used before its signature has been checked:

| Check | Refused when |
|---|---|
| Shape | It is not three base64url parts, or its header or claims are not JSON objects |
| Algorithm | The header's `alg` is not `ES256`, `RS256` or `PS256`. `none` and the shared-secret algorithms can never be named |
| Key | The header names a `kid` the client does not have, or names none while more than one of the client's keys fits the algorithm. The key must fit the algorithm: a P-256 key for `ES256`, an RSA key for `RS256` and `PS256`, and the key's own `alg` when it has one |
| Signature | It does not verify over the first two parts, exactly as they arrived |
| `iss` and `sub` | Either is not the client's identifier |
| `aud` | It does not hold the tenant's issuer or the address of the token endpoint, `{issuer}/oauth2/token`. Both are accepted: RFC 7523 names the token endpoint, and the revision of OAuth 2.1 recommends the issuer |
| `exp` | Missing, in the past (allowing 60 seconds for clocks), or more than 5 minutes ahead: an assertion is for one request, and a long one would have to be remembered long |
| `nbf`, `iat` | In the future, allowing 60 seconds |
| `jti` | Missing, longer than 255 characters, or seen before for this client |

**An assertion is used once.** As soon as it has been checked, and before anything else is done with the request, its `jti` is remembered with the client until the assertion expires. A second request with the same `jti` is refused, even when the first one failed afterwards, for example on a wrong code: an assertion that was sent once may have been seen by someone else.

A client key on P-384 or Ed25519 can be registered but cannot yet sign an assertion that Hodor accepts. Hodor's signature checking covers `ES256`, `RS256` and `PS256` today.

### Redeeming a code for tokens

With `grant_type=authorization_code`, the request carries `code`, `redirect_uri` and, when the code was issued with a challenge, `code_verifier`.

- **Redemption:** the code is redeemed by the rules of [redeeming a code](#redeeming-a-code); any refusal is `invalid_grant`.
- **Grant:** the grant the code was issued under must still be active.
- **Client:** the client must be allowed the `authorization_code` grant; otherwise the answer is `unauthorized_client`.

### The access token

The access token is a JSON Web Token per [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068), signed by the [keys context](keys.md) with the tenant's active `ES256` key.

| Part | Value |
|---|---|
| Header | `alg` `ES256`, `typ` `at+jwt`, `kid` the identifier of the key version that signed, as the [published key set](keys.md) names it |
| `iss` | The tenant's issuer |
| `sub` | The person's user identifier |
| `aud` | The audiences of the code: the resource servers of the request. A request that named none and asked only for OpenID Connect's scopes gets the issuer itself as its audience, for Hodor's own endpoints such as UserInfo (Issue-59) |
| `client_id` | The client |
| `scope` | The scopes of the code, separated by spaces |
| `iat`, `exp` | When it was issued, and that plus the client's access token lifetime |
| `jti` | 16 random bytes, base64url, unique to this token |
| `auth_time` | When the person signed in |

`acr` and `amr` are added with assurance levels (Issue-69): the methods a session records, such as `password` and `totp`, are Hodor's own names, and `amr` takes the names of [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176), which need a mapping that Issue-69 decides. `sid` comes with logout (Issue-60).

**No signed token outlives the rotation overlap.** The keys context keeps a retiring key published for `RotationPolicy::LONGEST_SIGNED_LIFETIME`, one hour, after it stops signing. The token policy therefore refuses an access or ID token lifetime longer than that, and the token endpoint refuses to sign one: a token checked after its key left the key set would be refused by everyone.

A tenant without an active signing key cannot issue tokens. The worker makes the first key ([keys](keys.md)), and the answer is `500` with `server_error` until it has.

### The answer

```json
{
  "access_token": "eyJ…",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "openid orders:read"
}
```

- **Caching:** the answer carries `Cache-Control: no-store` and `Pragma: no-cache`.
- **Errors:** they are JSON with `error` and `error_description` ([RFC 6749, section 5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2)).
- **Refresh token:** `refresh_token` is added by Issue-57.
- **ID token:** `id_token` is added by Issue-59 when the scopes hold `openid`.

### Events

| Event type | When |
|---|---|
| `oauth.access_token_issued` | An access token was issued. It carries the client, the grant, the user, the token's `jti` and when it expires, never the token |

### Ports

| Port | Purpose |
|---|---|
| `ClientAssertionStore` | Remember a client assertion's `jti` until it expires. It answers whether this was the first time, so that of two requests with the same assertion at the same moment exactly one goes on |
| `SignatureVerifier` | Checks a client's assertion, from the kernel |
| `KeyService` | Signs the access token with the tenant's active key, from the keys context |

### Storage

`oauth.client_assertion` holds `tenant_id`, `client_id`, `jti` and `expires_at`, with the tenant, the client and the `jti` as primary key. It is a tenant table under row-level security, and its client is referenced with the tenant, so its rows go when the client goes.

## Revocation, introspection and metadata

Issue-58.

## OpenID Provider

Issue-59 and Issue-60.

## Consent

Issue-62.

## Not built yet

| Item | Planned in |
|---|---|
| Refresh tokens and the client credentials grant | Issue-57 |
| The other endpoints | Issue-58 to Issue-60 |
| Calling the token endpoint from a browser on another origin: clients have no registered origins yet, so no cross-origin headers are sent | With origins in the client settings |
| Client assertions signed with `ES384` or `EdDSA`, which client keys on P-384 and Ed25519 would need | When the kernel's signature checking covers them |
| Limits on requests to the token endpoint per address | With the other limits per address |
| Removing remembered client assertions after they expire | A cleanup job, with the other expired rows |
| Asking a person for consent; until then only clients of first-party applications are answered | Issue-62 |
| Enforcing `acr_values` | Issue-69 |
| Limits on requests to the authorization endpoint per address | With the other limits per address, before any deployment behind a load balancer |
| Removing expired pending requests, codes and revoked grants | A cleanup job, with the other expired rows |
| Request objects (`request`, `request_uri`) and pushed authorization requests | Phase 4, after 0.2.0 |
| Pairwise subject identifiers, claim mappers per client | Phase 2, after 0.2.0 ([Decision 0023](../../decisions/0023-what-0.2.0-holds.md)) |
| Opaque access tokens chosen per client | Not planned for 0.2.0 |
| Accepting any port for a loopback redirect address, which RFC 8252 suggests | Not planned: exact equality is kept |
