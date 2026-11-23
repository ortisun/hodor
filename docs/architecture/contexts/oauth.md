# The OAuth context

The `oauth` context makes Hodor an OAuth 2.x authorization server and an OpenID Provider. It owns the applications a tenant registers, the clients through which they ask for tokens, the resource servers those tokens are for, and, in later issues, the codes, grants, tokens and consents of [Milestone 3](../../product/epics.md#milestone-3-applications-ask-hodor-who-someone-is).

It does not sign anyone in. When a request needs a person, it hands the request to the `authentication` context and takes the session that comes back. The two contexts do not depend on each other: the HTTP layer joins them ([crates.md](../crates.md)).

This page specifies what Issue-53 builds: applications, clients and resource servers, and the rules they keep; what Issue-55 builds: the authorization endpoint, grants and authorization codes; what Issue-56 builds: the token endpoint, client authentication and access tokens; what Issue-59 builds: the OpenID Provider; what Issue-60 builds: logout initiated by the relying party; and what Issue-62 builds: [consent](#consent). The other endpoints and tokens are added by Issue-57 and Issue-58, under the headings at the end of this page.

## Applications

An application is what a tenant's administrator registers: a web site, a mobile application, a service. It is the unit people recognize. It groups the clients that ask for tokens on its behalf, and it may expose one resource server.

| Field | Meaning |
|---|---|
| Identifier | An `ApplicationId` |
| Name | Shown to people, for example on the consent page. 1 to 100 characters, without control characters; spaces at either end are removed |
| First party | Whether the application belongs to whoever runs the tenant. A person is not asked for [consent](#consent) for a first-party application |
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
| Post-logout redirect addresses | Where [logout](#logout-initiated-by-the-relying-party) may send a person back to. At most 10 |
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
- **Only a client with `authorization_code` has post-logout redirect addresses**, since only it gets ID tokens and signs people in. It may have none.
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

**Post-logout redirect addresses** follow the same rules, checked the same way, and are a list of their own: an address where a person may be sent with a code is not, for that reason, one where they may be sent after signing out, and the reverse.

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

How an assertion is checked against these keys is in [checking a client assertion](#checking-a-client-assertion).

### Token policy

| Setting | Allowed | Default |
|---|---|---|
| Access token lifetime | 1 minute to 1 hour | 5 minutes ([Decision 0004](../../decisions/0004-token-formats.md)) |
| ID token lifetime | 1 minute to 1 hour | 5 minutes |
| Refresh token lifetime | 1 hour to 365 days; the most a refresh token family can live | 30 days |
| Refresh token idle time | 1 hour up to the refresh token lifetime; how long a refresh token lasts unused | 7 days |
| Consent lifetime | 1 to 730 days; how long a person's [consent](#consent) to the client lasts before they are asked again | 365 days |

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
| `hodor-cli client add --tenant acme --application … --name … --type confidential --grant authorization_code --redirect-uri https://… --scope openid` | Creates a client. `--grant`, `--redirect-uri`, `--post-logout-redirect-uri` and `--scope` are given once per value; `--method` chooses the authentication method and `--secret-days` the lifetime of the first secret. Prints the `client_id` and, for a client with a secret method, the secret, once |
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
| `grant_types`, `redirect_uris`, `post_logout_redirect_uris`, `allowed_scopes` | `text[]` | Redirect addresses of both kinds are compared byte for byte (`COLLATE "C"`) |
| `require_pkce` | `boolean` | A check constraint keeps it true for a public client |
| `access_token_seconds`, `id_token_seconds`, `refresh_token_seconds`, `refresh_idle_seconds`, `consent_seconds` | `integer` | The token policy |
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

**The resource servers of a request.** When the request names resources, they are the resource servers whose audiences it names, and every scope that is not one of OpenID Connect's must be defined by one of them. When it names none, they are the resource servers of the tenant that define the scopes asked for. The resource servers become the audiences of the tokens issued from the code (Issue-56).

`nonce`, `login_hint` and `ui_locales` are kept with the request for the [ID token and the pages](#what-a-request-may-ask-of-the-sign-in); `acr_values` and `max_age` decide [the assurance and the step-up](#assurance-and-step-up). Parameters the endpoint does not know are ignored, as RFC 6749 requires; `claims` is one of them, so an `acr` asked for through it asks for nothing.

### Whether the person must sign in

A checked request needs a person signed in to the tenant. The session cookie of the browser is looked up as for every route of the tenant, and the request decides whether that session is enough:

| Situation | What happens |
|---|---|
| No valid session, or `prompt` holds `login` or `select_account` | The person signs in, then the request goes on. With `prompt=none`, error `login_required` instead |
| A valid session that is [enough](#assurance-and-step-up) for the request | [Consent](#when-a-person-is-asked) is decided; when nobody needs to be asked, a code is issued at once |
| A valid session that is not enough: too old for `max_age`, or below the level asked for | A [step-up](#assurance-and-step-up) asks the person for what the session lacks, then the request goes on. With `prompt=none`, error `login_required` instead |
| A valid session that is not enough, and the person cannot reach the level asked for with the factors they have | Error `unmet_authentication_requirements` at the redirect address ([OpenID Connect Unmet Authentication Requirements](https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html)) |

`select_account` is treated as `login`: a browser holds one session per tenant, so the only way to choose another account is to sign in as it. `consent` asks the person for [consent](#consent) again.

### Assurance and step-up

An application asks how strongly the person must have proved who they are with `acr_values`, a list of the [assurance levels](tenant.md#assurance-levels) of the tenant, separated by spaces, and how recently with `max_age`.

**The level asked for.** The names of `acr_values` that are not levels of this tenant are ignored; a request that names none of its levels asks for no level. Of the levels it names, the weakest is what the request asks for: OpenID Connect lists the values the client accepts in order of preference, and any of them is acceptable, so the weakest is enough and a stronger one is more than enough. Hodor treats the request as one that must be met: a session below it is stepped up, and a person who cannot reach it gets `unmet_authentication_requirements` rather than a token with less.

**The methods that count.** Without `max_age`, every method of the session counts. With it, only the methods proven within `max_age` seconds count ([the session context](session.md#the-facts-a-session-carries)): a method proven earlier is stale, as if it had not been proven. When the request was kept while the person signed in or stepped up, a method proven after the request arrived was proven for it and counts whatever `max_age` says, so that `max_age=0` is met by the sign-in it asks for.

**When a session is enough.** It is enough when at least one of its methods counts, and the [assurance](authentication.md#what-a-sign-in-must-reach) that the methods that count amount to reaches the requirement of the level asked for, if any. The authentication context says what the methods amount to.

**The step-up.** When the session is not enough, the authorization endpoint asks the authentication context to start a [step-up](authentication.md#step-up) of the session, carrying the methods that count and demanding the requirement of the level asked for. Only what is missing is asked:

| Session | Request | The person is asked for |
|---|---|---|
| A password | `acr_values` of a multi-factor level | Their security key, or the code of their application |
| A password and a code of the application | `acr_values` of a phishing-resistant level | Their security key, or a passkey through it |
| A password and a code of the application | `acr_values` of a phishing-resistant level, and they have no security key | Nothing: `unmet_authentication_requirements` |
| A password proven two hours ago and a security key a minute ago | `max_age=600` | Their password, since the key alone is one factor and the password is stale |
| A password proven two hours ago | `max_age=600` | Their password. The identifier is not asked again: to sign in as someone else, the application sends `prompt=login` |

The authorization endpoint starts the step-up itself, keeps the request pending as for a sign-in, gives the browser the sign-in cookie of the step-up, and sends it to the sign-in page, which shows the step the step-up waits for. When the step-up completes, the session is raised, with a new token, and the request goes on.

**What the code says.** A code issued for a session carries only the methods that count, the time of the latest of them as when the person signed in, and the name of the strongest level of the tenant they reach, the `acr` of its tokens. A sign-in that reaches no level of the tenant has no `acr`. A token never names a level the methods it carries did not reach.

### Signing in and coming back

When the person must sign in, the request is kept and the browser is sent to the hosted pages.

1. The checked request is stored as a **pending authorization request**, for ten minutes, the life of a sign-in. It is bound to the browser exactly as a sign-in is: Hodor makes a random secret of 256 bits, stores only its SHA-256 hash with the request, and gives the browser the request's identifier and the secret in a cookie.
2. The browser is redirected to `/t/{slug}/account/sign-in?continue=authorization`. That address tells the sign-in page to start a sign-in even when the browser is signed in already, since the request asked for a new one.
3. The person signs in with any way the tenant offers, an identity provider included. When the sign-in completes, the interaction interface sees the cookie and adds `"continue": "/t/{slug}/oauth2/authorize/resume"` to its answer ([the interaction interface](../../api/interaction-api.md#what-a-sign-in-response-looks-like)). The page goes there instead of to the account page.
4. `GET /t/{slug}/oauth2/authorize/resume` reads the cookie, takes the pending request, which can therefore be resumed once, and removes the cookie. Without the cookie, with a wrong secret or after ten minutes, it answers with Hodor's own error page, `oauth.authorization_request_not_found`.
5. The session is checked again against the request. A request that asked for a new sign-in (`prompt=login` or `select_account`) needs a session that signed in after the request arrived; otherwise the answer is `access_denied` at the redirect address, because the person did not sign in again. Then the session must be [enough](#assurance-and-step-up): when it is, [consent](#when-a-person-is-asked) is decided and, when nobody needs to be asked, a code is issued. When it is not, after a new sign-in that did not reach the level asked for, a step-up is started as when the request arrived, and the request is kept again; when the person cannot reach the level, the answer is `unmet_authentication_requirements`. A step-up demands the level, so its completion is always enough, and the request does not go round twice.

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
- **The code** is 32 random bytes from the operating system, written as base64url without padding. Hodor keeps only its SHA-256 hash ([Decision 0004](../../decisions/0004-token-formats.md)), with the grant, the client, the redirect address, the code challenge, the scopes, the audiences, the `nonce`, the session, the user, when they signed in, with which methods and the `acr` they reached ([what the code says](#assurance-and-step-up)). It lives **60 seconds**.
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
| `oauth.authorization_code` | `tenant_id`, `code_hash` (32 bytes, the key), `grant_id`, `client_id`, `redirect_uri`, `scopes`, `audiences`, `code_challenge`, `nonce`, `session_id`, `user_id`, `signed_in_at`, `methods`, `acr` (null when no level was reached), `issued_at`, `expires_at`, `redeemed_at` |

All three are tenant tables under row-level security. The request and the code reference their client, and the code its grant, with the tenant in the reference. A pending request and a code hold the hash of a secret, never the secret.

## Token endpoint and client authentication

Issue-56 builds the token endpoint, the four ways a client proves who it is there, and the access token issued for a code. Issue-57 adds [refresh tokens](#refresh-tokens) and [client credentials](#client-credentials); the ID token is Issue-59. The endpoint is at `/t/{slug}/oauth2/token` and answers `POST` with a form (`application/x-www-form-urlencoded`) only ([RFC 6749, section 3.2](https://www.rfc-editor.org/rfc/rfc6749#section-3.2)).

### The request

- Any other method is answered `405`; a body that is not a form is `invalid_request`.
- A body larger than 64 kibibytes is refused, as for every request.
- A parameter given more than once is `invalid_request`, since the specification forbids it.
- `grant_type` is required:
  - missing: `invalid_request`;
  - `authorization_code`, `refresh_token` and `client_credentials`: answered as the sections below say;
  - anything else: `unsupported_grant_type`.
- A client that is not allowed the grant it asks for is answered `unauthorized_client`.

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
| `sub` | The person's user identifier; for [client credentials](#client-credentials), the client's identifier |
| `aud` | The audiences of the code: the resource servers of the request. When the scopes hold `openid`, the issuer is one of the audiences too, so that the same token reads [UserInfo](#userinfo); a request that named no resource server gets the issuer alone |
| `client_id` | The client |
| `scope` | The scopes of the code, separated by spaces |
| `iat`, `exp` | When it was issued, and that plus the client's access token lifetime |
| `jti` | 16 random bytes, base64url, unique to this token. It names the token's record in [the register of access tokens](#the-register-of-access-tokens) |
| `auth_time` | When the person signed in; absent for client credentials, where nobody signed in |
| `acr` | The level the sign-in reached, as the code says, and for a refreshed token as the code the refresh tokens came from says. Left out when it reached none, and for client credentials |
| `amr` | The methods of the sign-in, named as [methods and assurance](#methods-and-assurance) says. Left out when none of them has a name in RFC 8176, and for client credentials |

`acr`, `amr` and `auth_time` are the authentication claims of [RFC 9068, section 2.2.1](https://www.rfc-editor.org/rfc/rfc9068#section-2.2.1): a resource server that guards an operation behind a strong sign-in reads them from the token. `sid` is in the [ID token](#the-id-token) only.

**No signed token outlives the rotation overlap.** The keys context keeps a retiring key published for `RotationPolicy::LONGEST_SIGNED_LIFETIME`, one hour, after it stops signing. The token policy therefore refuses an access or ID token lifetime longer than that, and the token endpoint refuses to sign one: a token checked after its key left the key set would be refused by everyone.

A tenant without an active signing key cannot issue tokens. The worker makes the first key ([keys](keys.md)), and the answer is `500` with `server_error` until it has.

### Refresh tokens

A refresh token lets a client get new access tokens for a grant without the person, until the token, its grant or the person's standing ends ([Decision 0004](../../decisions/0004-token-formats.md), [RFC 9700, section 4.14](https://www.rfc-editor.org/rfc/rfc9700#section-4.14)).

**When one is issued.** A code is exchanged for a refresh token as well when the client is allowed the `refresh_token` grant. Every refresh token of a grant belongs to one **family**, which starts with the code and moves one **generation** at each use.

**Whether it outlives the session.** OpenID Connect gives `offline_access` for access that goes on after the person has left ([OpenID Connect Core, section 11](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess)):

- **With `offline_access`** among the scopes of the code, the family does not depend on the session it was made in.
- **Without it**, the family lasts only as long as that session. A refresh after the session has ended, been revoked or expired is refused.

Either way the person must still be allowed to sign in: a suspended, deactivated or deleted user's families stop working.

**What a refresh token is.** 32 bytes, written as base64url without padding, 43 characters, like a code. Hodor keeps only the SHA-256 hash of each, with its family and generation.

- The first token of a family is 32 random bytes.
- Each next one is derived from the one before: the SHA-256 of the family's secret followed by the presented token. The family's secret is 32 random bytes, made when the family starts and kept sealed by the tenant's secret box ([secrets at rest](../../security/secrets-at-rest.md)). Without that secret, a stolen token tells nothing about the tokens after it, and without the token, the sealed secret tells nothing either.

**A refresh**, `grant_type=refresh_token` with `refresh_token` and, if the client wants fewer scopes, `scope`. The checks, in order:

1. The client must be allowed the `refresh_token` grant; otherwise `unauthorized_client`.
2. The token is found by the hash of what was presented. An unknown token, a token of another tenant and a malformed one are all `invalid_grant`.
3. The family must still stand: not revoked, before its absolute lifetime and used within its idle time, both from the client's [token policy](#token-policy) when the family started. Otherwise `invalid_grant`.
4. **The client must be the one the family was issued to.** A token presented by another client has leaked: the family is revoked, and the answer is `invalid_grant`.
5. **A token that is not the newest of its family has been used before.** Within the retry window it may be [a retry](#a-retry-of-the-same-request). Otherwise this is reuse: the family and its grant are revoked, and everything issued from them with them, and the answer is `invalid_grant`.
6. The grant must still be active, the person allowed to sign in and, without `offline_access`, the session still active; otherwise `invalid_grant`.
7. `scope`, when given, must hold only scopes of the family; otherwise `invalid_scope`. A refresh can narrow the scopes of its access token and never widen them. The family keeps its own scopes, so a later refresh can ask for all of them again ([RFC 6749, section 6](https://www.rfc-editor.org/rfc/rfc6749#section-6)).
8. `resource`, when given, must be one of the family's audiences; the access token is then for it alone. Otherwise `invalid_target`.

Then the family moves one generation, the presented token stops being the newest, and the answer carries a new access token and the next refresh token. It carries no ID token: nobody signed in again. With `openid` among the scopes the access token asks for, the issuer is one of its audiences, as with a code. Moving is one conditional change in storage that names the generation it moves from. Of two refreshes with the same token at the same moment, exactly one moves the family; the other finds the token one generation old and is answered as a retry.

#### A retry of the same request

A client whose answer was lost, by a network that failed after Hodor answered, presents the same token again. Treating that as reuse would end a family that nobody stole. So within the **retry window**, 10 seconds by default and 0 to 60 as configured with `HODOR_REFRESH_RETRY_SECONDS`, a token one generation old is answered again instead, when:

- it is presented by the same client, which has authenticated again;
- it asks for the same scopes and resource as the request that moved the family;
- the family has not moved again since.

The answer is a new access token, with a new `jti`, and **the same next refresh token** as before: Hodor derives it again from the presented token and the family's secret, and checks that its hash is the newest of the family. Nothing of an answer is ever stored, neither the access token nor the refresh token.

What the window allows: someone who stole the token one generation old and presents it within those seconds gets what the client got, a token of the same family. Without the window, that thief would end the family instead; with it, the thief and the client share the newest token, and the first time either uses it, the other's next use is reuse and ends the family. A window of 0 turns retries off.

#### What ends a family

| Event | How |
|---|---|
| Reuse of a token, or a token presented by another client | The family is revoked; on reuse its grant as well |
| The grant revoked, such as by a second use of its code | The family's next refresh is refused |
| The session ended, without `offline_access` | The family's next refresh is refused |
| The person may no longer sign in | The family's next refresh is refused |
| The client or its application disabled, or the client no longer allowed the `refresh_token` grant | The family's next refresh is refused |
| The absolute lifetime or the idle time passed | The family's next refresh is refused |
| The client revoked a refresh token of the family at the [revocation endpoint](#revocation) | The family and its grant are revoked |

### Client credentials

With `grant_type=client_credentials`, a confidential client gets an access token for itself, with nobody signed in ([RFC 6749, section 4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)).

- **The client** must be allowed the `client_credentials` grant, which only confidential clients can be. A public client is answered `unauthorized_client`.
- **`scope`** holds scopes the client is allowed, none of OpenID Connect's: those are about a person. Without `scope`, the token carries every scope the client is allowed that a resource server defines.
- **`resource`**, when given, names one resource server of the tenant, and every scope must be one it defines. Without it, the token is for every resource server that defines one of the scopes. A scope no resource server defines is `invalid_scope`, and an unknown resource is `invalid_target`.
- **The access token** has the client's identifier as `sub` and `client_id`, and no `auth_time`. **No refresh token** is issued: the client can always authenticate again.

### The answer

```json
{
  "access_token": "eyJ…",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "openid orders:read",
  "refresh_token": "Vt3…"
}
```

- **Caching:** the answer carries `Cache-Control: no-store` and `Pragma: no-cache`.
- **Errors:** they are JSON with `error` and `error_description` ([RFC 6749, section 5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2)).
- **Refresh token:** `refresh_token` is there when one was issued: with a code, for a client allowed the `refresh_token` grant, and at every refresh.
- **ID token:** `id_token` is added when the scopes hold `openid`, as [the ID token](#the-id-token) says.

### Events

| Event type | When |
|---|---|
| `oauth.access_token_issued` | An access token was issued for a person. It carries the client, the grant, the user, the token's `jti` and when it expires, never the token |
| `oauth.client_access_token_issued` | An access token was issued to a client for itself. It carries the client, the token's `jti` and when it expires |
| `oauth.refresh_token_family_started` | A family started with a code. It carries the family, the grant, the client, the user and whether it is for offline access |
| `oauth.refresh_token_rotated` | A family moved to the generation it carries |
| `oauth.refresh_token_family_revoked` | A family was revoked. It carries the family, the grant, the client and the reason: `refresh_token_reused` or `other_client` |

No event carries a token or its hash.

### Ports

| Port | Purpose |
|---|---|
| `ClientAssertionStore` | Remember a client assertion's `jti` until it expires. It answers whether this was the first time, so that of two requests with the same assertion at the same moment exactly one goes on |
| `RefreshTokenStore` | Start a family with its first token; find a token's family and generation by the token's hash; move a family one generation only from the generation named, with the next token; revoke a family |
| `PersonStanding` | Whether a session of the person is still active, and whether the person may still sign in. The server implements it over the session and identity contexts |
| `SecretBox` | Seals and opens a family's secret, from the kernel |
| `SignatureVerifier` | Checks a client's assertion, from the kernel |
| `KeyService` | Signs the access token with the tenant's active key, from the keys context |

### Storage

`oauth.client_assertion` holds `tenant_id`, `client_id`, `jti` and `expires_at`, with the tenant, the client and the `jti` as primary key. It is a tenant table under row-level security, and its client is referenced with the tenant, so its rows go when the client goes.

| Table | Holds |
|---|---|
| `oauth.refresh_token_family` | `tenant_id`, `id`, `grant_id`, `client_id`, `user_id`, `session_id`, `scopes`, `audiences`, `offline`, `signed_in_at`, `methods`, the sealed family secret as `sealed_secret`, `generation`, `current_hash` (32 bytes), when the last move happened as `moved_at`, the scopes and resource that move asked for, `status` (`active` or `revoked`), `created_at`, `expires_at`, `idle_seconds`, `last_used_at`, `revoked_at`, `revocation_reason` |
| `oauth.refresh_token` | `tenant_id`, `token_hash` (32 bytes, the key with the tenant), `family_id`, `generation`, `issued_at`: every token a family has had, so that any earlier one is known as reuse |

Both are tenant tables under row-level security. A family references its grant and its client with the tenant, and a token its family. They hold hashes and a sealed secret, never a token.

## Revocation, introspection and metadata

Issue-58 lets a client end a token before it expires, at the revocation endpoint ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)), and lets a client ask whether a token is still good, at the introspection endpoint ([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)). The discovery document names both.

### The register of access tokens

An access token is a signed JSON Web Token that a resource server can check by itself, so Hodor cannot take one back from a resource server that never asks. What Hodor can do is keep, for every access token it issues, whether it is still **in force**. This is the deny-list of `jti` that [Decision 0004](../../decisions/0004-token-formats.md) names, kept the other way round: an access token is recorded when it is issued, and is in force only while its record says so.

**The record** holds the token's `jti`, the client it was issued to, the grant it was issued under (none for [client credentials](#client-credentials)), the refresh token family it came from (none for a code or client credentials), when it expires, and whether and why it was revoked. The token itself is never stored.

**An access token is in force** when:

- its record exists and is not revoked;
- the grant it was issued under, if any, is active;
- the refresh token family it came from, if any, is active.

A token without a record is not in force. That holds for a record removed with its client or grant, and for one removed after the token expired.

**Who asks.** Introspection and UserInfo ask, and refuse a token that is not in force. A resource server that checks tokens by itself keeps accepting a revoked token until it expires, five minutes by default. Decision 0004 accepts that window, and a resource server that wants none introspects.

**Cleanup.** The worker removes records whose token has expired, with the other cleanup jobs.

### The requests

Both endpoints answer `POST` with a form only, at `{issuer}/oauth2/revoke` and `{issuer}/oauth2/introspect`.

| Parameter | |
|---|---|
| `token` | Required: the token the request is about |
| `token_type_hint` | Optional: `access_token` or `refresh_token`. It is a hint and nothing more. A token not found as the hint says is looked for as the other kind ([RFC 7009, section 2.1](https://www.rfc-editor.org/rfc/rfc7009#section-2.1)), and any other value is ignored |

The rules of the request:

- **Reading the form:** a parameter given twice is `invalid_request`, and so is a body that is not a form.
- **The client:** it proves who it is exactly as at the token endpoint: one method only, its registered method, the same checks, and `invalid_client` with status `401`. An assertion's `aud` may also be the address of the endpoint it is sent to, besides the issuer and the token endpoint.
- **Errors:** they are JSON with `error` and `error_description`. No answer is kept by a cache: they carry `Cache-Control: no-store` and `Pragma: no-cache`.

### Revocation

**Who may revoke.** Any client of the tenant, a public one included with its `client_id` alone. RFC 7009 lets a public client revoke its own tokens, and a stolen `client_id` lets nobody revoke anything but that client's tokens.

**What a revocation does:**

| The token is | What is done |
|---|---|
| A refresh token issued to the client | Its family is revoked, with the reason `revoked_by_client`, and its grant with it. With the grant goes every access token issued under it, as RFC 7009 says a server should: a client that ends a refresh token ends what came of it |
| An access token issued to the client, with a good signature and not expired | Its record is revoked, with the reason `revoked_by_client`. The refresh token of its grant stays: RFC 7009 leaves this to the server, and a client that wants both revokes the refresh token |
| Unknown, malformed, expired, already revoked, of another client or of another tenant | Nothing |

**The answer** is `200` with an empty body, whatever was done. RFC 7009 would let Hodor refuse a token of another client, but such a refusal would tell the client that the token exists. A refresh token presented here by another client does not revoke its family either, unlike at the token endpoint. Otherwise any client could end the tokens of every other.

### Introspection

**Who may introspect.** A confidential client: one that proves who it is with a secret or an assertion. A public client is answered `invalid_client` with status `401`. It proves nothing, and introspection tells about tokens.

**What a caller may learn about:**

- an access token issued to the caller itself;
- an access token whose audience holds the audience of the resource server of the caller's application. An application has at most one resource server, and its clients introspect the tokens meant for it;
- a refresh token issued to the caller itself.

Any other token is answered as not active.

**An access token is active** when:

- it passes the checks of [UserInfo](#userinfo) up to `exp`: shape, header, a key the tenant publishes, the signature, the issuer and the expiry. Audience and scope are not asked for: they are part of the answer;
- it is [in force](#the-register-of-access-tokens).

**A refresh token is active** when:

- it is found by its hash, and is the newest of its family. A token that was rotated is not active, even within the retry window;
- its family is active, before its absolute lifetime and used within its idle time;
- its grant is active;
- the person may still sign in, and, without `offline_access`, the session is still active.

**Introspection changes nothing.** It never revokes, not even for a refresh token presented by another client.

**The answer** to a token that is not active, or that the caller may not learn about, is exactly `{"active": false}`, never more. An active token is answered:

| Member | For an access token | For a refresh token |
|---|---|---|
| `active` | `true` | `true` |
| `scope` | Its scopes | The scopes of its family |
| `client_id` | The client it was issued to | The client it was issued to |
| `sub` | Its `sub` | The person |
| `aud` | Its `aud` | The issuer, to whom a refresh token is presented |
| `iss` | The issuer | The issuer |
| `exp` | Its `exp` | The earlier of the end of its family's absolute lifetime and of its idle time |
| `iat` | Its `iat` | When this token was issued |
| `token_type` | `Bearer` | `refresh_token` |

### Limits

No limit on the number of requests is built for the token, revocation and introspection endpoints, per client or per address. The limits Hodor has today are the attempt counters of the [authentication context](authentication.md), and the OAuth context may not depend on it ([crates](../crates.md)). Limits per address wait for an address Hodor can trust behind a load balancer ([known gaps](../../product/progress.md#known-gaps-in-what-is-done)).

A limit would not be stopping guesses here. Secrets, codes and refresh tokens are 256 bits, and an assertion is signed and used once. What it would stop is load, and that is listed in [not built yet](#not-built-yet).

### Events

| Event type | When |
|---|---|
| `oauth.access_token_revoked` | A client revoked an access token. It carries the client, the token's `jti` and the reason, never the token |

Revoking a refresh token records `oauth.refresh_token_family_revoked` and `oauth.grant_revoked` with the reason `revoked_by_client`.

### Ports

| Port | Purpose |
|---|---|
| `AccessTokenRecordStore` | Record an access token when it is issued; find a record by `jti`; revoke a record; remove the records of tokens that expired |
| `RefreshTokenStore` | Also finds a family by its identifier, to tell whether an access token that came from it is still in force |

### Storage

`oauth.access_token` holds `tenant_id`, `token_id` (the `jti`), `client_id`, `grant_id`, `family_id`, `expires_at`, `revoked_at` and `revocation_reason`, with the tenant and the `jti` as primary key. It is a tenant table under row-level security. It references its client, its grant and its family with the tenant, so a record goes when they go, and the token with it.

## OpenID Provider

Issue-59 makes Hodor an OpenID Provider ([OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)): a client that asks for the scope `openid` learns who signed in from an ID token, reads the person's claims at UserInfo, and finds everything it needs in the tenant's discovery document. Logout initiated by the relying party is [its own section](#logout-initiated-by-the-relying-party). The sequence is [sequence 3](../../protocols/sequences.md#3-openid-provider).

### The ID token

When the scopes of a code hold `openid`, the token endpoint answers with an `id_token` beside the access token. It is a JSON Web Token signed by the [keys context](keys.md) exactly as the access token is, with the tenant's active `ES256` key, and it lives the client's ID token lifetime (five minutes unless changed, never more than `TokenPolicy::LONGEST_SIGNED_LIFETIME`).

| Part | Value |
|---|---|
| Header | `alg` `ES256`, `typ` `JWT`, `kid` the key version that signed |
| `iss` | The tenant's issuer |
| `sub` | The person's user identifier. Subjects are public: the same for every client of the tenant. Pairwise subjects are left to Phase 2 ([Decision 0023](../../decisions/0023-what-0.2.0-holds.md)) |
| `aud` | The client's identifier, alone |
| `iat`, `exp` | When it was issued, and that plus the client's ID token lifetime |
| `auth_time` | When the person signed in |
| `nonce` | The `nonce` of the authorization request, exactly as it was sent. Left out when the request had none |
| `acr` | The level the sign-in reached, as the code says ([assurance and step-up](#assurance-and-step-up)). Left out when it reached no level of the tenant |
| `amr` | The methods of the sign-in, as the next section says. Left out when none of them has a name in RFC 8176 |
| `at_hash` | The base64url of the left half of the SHA-256 of the access token, so that the client can tell the two belong together |
| `sid` | The identifier of the session the person signed in with: a UUID that names the session, never its token. [Logout](#logout-initiated-by-the-relying-party) uses it to know whether an ID token names the browser's current session |

`azp` is not added: the audience is always the one client, and OpenID Connect asks for `azp` only when it is not.

**The person's claims are not in the ID token.** OpenID Connect returns the claims of the `profile` and `email` scopes from UserInfo whenever an access token is issued as well ([section 5.4](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)), and Hodor always issues one. A client that wants the person's name or address reads UserInfo with the access token. This keeps personal data out of a token that a browser may hold.

### Methods and assurance

A session records the methods of its sign-in by Hodor's own names, such as `password` and `totp`. The ID token names them as [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176) does:

| Hodor's method | `amr` | Kind of factor |
|---|---|---|
| `password` | `pwd` | Something the person knows |
| `totp` | `otp` | Something the person has |
| `recovery_code` | `otp`: a code that is good once. RFC 8176 has no closer name | Something the person has |
| `webauthn` | `pop`: proof that the person holds a key. Whether the key is in hardware is not known, so neither `hwk` nor `swk` is claimed | Something the person has |
| `passkey` | `pop` and `user`: a key the person holds, unlocked by their fingerprint, face or code | Two factors in one gesture |
| `external` | Nothing: Hodor did not see how the identity provider signed the person in | Counted as one factor |

`mfa` is added when the sign-in proved two kinds of factor: something known and something held, or a passkey. Each value appears once, in a fixed order.

`acr` names the strongest [assurance level](tenant.md#assurance-levels) of the tenant that the sign-in reached. Every tenant starts with two:

| `acr` | Requirement |
|---|---|
| `urn:hodor:acr:single-factor` | `single_factor` |
| `urn:hodor:acr:mfa` | `multi_factor` |

A tenant may rename them, leave out the first, and add a level for `phishing_resistant`. The `acr` is chosen when the code is issued, from the methods it carries, and the ID token and the access token say the same. A request's `acr_values` decides what the person is asked for ([assurance and step-up](#assurance-and-step-up)); the token says what was reached, which is never less than what was asked.

### UserInfo

UserInfo is at `/t/{slug}/oauth2/userinfo` and answers `GET` and `POST` ([section 5.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)). The access token comes in the `Authorization` header as `Bearer` ([RFC 6750, section 2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1)); a token in the query or in a form is not read.

The token is checked before anything is read:

| Check | Refused when |
|---|---|
| Shape | It is not a compact JSON Web Signature, or its header or claims are not JSON objects |
| Header | `typ` is not `at+jwt`, or `alg` is not `ES256` |
| Key | `kid` is not a key version the tenant publishes, so a token of another tenant is refused here |
| Signature | It does not verify |
| `iss` | It is not this tenant's issuer |
| `aud` | It does not hold the issuer |
| `exp` | It has passed |
| Scope | `scope` does not hold `openid` |
| Person | The user does not exist or is not active |

After these checks the token must still be [in force](#the-register-of-access-tokens): not revoked, and its grant and its refresh token family still active.

A token that fails any check but the scope is answered `401` with `WWW-Authenticate: Bearer error="invalid_token"`; a request without a token, `401` with `WWW-Authenticate: Bearer` and no error. A token without `openid` is answered `403` with `error="insufficient_scope"`. The answer names no reason; Hodor's logs do.

The answer is JSON with `sub` and the claims of the token's scopes:

| Scope | Claims |
|---|---|
| `openid` | `sub` |
| `profile` | `name`, the person's display name; `preferred_username`, their primary username; `locale`; `updated_at`. Each is left out when the person has none |
| `email` | `email`, the person's primary email address, and `email_verified`. Left out when they have no address |

The answer carries `Cache-Control: no-store`. A browser on another origin cannot call UserInfo yet: clients have no registered origins, so no cross-origin headers are sent.

### What a request may ask of the sign-in

The authorization endpoint already checks and keeps these parameters ([checking the request](#checking-the-request)). What each one does:

| Parameter | What happens |
|---|---|
| `prompt=none` | No page is shown. Without a session that is enough, the answer is `login_required` at the redirect address |
| `prompt=login`, `prompt=select_account` | The person signs in again, even with a session |
| `prompt=consent` | The person is asked for [consent](#consent), even for a first-party application and with a consent that stands |
| `max_age` | Only the methods proven within this many seconds count. A session with none, or whose recent methods are not enough, is [stepped up](#assurance-and-step-up), and `auth_time` in the tokens says when the person last proved something |
| `acr_values` | The weakest of the tenant's levels named here is what the person must reach; the session is [stepped up](#assurance-and-step-up) to it, or the answer is `unmet_authentication_requirements` |
| `login_hint` | The sign-in page starts with the identifier filled in. The person can change it; it is a hint, never a claim |
| `ui_locales` | The pages use the first of these languages they have, before the browser's own |

`login_hint` and `ui_locales` reach the pages in the address of the sign-in page, as `login_hint` and `ui_locales`.

### Discovery

The tenant describes itself at two addresses, with the same document:

- `/t/{slug}/.well-known/openid-configuration`, where [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) looks for it, the issuer followed by the well-known path;
- `/t/{slug}/.well-known/oauth-authorization-server`, for OAuth clients that look for [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) metadata after the issuer the same way.

It names only what is built:

| Member | Value |
|---|---|
| `issuer` | The tenant's issuer, exactly as every token and redirect carries it |
| `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `revocation_endpoint`, `introspection_endpoint`, `end_session_endpoint` | The seven addresses under `{issuer}/oauth2`; the last is [logout](#logout-initiated-by-the-relying-party) |
| `response_types_supported` | `code` |
| `response_modes_supported` | `query` |
| `grant_types_supported` | The grants the token endpoint answers: `authorization_code`, `refresh_token` and `client_credentials` |
| `code_challenge_methods_supported` | `S256` |
| `token_endpoint_auth_methods_supported` | `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none` |
| `token_endpoint_auth_signing_alg_values_supported` | `ES256`, `RS256`, `PS256` |
| `revocation_endpoint_auth_methods_supported` | The four of the token endpoint: a public client may revoke its own tokens |
| `introspection_endpoint_auth_methods_supported` | `client_secret_basic`, `client_secret_post`, `private_key_jwt`: a public client may not introspect |
| `revocation_endpoint_auth_signing_alg_values_supported`, `introspection_endpoint_auth_signing_alg_values_supported` | `ES256`, `RS256`, `PS256` |
| `id_token_signing_alg_values_supported` | `ES256` |
| `subject_types_supported` | `public` |
| `scopes_supported` | `openid`, `profile`, `email`. A tenant's own scopes belong to its resource servers and are not listed |
| `claims_supported` | The claims of the ID token and of UserInfo |
| `acr_values_supported` | The names of the tenant's [assurance levels](tenant.md#assurance-levels), weakest first |
| `prompt_values_supported` | `none`, `login`, `consent`, `select_account` |
| `ui_locales_supported` | `en`, `pt-BR` |
| `authorization_response_iss_parameter_supported` | `true` |
| `request_parameter_supported`, `request_uri_parameter_supported`, `claims_parameter_supported` | `false` |

The document may be kept by caches for five minutes and carries `Access-Control-Allow-Origin: *`, as the key set does: it is public.

### Ports

| Port | Purpose |
|---|---|
| `KeyService` | Lists the tenant's published keys, to check an access token at UserInfo |
| `SignatureVerifier` | Checks the access token's signature, from the kernel |
| `IdentityService` | Reads the person, for UserInfo, from the identity context |

## Logout initiated by the relying party

Issue-60. An application that signed a person in through Hodor can send their browser to Hodor to sign out there too ([OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)). The **end-session endpoint** is at `/t/{slug}/oauth2/logout`, advertised in [discovery](#discovery) as `end_session_endpoint`. It answers `GET` with the parameters in the query and `POST` with them in a form.

### The parameters

| Parameter | Meaning |
|---|---|
| `id_token_hint` | An ID token Hodor issued to the application. It says who the application believes is signed in, with which session (`sid`), and for which client (`aud`) |
| `client_id` | The client, for an application that has no ID token at hand |
| `post_logout_redirect_uri` | Where to send the person back to afterwards. It must be one of the client's [post-logout redirect addresses](#redirect-addresses), character for character |
| `state` | Given back with the person at that address, as it came |
| `ui_locales` | The languages the question to the person is asked in, as at the authorization endpoint |

`logout_hint` and parameters the endpoint does not know are ignored.

### Checking the request

The request is checked before anything happens. A request that fails is answered with Hodor's own page, status `400`, that names the reason by its code, and **the browser is never sent to the address the request names**: until the request has been checked, that address could be anyone's.

| Failure | Code |
|---|---|
| A parameter is given more than once; `state` is longer than 1024 characters or holds characters outside printable ASCII; `ui_locales` is longer than 255 characters | `oauth.logout_request_invalid` |
| `id_token_hint` is not an ID token of this tenant: not three parts, a header that is not `typ` `JWT` and `alg` `ES256`, a `kid` the tenant does not publish, a signature that does not verify, or an `iss` that is not the tenant's issuer | `oauth.logout_id_token_hint_invalid` |
| `client_id` is not a client of this tenant, or the client or its application is disabled; or `post_logout_redirect_uri` is given and the request names no client, by `client_id` or by the hint's `aud` | `oauth.logout_client_unknown` |
| `client_id` and the hint's `aud` name different clients | `oauth.logout_client_mismatch` |
| `post_logout_redirect_uri` is not one of the client's post-logout redirect addresses | `oauth.logout_redirect_uri_unregistered` |

**The hint's `exp` is not checked.** The specification allows an expired ID token here: it is a hint of who is signed in, not a credential, and an ID token lives five minutes while a session lives hours. Its signature is checked, so that its `aud` can be trusted for the return address and its `sid` for skipping the question below.

### What happens

| The browser… | What happens |
|---|---|
| has no valid session of the tenant | There is nothing to end; the request [finishes](#finishing) |
| sent a `GET` with a valid session, and an `id_token_hint` whose `sub` is that person and whose `sid` is that session | The session ends at once and the request finishes |
| anything else: no hint, a hint for another session or another person, or a `POST` | The person is [asked](#asking-the-person) |

A `POST` always asks. A form that another site posts does not carry the session cookie (it is `SameSite=Lax`), so Hodor cannot see from such a request which session the browser holds; the question is asked from Hodor's own pages, which can.

The person is asked whenever the request does not prove that it comes from the session it ends, as the specification requires: otherwise any site could sign a person out of Hodor by sending their browser to this address.

**Ending the session** is what signing out does ([the interaction interface](../../api/interaction-api.md#routes-for-a-signed-in-person)): the session is revoked, with the reason `relying_party_logout` in its event and so in the audit log, and the browser is told to forget the session cookie. With it ends every refresh token family made in that session without `offline_access` (Issue-57). Access tokens already issued live out their few minutes; revoking them is Issue-58. Grants are not revoked: access the person gave with `offline_access` goes on.

### Asking the person

1. The checked request is kept in the cookie `__Secure-hodor_logout`: the client, the return address and `state`. It holds nothing secret; it only says where to go afterwards, and it is checked again when it is used. It is `HttpOnly`, `Secure`, `SameSite=Strict`, with `Path=/t/{slug}` and a `Max-Age` of 600 seconds.
2. The browser is sent to the hosted pages, `/t/{slug}/account/sign-out`, with `ui_locales` when the request had it.
3. The page asks who is signed in. When nobody is, it goes on to the [finish](#finishing) at once. Otherwise it asks "Sign out of {tenant}?", with two buttons:
   - **Sign out** ends the session through the interaction interface, as the account page does, and goes on to the finish.
   - **Stay signed in** goes to the account page. The application is not told: the person stays signed in to Hodor and can sign in to the application again.

### Finishing

`GET /t/{slug}/oauth2/logout/finish` is where a request that was asked about ends; a request that was not asked about ends the same way without it.

- The cookie is read and removed. Its client must still be a client of the tenant, enabled, and its return address still one of the client's post-logout redirect addresses; otherwise the return address is dropped.
- When the browser still has a valid session, the person chose to stay or came here some other way: the browser is sent to the account page.
- Otherwise, with a return address, the browser is sent there, with `state` when the request had one. Without one, it is sent to the sign-in page, which says the person is signed out.

Every answer of the end-session endpoint carries `Cache-Control: no-store`.

### Ports

| Port | Purpose |
|---|---|
| `KeyService` | Lists the tenant's published keys, to check the `id_token_hint` |
| `SignatureVerifier` | Checks the hint's signature, from the kernel |
| `ClientStore` | Loads the client, to check the return address |

The session is looked up and ended by the HTTP layer through the session context, as the authorization endpoint looks it up.

## Consent

Issue-62. A person is asked before a third-party application gets access to their account, and what they agreed to is remembered, can be withdrawn, and runs out ([Requirement-OAuth-09](../../product/requirements.md)). Clients of first-party applications are not asked: the tenant runs them, and its administrator decided that when the application was registered.

### What a consent is

A **consent** is what one person agreed to for one client: a set of scopes and the audiences of the resource servers they are for. A person has at most one consent per client.

| Field | Meaning |
|---|---|
| User, client | Whose and for which client. Together they identify the consent |
| Scopes | The scopes agreed to. `offline_access` is never kept: it is asked every time, as the next section says |
| Audiences | The audiences of the resource servers the scopes were agreed for |
| Given at | When the person last agreed |
| Expires at | Given at plus the client's consent lifetime |
| Withdrawn at, withdrawn by | When it was withdrawn, and whether by the `person` or an `administrator` |

**Agreeing again** to a consent that stands adds the new scopes and audiences to the old ones, and its expiry starts again from that moment. Agreeing after a consent expired or was withdrawn starts it over with only what was asked for.

**The consent lifetime** is part of the client's [token policy](#token-policy): 365 days unless an administrator changes it, from 1 to 730 days.

**Every change is kept in a history**: each time a person agrees, refuses, or a consent is withdrawn, one row records who, which client, what scopes and audiences, by whom and when. The history is never changed or removed by the application.

### When a person is asked

A checked request for a person who is signed in and whose session is enough then decides whether to ask:

| Situation | What happens |
|---|---|
| The client's application is first party, and `prompt` does not hold `consent` | No question: a code is issued |
| `prompt` holds `consent` | The person is asked, whatever they agreed to before |
| The scopes hold `offline_access`, for a third-party client | The person is asked, every time ([OpenID Connect Core, section 11](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess)): letting an application go on without the person is decided each time it is asked for |
| The person's consent for the client stands, has not expired, and holds every scope and audience of the request | No question: a code is issued |
| Anything else | The person is asked |

A request that must ask, with `prompt=none`, is answered `consent_required` at the redirect address ([OpenID Connect Core, section 3.1.2.6](https://openid.net/specs/openid-connect-core-1_0.html#AuthError)).

### Asking

Asking uses the same pending request as signing in ([signing in and coming back](#signing-in-and-coming-back)), with the person it is for:

1. The checked request is stored as a pending authorization request that **waits for consent**, with the user and the session it is for, and the browser gets the `__Secure-hodor_authorization` cookie as for a sign-in.
2. The browser is sent to the consent page, `/t/{slug}/account/consent`, of [the hosted pages](../hosted-pages.md#asking-for-consent).
3. The page reads what to show from `GET /t/{slug}/interaction/consent` and sends the person's answer to `POST /t/{slug}/interaction/consent` ([the interaction interface](../../api/interaction-api.md#consent)). Both need the browser's cookie and its session to be the one the request waits for; the answer needs the session's CSRF token and passes the origin check.
4. The answer is recorded on the pending request, once: a second answer is refused. Agreeing records the consent at once. The interface answers `{"continue": "/t/{slug}/oauth2/authorize/resume"}` either way.
5. The resume address takes the pending request as for a sign-in. A request that waits for consent is answered by its answer: agreed, a code is issued; refused or never answered, `access_denied` at the redirect address. The person must still be signed in with the same session; another session, or none, is `access_denied` as well.

When the person must sign in first, they sign in, the request is resumed, and only then is the question decided: the request is kept again, waiting for consent, for the person who signed in.

### What the page shows

`GET /interaction/consent` gives the page:

- the name of the **application**, as its administrator registered it;
- each **scope** asked for: for a scope of OpenID Connect, its name, which the page words in the person's language; for a scope of a resource server, the description the resource server gives, as written by the tenant's administrator, with the resource server's name;
- whether the request asks for **offline access**, so that the page says the application will keep access when the person is not there.

It never shows the redirect address or anything else the client chose, so that a client cannot put words on Hodor's page.

### Withdrawing a consent

A consent is withdrawn by the person, at `DELETE /t/{slug}/interaction/consents/{client_id}`, or by an administrator of the tenant, at `DELETE /api/v1/admin/users/{user_id}/consents/{client_id}` ([the administration interface](../../api/admin-api.md#consents)).

Withdrawing a consent **revokes every active grant of the person for that client**, with the reason `consent_withdrawn`. A refresh token family stops working when its grant is revoked ([what ends a family](#what-ends-a-family)), so no refresh token of those grants is accepted again; and an access token whose grant is revoked is no longer in force, so introspection answers it inactive and UserInfo refuses it ([the register of access tokens](#revocation-introspection-and-metadata)). A resource server that checks tokens on its own, without introspection, accepts one until it expires, five minutes unless the client's policy says otherwise.

The next request of the client for that person asks again.

### Events

| Event type | When |
|---|---|
| `oauth.consent_given` | A person agreed. It carries the client, the user and the scopes agreed to |
| `oauth.consent_refused` | A person refused. It carries the client and the user |
| `oauth.consent_withdrawn` | A consent was withdrawn. It carries the client, the user and `by`: `person` or `administrator` |

Withdrawing also records `oauth.grant_revoked` for each grant it revokes. No event carries more of the person than their identifier.

### Ports

| Port | Purpose |
|---|---|
| `ConsentStore` | Load a person's consent for a client; store it; list a person's consents; append to the history |
| `AuthorizationRequestStore` | As for a sign-in, and record the answer to a request that waits for consent, only if it has none |
| `GrantStore` | As before, and list a person's active grants for a client |

### Storage

| Table | Holds |
|---|---|
| `oauth.consent` | `tenant_id`, `user_id`, `client_id` (the key, with the tenant), `scopes`, `audiences`, `given_at`, `expires_at`, `withdrawn_at`, `withdrawn_by` |
| `oauth.consent_history` | `tenant_id`, `id`, `user_id`, `client_id`, `action` (`given`, `refused` or `withdrawn`), `scopes`, `audiences`, `by_whom` (`person` or `administrator`), `at`. The application may add rows and read them, never change or remove them |

Both are tenant tables under row-level security, and reference their client with the tenant. `oauth.authorization_request` gains the user and the session a request waits for consent for, and the answer, `agreed` or `refused`. `oauth.client` gains `consent_seconds`, the consent lifetime.

## Not built yet

| Item | Planned in |
|---|---|
| Back-channel and front-channel logout: telling the applications of a session that it ended | Phase 2, after 0.2.0 ([Decision 0023](../../decisions/0023-what-0.2.0-holds.md)) |
| Sending the person back to the application when they choose to stay signed in at the logout question | When an application asks for it |
| `logout_hint`, which names who to sign out | Not used: a browser holds one session per tenant |
| An `id_token_hint` signed by a key that has left the tenant's key set: it is refused, and the application can send `client_id` instead, which asks the person | When it matters |
| Limits on the number of requests to the token, revocation and introspection endpoints, per client and per address ([limits](#limits)) | With the other limits per address, before any deployment behind a load balancer |
| The metadata at the address RFC 8414 prefers for an issuer with a path, `/.well-known/oauth-authorization-server/t/{slug}`: it is outside the tenant's addresses, so only the address after the issuer is served | When a client needs it |
| Calling UserInfo from a browser on another origin | With origins in the client settings |
| The person's claims in the ID token when asked for with the `claims` parameter | Not planned for 0.2.0 |
| More than one `resource` in a refresh or client credentials request: a parameter may be given once | With resource indicators given more than once at the token endpoint |
| Removing refresh token families after they expire, with their tokens | A cleanup job, with the other expired rows |
| Calling the token endpoint from a browser on another origin: clients have no registered origins yet, so no cross-origin headers are sent | With origins in the client settings |
| Client assertions signed with `ES384` or `EdDSA`, which client keys on P-384 and Ed25519 would need | When the kernel's signature checking covers them |
| Removing remembered client assertions after they expire | A cleanup job, with the other expired rows |
| Asking for an `acr` with the `claims` parameter. `acr_values` is the way to ask | Not planned for 0.2.0 |
| A page where a person sees the history of their consents | The account console, Phase 2 |
| Removing withdrawn and expired consents | A cleanup job, with the other expired rows |
| Limits on requests to the authorization endpoint per address | With the other limits per address, before any deployment behind a load balancer |
| Removing expired pending requests, codes and revoked grants | A cleanup job, with the other expired rows |
| Request objects (`request`, `request_uri`) and pushed authorization requests | Phase 4, after 0.2.0 |
| Pairwise subject identifiers, claim mappers per client | Phase 2, after 0.2.0 ([Decision 0023](../../decisions/0023-what-0.2.0-holds.md)) |
| Opaque access tokens chosen per client | Not planned for 0.2.0 |
| Accepting any port for a loopback redirect address, which RFC 8252 suggests | Not planned: exact equality is kept |
