# The OAuth context

The `oauth` context makes Hodor an OAuth 2.x authorization server and an OpenID Provider. It owns the applications a tenant registers, the clients through which they ask for tokens, the resource servers those tokens are for, and, in later issues, the codes, grants, tokens and consents of [Milestone 3](../../product/epics.md#milestone-3-applications-ask-hodor-who-someone-is).

It does not sign anyone in. When a request needs a person, it hands the request to the `authentication` context and takes the session that comes back. The two contexts do not depend on each other: the HTTP layer joins them ([crates.md](../crates.md)).

This page specifies what Issue-53 builds: applications, clients and resource servers, and the rules they keep. The endpoints, the tokens and consent are added by Issue-55 to Issue-62, under the headings at the end of this page.

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

Issue-55.

## Token endpoint and client authentication

Issue-56 and Issue-57.

## Revocation, introspection and metadata

Issue-58.

## OpenID Provider

Issue-59 and Issue-60.

## Consent

Issue-62.

## Not built yet

| Item | Planned in |
|---|---|
| Managing applications, clients and resource servers through the administration interface, the command-line tool and the console | Issue-54 |
| Every endpoint | Issue-55 to Issue-60 |
| Pairwise subject identifiers, claim mappers per client | Phase 2, after 0.2.0 ([Decision 0023](../../decisions/0023-what-0.2.0-holds.md)) |
| Opaque access tokens chosen per client | Not planned for 0.2.0 |
| Accepting any port for a loopback redirect address, which RFC 8252 suggests | Not planned: exact equality is kept |
