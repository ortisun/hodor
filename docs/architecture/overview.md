# Architecture overview

Hodor is a **modular monolith**: a Rust workspace in which each bounded context is a crate with its own domain and use cases, and infrastructure enters through ports (traits) implemented in adapter crates. Three binaries share the same crates: `hodor-server` (HTTP), `hodor-worker` (background jobs) and `hodor-cli` (operations).

## Architectural style

Each context crate has three modules and nothing else:

| Module | Contains | May depend on |
|---|---|---|
| `domain` | Aggregates, value objects, events, rules | `kernel` |
| `application` | Use cases, outbound ports (traits), command and query DTOs | `domain`, `kernel`, the public API of upstream contexts |
| `api` (re-export) | Public facade: the use cases and types other crates may use | — |

Rules:

1. The domain does not know Axum, SQLx, Redis or Tokio, and does not use `serde_json::Value` as a rule type.
2. A context sees another only through its `api` facade; each crate's `domain` module is `pub(crate)`.
3. Dependencies between contexts form a fixed acyclic graph, described in [crates.md](crates.md) and checked in CI.
4. There is no generic mapper layer: the Postgres adapter turns rows into aggregates directly; `protocol-http` turns HTTP DTOs into commands.
5. Every port method that touches tenant data takes a `TenantContext`. There is no "global" repository for tenant data.
6. Side effects across contexts go through domain events written to an outbox in the same transaction.

## C4 Level 1: Context

```mermaid
flowchart TB
    user["End user"]
    admin["Tenant administrator"]
    operator["Platform operator"]
    app["Client applications<br/>Web, SPA, mobile, backend"]
    workload["Workloads and AI agents"]

    hodor["HODOR<br/>IdP, OAuth 2.x AS, OIDC OP,<br/>federation broker, PDP and PAP"]

    social["Social IdPs<br/>Google, Microsoft, GitHub, Apple"]
    enterprise["Enterprise IdPs<br/>Entra ID, Okta, ADFS, LDAP and AD"]
    opa["Open Policy Agent"]
    kms["External KMS<br/>AWS, GCP, Azure, Vault"]
    notify["Email and SMS"]
    siem["SIEM and webhooks"]
    scim["SCIM clients<br/>HR systems, upstream IdPs"]

    user -->|"sign-in, MFA, account"| hodor
    admin -->|"configures"| hodor
    operator -->|"operates"| hodor
    app -->|"OAuth, OIDC, SAML, authorization API"| hodor
    workload -->|"client credentials, token exchange"| hodor
    scim -->|"SCIM 2.0"| hodor

    hodor -->|"OIDC, OAuth 2.0"| social
    hodor -->|"OIDC, SAML, LDAPS"| enterprise
    hodor -->|"decisions, bundles, logs"| opa
    hodor -->|"sign, wrap keys"| kms
    hodor -->|"SMTP, API"| notify
    hodor -->|"audit events"| siem
```

## C4 Level 2: Containers

```mermaid
flowchart TB
    subgraph browser["Browser"]
        authui["auth-ui<br/>React, hosted login"]
        adminui["admin-console<br/>React"]
        accountui["account-console<br/>React"]
    end

    subgraph hodor["Hodor"]
        server["hodor-server<br/>Axum: protocols, APIs, console BFF"]
        worker["hodor-worker<br/>outbox, cleanup, key rotation,<br/>LDAP sync, OPA bundles"]
        cli["hodor-cli<br/>migrations, bootstrap, operations"]
    end

    pg[("PostgreSQL<br/>state, outbox, audit")]
    redis[("Redis, optional<br/>cache, rate limit, replay")]
    opa["OPA<br/>sidecar or remote"]
    otel["OpenTelemetry collector"]
    ext["IdPs, KMS, SMTP, SIEM"]

    authui --> server
    adminui --> server
    accountui --> server
    server --> pg
    server --> redis
    server -->|"POST /v1/data"| opa
    opa -->|"GET bundles, POST logs and status"| server
    worker --> pg
    worker --> redis
    worker --> ext
    server --> ext
    cli --> pg
    server --> otel
    worker --> otel
```

Decisions embedded in the diagram:

- `hodor-server` serves the three frontends as static assets on the tenant's own origin. `auth-ui` never receives tokens: it talks to a cookie-protected *interaction API*.
- `admin-console` and `account-console` are OIDC clients of Hodor itself through a BFF inside `hodor-server` (session cookie, no token in the browser). See [ADR-0011](../adr/0011-frontends-bff.md).
- OPA **pulls** bundles from Hodor and **pushes** decision logs and status to it: Hodor implements the service APIs OPA expects.
- Redis is optional. Without it, rate limiting and caches are per-node in memory and replay protection uses Postgres.

## C4 Level 3: Components

### `hodor-server`

```mermaid
flowchart TB
    subgraph http["protocol-http"]
        mw["Middleware<br/>tenant resolver, request id, rate limit,<br/>CSRF, security headers, auth"]
        r_oauth["OAuth and OIDC routes"]
        r_inter["Interaction API<br/>login, MFA, consent"]
        r_admin["Admin API"]
        r_account["Account API"]
        r_authz["Authorization API"]
        r_opa["OPA service API<br/>bundles, logs, status"]
        r_scim["SCIM"]
        r_saml["SAML"]
    end

    subgraph ctx["Contexts (use cases)"]
        tenant
        identity
        credential
        session
        authentication
        federation
        oauth
        keys
        authorization
        audit
        notification
    end

    subgraph adapters["Adapters"]
        a_pg["adapters-postgres"]
        a_redis["adapters-redis"]
        a_crypto["adapters-crypto"]
        a_kms["adapters-kms"]
        a_http["adapters-http"]
        a_native["authorization-native"]
        a_opa["authorization-opa"]
    end

    mw --> r_oauth & r_inter & r_admin & r_account & r_authz & r_opa & r_scim & r_saml
    r_oauth --> oauth
    r_inter --> authentication & federation & oauth
    r_admin --> tenant & identity & oauth & federation & authorization & audit & keys
    r_account --> identity & credential & session & oauth
    r_authz --> authorization
    r_opa --> authorization
    ctx -. "ports" .-> adapters
```

The composition root (`apps/hodor-server/src/main.rs`) is the only place that knows concrete adapter types. It builds an `AppState` holding one `Arc<dyn Port>` per port and hands it to `protocol-http`.

### `authentication` context

```mermaid
flowchart LR
    start["StartAuthentication"] --> engine["FlowEngine<br/>interprets the flow graph"]
    engine --> tx["AuthTransaction<br/>flow state, short TTL"]
    engine --> reg["AuthenticatorRegistry"]
    reg --> a1["PasswordAuthenticator"]
    reg --> a2["TotpAuthenticator"]
    reg --> a3["WebAuthnAuthenticator"]
    reg --> a4["ExternalIdpAuthenticator<br/>implemented in federation"]
    reg --> a5["WasmActionAuthenticator<br/>plugin-runtime"]
    engine --> risk["RiskEvaluator"]
    engine --> guard["AttemptGuard<br/>lockout, rate limit"]
    engine --> done["CompleteAuthentication<br/>creates or elevates the session"]
```

`Authenticator` is the context's SPI: `federation` and `plugin-runtime` implement it, which keeps `authentication` free of dependencies on them.

### `oauth` context

```mermaid
flowchart LR
    authz["AuthorizeRequest<br/>validates client, redirect, PKCE, PAR"] --> login{"Session satisfies<br/>acr, max_age, prompt?"}
    login -- no --> inter["Interaction: login or step-up"]
    login -- yes --> consent{"Consent covers<br/>the scopes?"}
    consent -- no --> cs["Interaction: consent"]
    consent -- yes --> code["Issue authorization code"]
    token["TokenRequest"] --> cauth["ClientAuthenticator"]
    cauth --> grants["GrantHandler per grant_type"]
    grants --> issuer["TokenIssuer<br/>claims mappers, signing via keys"]
    issuer --> store["Grant, RefreshTokenFamily"]
```

### `authorization` context

See [authorization.md](authorization.md).

## Cross-cutting concerns

| Concern | Where it lives | How |
|---|---|---|
| Tenant identification | `protocol-http` (middleware) | Host or `/t/{slug}` prefix → `TenantContext` in request extensions |
| Transactions | `application` | `UnitOfWork` port; the use case delimits the transaction, the adapter opens it with `SET LOCAL app.tenant_id` |
| Domain events | `kernel` + `adapters-postgres` | `DomainEvent` written to `outbox` in the transaction; `hodor-worker` dispatches |
| Errors | `kernel` | Typed `DomainError` per context; `protocol-http` translates to RFC 9457 or an OAuth error |
| Time and randomness | `kernel` | `Clock` and `RandomSource` ports, replaceable in tests |
| Secrets in memory | `kernel` | `Secret<T>`: redacted `Debug`, zeroized on drop, no `Serialize` |
| Configuration | `apps/*` | Typed struct, validated at startup, injected |
| Observability | `observability` | OTel bootstrap; spans created in `protocol-http` and in use cases |
