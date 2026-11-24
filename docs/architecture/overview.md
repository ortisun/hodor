# Architecture overview

Hodor is a **modular monolith**: a Rust workspace in which each bounded context is a crate with its own domain and use cases, and infrastructure enters through ports (traits) implemented in adapter crates. Three binaries share the same crates: `hodor-server` (HTTP), `hodor-worker` (background jobs) and `hodor-cli` (operations).

## Architectural style

Each context crate has three modules and nothing else:

| Module | Contains | May depend on |
|---|---|---|
| `domain` | Aggregates, value objects, events, rules | `kernel` |
| `application` | Use cases, outbound ports (traits), command and query data transfer objects | `domain`, `kernel`, the public API of upstream contexts |
| `api` (re-export) | Public facade: the use cases and types other crates may use | — |

Rules:

1. The domain does not know Axum, SQLx, Redis or Tokio, and does not use `serde_json::Value` as a rule type.
2. A context sees another only through its `api` facade; each crate's `domain` module is `pub(crate)`.
3. Dependencies between contexts form a fixed acyclic graph, described in [crates.md](crates.md) and checked in continuous integration.
4. There is no generic mapper layer: the Postgres adapter turns rows into aggregates directly; `protocol-http` turns HTTP data transfer objects into commands.
5. Every port method that touches tenant data takes a `TenantContext`. There is no "global" repository for tenant data.
6. Side effects across contexts go through domain events written to an outbox in the same transaction.

## C4 Level 1: Context

```mermaid
flowchart TB
    user["End user"]
    admin["Tenant administrator"]
    operator["Platform operator"]
    app["Client applications<br/>Web, single-page application, mobile, backend"]
    workload["Workloads and artificial intelligence agents"]

    hodor["HODOR<br/>identity provider, OAuth 2.x authorization server, OpenID Connect OpenID Provider,<br/>federation broker, policy decision point and policy administration point"]

    social["Social identity providers<br/>Google, Microsoft, GitHub, Apple"]
    enterprise["Enterprise identity providers<br/>Entra ID, Okta, Active Directory Federation Services, LDAP and Active Directory"]
    policyAgent["Open Policy Agent"]
    keyService["External key management service<br/>Amazon Web Services, Google Cloud, Azure, Vault"]
    notify["Email and SMS"]
    eventSink["security event management system and webhooks"]
    scim["SCIM clients<br/>human resources systems, upstream identity providers"]

    user -->|"sign-in, multi-factor authentication, account"| hodor
    admin -->|"configures"| hodor
    operator -->|"operates"| hodor
    app -->|"OAuth, OpenID Connect, SAML, authorization API"| hodor
    workload -->|"client credentials, token exchange"| hodor
    scim -->|"SCIM 2.0"| hodor

    hodor -->|"OpenID Connect, OAuth 2.0"| social
    hodor -->|"OpenID Connect, SAML, LDAPS"| enterprise
    hodor -->|"decisions, bundles, logs"| policyAgent
    hodor -->|"sign, wrap keys"| keyService
    hodor -->|"SMTP, API"| notify
    hodor -->|"audit events"| eventSink
```

## C4 Level 2: Containers

```mermaid
flowchart TB
    subgraph browser["Browser"]
        authInterface["auth-ui<br/>React, hosted login"]
        adminConsole["admin-console<br/>React"]
        accountConsole["account-console<br/>React"]
    end

    subgraph hodor["Hodor"]
        server["hodor-server<br/>Axum: protocols, APIs, console backend-for-frontend"]
        worker["hodor-worker<br/>outbox, webhooks, cleanup, key rotation,<br/>LDAP sync, Open Policy Agent bundles"]
        commandLineTool["hodor-cli<br/>migrations, bootstrap, operations"]
    end

    postgres[("PostgreSQL<br/>state, outbox, audit")]
    redis[("Redis, optional<br/>cache, rate limit, replay")]
    policyAgent["Open Policy Agent<br/>sidecar or remote"]
    telemetryCollector["OpenTelemetry collector"]
    externalServices["identity providers, key management service, SMTP, security event management system"]

    authInterface --> server
    adminConsole --> server
    accountConsole --> server
    server --> postgres
    server --> redis
    server -->|"POST /v1/data"| policyAgent
    policyAgent -->|"GET bundles, POST logs and status"| server
    worker --> postgres
    worker --> redis
    worker --> externalServices
    server --> externalServices
    commandLineTool --> postgres
    server --> telemetryCollector
    worker --> telemetryCollector
```

Decisions embedded in the diagram:

- `hodor-server` serves the three frontends as static assets on the tenant's own origin. `auth-ui` never receives tokens: it talks to a cookie-protected *interaction API*.
- `admin-console` and `account-console` are OpenID Connect clients of Hodor itself through a backend-for-frontend inside `hodor-server` (session cookie, no token in the browser). See [Decision 0011](../decisions/0011-frontends-bff.md).
- Open Policy Agent **pulls** bundles from Hodor and **pushes** decision logs and status to it: Hodor implements the service APIs Open Policy Agent expects.
- Redis is optional. Without it, rate limiting and caches are per-node in memory and replay protection uses Postgres.

## C4 Level 3: Components

### `hodor-server`

```mermaid
flowchart TB
    subgraph protocolHttp["protocol-http"]
        middleware["Middleware<br/>tenant resolver, request identifier, rate limit,<br/>CSRF, security headers, authentication"]
        oauthRoutes["OAuth and OpenID Connect routes"]
        interactionRoutes["Interaction API<br/>login, multi-factor authentication, consent"]
        adminRoutes["Admin API"]
        accountRoutes["Account API"]
        authorizationRoutes["Authorization API"]
        policyAgentRoutes["Open Policy Agent service API<br/>bundles, logs, status"]
        scimRoutes["SCIM"]
        samlRoutes["SAML"]
    end

    subgraph contexts["Contexts (use cases)"]
        tenant
        identity
        credential
        session
        authentication
        federation
        oauth
        provisioning
        keys
        authorization
        audit
        notification
        webhooks
    end

    subgraph adapters["Adapters"]
        adaptersPostgres["adapters-postgres"]
        adaptersRedis["adapters-redis"]
        adaptersCrypto["adapters-crypto"]
        adaptersKeyService["adapters-kms"]
        adaptersHttp["adapters-http"]
        authorizationNative["authorization-native"]
        authorizationPolicyAgent["authorization-opa"]
    end

    middleware --> oauthRoutes & interactionRoutes & adminRoutes & accountRoutes & authorizationRoutes & policyAgentRoutes & scimRoutes & samlRoutes
    oauthRoutes --> oauth
    interactionRoutes --> authentication & federation & oauth
    adminRoutes --> tenant & identity & oauth & federation & authorization & audit & keys & webhooks
    accountRoutes --> identity & credential & session & oauth
    authorizationRoutes --> authorization
    policyAgentRoutes --> authorization
    scimRoutes --> provisioning & oauth
    contexts -. "ports" .-> adapters
```

The composition root (`apps/hodor-server/src/main.rs`) is the only place that knows concrete adapter types. It builds an `AppState` holding one `Arc<dyn Port>` per port and hands it to `protocol-http`.

### `authentication` context

```mermaid
flowchart LR
    start["StartAuthentication"] --> engine["FlowEngine<br/>interprets the flow graph"]
    engine --> transaction["AuthTransaction<br/>flow state, short time to live"]
    engine --> registry["AuthenticatorRegistry"]
    registry --> passwordAuthenticator["PasswordAuthenticator"]
    registry --> totpAuthenticator["TotpAuthenticator"]
    registry --> webauthnAuthenticator["WebAuthnAuthenticator"]
    registry --> externalProviderAuthenticator["ExternalIdpAuthenticator<br/>implemented in federation"]
    registry --> pluginAuthenticator["WasmActionAuthenticator<br/>plugin-runtime"]
    engine --> risk["RiskEvaluator"]
    engine --> guard["AttemptGuard<br/>lockout, rate limit"]
    engine --> done["CompleteAuthentication<br/>creates or elevates the session"]
```

`Authenticator` is the context's service provider interface: `federation` and `plugin-runtime` implement it, which keeps `authentication` free of dependencies on them.

### `oauth` context

```mermaid
flowchart LR
    authorizeRequest["AuthorizeRequest<br/>validates client, redirect, PKCE, pushed authorization requests"] --> login{"Session satisfies<br/>acr, max_age, prompt?"}
    login -- no --> interaction["Interaction: login or step-up"]
    login -- yes --> consent{"Consent covers<br/>the scopes?"}
    consent -- no --> consentScreen["Interaction: consent"]
    consent -- yes --> code["Issue authorization code"]
    token["TokenRequest"] --> clientAuthenticator["ClientAuthenticator"]
    clientAuthenticator --> grants["GrantHandler per grant_type"]
    grants --> issuer["TokenIssuer<br/>claims mappers, signing via keys"]
    issuer --> store["Grant, RefreshTokenFamily"]
```

### `authorization` context

See [authorization.md](authorization.md).

## Cross-cutting concerns

| Concern | Where it lives | How |
|---|---|---|
| Tenant identification | `protocol-http` (middleware) | Host or `/t/{slug}` prefix → `TenantContext` in request extensions. The lookup goes through the `TenantResolver` trait, implemented by the composition root, so `protocol-http` depends on no adapter |
| Transactions | `kernel` + adapters | `UnitOfWork` port in `kernel`: the use case begins it, passes it to repositories, records events on it and commits. It is a trait object; an adapter downcasts it to reach its own transaction, which is bound to the tenant with a transaction-local `app.tenant_id` |
| Domain events | `kernel` + `adapters-postgres` | `DomainEvent` written to `outbox` in the transaction; `hodor-worker` dispatches |
| Errors | `kernel` | Typed `DomainError` per context; `protocol-http` translates to RFC 9457 or an OAuth error |
| Time and randomness | `kernel` | `Clock` and `RandomSource` ports, replaceable in tests |
| Secrets in memory | `kernel` | `Secret<T>`: redacted `Debug`, zeroized on drop, no `Serialize` |
| Configuration | `apps/*` | Typed struct, validated at startup, injected |
| Observability | `observability` | OpenTelemetry bootstrap; spans created in `protocol-http` and in use cases |
