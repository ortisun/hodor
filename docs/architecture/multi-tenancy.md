# Multi-tenant isolation strategy

## Model

The specification uses *tenant* and *organization* in overlapping ways and also asks for "global users with memberships in multiple organizations". This design fixes the meaning ([ADR-0005](../adr/0005-tenant-and-organization.md)):

- A **tenant** is the hard isolation boundary: its own issuer, signing keys, users, clients, IdPs, policies, sessions and audit trail. A user belongs to exactly one tenant.
- An **organization** lives inside a tenant and models a B2B customer. A user of the tenant may be a member of many organizations. This is what "global users with multiple memberships" maps to: global *within the tenant*.
- **Cross-tenant access** is federation: tenant A registers tenant B as an OIDC identity provider. No row is ever shared across tenants.
- The **`system` tenant** holds platform administrators. Platform operations (create tenant, suspend tenant, platform health) are a separate API with separate permissions; a platform administrator has no standing access to a tenant's data and gains it only through an audited, time-boxed support grant issued by that tenant or by break-glass.

```mermaid
flowchart TB
    subgraph platform["Holdor installation"]
        sys["system tenant<br/>platform admins"]
        subgraph t1["Tenant acme"]
            u1["Users"]
            o1["Organization: Contoso"]
            o2["Organization: Fabrikam"]
            c1["Clients, IdPs, policies, keys"]
        end
        subgraph t2["Tenant globex"]
            u2["Users"]
            c2["Clients, IdPs, policies, keys"]
        end
    end
    u1 --- o1
    u1 --- o2
    t2 -. "federation: globex trusts acme as IdP" .-> t1
```

## Tenant resolution

A request's tenant is resolved once, in the first middleware, from the URL and nothing else:

1. A verified custom domain (`login.acme.com`) → tenant.
2. Otherwise the path prefix `/t/{slug}`.

The resolved `TenantContext` (tenant ID, status, settings snapshot) is placed in the request extensions. Every credential presented later in the request (session cookie, access token, client credentials, API key) is looked up *within that tenant* and rejected if it belongs to another. A tenant identifier in a body, header or query parameter is never trusted.

### Shared host caveat

Tenants addressed by path on one host share a browser origin. Cookie `Path` and URL prefixes do not isolate them from each other in the browser: a script running under one tenant's pages could issue requests to another tenant's paths. Holdor therefore never serves tenant-supplied HTML or JavaScript, and themes are restricted to declarative tokens and vetted assets. Tenants that need custom scripts, or whose administrators are mutually untrusted at the browser level, must use a dedicated host (custom domain or `{slug}.` subdomain), which is the recommended production setup.

## Isolation by layer

| Layer | Mechanism |
|---|---|
| **Types** | `TenantContext` is a required argument of every port method on tenant data. It cannot be constructed outside the resolver middleware, the worker's job loader and tests. Aggregates carry `tenant_id`; loading one under another tenant's context is `NotFound` |
| **Database** | Every tenant table has `tenant_id uuid not null` as the leading column of its primary key and indexes. **Row-Level Security** is enabled and forced: `USING (tenant_id = current_setting('app.tenant_id')::uuid)`. The adapter runs `SET LOCAL app.tenant_id` at the start of each transaction. The application role does not own the tables and has no `BYPASSRLS` |
| **Foreign keys** | Composite, `(tenant_id, id)`, so a row cannot reference another tenant's row even by mistake |
| **Uniqueness** | Scoped by tenant: `(tenant_id, kind, value)` for identifiers, `(tenant_id, slug)` for clients |
| **Cache** | Keys are built by one function that requires a `TenantContext`: `t:{tenant_id}:{kind}:{key}`. No raw key API is exposed to contexts |
| **Sessions and cookies** | Session lookup is `(tenant_id, hash)`. On the shared host, cookies are scoped by `Path=/t/{slug}`; on custom domains, by host |
| **Tokens** | `iss` is the tenant issuer; validation rejects a token whose `iss` is not the request's tenant. Signing keys are per tenant |
| **Keys and secrets** | One data-encryption key per tenant, wrapped by the `KeyProvider`. Deleting the tenant's key makes its secrets unrecoverable (crypto-shredding) |
| **Policies** | Native policies are rows under RLS. OPA: per-tenant bundles; tenant-authored Rego only in a dedicated OPA ([authorization.md](authorization.md#tenant-isolation-in-opa)) |
| **Events and jobs** | Every outbox row and job carries `tenant_id`; the worker rebuilds a `TenantContext` before running a handler. Webhook endpoints belong to a tenant and only receive its events |
| **Audit** | Per-tenant hash chain; queries are tenant-scoped; platform-level events go to the `system` tenant |
| **Rate limits and quotas** | Counters keyed by tenant first, so one tenant cannot exhaust another's budget; global limits protect the platform |
| **Observability** | `tenant_id` is a span and log attribute, not a metric label by default (cardinality); per-tenant metrics are opt-in for a bounded set |
| **Frontends** | Branding assets are served per tenant; user-supplied HTML is not allowed in themes; CSP is per tenant origin |

RLS is defence in depth, not the primary control: queries always filter by `tenant_id` explicitly. The combination means a missing `WHERE` clause returns nothing instead of another tenant's data.

### Cross-tenant operations

A few operations legitimately span tenants: tenant resolution by slug or domain, platform listing of tenants, the outbox dispatcher, cleanup jobs and migrations. They use a separate database role (`holdor_platform`) and separate repository types whose names say so (`PlatformTenantDirectory`). Only the composition roots can construct them, and a CI test fails if a context crate references them.

## Why shared schema with RLS

| Option | Isolation | Operations at 10k tenants | Decision |
|---|---|---|---|
| Shared schema + `tenant_id` + RLS | Strong with discipline, enforced by the database | One migration, one pool | **Chosen** |
| Schema per tenant | Stronger by default | Migrations × tenants; catalog bloat; pool per search path | Rejected |
| Database per tenant | Strongest | Not viable as a default at this scale | Possible later as a dedicated-deployment tier |

Large or regulated customers who need physical isolation get a dedicated Holdor deployment, which the single-binary design makes cheap. See [ADR-0006](../adr/0006-tenant-isolation.md).

## Tenant lifecycle

```mermaid
stateDiagram-v2
    [*] --> Provisioning: create
    Provisioning --> Active: keys generated, admin invited, default flow and roles seeded
    Active --> Suspended: operator or billing action
    Suspended --> Active: reactivate
    Active --> PendingDeletion: delete requested
    Suspended --> PendingDeletion: delete requested
    PendingDeletion --> Active: cancelled within the grace period
    PendingDeletion --> Deleted: grace period over, rows purged, keys destroyed
    Deleted --> [*]
```

A suspended tenant keeps its data but refuses authentication, token issuance and API calls with a distinct error. Deletion is a worker job that purges table by table, destroys the tenant's keys and leaves a tombstone audit record in the `system` tenant.

## Validation

Tenant isolation is part of the definition of done, so it is tested mechanically:

- **Generic repository test**: for every repository, create a row under tenant A and assert that every read and write under tenant B fails as not found.
- **RLS test**: connect as the application role without setting `app.tenant_id` and assert every tenant table returns zero rows and rejects inserts.
- **Schema lint**: a test inspects the catalog and fails if a table lacks `tenant_id`, RLS or a composite foreign key, unless it is on the short platform allow-list.
- **API fuzz**: replay each authenticated request of tenant A against tenant B's URL prefix and assert rejection.
- **Token cross-use**: tokens, codes, sessions and refresh tokens issued by A are rejected at B.
