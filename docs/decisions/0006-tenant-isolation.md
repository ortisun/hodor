# Decision 0006: Shared schema with `tenant_id` and forced row-level security

Status: Proposed

## Context

Isolation must hold in the domain, the APIs, the database, the cache, sessions, policies and events, and the target is thousands of tenants in one cluster.

## Decision

- One database and one set of tables. Every tenant table has `tenant_id` leading its primary key and indexes; foreign keys are composite and include `tenant_id`.
- PostgreSQL row-level security is enabled and forced on every tenant table, keyed on a transaction-local setting that the adapter sets at the start of each transaction. The application role owns no tables and cannot bypass row-level security.
- In code, a `TenantContext` value is a mandatory argument of every port method on tenant data and can only be built by the request resolver, the worker's job loader and tests.
- Queries still filter by `tenant_id` explicitly; row-level security is the second line.
- Cross-tenant work uses a separate database role and distinctly named repository types available only to composition roots.
- A catalog test fails the build if a table lacks `tenant_id`, row-level security or composite keys without being on an explicit platform allow-list.
- Each tenant has its own data-encryption key; destroying it crypto-shreds the tenant's secrets.

## Consequences

- One migration run, one pool, cheap tenant creation.
- Two independent mechanisms have to fail for a cross-tenant read.
- Row-level security adds a small planning cost and requires care with connection poolers (transaction mode, `SET LOCAL`).
- Noisy-neighbor effects are handled by rate limits and quotas, not by physical separation.
- Customers needing physical isolation get a dedicated deployment.

## Alternatives considered

- **Schema per tenant**: migrations and catalog size scale with tenant count.
- **Database per tenant**: operationally unworkable as the default at the target scale.
- **Application-level filtering only**: a single forgotten predicate leaks data.
