# Decision 0005: Tenant is the isolation boundary; organizations live inside it

Status: Proposed

## Context

The specification lists Tenant, Organization, Organization Unit, Department and Group as multi-tenancy entities, places Organizations under Identity Management as well, requires tenant isolation in every layer, and also asks for "global users with memberships in multiple organizations". Read literally, a user that spans isolation boundaries contradicts the isolation requirement.

## Decision

- **Tenant** is the only hard isolation boundary: issuer, keys, users, clients, identity providers, policies, sessions, audit. It is owned by the `tenant` context. A user belongs to exactly one tenant.
- **Organization** is a B2B structure inside a tenant, owned by the `identity` context. A user may be a member of many organizations of its tenant. "Global user" means global within the tenant.
- **Organization Unit** is a tree inside an organization. **Department** is a unit with `kind = department`, not a separate entity.
- **Group** is a tenant-level collection of users, independent of organizations.
- Tokens can carry an organization context (`org_id` claim) selected at login or requested by the client; roles can be scoped to an organization.
- **Cross-tenant access** is federation: one tenant registers another as an OpenID Connect identity provider. No shared rows.
- A **`system` tenant** holds platform administrators; platform operations are a separate API. Platform administrators have no standing access to tenant data.

## Consequences

- Isolation rules are simple: everything except the tenant directory is tenant-scoped.
- A SaaS vendor uses one tenant with many organizations; an operator hosting unrelated customers uses one tenant per customer.
- A person working for two unrelated tenants has two accounts, optionally joined by federation. This is deliberate.
- Avoids the pattern where a master realm's administrators implicitly control every other realm.

## Alternatives considered

- **Truly global users shared across tenants**: breaks isolation of identifiers, credentials, audit and deletion; makes per-tenant policy (password, multi-factor authentication) ambiguous.
- **Organization as the isolation boundary, no tenant**: cannot give organizations separate issuers and keys without reinventing tenants.
