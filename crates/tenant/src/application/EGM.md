# Tenant application layer

## Overview

The use cases of the tenant context and the two ports they need. Tenant
changes run inside a unit of work bound to that tenant; lookups by slug go
through the one port that is not bound to a tenant. Both modules are
`pub(crate)` in `mod.rs` and reach other crates through `crate::api`.

## Interface

### Ports (`ports.rs`)

`TenantRepository` (`#[async_trait]`, `Send + Sync`) stores and loads the
tenant aggregate inside the tenant the unit of work is bound to. Implemented
by `PgTenantRepository` in `crates/adapters-postgres/src/tenant.rs` and by
`InMemoryTenants` in [the test-support module](../EGM.md).

| Method | Signature | Documented contract |
| --- | --- | --- |
| `insert` | `(&self, uow: &mut dyn UnitOfWork, tenant: &Tenant) -> Result<(), DomainError>` | `Conflict` `tenant.slug_taken` if another tenant has the slug. |
| `get` | `(&self, uow) -> Result<Option<Tenant>, DomainError>` | Loads the tenant the unit of work is bound to. |
| `update` | `(&self, uow, tenant: &Tenant) -> Result<(), DomainError>` | The version must be the loaded one; the stored version becomes one higher. `Conflict` `tenant.modified_concurrently` on a version mismatch, `NotFound` if absent. |

`TenantDirectory` (`#[async_trait]`, `Send + Sync`) finds tenants across the
installation; it is not bound to a tenant. Implemented by `PgTenantDirectory`
in `crates/adapters-postgres/src/tenant.rs` and by `InMemoryTenants`.

| Method | Signature | Meaning |
| --- | --- | --- |
| `find_by_slug` | `(&self, slug: &str) -> Result<Option<DirectoryEntry>, DomainError>` | The entry for a slug, if a tenant has it. |
| `list` | `(&self) -> Result<Vec<DirectoryEntry>, DomainError>` | Every tenant, ordered by slug. |

`DirectoryEntry { slug: Slug, tenant_id: TenantId, status: TenantStatus }` is
what routing needs to know about a tenant.

### Service (`service.rs`)

- `CreateTenant { slug: String, display_name: String, open_registration: bool, system: bool }`;
  `slug` is ignored when `system` is `true`.
- `TenantService::new(units_of_work: Arc<dyn UnitOfWorkFactory>, tenants: Arc<dyn TenantRepository>, directory: Arc<dyn TenantDirectory>, clock: Arc<dyn Clock>)`.

| Entry point | Returns | Meaning |
| --- | --- | --- |
| `create(&self, command: CreateTenant, caller: Caller)` | `Tenant` | Creates and activates a tenant with default settings, or open registration when asked. |
| `get(&self, context: &TenantContext)` | `Tenant` | The tenant of the context. |
| `suspend(&self, context, reason: &str, caller)` | `Tenant` | Suspends and records why. |
| `reactivate(&self, context, caller)` | `Tenant` | Suspended back to active. |
| `schedule_deletion(&self, context, grace: Option<time::Duration>, caller)` | `Tenant` | Schedules deletion after a grace period. |
| `cancel_deletion(&self, context, caller)` | `Tenant` | Cancels a scheduled deletion; the tenant becomes suspended. |
| `change_settings(&self, context, settings: TenantSettings, caller)` | `Tenant` | Replaces the settings. |
| `find_by_slug(&self, slug: &str)` | `Option<DirectoryEntry>` | Delegates to `TenantDirectory::find_by_slug`. |
| `list(&self)` | `Vec<DirectoryEntry>` | Delegates to `TenantDirectory::list`. |

There is no service entry point for `Tenant::mark_deleted`.

Kernel items used (`hodor_kernel`): `Caller`, `Clock`, `DomainError`,
`EventEnvelope`, `EventMetadata`, `TenantContext`, `TenantId`, `UnitOfWork`,
`UnitOfWorkFactory`.

## Invariants

- `create` uses `Slug::system()` when `command.system` is set, otherwise
  `Slug::parse(&command.slug)?`; all domain steps (`Tenant::create`, optional
  `change_settings` with `RegistrationPolicy::Open`, `activate`) succeed with
  one `now` before a unit of work begins (`service.rs:TenantService::create`).
- `create` opens its unit of work with `TenantContext::assume(tenant.id())`,
  the freshly generated identifier, then inserts, records the events and
  commits (`service.rs:TenantService::create`).
- Every other change runs through the private `change`: begin, load
  (`tenant.not_found` if absent), apply exactly one domain change, `update`,
  record its event, commit. A domain error aborts before any write
  (`service.rs:TenantService::change`, `TenantService::load`).
- Lifecycle rules (which status allows which change, the empty-reason and
  grace-period checks) are enforced in the domain, not here.
- `Caller` is not checked for authorization in this layer; it fills
  `EventMetadata` (`actor`, `correlation_id`) only
  (`service.rs:TenantService::record`).
- `get` begins a unit of work and never commits (`service.rs:TenantService::get`).

## Side Effects

- Reads the injected `Clock`.
- Begins units of work through `UnitOfWorkFactory::begin`; reads and writes
  through `TenantRepository`; reads through `TenantDirectory` outside any
  tenant-bound unit of work.
- Records `TenantEvent` envelopes with `UnitOfWork::record_event`; nothing is
  published directly from this layer.

## Verification

- Run: `cargo test -p hodor-tenant`
