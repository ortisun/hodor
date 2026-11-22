# hodor-tenant source

## Overview

The tenant context: tenants are the hard isolation boundary of Hodor. It
owns which tenants exist, whether a tenant may serve requests, and which
policies apply inside it (`lib.rs` crate documentation). The specification it
follows is `docs/architecture/contexts/tenant.md`.

`lib.rs` keeps `application` and `domain` private and exposes the public
surface through `pub mod api`.

## Interface

- `api` re-exports:
  - Ports: `TenantRepository`, `TenantDirectory`, `DirectoryEntry`.
  - Service: `TenantService`, `CreateTenant`.
  - Event: `TenantEvent`.
  - Domain: `Tenant`, `TenantSnapshot`, `TenantStatus`, `Slug`,
    `TenantSettings`, `PasswordPolicy`, `SessionPolicy`, `LockoutPolicy`,
    `RegistrationPolicy`.
  - From the kernel: `hodor_kernel::Caller`.
- `testing` (public test-support module, compiled only under
  `#[cfg(any(test, feature = "testing"))]`; the `testing` feature enables
  `hodor-kernel/testing`):
  - `InMemoryTenants`: implements both `TenantRepository` and
    `TenantDirectory` over a shared `Arc<Mutex<BTreeMap<TenantId, Tenant>>>`.
  - `Ports<'a> { units_of_work, tenants, directory }` and
    `run_contract(ports: Ports<'_>, prefix: &str)`: the contract both the
    in-memory fake and the PostgreSQL adapter run (module documentation);
    `prefix` keeps slugs apart when runs share a database.
- Subdirectories:
  - [application](./application/EGM.md): `TenantRepository` and
    `TenantDirectory` ports and `TenantService` use cases.
  - [domain](./domain/EGM.md): `Tenant` lifecycle, `Slug` rules,
    `TenantSettings` bounds and `TenantEvent`.

## Invariants

- Other crates may use only what `api` re-exports (`lib.rs`).
- The contract (`testing.rs:run_contract`) requires that a stored tenant
  loads back unchanged; a slug can be taken once (`tenant.slug_taken`); a
  tenant is invisible from another tenant's unit of work; an update raises
  the version by one; a stale update fails with
  `tenant.modified_concurrently`; an update from another tenant fails with
  `tenant.not_found`; the directory follows status changes and lists by slug.
- `InMemoryTenants::insert` rejects a unit of work bound to a different
  tenant with an internal `tenant.context_mismatch` error.

## Side Effects

- None at the crate root. The `testing` module mutates in-process memory
  only.

## Verification

- Run: `cargo test -p hodor-tenant`
