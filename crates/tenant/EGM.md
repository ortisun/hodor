# hodor-tenant

## Overview

The `hodor-tenant` crate (`Cargo.toml` description: "The tenant context:
tenants, their lifecycle and their settings."). It creates tenants, moves
them through their lifecycle, holds their policies, and lets the rest of the
system find a tenant by slug. Storage and time are reached through ports and
kernel traits.

## Interface

- Source and public surface: [src](./src/EGM.md).
- Ports implemented elsewhere: `TenantRepository` by `PgTenantRepository`
  and `TenantDirectory` by `PgTenantDirectory`, both in
  `crates/adapters-postgres/src/tenant.rs`.
- Workspace dependencies: `hodor-kernel` (`crates/kernel`), plus
  `async-trait`, `serde` and `time`.
- Feature `testing`: enables the public `testing` module and
  `hodor-kernel/testing`.
- Dev dependencies: `hodor-kernel` with `testing`, the crate itself with
  `testing`, `proptest`, `tokio`, `serde_json`.

## Invariants

- Only the `api` module is public to other crates; see
  [src](./src/EGM.md).
- `TenantDirectory` is the only port not bound to a tenant; every
  `TenantRepository` call is scoped to the unit of work's tenant (see
  [application](./src/application/EGM.md)).
- Lifecycle transitions, slug rules and settings bounds live in the domain
  (see [domain](./src/domain/EGM.md)).

## Side Effects

- Through `TenantRepository`: reads and writes tenants with optimistic
  versioning. Through `UnitOfWork::record_event`: records `tenant.*` events in
  the unit of work each change begins.

## Verification

- Run: `cargo test -p hodor-tenant`
