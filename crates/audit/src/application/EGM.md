# audit/src/application

## Overview

The use cases of the audit context and the one storage port they need
(`mod.rs`: "Use cases of the audit context and the port they need").
`AuditService` appends one record per event to the tenant's hash chain,
lists and pages records, and verifies the chain; `AuditHandler` connects the
service to the outbox dispatcher. Both modules are `pub(crate)`; the public
names reach other crates only through `hodor_audit::api` in `../lib.rs`.

## Interface

### Port trait (`ports.rs`)

`AuditLog` (`ports.rs:AuditLog`), implemented outside this crate by
`PgAuditLog` in `crates/adapters-postgres/src/audit.rs` and, for tests, by
`InMemoryAuditLog` in `../testing.rs`. Every method works inside the tenant
the unit of work is bound to.

- `lock_head(uow) -> ChainHead`: returns the head of the tenant's chain and
  keeps it locked until the unit of work ends; a tenant with no records has
  the empty head.
- `append(uow, record)`: appends a record and makes it the head; the record
  must follow the head returned by `lock_head` in the same unit of work.
- `head(uow) -> ChainHead`: returns the head without locking it.
- `list(uow, after, limit) -> Vec<AuditRecord>`: returns up to `limit`
  records whose sequence is greater than `after`, in order.

### Service entry points (`service.rs`)

- `AuditService` (`service.rs:AuditService`), `Clone`.
  - `new(units_of_work, log, digest, clock)`.
  - `record(uow, event: &EventEnvelope) -> AuditRecord`: appends a record for
    an event inside the caller's unit of work.
  - `list(tenant, after, limit) -> Vec<AuditRecord>`.
  - `page(tenant, page: &PageRequest) -> Page<AuditRecord>`: the cursor is the
    decimal sequence of the last record on the previous page.
  - `verify(tenant) -> Verification`: checks the whole chain and reports the
    first break.
- `AuditHandler` (`service.rs:AuditHandler`), `Clone`: `new(service)`;
  implements `hodor_kernel::EventHandler` with `name()` `"audit"`,
  `handles(_)` always `true`, and `handle(uow, event)` calling
  `AuditService::record`.

## Invariants

- `AuditLog::append` must return `Conflict` if the event was already
  recorded or the sequence is taken (`ports.rs:AuditLog::append`).
- `record` returns `Invalid` code `audit.foreign_event` when the event's
  tenant is not the unit of work's tenant; it then calls `lock_head`, builds
  the record with `AuditRecord::next` from that head, and calls `append` in
  the same unit of work, so the record exists if and only if the unit of
  work commits (`service.rs:AuditService::record`).
- `AuditHandler` runs in the transaction that marks the event delivered, so
  an event is recorded once, never zero times and never twice
  (`service.rs:AuditHandler` comment).
- `list` clamps `limit` to the range 1 to `MAX_PAGE` (200)
  (`service.rs:MAX_PAGE`, `service.rs:AuditService::list`).
- `page` returns `Invalid` code `request.cursor_invalid` for a cursor that is
  not a decimal sequence (`service.rs:AuditService::page`).
- `verify` reads records in pages of `VERIFY_PAGE` (500), reads every record
  the tenant has rather than only those up to the head, and repeats while the
  head moves ahead; a broken chain is an `Ok` result, and only storage
  failures are errors (`service.rs:VERIFY_PAGE`, `service.rs:AuditService::verify`).

## Side Effects

- `record` calls `AuditLog::lock_head` and `AuditLog::append` on the caller's
  unit of work, reads `hodor_kernel::Clock::now` for `recorded_at`, and
  hashes through `hodor_kernel::Digest` (`service.rs:AuditService::record`).
- `list`, `page` and `verify` each open a unit of work through
  `UnitOfWorkFactory::begin` and call `AuditLog::list` (and, for `verify`,
  `AuditLog::head`) (`service.rs:AuditService`).

## Verification

- Run: `cargo test -p hodor-audit`
