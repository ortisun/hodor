# hodor-audit

## Overview

The audit context: "one record per event, chained per tenant so that changing
or removing a record can be noticed" (`Cargo.toml` description). Every event
the outbox delivers becomes one audit record through `AuditHandler`; records
are hash-chained per tenant and can be verified with `AuditService::verify`.
The specification is `docs/architecture/contexts/audit.md` (`src/lib.rs`).

## Interface

- [src](./src/EGM.md): the public surface `hodor_audit::api`, the `testing`
  module, and links to `application` and `domain`.
- Port trait implemented by adapters: `AuditLog` (implemented in
  `crates/adapters-postgres/src/audit.rs`).
- Service entry points: `AuditService` (`record`, `list`, `page`, `verify`)
  and `AuditHandler`, a `hodor_kernel::EventHandler` named `"audit"`.
- Domain events: none; this context records the events of the others.

### Workspace dependencies (`Cargo.toml`)

- `hodor-kernel` (`crates/kernel`): units of work, event envelopes, event
  handler, errors, clock, digest, paging.
- External: `async-trait`, `serde_json`, `time`.

### Feature

- `testing = ["hodor-kernel/testing"]`: enables `src/testing.rs`, the
  in-memory log and its contract suite.

## Invariants

- A record is appended under the locked chain head in the caller's unit of
  work, so it exists if and only if that unit of work commits
  (`src/application/service.rs:AuditService::record`).
- The chain hash starts with the separator `hodor.audit.v1` and covers the
  record's contents and the previous hash (`src/domain/record.rs`).
- Details per directory are in [src](./src/EGM.md).

## Side Effects

- Storage only through `AuditLog`, inside `hodor_kernel` units of work.
- Reads the clock for `recorded_at` and hashes with SHA-256 through
  `hodor_kernel::Digest`.

## Verification

- Run: `cargo test -p hodor-audit`
