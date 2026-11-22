# audit/src

## Overview

The source root of the `hodor-audit` crate. `lib.rs` describes the context:
it "keeps the record of what happened: every event any context announces
becomes one audit record, written once and never changed. The records of a
tenant are chained, so that changing or removing one of them can be
noticed." The specification it follows is `docs/architecture/contexts/audit.md`
(`lib.rs` crate comment).

The modules `application` and `domain` are private; other crates use only
`pub mod api`.

## Interface

### `lib.rs: pub mod api`

- `AuditLog` (port trait), `AuditHandler`, `AuditService`, `AuditRecord`,
  `ChainBreak`, `ChainHead`, `Verification`, `Verifier`.

### `testing.rs` (public test support)

Compiled only under `#[cfg(any(test, feature = "testing"))]` (`lib.rs`), that
is, with the crate feature `testing`.

- `InMemoryAuditLog` (implements `AuditLog`), with `tamper` and `remove` to
  alter stored records for verification tests.
- `Ports { units_of_work, log }`, `sample_event(tenant, action, number)`,
  `run_contract(ports)`.

### Subdirectories

- [application](./application/EGM.md): `AuditService`, `AuditHandler` and the
  `AuditLog` port.
- [domain](./domain/EGM.md): `AuditRecord`, `ChainHead`, `ChainBreak`,
  `Verification` and `Verifier`.

## Invariants

- The contract suite `testing.rs:run_contract` states what every `AuditLog`
  must do: a tenant with no records has `ChainHead::EMPTY`; records come back
  exactly as appended, in order, with sequences 1, 2, 3 and so on; `list`
  returns only records after the given sequence, capped at the limit; each
  tenant has its own chain; appending an event already recorded, or a taken
  sequence, fails with `audit.already_recorded`.

## Side Effects

- `lib.rs` has none.
- `InMemoryAuditLog` keeps records in an `Arc<Mutex<BTreeMap<..>>>`; its
  `lock_head` takes no lock (`testing.rs:InMemoryAuditLog`).
- Side effects of the use cases are listed in
  [application](./application/EGM.md).

## Verification

- Run: `cargo test -p hodor-audit`
