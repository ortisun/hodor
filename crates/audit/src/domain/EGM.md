# audit/src/domain

## Overview

The domain model of the audit context (`mod.rs`): the audit record, the head
of a tenant's hash chain, and the verifier that walks a chain and reports the
first break. The code is pure: hashing goes through the `hodor_kernel::Digest`
it is given, and times arrive as parameters. The module `record` is
`pub(crate)`; its public names reach other crates through `hodor_audit::api`.
This context defines no domain events of its own.

## Interface

- `ChainHead { sequence, hash }` (`record.rs:ChainHead`); `ChainHead::EMPTY`
  has sequence 0 and an all-zero hash.
- `AuditRecord` (`record.rs:AuditRecord`): `sequence` (from 1), `event_id`,
  `action` (the event type), `occurred_at`, `recorded_at`, `actor`,
  `correlation_id`, `details` (the event payload as `serde_json::Value`),
  `previous_hash`, `hash`.
  - `next(tenant, head, event, recorded_at, digest)`: the record that follows
    `head`.
  - `computed_hash(tenant, digest)`: the hash the contents give, whatever
    hash the record carries.
  - `as_head()`.
- `ChainBreak` (`record.rs:ChainBreak`): `SequenceOutOfOrder`,
  `PreviousHashMismatch`, `ContentsChanged`, `HeadMismatch`;
  `description()` gives text for an operator.
- `Verification { records, broken: Option<(u64, ChainBreak)> }`
  (`record.rs:Verification`); `is_intact()`.
- `Verifier<'a>` (`record.rs:Verifier`): `new(tenant, digest)`,
  `check(record)`, `checked()`, `is_broken()`, `finish(head) -> Verification`.

## Invariants

- Every hash starts with the domain separator `DOMAIN = b"hodor.audit.v1"`
  (`record.rs:DOMAIN`).
- `computed_hash` covers, in order: the separator, the tenant identifier,
  sequence, event identifier, action, `occurred_at` in microseconds, actor
  text (`user:<id>`, `system` or `anonymous`), correlation identifier, the
  canonical JSON of `details`, and `previous_hash`; each field is preceded by
  its length. It does not cover `recorded_at` or the record's own hash. The
  tenant is hashed but not stored in the record
  (`record.rs:AuditRecord::computed_hash`, `record.rs:actor_text`).
- Canonical JSON sorts object keys at every level and writes no whitespace
  (`record.rs:write_canonical`).
- `next` truncates `occurred_at` and `recorded_at` to the microsecond and sets
  `sequence = head.sequence + 1` and `previous_hash = head.hash`
  (`record.rs:AuditRecord::next`, `record.rs:to_the_microsecond`).
- `Verifier::check` tests the sequence, then the previous hash, then the
  contents; after the first break nothing more is checked and that break is
  kept (`record.rs:Verifier::check`). `finish` reports `HeadMismatch` at the
  head's sequence when the stored head does not match the last record
  (`record.rs:Verifier::finish`).

## Side Effects

- Hashing with `Digest::sha256` from the `hodor_kernel::Digest` passed in
  (`record.rs:AuditRecord::computed_hash`).
- No storage, network or clock access.

## Verification

- Run: `cargo test -p hodor-audit`
