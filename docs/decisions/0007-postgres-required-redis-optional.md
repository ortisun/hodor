# Decision 0007: PostgreSQL is required; Redis is optional

Status: Proposed

## Context

The stack lists Redis as optional. If any feature silently needs it, "optional" is false and small installations pay for a second stateful system.

## Decision

- PostgreSQL holds all durable and all correctness-relevant state, including sessions, single-use artifacts, the outbox and the job queue.
- Every port that Redis can serve has a non-Redis implementation: in-memory (per node) for caches and rate limits, PostgreSQL for replay caches and the token deny-list.
- Redis, when configured, provides shared rate-limit counters, shared caches with pub/sub invalidation, and faster replay checks.
- Nothing stored in Redis is a source of truth; losing it costs performance only.
- The contract test suites run against both implementations.

## Consequences

- A single-node install is one binary and one database.
- Without Redis, rate limits are per node (effective limit multiplies by replica count) and caches rely on short lifetimes. This is documented, and Redis is recommended above one replica.
- Job and outbox processing on PostgreSQL (`SKIP LOCKED`) is sufficient for the expected volume; a broker can be added behind the same ports if it stops being so.

## Alternatives considered

- **Redis required**: better defaults for clusters, worse for adoption and operations.
- **Sessions in Redis only**: loses sessions on eviction or failover and complicates revocation guarantees.
