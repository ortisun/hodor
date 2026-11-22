# Decision 0001: Modular monolith with clean architecture per bounded context

Status: Proposed

## Context

Hodor covers many bounded contexts with very different change rates and risk profiles. The team is small at the start, and an identity server must be simple to deploy and reason about. The specification asks for clean, hexagonal architecture and forbids premature microservices.

## Decision

- One Cargo workspace; one crate per bounded context; three binaries (`hodor-server`, `hodor-worker`, `hodor-cli`) built from the same crates.
- Each context crate has `domain`, `application` and a public `api` facade. Infrastructure lives in adapter crates that implement the ports declared in `application`.
- Dependency direction is inward only and is enforced by Cargo (a crate cannot use what it does not depend on) plus an architecture test over `cargo metadata`.
- Composition happens only in `apps/*`.

## Consequences

- One deployable, one database, local calls, real transactions.
- Boundaries are compiler-checked, which is stronger than module conventions inside one crate.
- More crates mean more `Cargo.toml` upkeep and some boilerplate at ports; compile times benefit from parallel crate builds.
- A context can later be extracted into a service by replacing its in-process facade with a client adapter, because nobody depends on its internals or shares its tables.

## Alternatives considered

- **Single crate with modules**: boundaries erode because nothing stops a `use`.
- **Microservices from the start**: distributed transactions and operational weight with no present benefit.
- **Layered crates (one `domain`, one `application`, one `infra` for everything)**: organizes by technical layer, not by context, and couples all contexts together.
