# Decision 0013: Authentication flows are versioned data interpreted by one engine

Status: Proposed

## Context

The specification asks for a declarative, visual authentication flow engine with required, alternative, conditional and optional steps, versioning, simulation and validation. It is scheduled for Phase 4, but password login is needed in Phase 1. Building login twice (hard-coded now, engine later) would mean a risky rewrite of the most sensitive path.

## Decision

- From Phase 1 a login is the execution of an `AuthFlow`: a versioned, validated graph of steps stored as data. Phase 1 ships one built-in flow (`identifier → password`) and no editing API.
- A step names an `Authenticator` and a requirement type. Conditions are a small closed expression set over known facts (risk level, requested `acr`, user attributes, client, provider), not a general scripting language.
- Execution state is an `AuthTransaction` persisted server-side, so any node can continue a flow and the browser holds only a reference.
- The engine, not the authenticators, decides completion, computes `acr` and `amr`, and creates or elevates the session.
- A definition is validated before publication: reachable completion, no dead steps, every path reaches the tenant's minimum assurance, no cycle without an exit.
- Published versions are immutable; running transactions finish on the version they started with.
- Simulation runs the same interpreter with fake authenticators.
- The visual editor is a client of the flow API and is built last.

## Consequences

- One code path for authentication from the first release; later phases add authenticators and conditions, not a new mechanism.
- Phase 1 carries some engine complexity before it is visibly needed.
- The closed condition language limits expressiveness on purpose; custom logic goes into WebAssembly authentication actions.

## Alternatives considered

- **Hard-coded flows with configuration flags**: quick, but every new combination is code, and step-up becomes special-cased.
- **General scripting for flows**: maximal flexibility, minimal analyzability; validation and simulation become impossible to guarantee.
- **Client-driven flows (user interface decides the next step)**: moves security decisions to the browser.
