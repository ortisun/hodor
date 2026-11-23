# hodor-authorization-native

## Overview

The `hodor-authorization-native` crate (`Cargo.toml` description: "Conditions of the native engine in Common Expression Language, over the cel crate."). It provides `CelConditionLanguage`, the implementation of the `ConditionLanguage` port of [the authorization context](../authorization/EGM.md): it checks and compiles the conditions a role's permission carries, and runs them for the native engine. The authorization context knows nothing of the interpreter (Decision 0025). Specified in `docs/architecture/contexts/authorization.md`, "Conditions".

## Interface

- Source and public surface: [src](./src/EGM.md).
- Workspace dependencies: `hodor-kernel` and `hodor-authorization`, as the architecture test allows for this crate (`tests/architecture/src/lib.rs`, layer 3), plus `cel` at exactly 0.16.0 with only the `regex` feature (not `chrono`, which is unmaintained), `serde`, `serde_json` and `time`.
- Used by `apps/hodor-server`, which gives a `CelConditionLanguage` to the `NativeEngine` it registers.
- Dev dependencies: `async-trait`, `hodor-authorization` and `hodor-kernel` with `testing`, `tokio`.

## Invariants

- A condition is checked when it is compiled: the variables, the absence of message literals, the size, the nesting of comprehensions and the functions; see [src](./src/EGM.md).
- A run is bounded by an iteration budget and a deadline, and gives `Ok` only for a boolean; everything else is `authorization.condition_failed`.

## Verification

- Run: `cargo test -p hodor-authorization-native`. The unit tests cover compiling and running; `tests/conditions.rs` runs conditions through `RoleService` and `EvaluationService` with the native engine on the in-memory stores. No container is needed.
