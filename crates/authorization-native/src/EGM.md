# hodor-authorization-native source

## Overview

One file, `lib.rs`: `CelConditionLanguage` and the private `CelCondition` it compiles conditions into.

## Interface

- `CelConditionLanguage::new()` (also `Default`) builds a `cel::Env::stdlib()` with `RuntimeOptions::with_max_iterations(MAX_ITERATIONS)`.
- It implements `hodor_authorization::api::ConditionLanguage`: `compile(&Condition)` returns an `Arc<dyn CompiledCondition>`, or:
  - `authorization.condition_invalid` when `Env::compile` fails (the detail is the first line of the parser's message), the expression writes a message literal (`Expr::Struct`), it names a free variable other than `VARIABLES` (`subject`, `resource`, `action`, `context`), or calls a function whose name starts with a letter and that `Env::function` does not know;
  - `authorization.condition_too_costly` beyond `MAX_NODES` (256) nodes, or with comprehensions nested deeper than `MAX_COMPREHENSION_DEPTH` (2), as `measure` counts them.
- The compiled condition implements `CompiledCondition::holds(&ConditionInput, time_limit)`. It sets a `cel::Deadline` of `time_limit` as the context's interrupt, and binds:
  - `subject`, `resource` and `action` from the input, through `cel::to_value`;
  - `context` as a map of `attributes`, `application` (a string or `null`) and `time`: the input's `Timestamp` in UTC without its fraction of a second, as RFC 3339 text (`moment`). There is no timestamp type: `cel` is built without `chrono`, so `timestamp(…)` is an unknown function.
- Constants: `VARIABLES`, `MAX_NODES`, `MAX_COMPREHENSION_DEPTH`, `MAX_ITERATIONS` (1000).

## Invariants

- `holds` is `Ok(held)` only for `Value::Bool(held)`. A value of another type, an execution error (a missing key, a division by zero, `IterationBudgetExceeded`, `Interrupted`) or an attribute that cannot be converted is `authorization.condition_failed`.
- Operators are named with symbols in `cel` (`_==_`, `@in`, `!_`); only names starting with an ASCII letter are checked as functions.
- Comprehension variables are bound by the comprehension, not free, so `variables()` does not list them.
