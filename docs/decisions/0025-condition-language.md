# Decision 0025: Conditions are Common Expression Language, interpreted by the `cel` crate in a crate of their own

Status: Accepted (made for Issue-74; the project owner asked for the feature, not for this choice)

## Context

Issue-74 adds attribute-based access control to the native engine. A role's permission may carry a **condition** that must hold for that permission to allow: an expression over the subject, the resource, the action and the moment. The [authorization architecture](../architecture/authorization.md#native-engine) names the language, Common Expression Language, and its properties: compiled when published, no input or output, bounded cost. It left the interpreter to a spike.

The spike looked at what Rust offers in November 2026:

| | `cel` 0.16 (cel-rust) | `cel-core` 0.5 | `cel-cxx` 0.2 | `cel-interpreter` 0.10 |
|---|---|---|---|---|
| What it is | Parser and interpreter in Rust, the most used | Parser, type checker and interpreter in Rust, after cel-go's design | Bindings to Google's C++ implementation | The former name of `cel`, no longer released |
| Conformance | The language of the specification, with its standard functions and macros; no static type checking | Type checking against declared variables | Google's own implementation | Older `cel` |
| Maintenance | Active, several releases a year | One small team, few users | One person; follows cel-cpp | Abandoned |
| License | MIT; its parser runtime `antlr4rust` is BSD-3-Clause | MIT or Apache-2.0 | Apache-2.0, plus cel-cpp's build | MIT |
| Bounding a run | An iteration budget across every comprehension of one run, and an interrupt with a deadline, polled while iterating; a limit on the parser's nesting | Nothing | Iteration budget of cel-cpp | Nothing |
| Compile once, run many | `Env::compile` gives a `Program` that can run any number of times with different variables | Yes | Yes | Yes |
| Weight | About 50 crates with only the `regex` feature, all Rust | Small, all Rust | A C++ toolchain and cel-cpp's dependencies in the image | — |

## Decision

- **The interpreter is `cel` 0.16**, at an exact version, with only the `regex` feature. It is the one that can bound a run: its iteration budget and its deadline are what make "bounded cost" true for any expression. Its regular expressions are those of the `regex` crate, which run in linear time.
- **Without its `chrono` feature**, because `chrono` and `chrono-tz` are unmaintained (RUSTSEC-2026-0543 and RUSTSEC-2026-0555) and would ship in the server. So conditions have no timestamp or duration type, and the moment is given as **RFC 3339 text in UTC, to the second**, such as `2024-10-04T00:00:00Z`. Every moment has the same shape, so comparing the text compares the moments: `context.time < "2025-01-01T00:00:00Z"`.
- **It lives in its own crate, `hodor-authorization-native`**, already named in the architecture test's rules (kernel and `hodor-authorization` only). The authorization context declares a port, `ConditionLanguage`, and knows nothing of the interpreter; the native engine and `RoleService` use the port. A context's own tests use a fake language.
- **What the interpreter lacks, Hodor checks when a condition is published**, by walking the parsed expression:
  - the only variables are `subject`, `resource`, `action` and `context`;
  - no message literal (a CEL `Struct`), since conditions have no message types;
  - at most 256 nodes, and comprehensions (`all`, `exists`, `exists_one`, `map`, `filter`) nested at most two deep. A condition beyond those is refused as too costly.
- **Every run is bounded**: at most 1000 iterations across its comprehensions, and a deadline of 10 milliseconds or what is left of the engine's time limit, whichever comes first. A run that goes past either, fails in any other way, or gives anything but a boolean, makes the decision `indeterminate`.
- **No static type checking.** An expression that names an attribute a request does not carry fails when it runs, and the decision is `indeterminate`, never `allow`. Conditions guard such attributes with `has(…)`.

## Consequences

- Conditions are portable to other Common Expression Language implementations, since only the standard language is offered: no function of Hodor's own.
- A condition on the time of day is written with a regular expression over the text, such as `context.time.matches("T(09|1[0-6]):")` for nine to five in UTC; on the day of the week it cannot be written yet. When `cel` can do without `chrono`, or `chrono` is maintained again, `context.time` can become a timestamp and the text stay as another variable.
- A condition that type checking would have refused is caught only when it runs, as `indeterminate`. If `cel` or `cel-core` gains a checker that can be bounded too, it can be added to publishing without changing what is stored.
- The image carries an ANTLR parser runtime. If its weight starts to matter, `cel` has a feature for a hand-written parser (`parser_pratt`) to try.
- An upgrade of `cel` may change what parses. Stored conditions are compiled again when the native engine loads them; one that no longer compiles makes the decisions it would take part in `indeterminate`, so an upgrade can deny, never allow.

## Alternatives considered

- **`cel-core`, for its type checker.** Nothing bounds a run, and a bound is a requirement while type checking is not. Fewer people use it.
- **`cel-cxx`, Google's implementation through bindings.** The most conformant, but it brings a C++ toolchain into the build and the image, and code outside Rust's memory safety into the decision path.
- **The interpreter directly in `hodor-authorization`.** Simpler wiring, but it would make every user of the context carry a parser runtime, and tie the context's types to one interpreter.
- **A small expression language of Hodor's own.** It would need its own parser and its own documentation, and conditions could not be shared with other engines.
