# hodor-adapters-policy-check source

## Overview

One module, `lib.rs`: `OpaProcessChecker`, which runs `opa` for each check, test or simulation of a policy version.

## Interface

- `OpaProcessChecker::verified(binary, sha256, digest, limits, scratch)` reads the binary, compares its SHA-256 with `sha256` when given, and runs `opa version`, which must print `Version: 1.10.1` (`OPA_VERSION`). Anything else is `authorization.policy_checker_binary_refused`. The version is asked with a limit of its own, at least 10 seconds. Runs are made under `scratch`, or the system's temporary directory.
- `RunLimits { time, memory_mebibytes, output_bytes }`, by default 30 seconds, 256 mebibytes and 1 mebibyte.
- `CAPABILITIES`: `deploy/open-policy-agent/capabilities.json`, included in the code.
- `impl PolicyChecker for OpaProcessChecker`:
  - `check`: `opa check --strict --capabilities capabilities.json --format json policy`; exit 0 is a report with no problem, anything else the errors `opa` printed;
  - `test`: `opa test --capabilities capabilities.json --format json --timeout <limit> policy`; each result becomes a `TestResult`, failed when `fail` is true or it has an `error`. A run that fails without naming a test is a problem of its own;
  - `evaluate`: writes `simulation/simulation.rego`, package `hodor_simulation`, whose `results[i]` is `data.<package>.decision` with each input of `simulation/data.json`. It then runs `opa eval --capabilities capabilities.json --format json --data policy --data simulation data.hodor_simulation.results`. The answer of each input is its entry, or `None` where the rule is undefined. A package that is not letters, digits, `_` and `.` is refused without a run.

## Invariants

- Each run has a directory of its own, `hodor-policy-<UUID>`, made with mode 0700, holding only `capabilities.json` and the files under `policy/hodor/tenants/t<tenant>/`; it is removed when the run ends, whatever happened (`Scratch` is dropped).
- A file whose path has an empty, `.` or `..` segment is refused before anything is written.
- The child process starts with `env_clear`, then only `HOME` (the run's directory), `GOMEMLIMIT` and `GOMAXPROCS=2`; no standard input; the run's directory as its working directory; `kill_on_drop`.
- A run that takes longer than `time` is killed and reported `policy_check_timed_out`. Output beyond `output_bytes` stops the process and is reported `policy_check_output_too_large`. Neither is an `Err`: the policy did it.
- `Err` (`authorization.policy_checker_unavailable`) only when the process could not start, its output could not be read, or the directory could not be written.
- File names in a report are given relative to the tenant's tree (`relative`).

## Side Effects

- A directory under the scratch directory and a child process per run; nothing else. No network: the built-ins that would reach it are not in the capabilities file.
